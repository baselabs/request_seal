defmodule RequestSeal.Conformance.Quorum do
  @moduledoc false
  alias RequestSeal.{Conformance, Custody.Local, Policy, Quorum, Replay}
  alias RequestSeal.Conformance.Surfaces

  def verify(root, %{"inputs" => input, "now" => now}) do
    {:ok, pid} = Replay.ETS.start_link(max_entries: 8)
    now = Conformance.int(now)
    material = Conformance.read_file(root, "sources/rfc9421/keys/hmac.txt")
    {:ok, published} = material |> String.trim() |> Base.decode64()

    handles =
      Map.new(input["keys"], fn {id, source} ->
        key =
          case source do
            "published" -> published
            "derived" -> :crypto.hash(:sha256, [published, id])
          end

        {:ok, handle} = Local.new("hmac-sha256", {:hmac, key}, equivalence: id)
        {id, handle}
      end)

    try do
      run(root, input, now, pid, handles)
    after
      Enum.each(handles, fn {_, handle} -> :ok = Local.release(handle) end)
      GenServer.stop(pid)
    end
  end

  defp run(root, input, now, pid, handles) do
    slots =
      Enum.map(input["slots"], fn %{"id" => id, "keyid" => keyid, "required" => required} ->
        {:ok, policy} =
          Policy.new(%{
            algorithms: ["hmac-sha256"],
            components: input["components"],
            key_resolver: fn
              %{keyid: ^keyid} ->
                {:ok, %{key: Map.fetch!(handles, keyid), algorithm: "hmac-sha256"}}

              _ ->
                :error
            end,
            content: :not_required,
            freshness: %{clock: fn -> now end, max_age: 120, skew: 0, require_expires: true},
            replay: :not_required
          })

        %{id: slot_id(id), required: required, policy: policy}
      end)

    identifier =
      case input["identifier"] do
        "shared_nonce" -> {:nonce, :shared}
        %{"operation" => ids} -> {:operation, ids}
      end

    mode =
      case input["mode"] do
        "all" -> :all
        %{"threshold" => count} -> {:threshold, Conformance.int(count)}
      end

    {:ok, policy} =
      Quorum.new(%{
        mode: mode,
        unit: :key,
        slots: slots,
        unexpected: :reject,
        invalid: :reject,
        replay: %{
          identifier: identifier,
          scope: :namespace,
          namespace: "corpus",
          store: Replay.ETS.store(pid),
          timeout: 1000,
          retain_until: Conformance.int(input["retain_until"])
        }
      })

    result = RequestSeal.verify_quorum(Surfaces.message(root, input["message"]), policy, [])
    table = :sys.get_state(pid).table

    case result do
      {:ok, verdict} ->
        [{{:claim, "corpus", commitment}, retain_until}] =
          :ets.match_object(table, {{:claim, "corpus", :_}, :_})

        {:ok,
         %{
           "count" => %{"int" => Integer.to_string(verdict.count)},
           "slots" =>
             verdict.assignments |> Map.keys() |> Enum.map(&Atom.to_string/1) |> Enum.sort(),
           "commitment" => Conformance.b64(commitment),
           "retain_until" => %{"int" => Integer.to_string(retain_until)}
         }}

      {:error, _} = error ->
        [] = :ets.match_object(table, {{:claim, "corpus", :_}, :_})
        error
    end
  end

  defp slot_id("primary"), do: :primary
  defp slot_id("optional"), do: :optional
  defp slot_id("third"), do: :third
end
