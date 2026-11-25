defmodule RequestSeal.Conformance.Quorum do
  @moduledoc false
  alias RequestSeal.{Conformance, Custody.Local, Policy, Quorum, Replay}
  alias RequestSeal.Conformance.Surfaces
  alias RequestSeal.SignatureFields

  @slots ~w(
    primary optional third fourth fifth sixth seventh eighth ninth tenth eleventh twelfth
  )a

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
    clock = fn -> now end

    slots =
      Enum.map(input["slots"], fn slot ->
        %{"id" => id, "keyid" => keyid, "required" => required} = slot

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
            field_schemas: schemas(slot["flags_schema"]),
            freshness: %{clock: clock, max_age: 120, skew: 0, require_expires: true},
            replay: :not_required
          })

        attrs = %{id: slot_id(id), required: required, policy: policy}
        if Map.has_key?(slot, "label"), do: Map.put(attrs, :label, slot["label"]), else: attrs
      end)

    identifier =
      case input["identifier"] do
        "shared_nonce" -> {:nonce, :shared}
        %{"operation" => ids} -> {:operation, ids}
      end

    mode =
      case input["mode"] do
        "all" -> :all
        "any" -> :any
        %{"threshold" => count} -> {:threshold, Conformance.int(count)}
      end

    policy =
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

    table = :sys.get_state(pid).table

    case policy do
      {:ok, quorum} ->
        verdict(root, input, quorum, table)

      {:error, _} = error ->
        [] = rows(table)
        error
    end
  end

  defp verdict(root, input, policy, table) do
    result = RequestSeal.verify_quorum(Surfaces.message(root, input["message"]), policy, [])

    case result do
      {:ok, verdict} ->
        [{{:claim, "corpus", commitment}, retain_until}] = rows(table)

        facts = %{
          "count" => %{"int" => Integer.to_string(verdict.count)},
          "slots" =>
            verdict.assignments |> Map.keys() |> Enum.map(&Atom.to_string/1) |> Enum.sort(),
          "commitment" => Conformance.b64(commitment),
          "retain_until" => %{"int" => Integer.to_string(retain_until)}
        }

        case input["retry"] do
          nil ->
            {:ok, facts}

          retry ->
            {:error, error} = RequestSeal.verify_quorum(Surfaces.message(root, retry), policy, [])
            [{{:claim, "corpus", ^commitment}, ^retain_until}] = rows(table)
            {:ok, Map.put(facts, "retry_rule_id", Conformance.rule_id(error))}
        end

      {:error, _} = error ->
        [] = rows(table)
        error
    end
  end

  defp rows(table), do: :ets.match_object(table, {{:claim, "corpus", :_}, :_})

  defp schemas(nil), do: %{}
  defp schemas("list"), do: %{"flags" => SignatureFields.schema(:list, [:token, :boolean])}
  defp schemas("dictionary"),
    do: %{"flags" => SignatureFields.schema(:dictionary, [:token, :boolean])}

  defp slot_id(id), do: Enum.find(@slots, &(Atom.to_string(&1) == id))
end
