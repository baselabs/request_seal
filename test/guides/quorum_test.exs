defmodule RequestSeal.GuideQuorumTest do
  use ExUnit.Case, async: true
  alias RequestSeal.DocsExamples, as: E

  test "the guide example executes with real signing and replay storage" do
    binding = []

    E.eval(
      ~S'''
      alias RequestSeal.{Custody, Message, Policy, Quorum, Replay}

      now = System.system_time(:second)
      clock = fn -> now end
      components = ~s[("@method" "@target-uri")]
      {:ok, message} = Message.request("GET", "https://api.example.test/jobs/7", [], nil)
      {:ok, store} = Replay.ETS.start_link(max_entries: 100)

      {signed, slots, handles} =
        Enum.reduce([:build, :review], {message, [], []}, fn id, {message, slots, handles} ->
          {:ok, handle} = Custody.Local.generate("ed25519", [])
          {:ok, key} = Custody.public_key(handle)
          label = Atom.to_string(id)
          spec = %{label: label, components: components, algorithm: "ed25519", expires_in: 60}
          {:ok, message} = RequestSeal.sign(message, spec, handle, clock: clock)

          {:ok, policy} =
            Policy.new(%{
              algorithms: ["ed25519"],
              components: components,
              key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
              freshness: %{clock: clock, max_age: 60, skew: 0, require_expires: true},
              content: :not_required,
              replay: :not_required
            })

          slot = %{id: id, label: label, required: true, policy: policy}
          {message, [slot | slots], [handle | handles]}
        end)

      {:ok, quorum} =
        Quorum.new(%{
          slots: slots,
          mode: :all,
          unit: :key,
          invalid: :reject,
          unexpected: :reject,
          replay: %{
            identifier: {:operation, [~s["@method"], ~s["@target-uri"]]},
            scope: :namespace,
            namespace: "jobs",
            retain_until: now + 120,
            store: Replay.ETS.store(store),
            timeout: 1_000
          }
        })

      {:ok, %Quorum.Verification{count: 2}} = RequestSeal.verify_quorum(signed, quorum, [])
      {:error, %RequestSeal.Error{reason: :replayed}} =
        RequestSeal.verify_quorum(signed, quorum, [])
      Enum.each(handles, fn handle -> :ok = Custody.Local.release(handle) end)
      :ok = GenServer.stop(store)
      ''',
      binding,
      "docs/guides/quorum.md",
      1
    )

    E.assert_fences("docs/guides/quorum.md", 1)
  end
end
