defmodule RequestSeal.GuideReplayProtectionTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  setup_all do
    binding = []

    binding =
      E.eval(
        ~S'''
        {_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        {:ok, key} = RequestSeal.Custody.public_key(handle)
        {:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
        signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
        ''',
        binding,
        "docs/guides/replay-protection.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, message} =
          RequestSeal.Message.request(
            "POST",
            "https://api.example.com/webhooks",
            [],
            ~s({"event":"created"})
          )
        ''',
        binding,
        "docs/guides/replay-protection.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        {:ok, policy} =
          RequestSeal.Policy.new(%{
            algorithms: ["ed25519"],
            components: ~s[("@method" "@scheme" "@authority" "@path" "content-digest")],
            key_resolver: fn
              %{keyid: "demo-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
              _ -> :error
            end,
            freshness: %{
              clock: fn -> System.system_time(:second) end,
              max_age: 60,
              skew: 5,
              require_expires: true
            },
            content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
            replay: :not_required
          })
        ''',
        binding,
        "docs/guides/replay-protection.md",
        3
      )

    assert RequestSeal.Policy.valid?(Keyword.fetch!(binding, :policy))

    binding =
      E.eval(
        ~S'''
        signing = %{
          label: "sig",
          algorithm: "ed25519",
          components: ~s[("@method" "@scheme" "@authority" "@path" "content-digest")],
          expires_in: 60,
          keyid: "demo-key",
          digest: ["sha-256"]
        }

        {:ok, signed} = RequestSeal.sign(message, signing, handle)
        ''',
        binding,
        "docs/guides/replay-protection.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        {:ok, replay_pid} = RequestSeal.Replay.ETS.start_link(max_entries: 10_000)

        replay = %{
          identifier: :nonce,
          namespace: "demo-api",
          commitment: fn facts -> {:ok, facts.identifier} end,
          store: RequestSeal.Replay.ETS.store(replay_pid),
          timeout: 5_000
        }

        {:ok, replay_policy} = RequestSeal.Policy.new(%{Map.from_struct(policy) | replay: replay})
        {:ok, accepted} = RequestSeal.verify(signed, replay_policy, label: "sig")
        ''',
        binding,
        "docs/guides/replay-protection.md",
        5
      )

    assert %RequestSeal.Replay.Receipt{} = Keyword.fetch!(binding, :accepted).replay

    binding =
      E.eval(
        ~S'''
        RequestSeal.verify(signed, replay_policy, label: "sig")
        # => {:error, %RequestSeal.Error{reason: :replayed, ...}}
        ''',
        binding,
        "docs/guides/replay-protection.md",
        6
      )

    assert {:error, %RequestSeal.Error{reason: :replayed}} =
             RequestSeal.verify(
               Keyword.fetch!(binding, :signed),
               Keyword.fetch!(binding, :replay_policy),
               label: "sig"
             )

    binding =
      E.eval(
        ~S'''
        retain_until = accepted.replay.retain_until
        RequestSeal.Replay.ETS.sweep(replay_pid, retain_until - 1)
        # => {:ok, 0}
        ''',
        binding,
        "docs/guides/replay-protection.md",
        7
      )

    example_result = Keyword.fetch!(binding, :example_result)
    assert example_result == {:ok, 0}

    binding =
      E.eval(
        ~S'''
        RequestSeal.Replay.ETS.sweep(replay_pid, retain_until)
        # => {:ok, 1}
        ''',
        binding,
        "docs/guides/replay-protection.md",
        8
      )

    example_result = Keyword.fetch!(binding, :example_result)
    assert example_result == {:ok, 1}
    E.assert_rejected_signature(binding)

    executed = Process.get({RequestSeal.DocsExamples, "docs/guides/replay-protection.md"})
    assert executed == Enum.to_list(1..8)

    on_exit(fn ->
      RequestSeal.Custody.Local.release(Keyword.fetch!(binding, :handle))
      pid = Keyword.fetch!(binding, :replay_pid)
      if Process.alive?(pid), do: GenServer.stop(pid)
    end)

    %{binding: binding, executed: executed}
  end

  test "portable replay fences execute with real cryptography and ETS", %{
    binding: binding,
    executed: executed
  } do
    assert executed == Enum.to_list(1..8)

    assert %RequestSeal.Replay.Receipt{store: RequestSeal.Replay.ETS} =
             Keyword.fetch!(binding, :accepted).replay
  end

  if Code.ensure_loaded?(AshOnetime.Transaction) do
    @tag :owned_integrations
    @tag :postgres
    test "durable replay fence uses ash_onetime", %{binding: common, executed: executed} do
      prefix = RequestSeal.OwnedDatabase.start()
      on_exit(fn -> RequestSeal.OwnedDatabase.drop(prefix) end)
      binding = common ++ [repo: RequestSeal.OwnedRepo, prefix: prefix]
      Process.put({RequestSeal.DocsExamples, "docs/guides/replay-protection.md"}, executed)

      binding =
        E.eval(
          ~S'''
          durable_store = RequestSeal.Replay.AshOnetime.store(repo,
            partition: "demo-api", prefix: prefix)
          durable_replay = %{replay | store: durable_store}
          {:ok, durable_policy} = RequestSeal.Policy.new(%{Map.from_struct(policy) | replay: durable_replay})
          {:ok, durable_accepted} = RequestSeal.verify(signed, durable_policy, label: "sig")
          ''',
          binding,
          "docs/guides/replay-protection.md",
          9
        )

      assert %RequestSeal.Replay.Receipt{store: RequestSeal.Replay.AshOnetime} =
               Keyword.fetch!(binding, :durable_accepted).replay

      E.assert_fences("docs/guides/replay-protection.md", 9)
      assert is_list(binding)
    end
  end
end
