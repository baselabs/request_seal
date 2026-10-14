defmodule RequestSeal.GuideErrorsTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography" do
    binding = []

    binding =
      E.eval(
        ~S'''
        log_fields = fn
          %RequestSeal.Error{} = error ->
            %{reason: error.reason, layer: error.layer, detail: error.detail, correlation: error.correlation}

          %RequestSeal.Adapter.Error{} = error ->
            %{reason: error.reason, adapter: error.adapter, stage: error.stage, correlation: error.correlation}

          %{reason: reason} ->
            %{reason: reason}
        end
        ''',
        binding,
        "docs/guides/errors.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        {:ok, key} = RequestSeal.Custody.public_key(handle)
        {:ok, store} = RequestSeal.Replay.ETS.start_link(max_entries: 1_000)
        components = ~s[("@method" "@scheme" "@authority" "@path" "content-digest")]
        now = System.system_time(:second)

        signing = %{
          label: "sig",
          algorithm: "ed25519",
          components: components,
          expires_in: 60,
          keyid: "docs-key"
        }

        build = fn url, body ->
          RequestSeal.Message.request("PUT", url, [], body, digest: ["sha-256"])
        end

        {:ok, message} = build.("https://files.example.com/reports/q3.pdf", "report bytes")
        {:ok, signed} = RequestSeal.sign(message, signing, handle, clock: fn -> now end)

        policy_fields = %{
          algorithms: ["ed25519"],
          components: components,
          key_resolver: fn
            %{keyid: "docs-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
            _ -> :error
          end,
          freshness: %{clock: fn -> now end, max_age: 60, skew: 5, require_expires: true},
          content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
          replay: %{
            identifier: :nonce,
            namespace: "errors-guide",
            commitment: fn facts -> {:ok, facts.identifier} end,
            store: RequestSeal.Replay.ETS.store(store),
            timeout: 5_000
          }
        }

        {:ok, policy} = RequestSeal.Policy.new(policy_fields)
        ''',
        binding,
        "docs/guides/errors.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        headers = Enum.map(signed.fields, &{&1.name, &1.value})
        {:ok, other_path} = RequestSeal.Message.request("PUT", "https://files.example.com/reports/q4.pdf", headers, "report bytes")
        {:ok, other_body} = RequestSeal.Message.request("PUT", "https://files.example.com/reports/q3.pdf", headers, "edited bytes")
        {:ok, uncovered} = build.("https://files.example.com/reports/q3.pdf", "report bytes")

        {:ok, uncovered} =
          RequestSeal.sign(uncovered, %{signing | components: ~s[("@method" "@scheme" "@authority" "@path")]},
            handle, clock: fn -> now end)

        {:ok, nonceless} = build.("https://files.example.com/reports/q3.pdf", "report bytes")
        {:ok, nonceless} = RequestSeal.sign(nonceless, Map.put(signing, :nonce, nil), handle, clock: fn -> now end)

        policy_with = fn changes ->
          {:ok, changed} = RequestSeal.Policy.new(Map.merge(policy_fields, changes))
          changed
        end

        at = fn clock -> %{policy_fields.freshness | clock: fn -> clock end} end

        cases = [
          {"path changed", other_path, policy, :crypto, :invalid_signature},
          {"body changed", other_body, policy, :content, :digest_mismatch},
          {"after expiry", signed, policy_with.(%{freshness: at.(now + 120)}), :freshness, :expired},
          {"before created", signed, policy_with.(%{freshness: at.(now - 600)}), :freshness, :created_in_future},
          {"older than max age", signed,
           policy_with.(%{freshness: %{at.(now + 45) | max_age: 30}}), :freshness,
           :too_old},
          {"unknown key", signed, policy_with.(%{key_resolver: fn _ -> :error end}), :key, :unknown_key},
          {"algorithm not allowed", signed, policy_with.(%{algorithms: ["ecdsa-p256-sha256"]}), :policy,
           :algorithm_not_permitted},
          {"extra coverage", signed,
           policy_with.(%{components: ~s[("@method")], extra_components: :reject}), :policy,
           :unexpected_component},
          {"digest not required or signed", uncovered, policy, :policy, :missing_required_component},
          {"digest not signed", uncovered,
           policy_with.(%{components: ~s[("@method" "@scheme" "@authority" "@path")]}), :content,
           :digest_not_covered},
          {"no nonce", nonceless, policy, :replay, :missing_replay_identifier}
        ]

        for {name, request, case_policy, layer, reason} <- cases do
          {:error, %{layer: ^layer, reason: ^reason}} = RequestSeal.verify(request, case_policy, label: "sig")
          {name, reason}
        end

        {:error, %{layer: :fields, reason: :unknown_label}} = RequestSeal.verify(signed, policy, label: "other")
        {:ok, _first} = RequestSeal.verify(signed, policy, label: "sig")
        {:error, %{layer: :replay, reason: :replayed}} = RequestSeal.verify(signed, policy, label: "sig")
        ''',
        binding,
        "docs/guides/errors.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        :ok = RequestSeal.Custody.Local.release(handle)

        {:error, %{reason: :signing_failed, layer: :crypto, source: %{reason: :key_not_found}}} =
          RequestSeal.sign(message, signing, handle)

        GenServer.stop(store)
        ''',
        binding,
        "docs/guides/errors.md",
        4
      )

    log_fields = Keyword.fetch!(binding, :log_fields)

    error = %RequestSeal.Error{
      reason: :expired,
      layer: :freshness,
      correlation: "0123456789abcdef"
    }

    assert log_fields.(error) == %{
             reason: :expired,
             layer: :freshness,
             detail: nil,
             correlation: "0123456789abcdef"
           }

    assert length(Keyword.fetch!(binding, :cases)) == 11
    E.assert_fences("docs/guides/errors.md", 4)
  end
end
