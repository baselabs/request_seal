defmodule RequestSeal.GuideSigningAndVerifyingTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography" do
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
        "docs/guides/signing-and-verifying.md",
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
            ~s({"event":"created"}),
            digest: ["sha-256"]
          )
        ''',
        binding,
        "docs/guides/signing-and-verifying.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        {:ok, response} =
          RequestSeal.Message.response(200, [{"content-type", "text/plain"}], "accepted",
            request: message,
            digest: ["sha-256"]
          )
        ''',
        binding,
        "docs/guides/signing-and-verifying.md",
        3
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
        "docs/guides/signing-and-verifying.md",
        4
      )

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
        "docs/guides/signing-and-verifying.md",
        5
      )

    binding =
      E.eval(
        ~S'''
        {:ok, verification} = RequestSeal.verify(signed, policy, label: "sig")
        verification.signature.crypto
        # => :valid
        verification.authorization
        # => :not_evaluated
        ''',
        binding,
        "docs/guides/signing-and-verifying.md",
        6
      )

    binding =
      E.eval(
        ~S'''
        {:ok, quorum} =
          RequestSeal.Quorum.new(%{
            mode: :all,
            unit: :key,
            unexpected: :reject,
            invalid: :reject,
            slots: [%{id: :sender, label: "sig", required: true, policy: policy}]
          })

        {:ok, result} = RequestSeal.verify_quorum(signed, quorum, [])
        result.count
        # => 1
        result.satisfied
        # => [:sender]
        ''',
        binding,
        "docs/guides/signing-and-verifying.md",
        7
      )

    built_message = Keyword.fetch!(binding, :message)

    binding =
      E.eval(
        ~S'''
        {:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: ~s({"event":"created"})})
        {:ok, digest} = RequestSeal.Digest.compute(body, ["sha-256"])
        {:ok, digest_wire} = RequestSeal.Digest.serialize(digest)

        {:ok, digest_field} =
          RequestSeal.FieldOccurrence.new(%{
            name: "content-digest",
            value: digest_wire,
            section: :headers
          })
        ''',
        binding,
        "docs/guides/signing-and-verifying.md",
        8
      )

    binding =
      E.eval(
        ~S'''
        {:ok, transport} = RequestSeal.TransportFacts.new(%{})

        {:ok, message} =
          RequestSeal.Message.new(%{
            kind: :request,
            method: "POST",
            raw_target: "/webhooks",
            target_form: :origin,
            scheme: "https",
            authority: "api.example.com",
            fields: [digest_field],
            trailers: :unavailable,
            body: body,
            transport: transport
          })
        ''',
        binding,
        "docs/guides/signing-and-verifying.md",
        9
      )

    assert Keyword.fetch!(binding, :message) == built_message

    binding =
      E.eval(
        ~S'''
        {:ok, low_level_signed} =
          RequestSeal.sign(
            message,
            %{
              label: "manual",
              algorithm: "ed25519",
              signature_input:
                ~s[("@method" "@scheme" "@authority" "@path" "content-digest");alg="ed25519";keyid="demo-key"]
            },
            signer,
            field_schemas: %{}
          )
        ''',
        binding,
        "docs/guides/signing-and-verifying.md",
        10
      )

    assert Keyword.fetch!(binding, :verification).signature.crypto == :valid
    assert Keyword.fetch!(binding, :verification).authorization == :not_evaluated
    assert Keyword.fetch!(binding, :result).satisfied == [:sender]
    assert :ok = RequestSeal.Message.validate(Keyword.fetch!(binding, :low_level_signed))
    E.assert_rejected_signature(binding)
    E.assert_fences("docs/guides/signing-and-verifying.md", 10)
  end
end
