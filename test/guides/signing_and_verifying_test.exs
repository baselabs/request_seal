defmodule RequestSeal.GuideSigningAndVerifyingTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography" do
    binding = []
    code = ~S'
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
'
    binding = E.eval(code, binding)
    code = ~S'
{:ok, message} = RequestSeal.Message.request("POST", "https://api.example.com/webhooks", [], ~s({"event":"created"}), digest: ["sha-256"])
'
    binding = E.eval(code, binding)
    code = ~S'
{:ok, response} = RequestSeal.Message.response(200, [{"content-type", "text/plain"}], "accepted", request: message, digest: ["sha-256"])
'
    binding = E.eval(code, binding)
    code = ~S'
{:ok, policy} =
  RequestSeal.Policy.new(%{
    algorithms: ["ed25519"],
    components: ~s[("@method" "@authority" "@path" "content-digest")],
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
'
    binding = E.eval(code, binding)
    code = ~S'
signing = %{
  label: "sig",
  algorithm: "ed25519",
  components: ~s[("@method" "@authority" "@path" "content-digest")],
  parameters: %{created: true, expires_in: 60, nonce: :random, alg: true, keyid: "demo-key", tag: nil},
  digest: ["sha-256"],
  field_schemas: %{}
}
{:ok, signed} = RequestSeal.sign(message, signing, handle)
'
    binding = E.eval(code, binding)
    code = ~S'
{:ok, verification} = RequestSeal.verify(signed, policy, label: "sig")
verification.signature.crypto
# => :valid
verification.authorization
# => :not_evaluated
'
    binding = E.eval(code, binding)
    code = ~S'
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
'
    binding = E.eval(code, binding)
    built_message = Keyword.fetch!(binding, :message)
    code = ~S'
{:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: ~s({"event":"created"})})
{:ok, digest} = RequestSeal.Digest.compute(body, ["sha-256"])
{:ok, digest_wire} = RequestSeal.Digest.serialize(digest)

{:ok, digest_field} =
  RequestSeal.FieldOccurrence.new(%{
    name: "content-digest",
    value: digest_wire,
    section: :headers
  })
'
    binding = E.eval(code, binding)
    code = ~S'
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
'
    binding = E.eval(code, binding)
    assert Keyword.fetch!(binding, :message) == built_message
    code = ~S'
{:ok, low_level_signed} = RequestSeal.sign(message, %{
  label: "manual", algorithm: "ed25519",
  signature_input: ~s[("@method" "@authority" "@path" "content-digest");alg="ed25519";keyid="demo-key"]
}, signer, field_schemas: %{})
'
    binding = E.eval(code, binding)
    assert Keyword.fetch!(binding, :verification).signature.crypto == :valid
    assert Keyword.fetch!(binding, :verification).authorization == :not_evaluated
    assert Keyword.fetch!(binding, :result).satisfied == [:sender]
    assert :ok = RequestSeal.Message.validate(Keyword.fetch!(binding, :low_level_signed))
    E.assert_rejected_signature(binding)
  end
end
