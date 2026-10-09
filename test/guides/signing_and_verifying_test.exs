defmodule RequestSeal.GuideSigningAndVerifyingTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
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
    assert RequestSeal.Policy.valid?(Keyword.fetch!(binding, :policy))
    code = ~S'
now = System.system_time(:second)
nonce = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)

input =
  Enum.join(
    [
      ~s[("@method" "@authority" "@path" "content-digest")],
      "created=#{now}",
      "expires=#{now + 60}",
      ~s[nonce="#{nonce}"],
      ~s[keyid="demo-key"],
      ~s[alg="ed25519"]
    ],
    ";"
  )

{:ok, signed} =
  RequestSeal.sign(
    message,
    %{label: "sig", signature_input: input, algorithm: "ed25519"},
    signer,
    []
  )
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
    verification = Keyword.fetch!(binding, :verification)
    assert verification.signature.crypto == :valid
    assert verification.authorization == :not_evaluated
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
    result = Keyword.fetch!(binding, :result)
    assert result.count == 1
    assert result.required == [:sender]
    assert result.satisfied == [:sender]
    assert result.signatures["sig"].signature.crypto == :valid
    E.assert_rejected_signature(binding)
    assert is_list(binding)
  end
end
