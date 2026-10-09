defmodule RequestSeal.ReadmeTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
    binding = []
    code = ~S'
{:request_seal, git: "https://github.com/baselabs/request_seal.git"}
'
    binding = E.eval(code, binding)
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
signing = %{
  label: "sig",
  algorithm: "ed25519",
  components: ~s[("@method" "@authority" "@path" "content-digest")],
  parameters: %{
    created: true,
    expires_in: 60,
    nonce: :random,
    alg: true,
    keyid: "demo-key",
    tag: nil
  },
  digest: ["sha-256"],
  field_schemas: %{}
}
'
    binding = E.eval(code, binding)
    binding = E.endpoint(binding, RequestSeal.DocsPipeline, RequestSeal.DocsController)
    code = ~S'
url = Application.fetch_env!(:my_app, :webhook_url)
{:ok, _pool} = Finch.start_link(name: MyApp.Finch)

request =
  Req.new(
    url: url,
    method: :post,
    json: %{"event" => "created"},
    finch: [name: MyApp.Finch],
    retry: false
  )

{:ok, request} = RequestSeal.Req.attach(request, sign: signing, signer: handle, verify: :none)
{:ok, response} = Req.request(request)
'
    binding = E.eval(code, binding)
    assert Keyword.fetch!(binding, :response).status == 200
    E.assert_received_request()
    code = ~S'
defmodule MyApp.VerifySignature do
  def init(options), do: options

  def call(conn, _options) do
    policy = Application.fetch_env!(:my_app, :http_signature_policy)

    options =
      RequestSeal.Plug.Verify.init(
        policy: policy,
        label: "sig",
        assign: :verified,
        on_reject: {:halt, 401}
      )

    RequestSeal.Plug.Verify.call(conn, options)
  end
end
'
    binding = E.eval(code, binding)
    code = ~S'
defmodule MyApp.WebhookPipeline do
  use Plug.Builder

  plug(RequestSeal.Plug.Capture,
    origin: :connection,
    max_body_bytes: 1_048_576,
    read_timeout: 5_000
  )

  plug(Plug.Parsers,
    parsers: [:json],
    pass: ["*/*"],
    json_decoder: Jason,
    body_reader: {RequestSeal.Plug.Capture, :read_body, []}
  )

  plug(MyApp.VerifySignature)
end
'
    binding = E.eval(code, binding)
    code = ~S'
defmodule MyApp.WebhookController do
  use Phoenix.Controller, formats: [:json]

  def create(conn, params) do
    {:ok, verified} = RequestSeal.Plug.verification(conn)
    json(conn, %{signature_label: verified.label, event: params["event"]})
  end
end
'
    binding = E.eval(code, binding)
    endpoint = Application.fetch_env!(:request_seal, :docs_endpoint)

    E.configure(:request_seal, :docs_endpoint, %{
      endpoint
      | pipeline: MyApp.WebhookPipeline,
        controller: MyApp.WebhookController
    })

    {:ok, response} = Req.request(Keyword.fetch!(binding, :request))
    assert response.status == 200
    E.assert_received_request()
    E.assert_rejected_request(binding)
    code = ~S'
now = System.system_time(:second)

{:ok, agent_request} =
  RequestSeal.WebBotAuth.sign(
    message,
    %{
      label: "agent",
      agent: %{location: "https://agent.example", type: :directory},
      key: key,
      algorithm: "ed25519",
      created: now,
      expires: now + 60,
      nonce: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    },
    signer
  )
'
    binding = E.eval(code, binding)
    code = ~S'
{:ok, agent_policy} =
  RequestSeal.WebBotAuth.Policy.new(%{
    algorithms: ["ed25519"],
    agents: fn _ -> :error end,
    cache: nil,
    unresolved:
      {:held_keys,
       fn
         %{keyid: ^thumbprint} -> {:ok, %{algorithm: "ed25519", key: key}}
         _ -> :error
       end},
    freshness: %{clock: fn -> System.system_time(:second) end, max_age: 60, skew: 5},
    content: :not_required,
    replay: :not_required
  })

{:ok, envelope} = RequestSeal.WebBotAuth.verify(agent_request, agent_policy)
verification = envelope.signatures["agent"]
'
    binding = E.eval(code, binding)

    assert Keyword.fetch!(binding, :verification).principal == %{
             kind: :key,
             thumbprint: Keyword.fetch!(binding, :thumbprint)
           }

    record = E.seed_documents(MyApp.Document)
    code = ~S'
{:ok, scope} =
  RequestSeal.Ash.scope(verification, %{
    actor: fn
      %{kind: :key, thumbprint: ^thumbprint} -> {:ok, %{role: :reader}}
      _ -> :error
    end,
    tenant: {:value, "demo"},
    unattributed: :reject
  })

documents = Ash.read!(MyApp.Document, scope: scope, authorize?: true)
'
    binding = E.eval(code, binding)
    E.assert_ash_read(binding, record)
    E.assert_ash_denial(binding, MyApp.Document)
    assert Protocol.consolidated?(Ash.ToTenant)
    assert Protocol.consolidated?(Ash.Scope.ToOpts)
    code = ~S'
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
'
    binding = E.eval(code, binding)
    assert %RequestSeal.Replay.Receipt{} = Keyword.fetch!(binding, :accepted).replay
    code = ~S'
RequestSeal.verify(signed, replay_policy, label: "sig")
# => {:error, %RequestSeal.Error{reason: :replayed, ...}}
'
    binding = E.eval(code, binding)

    assert {:error, %RequestSeal.Error{reason: :replayed}} =
             RequestSeal.verify(
               Keyword.fetch!(binding, :signed),
               Keyword.fetch!(binding, :replay_policy),
               label: "sig"
             )

    E.assert_rejected_signature(binding)
    assert is_list(binding)
  end
end
