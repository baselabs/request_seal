<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# RequestSeal

RequestSeal signs and verifies HTTP requests and responses in Elixir with RFC 9421 HTTP Message Signatures, including Web Bot Auth for AI agents and crawlers.
Drop-in integrations support Plug and Phoenix, Req and Finch, and Ash; JOSE supports JWS signing and JWE encryption.

Use it to:

- Verify signed webhooks and service-to-service calls.
- Sign outgoing API requests.
- Identify and verify AI agents and crawlers with Web Bot Auth.
- Turn a verified caller into an Ash actor and tenant.
- Protect against replayed requests.

## Why RequestSeal

- Match the standard's bytes: published RFC 9421 signature bases and cryptographic vectors are checked against the original bytes.
- Decide what to accept: you explicitly select trusted keys, algorithms, covered fields, freshness, body integrity, and replay rules.
- Reject repeated signed requests with replay protection backed by ETS or optional PostgreSQL storage.
- Keep private keys in isolated, sensitive processes or sign through your OpenSSH agent without exporting its keys.
- Bound input processing: parsers enforce byte, count, and depth limits.
- Start only what you choose: loading RequestSeal starts no processes, pools, connections, or background fetches.
- Add frameworks when you need them: optional transport adapters and the Ash protocol compile only when their dependencies are present.

## Installation

Add this entry to your `mix.exs` dependency list, then run `mix deps.get`:

```elixir
{:request_seal, git: "https://github.com/baselabs/request_seal.git"}
```

The repository is private until the first release, so the Git dependency requires access. The first release will be published to Hex. For reproducible builds, pin the Git dependency to a commit with `ref:`.

Add the optional dependencies for the integrations you use. The JSON pipeline examples also use Jason (`~> 1.0`), already included by Req and Ash; add it explicitly in a Plug-only application:

| Dependency | Requirement | Use |
| --- | --- | --- |
| `:plug` | `~> 1.20.3` | Plug and Phoenix pipelines |
| `:req` | `~> 0.7.4` | Req signing and response verification; also add Finch |
| `:finch` | `>= 0.23.0 and < 0.25.0` | Finch transport and caller-started pools |
| `:ash` | `~> 3.34` | Ash scope protocol and authorization-enabled actions |
| `:postgrex` | `~> 0.22.4` | PostgreSQL replay storage using your existing connection |

## Quick start

### Sign and verify a request

No HTTP client or server is needed. Generate an Ed25519 key for this example; in your application, reuse a key handle owned by a long-lived process and share its public key with the verifier through a trusted channel.

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
```

Retain the exact request body and compute its content digest, a checksum that the signature will cover:

```elixir
{:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: ~s({"event":"created"})})
{:ok, digest} = RequestSeal.Digest.compute(body, ["sha-256"])
{:ok, digest_wire} = RequestSeal.Digest.serialize(digest)

{:ok, digest_field} =
  RequestSeal.FieldOccurrence.new(%{
    name: "content-digest",
    value: digest_wire,
    section: :headers
  })
```

Build a request message with the method, path, origin, and digest header:

```elixir
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
```

Choose a signature label (`"sig"` links the two signature headers), fields to cover, and a 60-second validity window. The signature input joins the covered fields and parameters with semicolons:

```elixir
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
```

The verifier chooses which keys, coverage, freshness, body integrity, and replay rules to accept:

```elixir
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
```

Verify the signed message under that policy:

```elixir
{:ok, verification} = RequestSeal.verify(signed, policy, label: "sig")
verification.signature.crypto
# => :valid
verification.authorization
# => :not_evaluated
```

A valid signature does not authorize an action. [Signing and verifying](docs/guides/signing-and-verifying.md) explains results, errors, and quorum verification.

### Sign outgoing requests with Req

Reuse the key handle above. Req constructs the message and digest for you; choose how each finalized request is signed:

```elixir
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
```

Set `:webhook_url` in your application configuration to your receiving endpoint. Start a Finch pool and send the request:

```elixir
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
```

Supervise and reuse the pool in your application. `verify: :none` explicitly leaves the response unverified; [Req and Finch](docs/guides/req-and-finch.md) shows how to require signed responses.

### Verify incoming requests in Phoenix or Plug

Configure `:my_app, :http_signature_policy` with the `policy` above on your receiving application. Install this pipeline before the endpoint's existing parsers: capture the bytes, parse with the RequestSeal body reader, then verify before the controller.

```elixir
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
```

Capture and parse the body before calling the verifier:

```elixir
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
```

Route `POST /webhooks` to this controller. Only requests that pass verification reach it:

```elixir
defmodule MyApp.WebhookController do
  use Phoenix.Controller, formats: [:json]

  def create(conn, params) do
    {:ok, verified} = RequestSeal.Plug.verification(conn)
    json(conn, %{signature_label: verified.label, event: params["event"]})
  end
end
```

This verifies RFC 9421 webhook signatures; use the sender's documented scheme for other signing formats. [Phoenix and Plug](docs/guides/phoenix-and-plug.md) covers proxies, response signing, and supported components.

### Sign and verify with Web Bot Auth

Web Bot Auth identifies signed requests from agents and crawlers. Sign the `message` above with protocol-00:

```elixir
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
```

Verify against the public key's thumbprint, a hash identifying that key. This held-key policy trusts the key without attributing ownership of `agent.example`:

```elixir
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
```

To authenticate an agent URL, resolve it through a source you trust. [Web Bot Auth](docs/guides/web-bot-auth.md) shows discovery, nested signatures, and draft-specific errors.

### Turn a verified caller into an Ash actor and tenant

The Web Bot Auth `verification` above identifies the held key. Map that principal to an actor and tenant, then read your `MyApp.Document` resource. This example assumes the resource has attribute-based multitenancy and a read policy for `%{role: :reader}`; the [Ash guide](docs/guides/ash.md) includes the resource definition.

```elixir
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
```

Your mapping chooses the actor and tenant; Ash policies decide access. Generic RFC 9421 verification does not attribute an identity. Choose `unattributed: :anonymous` explicitly for anonymous access, or reject it.

### Add replay protection

Accept the `signed` request from the first example only once. If its 60-second validity window has elapsed, rerun that example's signing step. The original policy checks cryptography and body integrity; this policy also claims its nonce, the random value identifying the request:

```elixir
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
```

A second verification rejects the same nonce:

```elixir
RequestSeal.verify(signed, replay_policy, label: "sig")
# => {:error, %RequestSeal.Error{reason: :replayed, ...}}
```

Here one trusted key uses one namespace. Define your own commitment for your trust and tenant boundaries. ETS is local and loses claims when its owner stops; supervise the store in your application. [Replay protection](docs/guides/replay-protection.md) covers retention, sweeping, and PostgreSQL storage.

## What's included

| Capability | Module | Standard |
| --- | --- | --- |
| HTTP request/response signatures and quorum | `RequestSeal`, `RequestSeal.Quorum` | [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) |
| Structured HTTP fields | `RequestSeal.StructuredFields` | [RFC 9651](https://www.rfc-editor.org/rfc/rfc9651.html), with explicit RFC 8941 schemas where required |
| Content and representation digests | `RequestSeal.Digest` | [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) |
| Compact JWS/JWE and one JWS inside one JWE | `RequestSeal.JOSE` | [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [7516](https://www.rfc-editor.org/rfc/rfc7516.html), [7518](https://www.rfc-editor.org/rfc/rfc7518.html) |
| Public keys and SHA-256 JWK thumbprints | `RequestSeal.PublicKey` | [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), [8037](https://www.rfc-editor.org/rfc/rfc8037.html) |
| Web Bot Auth signing and verification | `RequestSeal.WebBotAuth` | [Web Bot Auth protocol-00 draft](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html) |
| Bounded HTTPS key discovery: JWKS, key directories, CIMD | `RequestSeal.Discovery` | [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), Web Bot Auth protocol-00, [CIMD-02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html) |

## Integrations

| Integration | Optional dependency | Entry module | What it does |
| --- | --- | --- | --- |
| Plug and Phoenix | `:plug` | `RequestSeal.Plug` | Capture request bytes, verify before controllers, sign final responses |
| Req | `:req`, `:finch` | `RequestSeal.Req` | Sign each finalized attempt and verify responses before decoding or delivery |
| Finch | `:finch` | `RequestSeal.Finch` | Sign requests and verify responses against the exact sent request |
| Ash | `:ash` | `RequestSeal.Ash` | Map verified facts to actors, tenants, and scopes with authorization enabled |
| PostgreSQL replay | `:postgrex` | `RequestSeal.Replay.Postgres` | Atomically claim nonces using your connection and table |

## Compatibility

Elixir 1.18 or newer on OTP 27 or newer. CI tests 1.18.4/27, 1.19.5/28, and 1.20.4/29. Development instructions work on macOS and Linux; Windows developers use WSL2.

## Security model

A valid signature proves which key signed which covered bytes; a trusted association establishes who holds that key. Your application still decides what that signer may do. Read the [threat model](docs/design/threat-model.md) for the trust boundaries and [SECURITY.md](SECURITY.md) to report a vulnerability.

## Documentation

- [Sign and verify without a framework](docs/guides/signing-and-verifying.md), including verification results and quorum
- [Req and Finch](docs/guides/req-and-finch.md)
- [Phoenix and Plug](docs/guides/phoenix-and-plug.md)
- [Web Bot Auth](docs/guides/web-bot-auth.md)
- [Ash actors, tenants, and authorization](docs/guides/ash.md)
- [Replay protection](docs/guides/replay-protection.md)
- [Key discovery](docs/guides/key-discovery.md)
- [JOSE: JWS and JWE](docs/guides/jose.md)
- [Key custody](docs/guides/key-custody.md)
- [Local development](docs/guides/getting-started.md), [testing](docs/guides/testing.md), and [Livebooks](livebooks/README.md)
- [Architecture](docs/design/architecture.md), [threat model](docs/design/threat-model.md), [ADRs](docs/adr/0001-library-boundary.md), [glossary](docs/reference/glossary.md), and [standards](docs/reference/standards.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Run the declared gate: `python3 scripts/check.py`.

## License

[Apache-2.0](LICENSE). RFC code components use BSD-3-Clause under [NOTICE](NOTICE); external vectors retain their attribution there.
