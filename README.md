<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# RequestSeal

RequestSeal signs and verifies HTTP requests and responses in Elixir with RFC 9421 HTTP Message Signatures, including Web Bot Auth for AI agents and crawlers.
Integrations support Req, Finch, and Ash; Phoenix uses the Plug integration; JOSE supports JWS signing and JWE encryption.

Use it to:

- Verify signed webhooks and service-to-service calls.
- Sign outgoing API requests.
- Identify and verify AI agents and crawlers with Web Bot Auth.
- Turn a verified caller into an Ash actor and tenant.
- Protect against replayed requests.

## Concepts in one minute

- **Key handle:** a private key held in its own process, used through an opaque handle.
- **Message:** the request or response, including its exact body and ordered headers.
- **Signing spec:** the label, algorithm, coverage, and lifetime of a signature.
- **Covered components:** the `("@method" ...)` list is RFC 9421's syntax for which parts of the request are signed.
- **Policy:** the verifier's explicit choices about keys, coverage, freshness, body integrity, and replay.
- **Verification result:** the facts established by those checks; your application decides access.

## Hello world

The examples cover `@scheme` as well as `@authority`: default HTTP port 80 and
HTTPS port 443 are omitted from the authority, so authority alone does not bind
the scheme. See [coverage choices](docs/guides/signing-and-verifying.md).

```elixir
{_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
components = ~s[("@method" "@scheme" "@authority" "@path")]
{:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60}
{:ok, signed} = RequestSeal.sign(message, spec, handle)
resolve = fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end
clock = fn -> System.system_time(:second) end

{:ok, policy} =
  RequestSeal.Policy.new(%{
    algorithms: ["ed25519"],
    components: components,
    key_resolver: resolve,
    freshness: %{clock: clock, max_age: 60, skew: 5, require_expires: true},
    content: :not_required,
    replay: :not_required
  })

{:ok, verification} = RequestSeal.verify(signed, policy, label: "sig")
IO.inspect(verification.signature.crypto)
```

Expected output:

```text
:valid
```

## Installation

Add this entry to your `mix.exs` dependency list, then run `mix deps.get`:

```elixir
{:request_seal, git: "https://github.com/baselabs/request_seal.git"}
```

The repository is private until the first Hex release, so the Git dependency requires access. For reproducible builds, pin the Git dependency to a commit with `ref:`.

Add optional dependencies for the integrations you use. The table is a reference; the complete webhook dependency list follows.

| Dependency | Requirement | Use |
| --- | --- | --- |
| `:plug` | `~> 1.20.3` | Plug pipelines, also used by Phoenix |
| `:bandit` | `~> 1.12.5` | To run the example receiver |
| `:phoenix` | `~> 1.8.15` | Only for the Phoenix controller example |
| `:req` | `~> 0.7.4` | Req signing and response verification; also add Finch |
| `:finch` | `>= 0.23.0 and < 0.25.0` | Finch transport and caller-started pools |
| `:ash` | `>= 3.34.3 and < 4.0.0` | Ash scope protocol and authorization-enabled actions |
| `:ash_onetime` | `~> 1.5` | Recommended durable replay; Elixir 1.20+ |
| `:ash_hooks` | `~> 2.0` | Webhook signing and verification; Elixir 1.20+ |
| `:postgrex` | `~> 0.22.4` | PostgreSQL replay storage using your existing connection |

For both HTTP scripts below, paste this complete list into your `deps/0` function. Jason decodes the webhook JSON:

```elixir
[
  {:request_seal, git: "https://github.com/baselabs/request_seal.git"},
  {:req, "~> 0.7.4"},
  {:finch, ">= 0.23.0 and < 0.25.0"},
  {:plug, "~> 1.20.3"},
  {:bandit, "~> 1.12.5"},
  {:jason, "~> 1.0"}
]
```

## Send and receive a signed webhook

Save this entire script as `webhook.exs` in a fresh `mix new` project with the dependencies above, run `mix deps.get`, then `mix run webhook.exs`. It starts a receiver on an available local port, sends a signed request, and checks unsigned rejection.

In a real deployment, the receiver gets the sender's public key out of band or from a trusted JWKS URL or key directory; see [key discovery](docs/guides/key-discovery.md).

```elixir
defmodule WebhookReceiver do
  use Plug.Router

  # Capture keeps the signed body bytes before Parsers consumes them.
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

  plug(RequestSeal.Plug.Verify,
    policy: {Application, :fetch_env!, [:webhook_demo, :signature_policy]},
    label: "sig",
    on_reject: {:halt, 401}
  )

  plug(:match)
  plug(:dispatch)

  post "/webhooks" do
    {:ok, verified} = RequestSeal.Plug.verification(conn)
    send_resp(conn, 200, "#{verified.signature.crypto}: #{conn.body_params["event"]}")
  end

  match _ do
    send_resp(conn, 404, "not found")
  end
end

# The sender owns the private key; the receiver gets only its public key.
{_public, webhook_seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, webhook_handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, webhook_seed})
{:ok, webhook_key} = RequestSeal.Custody.public_key(webhook_handle)
webhook_components = ~s[("@method" "@scheme" "@authority" "@path" "content-digest")]

{:ok, webhook_policy} =
  RequestSeal.Policy.new(%{
    algorithms: ["ed25519"],
    components: webhook_components,
    key_resolver: fn
      %{keyid: "sender-key"} -> {:ok, %{algorithm: "ed25519", key: webhook_key}}
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

webhook_signing = %{
  label: "sig",
  algorithm: "ed25519",
  components: webhook_components,
  expires_in: 60,
  keyid: "sender-key",
  digest: ["sha-256"]
}

Application.put_env(:webhook_demo, :signature_policy, webhook_policy)
{:ok, webhook_apps} = Application.ensure_all_started(:req)
{:ok, webhook_pool} = Finch.start_link(name: WebhookFinch)

{:ok, receiver} =
  Bandit.start_link(
    plug: WebhookReceiver,
    ip: {127, 0, 0, 1},
    port: 0,
    http_options: [compress: false]
  )

{:ok, {_, port}} = ThousandIsland.listener_info(receiver)

try do
  request =
    Req.new(
      url: "http://127.0.0.1:#{port}/webhooks",
      method: :post,
      json: %{"event" => "created"},
      finch: [name: WebhookFinch],
      retry: false
    )

  # verify: :none skips response verification; the receiver verifies this request.
  {:ok, request} =
    RequestSeal.Req.attach(request, sign: webhook_signing, signer: webhook_handle, verify: :none)

  {:ok, response} = Req.request(request)
  # {200, "valid: created"}
  IO.inspect({response.status, response.body})

  unsigned =
    Req.post!("http://127.0.0.1:#{port}/webhooks", json: %{"event" => "created"}, retry: false)

  # 401
  IO.inspect(unsigned.status)

  unless response.status == 200 and response.body == "valid: created" and unsigned.status == 401,
    do: raise("webhook verification failed")
after
  Supervisor.stop(receiver)
  Application.delete_env(:webhook_demo, :signature_policy)
  Supervisor.stop(webhook_pool)
  RequestSeal.Custody.Local.release(webhook_handle)
  Enum.each(Enum.reverse(webhook_apps), &Application.stop/1)
end
```

Expected output (Bandit may first log one `[info] Running WebhookReceiver ...` line; when run inside an existing VM, cleanup may log `[notice] Application ... exited: :stopped` for each application this script started):

```text
{200, "valid: created"}
401
```

`verify: :none` leaves the response unverified; the receiver verifies the request. [Req and Finch](docs/guides/req-and-finch.md) covers signed responses and retries. Supervise and reuse keys and pools in your application.

## Sign outgoing requests with Req

Save as `req.exs` and run `mix run req.exs` with the dependency list above.
The webhook example shows how a receiver verifies a signed request.

Configure `:my_app, :outgoing_url` in `config/config.exs` with the URL of a
receiver you own, for example `config :my_app, :outgoing_url, "https://your-receiver.example/"`.
Start that receiver first; the expected status below assumes it returns 200.
The example sends an actual HTTP request to your configured URL.

```elixir
{_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, apps} = Application.ensure_all_started(:req)
{:ok, pool} = Finch.start_link(name: OutgoingFinch)
try do
  request = Req.new(url: Application.fetch_env!(:my_app, :outgoing_url), finch: [name: OutgoingFinch], retry: false)
  spec = %{label: "sig", algorithm: "ed25519", components: ~s[("@method" "@scheme" "@authority" "@path")], expires_in: 60}
  # verify: :none skips verification of this unsigned response.
  {:ok, request} = RequestSeal.Req.attach(request, sign: spec, signer: handle, verify: :none)
  {:ok, response} = Req.request(request)
  IO.inspect(response.status)
after
  Supervisor.stop(pool)
  RequestSeal.Custody.Local.release(handle)
  Enum.each(Enum.reverse(apps), &Application.stop/1)
end
```

Expected output (cleanup inside an existing VM may also log application-stop notices):

```text
200
```

## In Phoenix

Phoenix uses the same Plug integration. The code below uses `webhook_policy` from the webhook example to configure the policy at startup. In your app, construct it with your trusted sender's public key. The request-time function form reads the current policy on each request. Add the shown plugs and route to your existing endpoint and router; Capture must precede the endpoint's `Plug.Parsers`.

```elixir
Application.put_env(:my_app, :http_signature_policy, webhook_policy)

defmodule MyAppWeb.SignedWebhookPipeline do
  use Plug.Builder

  def signature_policy, do: Application.fetch_env!(:my_app, :http_signature_policy)

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

  plug(RequestSeal.Plug.Verify,
    policy: &__MODULE__.signature_policy/0,
    label: "sig",
    on_reject: {:halt, 401}
  )
end

defmodule MyAppWeb.WebhookController do
  use Phoenix.Controller, formats: [:json]

  def create(conn, params) do
    {:ok, verified} = RequestSeal.Plug.verification(conn)
    json(conn, %{signature_label: verified.label, event: params["event"]})
  end
end

defmodule MyAppWeb.Router do
  use Phoenix.Router

  scope "/", MyAppWeb do
    post("/webhooks", WebhookController, :create)
  end
end

defmodule MyAppWeb.Endpoint do
  use Phoenix.Endpoint, otp_app: :my_app

  plug(MyAppWeb.SignedWebhookPipeline)

  plug(Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Jason
  )

  plug(MyAppWeb.Router)
end
```

The module definitions print no output. A valid `POST /webhooks` with `{"event":"created"}` returns status 200 and JSON `{"event":"created","signature_label":"sig"}`; an unsigned request returns 401 with an empty body.

[Phoenix and Plug](docs/guides/phoenix-and-plug.md) covers trusted proxies and response signing. [Signing and verifying](docs/guides/signing-and-verifying.md) explains core results, errors, and exact wire control.

## More examples

### Web Bot Auth

Uses `message`, `key`, and `handle` from Hello world. Web Bot Auth identifies signed requests from agents and crawlers. Sign with protocol-00:

```elixir
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
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

IO.puts("signed agent request")
```

Expected output:

```text
signed agent request
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
IO.inspect(verification.signature.crypto)
```

Expected output:

```text
:valid
```

To authenticate an agent URL, resolve it through a source you trust. [Web Bot Auth](docs/guides/web-bot-auth.md) shows discovery, nested signatures, and draft-specific errors.

### Ash

Uses `verification` and `thumbprint` from Web Bot Auth above. That result identifies the held key. Map that principal to an actor and tenant, then read your `AshApp.Document` resource. This example assumes the resource has attribute-based multitenancy and a read policy for `%{role: :reader}`; the [Ash guide](docs/guides/ash.md) includes the resource definition.

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

documents = Ash.read!(AshApp.Document, scope: scope, authorize?: true)
IO.inspect(scope.tenant)
```

Expected output:

```text
"demo"
```

Your mapping chooses the actor and tenant; Ash policies decide access. Generic RFC 9421 verification does not attribute an identity. Choose `unattributed: :anonymous` explicitly for anonymous access, or reject it.

### Replay protection

Uses `signed` and `policy` from Hello world. Accept that request only once. If its 60-second validity window has elapsed, rerun that example's signing step. The Hello world policy checks the signature and freshness; it does not require body integrity. This policy also claims its nonce, the random value identifying the request:

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
IO.inspect(accepted.signature.crypto)
```

Expected output:

```text
:valid
```

A second verification rejects the same nonce:

```elixir
{:error, replay_error} = RequestSeal.verify(signed, replay_policy, label: "sig")
IO.inspect(replay_error.reason)
```

Expected output:

```text
:replayed
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
| Plug (including Phoenix) | `:plug` | `RequestSeal.Plug` | Capture request bytes, verify before controllers, sign final responses |
| Req | `:req`, `:finch` | `RequestSeal.Req` | Sign each finalized attempt and verify responses before decoding or delivery |
| Finch | `:finch` | `RequestSeal.Finch` | Sign requests and verify responses against the exact sent request |
| Ash | `:ash` | `RequestSeal.Ash` | Map verified facts to actors, tenants, and scopes with authorization enabled |
| ash_onetime | `:ash_onetime` | `RequestSeal.Replay.AshOnetime` | Recommended durable atomic replay with caller-owned Postgres |
| ash_hooks | `:ash_hooks` | `RequestSeal.AshHooks.Http`, `RequestSeal.AshHooks` | Sign deliveries and verify ingress; ash_hooks owns transport and ledger |
| PostgreSQL replay | `:postgrex` | `RequestSeal.Replay.Postgres` | Atomically claim nonces using your connection and table |

## Compatibility

Elixir 1.18 or newer on OTP 27 or newer. CI tests 1.18.4/27, 1.19.5/28, and 1.20.4/29. The optional ash_onetime and ash_hooks integrations require Elixir 1.20; floor and mid toolchains omit those dependencies and tests. The latest CI lane executes them. Development instructions work on macOS and Linux; Windows developers use WSL2.

## Security model

A valid signature proves which key signed which covered bytes; a trusted association establishes who holds that key. Your application still decides what that signer may do. Read the [threat model](docs/design/threat-model.md) for the trust boundaries and [SECURITY.md](SECURITY.md) to report a vulnerability.

## Documentation

### Guides

- [Sign and verify without a framework](docs/guides/signing-and-verifying.md), including verification results and quorum
- [Req and Finch](docs/guides/req-and-finch.md)
- [Phoenix and Plug](docs/guides/phoenix-and-plug.md)
- [Web Bot Auth](docs/guides/web-bot-auth.md)
- [Ash actors, tenants, and authorization](docs/guides/ash.md)
- [Webhooks with ash_hooks](docs/guides/ash-hooks.md)
- [Replay protection](docs/guides/replay-protection.md)
- [Key discovery](docs/guides/key-discovery.md)
- [JOSE: JWS and JWE](docs/guides/jose.md)
- [Key custody](docs/guides/key-custody.md)
- [Livebooks](livebooks/README.md)

### Contributing

- [Develop RequestSeal](docs/guides/getting-started.md) and [testing](docs/guides/testing.md)
- [Architecture](docs/design/architecture.md), [threat model](docs/design/threat-model.md), [ADRs](docs/adr/0001-library-boundary.md), [glossary](docs/reference/glossary.md), and [standards](docs/reference/standards.md)

See [CONTRIBUTING.md](CONTRIBUTING.md) for contributor checks.

## License

[Apache-2.0](LICENSE). RFC code components use BSD-3-Clause under [NOTICE](NOTICE); external vectors retain their attribution there.
