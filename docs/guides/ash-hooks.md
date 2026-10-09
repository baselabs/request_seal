<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and ADRs 0005, 0007, 0008, and 0011 · Review when: ash_hooks adapter or provider contracts change -->

# Webhooks with ash_hooks

Add optional `{:ash_hooks, "~> 2.0", optional: true}` with Elixir 1.20 or newer.
RequestSeal adds RFC 9421 signatures to ash_hooks deliveries and verifies inbound
requests. ash_hooks owns delivery rows, retry/backoff, Retry-After, destination
validation and pinning, secret references, and its ingress ledger. RequestSeal
starts no server, pool, or database.

This example applies [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html),
[Content-Digest](https://www.rfc-editor.org/rfc/rfc9530.html), and the public
[ash_hooks HTTP adapter](https://hexdocs.pm/ash_hooks/AshHooks.Http.html),
[delivery](https://hexdocs.pm/ash_hooks/AshHooks.Delivery.html), and
[provider](https://hexdocs.pm/ash_hooks/AshHooks.Provider.html) contracts. It is
an explicit application coverage choice, not a named provider profile or an
external conformance vector. Configure receiver trust independently in production.

## Select custody, coverage, and receiver policy

The example uses an ephemeral Ed25519 handle. Production custody belongs to the
caller. The receiver requires every covered component, freshness, and body integrity.
`replay: :not_required` is explicit here; select the recommended
[durable replay store](replay-protection.md) when each signed nonce must be spent once.

```elixir
{_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
components = ~s[("@method" "@authority" "@path" "content-digest" "content-type" "webhook-id")]
spec = %{
  label: "sig",
  algorithm: "ed25519",
  components: components,
  expires_in: 60,
  keyid: "webhook-key",
  digest: ["sha-256"]
}
{:ok, policy} = RequestSeal.Policy.new(%{
  algorithms: ["ed25519"],
  components: components,
  key_resolver: fn
    %{keyid: "webhook-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
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

## Verify before ash_hooks ingress

Use this pipeline upstream of the consumer's ash_hooks ingress. Capture preserves
ordered header occurrences and bounded exact body bytes. Verify retains the full
result and rejects before handling. `AshHooks.BodyReader` receives the unchanged
bytes replayed by Capture. Plug does not establish the exact raw target; this
example covers `@path`, not `@request-target`, `@target-uri`, or `@query`.

```elixir
defmodule SignedWebhookIngress do
  @behaviour Plug
  def init(opts), do: opts

  def call(conn, opts) do
    conn = RequestSeal.Plug.Capture.call(conn,
      RequestSeal.Plug.Capture.init(
        origin: :connection, max_body_bytes: 100_000, read_timeout: 5_000))
    conn = RequestSeal.Plug.Verify.call(conn,
      RequestSeal.Plug.Verify.init(
        policy: opts[:policy], label: "sig", on_reject: {:halt, 401}, assign: :verified_webhook))

    if conn.halted do
      conn
    else
      {:ok, body, conn} = AshHooks.BodyReader.read_body(conn, [])
      Plug.Conn.assign(conn, :webhook_body, body)
    end
  end
end
```

For proxy deployments, configure Capture's explicit trusted origin instead of
accepting forwarded headers implicitly. The application chooses how to use the
verification result; cryptography does not authorize a handler action. Do not
claim the same required nonce again in the provider helper after Plug has spent it.

## Sign deliveries

Supply your existing `deliveries` and `endpoints` resource modules and a
`secret_resolver` implementing ash_hooks' public contract. The endpoint still
needs its Standard Webhooks secret reference; ash_hooks adds those headers first,
then this adapter appends RFC 9421 fields over the final method, URL, headers,
and exact body. Neither the payload nor covered headers may change afterward.

```elixir
config = [
  deliveries: deliveries,
  endpoints: endpoints,
  secret_resolver: secret_resolver,
  http: RequestSeal.AshHooks.Http,
  http_opts: [request_seal: [spec: spec, signer: handle]]
]
```

With an existing pending `delivery` row, run the real driver:

```elixir
:ok = AshHooks.Delivery.run(%{
  "endpoint_id" => delivery.endpoint_id,
  "event_uuid" => delivery.event_uuid
}, config)
```

The driver records success only after the receiver returns 2xx. It owns retries,
redirect refusal, 410 handling, and delivery leases. Every attempt is freshly
signed. `http_opts` can also be an ash_hooks MFA resolver; the HTTP adapter itself
receives no endpoint or tenant identity, so choose custody in that configuration.
The adapter delegates to `AshHooks.Http.Bounded` with the remaining total deadline
and retains its SSRF defaults. Existing signature fields, transport-owned headers,
case collisions, insufficient coverage, and digest conflicts reject before sending.

## Delegate from a Provider

A consumer's `c:AshHooks.Provider.verify_signature/3` can call
`RequestSeal.AshHooks.verify_signature/4` with its raw body, provider context,
nonempty binary key reference, and trusted policy source. For a received request
whose exact `body`, header map `headers`, and absolute `destination` are supplied:

```elixir
context = %{
  method: "POST",
  request_uri: destination,
  headers: headers,
  signature: headers["signature"],
  tenant: nil
}
:ok = RequestSeal.AshHooks.verify_signature(body, context, "webhook-key",
  policy: fn "webhook-key" -> policy end, label: "sig")
```

ash_hooks currently passes a headers map and accepts only `:ok` or its signature
errors. The helper cannot restore lost duplicate lines/order or return verified
facts through that callback. The upstream Plug pattern preserves those facts and
ordered occurrences. An absent key reference returns `:no_webhook_secret`;
verification or policy failures return `:invalid_signature`. Configure provider
key-reference resolution independently of the inbound request.
