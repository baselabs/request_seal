<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# Verify webhook signatures in Phoenix and Plug

**What you will build:** A Phoenix webhook pipeline that captures request bytes, verifies a signature before the controller, and signs the buffered response. Install Phoenix with Plug (`~> 1.20.3`) and Jason (`~> 1.0`) for JSON parsing. Your sender must implement [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html). This is not a verifier for every vendor-specific webhook format.

## 1. Configure the trusted policy

Generate an example Ed25519 key. In your application, reuse a long-lived key handle and configure trust in its public key independently.

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
```

Select the trusted key, required coverage, freshness, body integrity, and replay rules:

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

Store `policy` under `:my_app, :http_signature_policy` during application startup. The pipeline retrieves it for each request. Share the public key and the `"demo-key"` key ID with your sender through a trusted channel.

## 2. Capture, parse, then verify

```elixir
defmodule WebhookApp.VerifySignature do
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
defmodule WebhookApp.WebhookPipeline do
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

  plug(WebhookApp.VerifySignature)
end
```

Use `WebhookApp.WebhookPipeline` before the existing endpoint parsers (or move these capture/parser plugs into the endpoint itself). Capture must run before any body read, parser, origin rewrite, or remote-IP rewrite. Use the RequestSeal reader and return its bytes unchanged; verification authenticates retained bytes, not arbitrary parser output. A partially drained reader or replaced adapter rejects. A pass-through parser may leave raw content unread for an application reader.

## 3. Read the result in your controller

```elixir
defmodule WebhookApp.WebhookController do
  use Phoenix.Controller, formats: [:json]

  def create(conn, params) do
    {:ok, verified} = RequestSeal.Plug.verification(conn)
    json(conn, %{signature_label: verified.label, event: params["event"]})
  end
end
```

Route `POST /webhooks` to this controller. Verification also assigns `conn.assigns.verified`; the private result remains accessible through `RequestSeal.Plug.verification/1`. Failure with `on_reject: {:halt, 401}` halts before the controller.

## 4. Sign a buffered response

Choose the response status, related request method/path, and body digest as the signed coverage:

```elixir
response_signing = %{
  label: "res",
  algorithm: "ed25519",
  components: ~s[("@status" "@method";req "@path";req "content-digest")],
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

Call `WebhookApp.ResponseSignature.sign(conn, handle, response_signing)` in your endpoint after capture and before the controller sends the response:

```elixir
defmodule WebhookApp.ResponseSignature do
  def sign(conn, handle, signing) do
    options =
      RequestSeal.Plug.SignResponse.init(
        sign: signing,
        signer: handle,
        signing_timeout: 5_000,
        clock: fn -> System.system_time(:second) end,
        on_failure: {:respond, 503}
      )

    RequestSeal.Plug.SignResponse.call(conn, options)
  end
end
```

Cover the final bytes: disable server compression after signing. File and chunked bodies cannot establish retained body integrity. Pending `resp_cookies` prevent signing `set-cookie`, because Plug merges cookies after callbacks; use explicit final response headers when signing cookies. Application plugs that modify captured private state are trusted server code.

## Origin and transport options

`origin: :connection` ignores forwarded fields. Behind a proxy, choose an explicit `{:declared, "https", "api.example.com"}` or `{:forwarded, %{trusted_peers: [{ip_tuple, prefix}], field: :forwarded}}` based on your actual deployment. Forwarded mode checks the actual peer and uses the last element; it preserves ingress facts separately. Do not derive trust from a sender-controlled forwarded header.

Cover `@method`, `@authority`, `@path`, headers, and retained content. Plug cannot preserve the exact consumed request target: `@request-target`, `@target-uri`, and `@query` reject, including with a nonempty query. This also applies to response request components. Request trailers are unavailable. See `RequestSeal.Plug` for the measured Bandit HTTP/1 and HTTP/2 transport behavior.

## Errors

| Adapter reason | Meaning and action |
| --- | --- |
| `:parser_order` | Move Capture before reads/parsers; keep the replay adapter and drain readers completely. |
| `:not_captured` | Install Capture before Verify or SignResponse. |
| `:unsupported_component` | Choose coverage the Plug transport preserves. |
| `:request_rejected` | Inspect the bounded core `source.reason`; reject the request. |
| `:limit` | Capture halts with 413; adjust your explicit body budget if appropriate. |
| `:unsupported_delivery` | Use a buffered response, finalized cookies, and no post-signing transformation. |

Capture's other failures halt with 400. Required verification does not authorize the action; apply your access policy afterward.

Module docs: `RequestSeal.Plug`, `RequestSeal.Plug.Capture`, `RequestSeal.Plug.Verify`, `RequestSeal.Plug.SignResponse`, `RequestSeal.Adapter.Error`.
