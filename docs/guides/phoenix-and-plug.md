# Verify webhook signatures in Phoenix and Plug

**What you will build:** A Phoenix webhook pipeline that captures request bytes, verifies a signature before the controller, and signs the buffered response. Install Phoenix (`>= 1.8.17 and < 2.0.0`), Plug (`>= 1.20.4 and < 2.0.0`), and Jason (`~> 1.4`) for JSON parsing. Your sender must implement [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html). This is not a verifier for every vendor-specific webhook format.

## Bind a tenant from the signed path

After Capture, the applicable body parsers, and Verify, apply a scope template
to a route whose policy requires `"@path"`. The application supplies a tenant
mapping backed by its trusted verification policy.

    scope =
      RequestSeal.Plug.Scope.init(
        template: "/teams/:team/*",
        tenant: :team,
        principal_tenant: &MyApp.Trust.tenant_for/1,
        on_reject: {:halt, 403}
      )

    conn = RequestSeal.Plug.Scope.call(conn, scope)
    {:ok, %{tenant: tenant}} = RequestSeal.Plug.scope(conn)

The callback returns `{:ok, tenant}` from trusted context or `:error`. Generic
RFC 9421 verification returns `:unattributed`. For such policies, use a mapping
closed over an independently established tenant for the trusted verifier; reject
when the policy cannot establish one tenant. Never take that value from the
route, headers, query, body, or sender-supplied key ID.

Use lowercase tokens or lowercase UUID text for tenant captures. Percent
escapes, dot segments, empty segments and case variants of captures are
refused. The scope rejects competing selectors named `tenant`, `tenant_id`,
or the nominated capture in query or body maps and lists at any depth. It
also refuses the `x-tenant` and `x-tenant-id` headers. Add application aliases
with `:refuse_names` and `:refuse_headers`.

Place the configured body parser between Capture and Verify. A nonempty body
must be fully read through Capture's retained adapter and parsed into a map
before Scope runs. A pass-through parser leaves the body indeterminate and
Scope refuses it. Multipart uploads are opaque leaves. The trusted mapping
uses a 1,000 ms deadline by default, selectable with `:lookup_timeout`.

Tenant agreement supplies the data layer with routing context. Signer
attribution comes from a trusted verification profile or independently
established application configuration. Ash policies still decide access.

## 1. Configure the trusted policy

Generate an example Ed25519 key. In your application, reuse a long-lived key handle and configure trust in its public key independently.

```elixir
{:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", [])
{:ok, key} = RequestSeal.Custody.public_key(handle)
```

Select the trusted key, required coverage, freshness, body integrity, and replay rules:

```elixir
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
```

Store `policy` under `:my_app, :http_signature_policy` during application startup. The pipeline retrieves it for each request. Share the public key and the `"demo-key"` key ID with your sender through a trusted channel.

## 2. Capture, parse, then verify

```elixir
Application.put_env(:my_app, :http_signature_policy, policy)
```

Capture and parse the body, then use the verifier directly. Its policy MFA returns the current policy on each request:

```elixir
defmodule WebhookApp.WebhookPipeline do
  use Plug.Builder

  # Verify signatures only on webhook paths; every other request passes through.
  def call(%Plug.Conn{path_info: ["webhooks" | _]} = conn, opts), do: super(conn, opts)
  def call(conn, _opts), do: conn

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
    policy: {Application, :fetch_env!, [:my_app, :http_signature_policy]},
    label: "sig",
    assign: :verified,
    on_reject: {:halt, 401}
  )
end
```

The two `call/2` clauses run the pipeline only on `/webhooks` paths, so pages, assets and health checks never need a signature. Use `WebhookApp.WebhookPipeline` before the existing endpoint parsers (or move these capture/parser plugs into the endpoint itself). Capture must run before any body read, parser, origin rewrite, or remote-IP rewrite. Use the RequestSeal reader and return its bytes unchanged; verification authenticates retained bytes, not arbitrary parser output. A partially drained reader or replaced adapter rejects. A pass-through parser may leave raw content unread for an application reader.

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

Route `POST /webhooks` to this controller. Verification also assigns `conn.assigns.verified`; the private result remains accessible through `RequestSeal.Plug.verification/1`. Failure with `on_reject: {:halt, 401}` halts before the controller. `policy:` also accepts a valid policy directly or a zero-arity function returning a policy. Function and MFA results are validated; invalid results and callback failures reject the request.

Start your Phoenix endpoint with its development default port 4000. The companion
[Req and Finch guide](req-and-finch.md) targets `http://127.0.0.1:4000/webhooks`;
configure `:my_app, :webhook_url` when your receiver uses a different address.

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

Cover the final bytes: disable server compression after signing. Bandit compresses only bodies of at least its `compress_threshold` (300 bytes by default), so a small signed response can verify while a larger one fails; set `compress: false` rather than relying on the threshold. File and chunked bodies cannot establish retained body integrity. Pending `resp_cookies` prevent signing `set-cookie`, because Plug merges cookies after callbacks; use explicit final response headers when signing cookies. Application plugs that modify captured private state are trusted server code.

## Origin and transport options

`origin: :connection` takes the scheme from the socket and the authority from the request's Host line or HTTP/2 `:authority`, which the sender chooses, and ignores forwarded fields. A request signed for another site's authority then verifies wherever the application answers for any host, which Bandit, Cowboy and Phoenix do by default. In production, declare the origin with `{:declared, "https", "api.example.com"}`, or reject requests for authorities you don't serve before Capture ([RFC 9110 Section 7.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.4); [RFC 9421 Section 7.4.3](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.4.3)). Behind a proxy, choose an explicit `{:declared, "https", "api.example.com"}` or `{:forwarded, %{trusted_peers: [{ip_tuple, prefix}], field: :forwarded}}` (or `field: :x_forwarded` for `X-Forwarded-Proto` and `X-Forwarded-Host`) based on your actual deployment. Forwarded mode checks the actual peer and uses the last element; it preserves ingress facts separately. Do not derive trust from a sender-controlled forwarded header.

All three origin modes lowercase scheme and host and omit default ports per
[RFC 9421 Section 2.2.3](https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.3).
Coverage of `@authority` without `@scheme` or `@target-uri` can accept the same
signature across `http://example.com`, `http://example.com:80`,
`https://example.com`, and `https://example.com:443` when other covered values
match. Require `@scheme` whenever scheme matters. `@target-uri` also binds the
scheme where exact target evidence is available; Plug cannot provide that evidence.

Cover `@method`, `@scheme`, `@authority`, `@path`, headers, and retained content. Plug cannot preserve the exact consumed request target: `@request-target`, `@target-uri`, and `@query` reject, including with a nonempty query. This also applies to response request components. Request trailers are unavailable. See `RequestSeal.Plug` for the measured Bandit HTTP/1 and HTTP/2 transport behavior.

## Errors

| Adapter reason | Meaning and action |
| --- | --- |
| `:parser_order` | Move Capture before reads/parsers; keep the replay adapter and drain readers completely. |
| `:not_captured` | Install Capture before Verify or SignResponse. |
| `:unsupported_component` | Choose coverage the Plug transport preserves. |
| `:request_rejected` | Inspect the bounded core `source.reason`; reject the request. |
| `:limit` | Capture halts with 413; adjust your explicit body budget if appropriate. |
| `:unsupported_delivery` | Use a buffered response, finalized cookies, and no post-signing transformation. |
| `:untrusted_proxy` | Forwarded mode saw a peer outside `trusted_peers`; Capture halts with 400. |
| `:invalid_request` | CONNECT, an empty host, or malformed forwarded fields; Capture halts with 400. |
| `:invalid_options` | A plug option, or the policy returned by a policy function or MFA, is invalid. |
| `:already_verified` | A second Verify with a different policy or label ran on a verified request. The request is no longer verified, Verify's assigns are removed, and `on_reject` applies. A repeat with the same policy and label reuses the first result; with the `:name` option, a repeat under the same name and label reuses the first result even when the policy value is a rebuilt-equivalent struct whose function fields differ — the name is your explicit assertion that it is the same policy. Install Verify once. |
| `:signing_failed` | The response signer or its custody failed; SignResponse sends its `on_failure` status. |

Capture's other failures halt with 400. Required verification does not authorize the action; apply your access policy afterward.

Module docs: `RequestSeal.Plug`, `RequestSeal.Plug.Capture`, `RequestSeal.Plug.Verify`, `RequestSeal.Plug.SignResponse`, `RequestSeal.Adapter.Error`.
