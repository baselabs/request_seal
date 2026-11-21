# Sign Req and Finch requests and verify responses

**What you will build:** A Req client that signs outgoing JSON requests and verifies signed responses, followed by the equivalent Finch calls. Install Req (`~> 0.7.4`) and Finch (`>= 0.24.0 and < 0.25.0`), and run the receiver from [Phoenix and Plug](phoenix-and-plug.md) on Phoenix's development default port 4000 at `http://127.0.0.1:4000/webhooks`. These examples use [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) and [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html).

## 1. Shared setup and outgoing coverage

Generate a key and select acceptance rules once. A signing specification requires `label`, `algorithm`, `components`, and a positive `expires_in`. Req and Finch share the defaults of `RequestSeal.sign/4`: creation time, a fresh random nonce per attempt, and the algorithm parameter (omitted for JWS tuples). Key ID, tag, and digest default to nil; field schemas default to `%{}`. Full explicit specs remain supported.

```elixir
{:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", [])
{:ok, key} = RequestSeal.Custody.public_key(handle)
components = ~s[("@method" "@scheme" "@authority" "@path" "content-digest")]

{:ok, policy} =
  RequestSeal.Policy.new(%{
    algorithms: ["ed25519"],
    components: components,
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

signing = %{
  label: "sig",
  algorithm: "ed25519",
  components: components,
  expires_in: 60,
  keyid: "demo-key",
  digest: ["sha-256"]
}
```

## 2. Start your pool and send with Req

The default URL below targets that local Phoenix receiver on port 4000. Set `:my_app, :webhook_url` to your deployed receiver's URL or another local port when integrating.

```elixir
url = Application.get_env(:my_app, :webhook_url, "http://127.0.0.1:4000/webhooks")
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

In an application, supervise and reuse your Finch pool. Loading RequestSeal starts none. The adapter signs JSON/compressed bytes after Req finalizes them, and regenerates signature parameters for each retry or redirect attempt. Keep signing as the last request step.

## 3. Require signed responses

Configure the server with `RequestSeal.Plug.SignResponse` as shown in [Phoenix and Plug](phoenix-and-plug.md), covering status, associated request method/path, and the response content digest:

```elixir
{:ok, response_policy} =
  RequestSeal.Policy.new(%{
    Map.from_struct(policy)
    | components: ~s[("@status" "@method";req "@path";req "content-digest")]
  })
```

Attach both signing and response verification before sending:

```elixir
{:ok, request} =
  RequestSeal.Req.attach(
    Req.new(
      url: url,
      method: :post,
      json: %{"event" => "created"},
      finch: [name: MyApp.Finch],
      retry: false
    ),
    sign: signing,
    signer: handle,
    verify: %{policy: response_policy, label: "res", max_stream_bytes: 1_048_576}
  )

{:ok, response} = Req.request(request)
{:ok, verified_response} = RequestSeal.Req.verification(response)
verified_response.signature.crypto
# => :valid
```

Verification runs before retries, redirects, HTTP error handling, decompression, and decoding. Every intermediate response must pass; an unsigned 3xx or 5xx fails closed. Chunks and collectables receive bytes only after verification, within `max_stream_bytes`.

## 4. Use Finch directly

```elixir
request = Finch.build(:post, url, [{"content-type", "application/json"}], ~s({"event":"created"}))
{:ok, request} = RequestSeal.Finch.sign(request, signing, handle)
{:ok, response} = Finch.request(request, MyApp.Finch)

{:ok, verified_response} =
  RequestSeal.Finch.verify(response, request, response_policy, label: "res")

verified_response.signature.crypto
# => :valid
```

Pass the exact signed request when verifying its response; request association is part of the signature. With streaming Finch, feed each chunk into `RequestSeal.Digest`, retain headers/trailers, and pass `digest_state:` at EOF. Withhold application effects until verification succeeds.

## Options that matter

- Cover `@authority` instead of `host`. Request `req`/`tr` components and unretained body coverage reject.
- Choose `request_body: {:retain, max}` in Req or `body: {:retain, max}` in Finch to retain a request stream under a byte bound; the resulting bytes can be sent again on retry.
- `RequestSeal.Req.attach/2` defaults to `redirect: :same_origin` (origin is scheme, host, and port). Explicit `redirect: {:allow, [origin]}` permits other origins and strips authorization, cookies, proxy authorization, and your `credential_headers`.
- `RequestSeal.Finch` rejects a caller-supplied `Host` header with `:invalid_options`, as Req does; Mint derives Host from the URL, so the signed `@authority` matches what is sent.
- Retaining a request body stops with `:limit` at 16,384 chunks (empty chunks count) or after 5,000 ms, whichever comes first; Req's response collection stops with `:limit` at 16,384 chunks or at `:max_stream_bytes`.
- A signed `@target-uri` keeps the URL's host case and omits only the scheme's default port, matching the Host or `:authority` Mint sends.
- `signing_timeout` bounds custody signing. Direct Req verification refuses `into: :self`, caller response steps before verification, caches, raising HTTP errors, and other delivery paths that could expose unverified content.

## Errors

`RequestSeal.Adapter.Error` hides framework exception text. `:not_final_step` means a request step follows signing; move attachment last. `:response_rejected` wraps the bounded verification error and returns no response body. `:cross_origin_redirect` requires an explicit trusted origin if you intend to permit it. `:limit` means a retained or received body exceeded your budget. `:unsupported_delivery` or `:invalid_options` means your delivery/client customization cannot preserve the signing or verification contract; consult the supported options before changing it. `:unsupported_component` means coverage the transport cannot supply, such as `host` or request `req`/`tr` components. `:body_unavailable` means covered content was not retained; choose `{:retain, max}`. `:digest_conflict` means a caller-supplied digest disagrees with the bytes. `:signing_failed` carries a bounded custody error in `source`.

On Req attempt two or later, a final `Req.TransportError` or `Req.HTTPError`
becomes `{:error, %RequestSeal.Adapter.Error{reason: :transport_failed,
stage: :transport, attempt: n, source: nil}}`. An HTTP/2 stream or pool refusal
with a non-nil sent Finch body produces the same error on any attempt, including
attempt one. The bounded error retains the signing attempt number and discards
the framework exception and its transport details. Other first-attempt
transport errors retain Req's own shape. RequestSeal appends an
error step after Req's retry handling, so Req still sees its original transport
errors when deciding whether to retry. Keep this step last; removing or moving
it causes a signing refusal before transport. Sign and verification refusals
halt directly, preserving their original reason, stage, and attempt.

Module docs: `RequestSeal.Req`, `RequestSeal.Finch`, `RequestSeal.Adapter.Error`, `RequestSeal.Digest`.

## Classify delivery before retrying

`RequestSeal.Req.classify/1` accepts the result of an attached Req call.
`RequestSeal.Finch.classify/2` accepts the result and the exact signed
`Finch.Request` passed to transport; any other second argument returns
`:unknown`. Both return `:answered`, `:refused`, or `:unknown`. Only `:refused` is safe
to retry automatically: its evidence proves no request processing occurred.
Disable Req's automatic retries when applying this decision yourself, as in the
examples above. Classification covers the whole Req call, including every
redirect and retry attempt. An attach refusal (attempt zero) or a signing
refusal on attempt one is `:refused`. A signing refusal on attempt two or later
is `:unknown`, as is a later `:transport_failed` error: an earlier attempt may
already have delivered the operation. For example, a POST answered with a 303
to a different origin has unknown delivery when the second attempt rejects
with `:cross_origin_redirect`; allowing that redirect and then failing name
resolution also leaves delivery unknown. The final error cannot establish the
earlier outcome. Finch does not follow redirects or retry HTTP statuses.
`:answered` includes error statuses such as 503 and does not
make repeating the operation safe. Status 502 or 504 is `:unknown`, since a
gateway cannot establish whether the origin processed the request
([RFC 9110 Sections 15.6.3 and 15.6.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.6.3)).

Receive timeouts, mid-exchange closes, failed response verification, and unknown
errors require the application's own idempotency protection. The locked clients
report a socket error with the same reason whether it happened during connect or
on an open connection after sending, so a refused connection, an unreachable host
or network, a socket timeout and a TLS alert also remain `:unknown`. A
name-resolution failure (`:nxdomain`) on the first attempt happens before any
connection exists and is `:refused`. First-attempt HTTP/2 REFUSED_STREAM and
GOAWAY's per-stream unprocessed indication supply explicit refusal evidence
only when the sent Finch request body is nil
([RFC 9113 Section 8.7](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.7)).

Finch can restart a partially sent HTTP/2 request after a `:read_only` pool error.
Both classifiers therefore return `:unknown` for HTTP/2 stream or pool refusals
when the sent Finch body was non-nil, including `""`. A nil body cannot take
that partial-upload rerun path. Req records this fact from the finalized Finch
body; Finch's classifier reads it from the supplied request. Raw DNS and ALPN
failures stay pre-send refusals: HTTP/2 connection failures happen in the
background pool and surface as pool errors, which follow the body rule.

```elixir
:answered = RequestSeal.Finch.classify({:ok, response}, request)
:unknown = RequestSeal.Req.classify({:error, %Req.TransportError{reason: :timeout}})
```
