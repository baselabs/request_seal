<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# Sign Req and Finch requests and verify responses

**What you will build:** A Req client that signs outgoing JSON requests and verifies signed responses, followed by the equivalent Finch calls. Install Req (`~> 0.7.4`) and Finch (`>= 0.23.0 and < 0.25.0`), and configure `:my_app, :webhook_url` with your receiving endpoint. These examples use [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) and [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html).

## Set up the key and trust policy

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

## 1. Choose outgoing coverage

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

## 2. Start your pool and send with Req

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
- Req defaults to same-origin redirects. Explicit `redirect: {:allow, [origin]}` permits other origins and strips authorization, cookies, proxy authorization, and your `credential_headers`.
- `signing_timeout` bounds handle and function signers. Direct Req verification refuses `into: :self`, caller response steps before verification, caches, raising HTTP errors, and other delivery paths that could expose unverified content.

## Errors

`RequestSeal.Adapter.Error` hides framework exception text. `:not_final_step` means a request step follows signing; move attachment last. `:response_rejected` wraps the bounded verification error and returns no response body. `:cross_origin_redirect` requires an explicit trusted origin if you intend to permit it. `:limit` means a retained or received body exceeded your budget. `:unsupported_delivery` or `:invalid_options` means your delivery/client customization cannot preserve the signing or verification contract; consult the supported options before changing it.

Module docs: `RequestSeal.Req`, `RequestSeal.Finch`, `RequestSeal.Adapter.Error`, `RequestSeal.Digest`.
