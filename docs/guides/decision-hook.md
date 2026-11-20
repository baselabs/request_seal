# Sign a decision hook and its response

**What you will build:** A caller sends a signed hook request to a decision
service. The service verifies it, applies a caller-owned decision function, and
signs either an allow or deny response. The caller verifies the response before
reading its decision. Install the optional Req, Finch, Plug and Bandit packages
using the versions in the [Req and Finch](req-and-finch.md) and
[Plug](phoenix-and-plug.md) guides; this runnable example also uses Bandit
(`~> 1.15`). RequestSeal starts none of these processes itself.

The recipe applies [RFC 9421 Section 2.4](https://www.rfc-editor.org/rfc/rfc9421.html#section-2.4)
request-bound response signatures and [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html)
body integrity. Its coverage is an explicit application choice, not a named
provider profile or an external conformance vector. Signature verification
authenticates bytes; the application still owns access policy and effects.

## 1. Configure separate caller and service trust

Generate two ephemeral example keys. In production, each party keeps its own
long-lived custody handle and configures trust in the other's public key
independently. An inbound key ID never establishes that trust.

```elixir
{_public, caller_seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, caller_handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, caller_seed})
{:ok, caller_key} = RequestSeal.Custody.public_key(caller_handle)
{_public, service_seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, service_handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, service_seed})
{:ok, service_key} = RequestSeal.Custody.public_key(service_handle)

request_components = ~s[("@method" "@scheme" "@authority" "@path" "content-type" "content-digest")]
response_components = ~s[("@status" "content-type" "content-digest" "@method";req "@scheme";req "@authority";req "@path";req "content-digest";req "signature";req)]

policy_for = fn key, trusted_id, components ->
  RequestSeal.Policy.new(%{
    algorithms: ["ed25519"],
    components: components,
    key_resolver: fn
      %{keyid: ^trusted_id} -> {:ok, %{algorithm: "ed25519", key: key}}
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
end

{:ok, request_policy} = policy_for.(caller_key, "caller-key", request_components)
{:ok, response_policy} = policy_for.(service_key, "service-key", response_components)
request_signing = %{
  label: "sig",
  algorithm: "ed25519",
  components: request_components,
  expires_in: 60,
  keyid: "caller-key",
  digest: ["sha-256"]
}
response_signing = %{
  label: "decision",
  algorithm: "ed25519",
  components: response_components,
  parameters: %{
    created: true,
    expires_in: 60,
    nonce: :random,
    alg: true,
    keyid: "service-key",
    tag: nil
  },
  digest: ["sha-256"],
  field_schemas: %{}
}
```

`RequestSeal.Plug.SignResponse` takes the full signing map, with explicit
parameters and field schemas, rather than the short request form. The response covers its status, content type and digest, plus the originating
request's method, origin, path, digest and signature via `;req`. Covering the
request signature distinguishes fresh requests with identical payloads, because
each request signs a fresh random nonce. Freshness does not spend nonces: choose
[durable replay protection](replay-protection.md) when requests may be acted on
only once. This example explicitly permits repeated verification.

## 2. Verify before deciding; sign both outcomes

Capture runs before any body reader or parser. SignResponse runs over the final
buffered response and uses the captured request for `;req`. An invalid request
halts with 401 before calling the decision function. Signing failure replaces the
response with 503, which the caller's required response verification rejects.

```elixir
defmodule DecisionHookExample.Receiver do
  @behaviour Plug
  def init(options), do: options

  def call(%Plug.Conn{method: "POST", request_path: "/decision", query_string: ""} = conn, options) do
    conn = RequestSeal.Plug.Capture.call(conn,
      RequestSeal.Plug.Capture.init(
        origin: :connection, max_body_bytes: 4096, read_timeout: 5_000))
    conn = RequestSeal.Plug.Verify.call(conn,
      RequestSeal.Plug.Verify.init(
        policy: options[:request_policy], label: "sig", on_reject: {:halt, 401}))

    if conn.halted do
      conn
    else
      {:ok, capture} = RequestSeal.Plug.capture(conn)
      {status, decision} =
        case options[:decide].(capture.message.body.bytes) do
          :allow -> {200, "allow"}
          _ -> {403, "deny"}
        end

      conn = RequestSeal.Plug.SignResponse.call(conn,
        RequestSeal.Plug.SignResponse.init(
          sign: options[:response_signing], signer: options[:service_handle],
          signing_timeout: 5_000, clock: fn -> System.system_time(:second) end,
          on_failure: {:respond, 503}))

      body = :json.encode(%{"decision" => decision}) |> IO.iodata_to_binary()
      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.send_resp(status, body)
    end
  end

  def call(conn, _options), do: Plug.Conn.send_resp(conn, 404, "")
end
```

The decision callback below is an illustrative application policy: reads allow;
other operations deny. Replace it with your own policy. No application effect is
performed by this recipe. Plug cannot establish the exact raw target; this
endpoint takes no query parameters and covers `@path`. In production configure
Capture with `{:declared, "https", "decisions.example.com"}` or reject authorities
you do not serve, as the [origin guide](phoenix-and-plug.md#origin-and-transport-options)
explains. Disable compression and other transformations after signing.

## 3. Start the example's real listener and client pool

```elixir
{:ok, pool} = Finch.start_link(name: DecisionHookExample.Finch)
{:ok, server} = Bandit.start_link(
  plug: {DecisionHookExample.Receiver,
    request_policy: request_policy,
    response_signing: response_signing,
    service_handle: service_handle,
    decide: fn body ->
      if :json.decode(body) == %{"operation" => "read"}, do: :allow, else: :deny
    end},
  ip: {127, 0, 0, 1}, port: 0, startup_log: false,
  http_options: [compress: false])
{:ok, {_, port}} = ThousandIsland.listener_info(server)
url = "http://127.0.0.1:#{port}/decision"
```

The loopback listener and generated keys belong to this example. Supervise and
reuse pools and custody owners in your application; use TLS between services.

## 4. Require a verified response in Req

Both outcomes pass the same signature policy, including a 403 deny. Keep
automatic retries and redirects disabled; a signed denial is a decision, and
transport ambiguity is not an allow. `decode_body: false` keeps the bytes intact
until verification has succeeded.

```elixir
decisions =
  for {operation, expected_status, expected_decision} <- [
        {"read", 200, "allow"}, {"write", 403, "deny"}
      ] do
    body = :json.encode(%{"operation" => operation}) |> IO.iodata_to_binary()
    {:ok, request} = RequestSeal.Req.attach(
      Req.new(url: url, method: :post, body: body,
        headers: [{"content-type", "application/json"}],
        finch: [name: DecisionHookExample.Finch],
        retry: false, redirect: false, decode_body: false),
      sign: request_signing, signer: caller_handle,
      verify: %{policy: response_policy, label: "decision", max_stream_bytes: 4096})
    {:ok, response} = Req.request(request)
    ^expected_status = response.status
    {:ok, verification} = RequestSeal.Req.verification(response)
    :valid = verification.signature.crypto
    %{"decision" => ^expected_decision} = :json.decode(response.body)
    {operation, response, verification}
  end
```

Handle `{:error, %RequestSeal.Adapter.Error{reason: :response_rejected}}` as an
unauthenticated response. Do not read it as an allow or deny. Other delivery
errors follow [delivery classification](req-and-finch.md#classify-delivery-before-retrying).

## 5. Prove request binding and reject changed or unsigned responses

Finch requires the exact signed request when verifying the response. A second
signature over the same method, URL and body is a different request. The first
response cannot be transplanted to it. Body mutation and missing signature
fields also reject.

```elixir
request = Finch.build(:post, url, [{"content-type", "application/json"}], ~s({"operation":"read"}))
{:ok, sent} = RequestSeal.Finch.sign(request, request_signing, caller_handle)
{:ok, response} = Finch.request(sent, DecisionHookExample.Finch)
{:ok, _verified} = RequestSeal.Finch.verify(response, sent, response_policy, label: "decision")

{:ok, other_request} = RequestSeal.Finch.sign(request, request_signing, caller_handle)
{:error, %RequestSeal.Adapter.Error{reason: :response_rejected}} =
  RequestSeal.Finch.verify(response, other_request, response_policy, label: "decision")
{:error, %RequestSeal.Adapter.Error{reason: :response_rejected}} =
  RequestSeal.Finch.verify(%{response | body: ~s({"decision":"deny"})}, sent,
    response_policy, label: "decision")
unsigned = %{response | headers: Enum.reject(response.headers, fn {name, _} ->
  String.downcase(name) in ["signature", "signature-input"]
end)}
{:error, %RequestSeal.Adapter.Error{reason: :response_rejected}} =
  RequestSeal.Finch.verify(unsigned, sent, response_policy, label: "decision")
```

[Standard Webhooks](https://github.com/standard-webhooks/standard-webhooks/blob/main/spec/standard-webhooks.md)
signs webhook requests and defines delivery success from HTTP status. It does
not specify a signed response bound to the originating request. A Standard
Webhooks response is therefore unauthenticated at the message-signature layer;
its 2xx status alone is not a cryptographically authenticated decision. TLS has
its own transport authentication. Add the explicit RFC 9421 response policy when
the application needs an authenticated allow or deny. The unsigned mutation
above tests that requirement; it is not a Standard Webhooks conformance test.

For deliveries managed by ash_hooks, see [Webhooks with ash_hooks](ash-hooks.md).
That integration owns delivery and retry behavior; its delivery-success status
does not supply this decision-response contract.

## 6. Stop the example's resources

```elixir
:ok = Supervisor.stop(server)
:ok = Supervisor.stop(pool)
:ok = RequestSeal.Custody.release(caller_handle)
:ok = RequestSeal.Custody.release(service_handle)
```

Module docs: `RequestSeal.Req`, `RequestSeal.Finch`, `RequestSeal.Plug.SignResponse`,
`RequestSeal.Policy`, `RequestSeal.Custody`.
