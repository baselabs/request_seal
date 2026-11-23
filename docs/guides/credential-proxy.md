# Sign outbound requests in a credential proxy

**What you will build:** A proxy owns signing custody and sends signed requests
to a configured upstream using either Req or Finch. Its clients submit payloads
without receiving keys or custody handles. The runnable example starts two real
loopback Bandit listeners: the proxy and an upstream that verifies signatures.
Install the optional Req, Finch and Plug packages from the
[client guide](req-and-finch.md), plus Bandit (`>= 1.15.0 and < 2.0.0`) for the example listeners.
RequestSeal starts no server or pool automatically.

This applies [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) signatures,
[RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html) body integrity and the
[caller-owned custody](key-custody.md). The selected coverage
is an explicit application choice, not a provider profile or an external
conformance vector. No new RequestSeal API is needed.

## 1. Provision example custody and trust

Generate the signing key inside custody. This example's calling process owns
the handle for the entire run; the HTTP handlers receive a capability without
owning or exporting the key. Keep that process alive until the listeners stop.
For persistent keys across restarts, use the provisioned sources and supervised
Owner in [key custody](key-custody.md#long-lived-owner).

```elixir
{:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", [])
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, supervisor} = Supervisor.start_link(
  [{Finch, name: CredentialProxyExample.Finch}], strategy: :one_for_one)

components = ~s[("@method" "@scheme" "@authority" "@path" "content-type" "content-digest")]
signing = %{
  label: "sig", algorithm: "ed25519", components: components,
  expires_in: 60, keyid: "proxy-key", digest: ["sha-256"]
}
{:ok, policy} = RequestSeal.Policy.new(%{
  algorithms: ["ed25519"], components: components,
  key_resolver: fn
    %{keyid: "proxy-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
    _ -> :error
  end,
  freshness: %{
    clock: fn -> System.system_time(:second) end,
    max_age: 60, skew: 5, require_expires: true
  },
  content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
  replay: :not_required
})
```

This example permits repeated delivery. Use the caller-owned
[replay policy](replay-protection.md) when each request must be spent once.

## 2. Build the verifying upstream and forwarding proxy

The upstream captures bytes before parsing and verifies them before returning
the exact payload. Its example route has no query parameters. For production,
declare the upstream origin or enforce its served authorities as described in
the [Plug guide](phoenix-and-plug.md#origin-and-transport-options).

```elixir
defmodule CredentialProxyExample.Upstream do
  @behaviour Plug
  def init(options), do: options

  def call(%Plug.Conn{method: "POST", request_path: "/events", query_string: ""} = conn, options) do
    conn = RequestSeal.Plug.Capture.call(conn,
      RequestSeal.Plug.Capture.init(
        origin: :connection, max_body_bytes: 4096, read_timeout: 5_000))
    conn = RequestSeal.Plug.Verify.call(conn,
      RequestSeal.Plug.Verify.init(
        policy: options[:policy], label: "sig", on_reject: {:halt, 401}))

    if conn.halted do
      conn
    else
      {:ok, capture} = RequestSeal.Plug.capture(conn)
      Plug.Conn.send_resp(conn, 200, capture.message.body.bytes)
    end
  end

  def call(conn, _options), do: Plug.Conn.send_resp(conn, 404, "")
end

defmodule CredentialProxyExample.Proxy do
  @behaviour Plug
  def init(options), do: options

  def call(%Plug.Conn{method: "POST", path_info: ["forward", client], query_string: ""} = conn, options)
      when client in ["req", "finch"] do
    case Plug.Conn.read_body(conn, length: 4096, read_timeout: 5_000) do
      {:ok, body, conn} when byte_size(body) <= 4096 ->
        handle = options[:handle]
        case RequestSeal.Custody.public_key(handle) do
          {:ok, _public_key} ->
            case forward(client, body, handle, options) do
              {:ok, %{status: status, body: bytes}} -> Plug.Conn.send_resp(conn, status, bytes)
              {:error, _} -> Plug.Conn.send_resp(conn, 502, "upstream exchange failed")
            end

          {:error, _} ->
            Plug.Conn.send_resp(conn, 503, "signing unavailable")
        end

      {:ok, _body, conn} -> Plug.Conn.send_resp(conn, 413, "")
      {:more, _body, conn} -> Plug.Conn.send_resp(conn, 413, "")
      {:error, _} -> Plug.Conn.send_resp(conn, 400, "")
    end
  end

  def call(conn, _options), do: Plug.Conn.send_resp(conn, 404, "")

  defp forward("req", body, handle, options) do
    request = Req.new(
      method: :post, url: options[:upstream], body: body,
      headers: [{"content-type", "application/octet-stream"}],
      finch: [name: CredentialProxyExample.Finch],
      retry: false, redirect: false, decode_body: false)

    with {:ok, request} <- RequestSeal.Req.attach(request,
           sign: options[:signing], signer: handle, verify: :none) do
      Req.request(request)
    end
  end

  defp forward("finch", body, handle, options) do
    request = Finch.build(:post, options[:upstream],
      [{"content-type", "application/octet-stream"}], body)

    with {:ok, request} <- RequestSeal.Finch.sign(request, options[:signing], handle) do
      Finch.request(request, CredentialProxyExample.Finch)
    end
  end
end
```

The proxy constructs its outbound method, URL and headers from trusted
configuration. It forwards only the bounded body; inbound Host, Authorization,
signature fields and destination hints are not copied. Req signs after its last
request transformation. Finch signs the fully built request; send the returned
request unchanged. Retain a bounded stream explicitly before signing if your
application uses streams instead of buffered bodies.

The loopback demo grants local callers access to this one operation. Before
exposing a credential proxy, put your application's existing client authentication
and authorization in front of it, and restrict destinations and operations in
trusted configuration. Possessing a network route to a signer is not permission
to use its credential. RequestSeal does not supply that access policy.

## 3. Start both listeners under the example supervisor

```elixir
{:ok, upstream_server} = Supervisor.start_child(supervisor,
  Supervisor.child_spec({Bandit,
    plug: {CredentialProxyExample.Upstream, policy: policy},
    ip: {127, 0, 0, 1}, port: 0, startup_log: false,
    http_options: [compress: false]}, id: :example_upstream))
{:ok, {_, upstream_port}} = ThousandIsland.listener_info(upstream_server)
upstream_url = "http://127.0.0.1:#{upstream_port}/events"

{:ok, proxy_server} = Supervisor.start_child(supervisor,
  Supervisor.child_spec({Bandit,
    plug: {CredentialProxyExample.Proxy,
      handle: handle, upstream: upstream_url, signing: signing},
    ip: {127, 0, 0, 1}, port: 0, startup_log: false,
    http_options: [compress: false]}, id: :example_proxy))
{:ok, {_, proxy_port}} = ThousandIsland.listener_info(proxy_server)
proxy_url = "http://127.0.0.1:#{proxy_port}"
```

Use TLS for service traffic. `verify: :none` deliberately leaves the upstream's
response unsigned and unverified at the message layer in this recipe. Its echo
demonstrates request transport; do not treat its response as an authenticated
authorization decision. The [decision-hook recipe](decision-hook.md) shows
required response verification and binding to the request.

## 4. Send through each adapter without giving the client a credential

The client sends no signature or custody reference. Only the proxy uses the
configured handle, and only the verifying upstream returns 200 with the received payload.

```elixir
payload = <<0, 255, "exact proxy bytes\r\n", 0>>
responses =
  for client <- ["req", "finch"] do
    request = Finch.build(:post, proxy_url <> "/forward/" <> client, [], payload)
    {:ok, response} = Finch.request(request, CredentialProxyExample.Finch)
    200 = response.status
    ^payload = response.body
    response
  end
```

Retries and redirects are disabled on the outbound Req request. Neither branch
retries a failed exchange. The proxy's generic 502 does not prove the upstream
did nothing; use [delivery classification](req-and-finch.md#classify-delivery-before-retrying)
and application idempotency before repeating operations. Response signing is a
separate choice; it does not make a repeated operation safe.

## 5. Refuse when custody is unavailable

This last example deliberately releases the disposable example handle. Both
routes return 503 without falling back to an unsigned request. Keep production
key lifetimes under their owning process rather than releasing them per request.

```elixir
:ok = RequestSeal.Custody.release(handle)
refusals =
  for client <- ["req", "finch"] do
    request = Finch.build(:post, proxy_url <> "/forward/" <> client, [], payload)
    {:ok, response} = Finch.request(request, CredentialProxyExample.Finch)
    503 = response.status
    "signing unavailable" = response.body
    response
  end
```

## 6. Stop and remove the example's resources

The supervisor owns both listeners and Finch. Release the calling process's
handle explicitly after stopping the listeners; release is idempotent.

```elixir
:ok = Supervisor.stop(supervisor)
:ok = RequestSeal.Custody.release(handle)
```

Module docs: `RequestSeal.Req`, `RequestSeal.Finch`, `RequestSeal.Custody`,
`RequestSeal.Custody.Local`.
