# Discover trusted public keys over HTTPS

**What you will build:** An HTTPS JWKS fetcher, an explicit verification policy using its keys, and a caller-owned cache with key removal. Install RequestSeal and choose a trusted HTTPS publisher. Set `JWKS_URL` in your environment to your trusted publisher's HTTPS endpoint. System CA roots and public addresses are the defaults; for an approved private publisher, set `JWKS_CA_FILE` to a PEM CA file and `JWKS_PERMITTED_ADDRESSES` to comma-separated IP addresses. Select the source independently of message-supplied key IDs. Sources: [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), [Web Bot Auth protocol-00](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html), and [CIMD-02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html), with the stricter root-path rule of [CIMD-03](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03) Section 3: a client identifier whose path is only `/` rejects.

## 1. Fetch only your configured source

```elixir
jwks_url = System.fetch_env!("JWKS_URL")

trust_roots =
  case System.get_env("JWKS_CA_FILE") do
    nil ->
      :os

    path ->
      for {:Certificate, der, :not_encrypted} <- :public_key.pem_decode(File.read!(path)), do: der
  end

permitted_addresses =
  for address <- String.split(System.get_env("JWKS_PERMITTED_ADDRESSES", ""), ",", trim: true) do
    {:ok, ip} = :inet.parse_address(String.to_charlist(String.trim(address)))
    ip
  end

{:ok, _apps} = Application.ensure_all_started(:ssl)

{:ok, source} =
  RequestSeal.Discovery.Source.new(%{
    type: :jwks_uri,
    location: jwks_url,
    cacerts: trust_roots,
    permitted_addresses: permitted_addresses,
    timeout: 5_000
  })

{:ok, key_set} = RequestSeal.Discovery.fetch(source)
```

Use the fetched keys in a resolver and select the rest of your acceptance policy explicitly:

```elixir
{thumbprint, _entry} = Enum.at(key_set.keys, 0)
resolver = RequestSeal.Discovery.resolver(key_set, algorithms: ["ed25519"])
{:ok, %{key: discovered_key}} = resolver.(%{keyid: thumbprint})

{:ok, discovered_policy} =
  RequestSeal.Policy.new(%{
    algorithms: ["ed25519"],
    components: ~s[("@method" "@scheme" "@authority" "@path" "content-digest")],
    key_resolver: resolver,
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

This example uses an Ed25519 JWKS publisher. Selecting a fetched key demonstrates resolution; application policy chooses which publisher and keys to trust. In your app, configure the source and accepted key IDs independently. No message-supplied ID selects a URL. `fetch/2` performs one bounded operation; you start SSL and choose addresses, roots, redirects, and byte/key/time limits.

## 2. Cache explicitly and remove a key

```elixir
{:ok, cache} = RequestSeal.Discovery.Cache.start_link(max_sources: 8)
{:ok, _snapshot} = RequestSeal.Discovery.Cache.refresh(cache, source)

{:ok, resolution} =
  RequestSeal.Discovery.Cache.resolve(cache, source, thumbprint, algorithms: ["ed25519"])

:ok = RequestSeal.Discovery.Cache.remove(cache, source, thumbprint)
:ok = RequestSeal.Discovery.Cache.invalidate(cache, source)
RequestSeal.Discovery.Cache.resolve(cache, source, thumbprint, algorithms: ["ed25519"])
# => {:error, %RequestSeal.Discovery.Error{reason: :revoked_key, ...}}
```

Use `Discovery.resolver({cache, source}, algorithms: [...])` for a generic policy backed by the cache. Cache misses/expiry may fetch under your source configuration; refresh, removal, and invalidation are explicit. Removal is a persistent thumbprint denial, including after refresh or invalidation. Removing a directory proof signer also removes keys authenticated by that proof, including from responses already in flight. The cache has no background timer and never serves expired keys after a failed refresh.

## Source and key-ID options

Choose `:directory`, `:jwks_uri`, or `:cimd`; each requires explicit HTTPS. A directory origin expands to its well-known path. Signed directory possession proofs are required by default and establish possession; your profile's trust policy owns principal attribution. CIMD requires the exact document `client_id` spelling and may resolve a same-origin JWKS subresource.

Default key IDs are SHA-256 RFC 7638/8037 thumbprints. JWKS and CIMD may explicitly choose `key_id: :directory` for unique directory-assigned IDs; thumbprints still govern identity, revocation, and removal. Directory sources always require thumbprint IDs. A timed rotation can publish several candidates under one directory ID. Resolution succeeds only when one candidate is valid throughout the lookup interval and no other candidate could be valid within it. Source revocations apply to the selected key and all signers of its directory proof. Private, malformed, revoked, expired, not-yet-valid, or verification-forbidden keys cannot establish a resolver success. A JWKS key's `alg` may use its standard RFC 7517 JOSE name (`"EdDSA"`) or the HTTP registry identifier (`"ed25519"`); either spelling normalizes once at import, and either allowlist spelling selects the key. A key whose `alg` names an algorithm RequestSeal does not verify with — an encryption key, or a name outside both registries — is skipped and the rest of the set still resolves; a malformed non-string `alg` still rejects the whole set.

HTTP freshness honors Cache-Control max-age before Expires, adjusted by Date, Age, and source bounds. Both 200 and 304 responses use the earliest possible request and response times for cache freshness under RFC 9111 Section 4.2.3. The reported fetch time remains the upper end of the response interval. Without explicit freshness, the fallback defaults to 300 seconds. No-cache and no-store responses serve only the current fetch, including qualified directives such as `no-cache="content-type"`. An `ETag` enables conditional revalidation with `If-None-Match`. A 304 with the stored ETag keeps the stored keys and replaces the freshness fields it supplies. Stored fields such as an absolute Expires still apply if omitted. A 304 without an ETag causes an unconditional fetch. Key and proof expiry still bound reuse. Negative caching is at most 300 seconds from the lower endpoint of the failure interval. CIMD failures are never cached. Discovery and custody workers terminate on deadlines or caller death.

The HTTP parser skips at most four interim 1xx responses. Field values are trimmed of space and horizontal tab under RFC 9110 Section 5.6.3. A malformed content length, transfer encoding, content encoding, or media type rejects with `:invalid_response`.

## Errors

`RequestSeal.Discovery.Error` separates `:address_denied` and `:redirect_denied` (source policy) from TLS/transport errors, `:invalid_key_set` (document/key shape), `:unknown_key` (no eligible selected ID), `:revoked_key`, `:source_unavailable`, and `:cache_overloaded`. `:unexpected_status` is retryable for 5xx and nonretryable for 4xx; your application owns retry scheduling. No exception text or URL is retained in the bounded error. `:transport_unavailable` means the `:ssl` application is not started. `RequestSeal.Discovery.Source.new/1` returns `:invalid_source` for a malformed source and `:invalid_options` for out-of-range options such as a `negative_ttl` above 300.

Module docs: `RequestSeal.Discovery`, `RequestSeal.Discovery.Source`, `RequestSeal.Discovery.KeySet`, `RequestSeal.Discovery.Resolution`, `RequestSeal.Discovery.Cache`, `RequestSeal.Discovery.Error`.
