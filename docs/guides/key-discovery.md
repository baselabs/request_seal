<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# Discover trusted public keys over HTTPS

**What you will build:** An HTTPS JWKS fetcher, an explicit verification policy using its keys, and a caller-owned cache with key removal. Install RequestSeal and configure `:my_app` with `:jwks_url` (your trusted publisher), `:trusted_key_thumbprint` (the public key ID you expect), `:jwks_ca_roots` (`:os` or DER CA certificates), and `:jwks_permitted_addresses` (`[]` for public hosts or explicit IP tuples for a trusted private deployment). Sources: [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html), [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html), [Web Bot Auth protocol-00](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html), and [CIMD-02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.html).

## 1. Fetch only your configured source

```elixir
jwks_url = Application.fetch_env!(:my_app, :jwks_url)
thumbprint = Application.fetch_env!(:my_app, :trusted_key_thumbprint)
trust_roots = Application.fetch_env!(:my_app, :jwks_ca_roots)
permitted_addresses = Application.fetch_env!(:my_app, :jwks_permitted_addresses)
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
resolver = RequestSeal.Discovery.resolver(key_set, algorithms: ["ed25519"])
{:ok, %{key: discovered_key}} = resolver.(%{keyid: thumbprint})

{:ok, discovered_policy} =
  RequestSeal.Policy.new(%{
    algorithms: ["ed25519"],
    components: ~s[("@method" "@authority" "@path" "content-digest")],
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

This example expects the publisher to publish the matching key. In your app, configure the source and accepted key IDs independently. No message-supplied ID selects a URL. `fetch/2` performs one bounded operation; you start SSL and choose addresses, roots, redirects, and byte/key/time limits.

## 2. Cache explicitly and remove a key

```elixir
{:ok, cache} = RequestSeal.Discovery.Cache.start_link(max_sources: 8)
{:ok, _snapshot} = RequestSeal.Discovery.Cache.refresh(cache, source)

{:ok, resolution} =
  RequestSeal.Discovery.Cache.resolve(cache, source, thumbprint, algorithms: ["ed25519"])

RequestSeal.Discovery.Cache.remove(cache, source, thumbprint)
# => :ok
RequestSeal.Discovery.Cache.invalidate(cache, source)
# => :ok
RequestSeal.Discovery.Cache.resolve(cache, source, thumbprint, algorithms: ["ed25519"])
# => {:error, %RequestSeal.Discovery.Error{reason: :revoked_key, ...}}
```

Use `Discovery.resolver({cache, source}, algorithms: [...])` for a generic policy backed by the cache. Cache misses/expiry may fetch under your source configuration; refresh, removal, and invalidation are explicit. Removal is a persistent thumbprint denial, including after refresh or invalidation. The cache has no background timer and never serves expired keys after a failed refresh.

## Source and key-ID options

Choose `:directory`, `:jwks_uri`, or `:cimd`; each requires explicit HTTPS. A directory origin expands to its well-known path. Signed directory possession proofs are required by default and establish possession; your profile's trust policy owns principal attribution. CIMD requires the exact document `client_id` spelling and may resolve a same-origin JWKS subresource.

Default key IDs are SHA-256 RFC 7638/8037 thumbprints. JWKS and CIMD may explicitly choose `key_id: :directory` for unique directory-assigned IDs; thumbprints still govern identity, revocation, and removal. Directory sources always require thumbprint IDs. Private, malformed, revoked, expired, not-yet-valid, or verification-forbidden keys cannot establish a resolver success.

HTTP freshness honors Cache-Control max-age before Expires, adjusted by Date/Age and source bounds. Without either field, fallback freshness defaults to 300 seconds. No-cache/no-store is not retained. Negative caching is at most 300 seconds; CIMD failures are not cached. Configure trusted clocks and do not silently reuse a stale snapshot. Discovery and custody workers terminate on deadlines or caller death.

## Errors

`RequestSeal.Discovery.Error` separates `:address_denied` and `:redirect_denied` (source policy) from TLS/transport errors, `:invalid_key_set` (document/key shape), `:unknown_key` (no eligible selected ID), `:revoked_key`, `:source_unavailable`, and `:cache_overloaded`. `:unexpected_status` is retryable for 5xx and nonretryable for 4xx; your application owns retry scheduling. No exception text or URL is retained in the bounded error.

Module docs: `RequestSeal.Discovery`, `RequestSeal.Discovery.Source`, `RequestSeal.Discovery.KeySet`, `RequestSeal.Discovery.Resolution`, `RequestSeal.Discovery.Cache`, `RequestSeal.Discovery.Error`.
