<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# Sign and verify Web Bot Auth agents

**What you will build:** A signed agent request verified against a held public key, then a request whose agent URL is authenticated through trusted HTTPS key discovery. Install RequestSeal; the held-key example needs no framework or network. The implemented revision is [draft-ietf-webbotauth-httpsig-protocol-00](https://www.ietf.org/archive/id/draft-ietf-webbotauth-httpsig-protocol-00.html); select this revision explicitly when checking interoperability.

## Set up the key and request

Generate an example Ed25519 key. In your application, reuse a long-lived key handle and configure trust in its public key independently.

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
signer = fn "ed25519", bytes -> RequestSeal.Custody.sign(handle, bytes) end
```

Build the request once, retaining its exact JSON bytes and digest. This held-key policy leaves body integrity unchecked:

```elixir
{:ok, message} =
  RequestSeal.Message.request(
    "POST",
    "https://api.example.com/webhooks",
    [],
    ~s({"event":"created"}),
    digest: ["sha-256"]
  )
```

## 1. Sign and verify with a held key

```elixir
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
```

Trust the key by its thumbprint and select the verified signature from the envelope:

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
```

`agents: fn _ -> :error end` intentionally trusts no agent URL. `unresolved: {:held_keys, ...}` explicitly permits only the pinned public key. It does not certify the advertised URL. The result is an envelope; select a verified label from `envelope.signatures`.

## 2. Authenticate an agent URL

Configure `:my_app, :agent_jwks_url` with an HTTPS publisher that serves the public key above, `:agent_ca_roots` with `:os` or trusted DER CA certificates, and `:agent_permitted_addresses` with `[]` for public hosts or explicit IP tuples for a trusted private deployment. Configure your source independently of the received request:

```elixir
jwks_url = Application.fetch_env!(:my_app, :agent_jwks_url)
trust_roots = Application.fetch_env!(:my_app, :agent_ca_roots)
permitted_addresses = Application.fetch_env!(:my_app, :agent_permitted_addresses)
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

Sign and verify against that configured association:

```elixir
{:ok, discovered_agent_policy} =
  RequestSeal.WebBotAuth.Policy.new(%{
    algorithms: ["ed25519"],
    cache: nil,
    agents: fn
      %{location: location, type: :jwks_uri} when location == key_set.source.location ->
        {:ok, key_set}

      _ ->
        :error
    end,
    freshness: %{clock: fn -> System.system_time(:second) end, max_age: 60, skew: 5},
    content: :not_required,
    replay: :not_required
  })
```

Sign with the same key and verify the association to the configured URL:

```elixir
now = System.system_time(:second)

{:ok, discovered_request} =
  RequestSeal.WebBotAuth.sign(
    message,
    %{
      label: "agent",
      agent: %{location: key_set.source.location, type: :jwks_uri},
      key: key,
      algorithm: "ed25519",
      created: now,
      expires: now + 60,
      nonce: nil
    },
    signer
  )

{:ok, discovered_envelope} =
  RequestSeal.WebBotAuth.verify(
    discovered_request,
    discovered_agent_policy
  )

discovered_envelope.signatures["agent"].principal.kind
# => :agent
```

Instead of a fetched KeySet, your trust callback may return a configured `Discovery.Source` and use a caller-started `cache`. The received URL never selects an arbitrary network destination. Directory proofs establish key possession; your chosen source policy establishes the trusted association. Discovery supports directories, JWKS, and CIMD; [key discovery](key-discovery.md) covers source configuration and caching.

## Draft rules and options

Every selected `web-bot-auth` signature independently needs created/expires, a SHA-256 JWK thumbprint key ID, authority or target URI coverage, and its matching dictionary `Signature-Agent` member when present. Legacy string fields reject. Signing adds the matching member and always covers authority and agent identity; extra `components:` adds coverage. HMAC is forbidden. Signing lifetimes are positive and at most 86,400 seconds; verification has an explicit `max_lifetime` bound. Published test keys reject by default.

Nested signatures cover the inner Signature-Input and all inner components independently. `evidence` records inner labels, without implying delegation. Required replay claims once only after every selected signature and nested requirement passes; see [replay protection](replay-protection.md). Held-key mode waives field presence only when the field is absent; a present dictionary still needs the selected member. `untagged: :ignore` records unrelated labels in `ignored`; choose `:reject` to forbid them.

## Errors

`RequestSeal.Error` remains bounded. `:agent_unresolved` identifies association failures such as `:missing_member`, `:untrusted_agent`, `:source_mismatch`, `:unknown_key`, or `:timeout`; it is not a claim of invalid cryptography. `:invalid_signature_agent` means the field grammar or dictionary members violate this draft. `:lifetime_exceeded` rejects the timestamp window; `:nested_coverage_incomplete` rejects incomplete inner coverage; `:test_key_rejected` rejects a known published test key.

Protocol-00 appendix examples contain member-label and lifetime contradictions. [Testing and evidence](testing.md#web-bot-auth-evidence) explains which published bytes verify generically and which profile checks reject them. Local examples establish construction and configured verification, not acceptance by a deployed agent provider.

Module docs: `RequestSeal.WebBotAuth`, `RequestSeal.WebBotAuth.Policy`, `RequestSeal.WebBotAuth.Verification`, `RequestSeal.Discovery`, `RequestSeal.Error`.
