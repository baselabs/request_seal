<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# Sign JWS and encrypt JWE envelopes

**What you will build:** A compact signed JWS wrapped in an encrypted JWE, with authentication of both envelopes before reading the payload. Prerequisite: RequestSeal installed; no framework is needed. Sources: [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), and [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html).

## 1. Sign and verify JWS

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, jose_handle} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
{:ok, jose_key} = RequestSeal.Custody.public_key(jose_handle)
{:ok, token} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}], "signed payload", jose_handle)
```

Trust the public key and allow only EdDSA when verifying:

```elixir
jws_policy = %{
  algorithms: ["EdDSA"],
  timeout: 5_000,
  key_resolver: fn %{algorithm: "EdDSA"} ->
    {:ok, %{algorithm: "EdDSA", key: jose_key}}
  end
}

{:ok, result} = RequestSeal.JOSE.JWS.verify(token, jws_policy)
result.payload
# => "signed payload"
```

HTTP and JOSE algorithm tokens are separate; `{:jws, "EdDSA"}` binds this handle to JOSE. `JWS.sign_protected/4` accepts your serialized protected JSON when exact protected bytes matter. The resolver selects trusted key material; `kid` and `x5c` alone confer no trust.

## 2. Encrypt the signed envelope and verify the inner signature

```elixir
wrapping_key = {:aes, :crypto.strong_rand_bytes(32)}

wrap = fn algorithm, cek ->
  RequestSeal.JOSE.KeyManagement.wrap(algorithm, cek, %{}, wrapping_key)
end

{:ok, encrypted} =
  RequestSeal.JOSE.JWE.encrypt(
    [{"alg", "A256GCMKW"}, {"enc", "A256GCM"}],
    token,
    wrap
  )
```

Select the trusted wrapping key and verify the inner signature after decryption:

```elixir
jwe_policy = %{
  algorithms: ["A256GCMKW"],
  encryption: ["A256GCM"],
  max_plaintext: 1_048_576,
  timeout: 5_000,
  key_resolver: fn %{algorithm: "A256GCMKW"} ->
    {:ok,
     %{
       algorithm: "A256GCMKW",
       unwrap: fn bytes, header ->
         RequestSeal.JOSE.KeyManagement.unwrap("A256GCMKW", bytes, header, wrapping_key)
       end
     }}
  end
}

{:ok, decrypted} = RequestSeal.JOSE.JWE.decrypt(encrypted, jwe_policy)
{:ok, inner} = RequestSeal.JOSE.JWS.verify(decrypted.plaintext, jws_policy)
inner.payload
# => "signed payload"
```

The wrapping key stays in your callback. Encryption uses fresh content-encryption keys and IVs from the real random generator. `RequestSeal.JOSE.Nested.verify/4` also supports one-level JWS-in-JWE verification with explicit outer/inner policies and `content_types: ["JWS"]` when the outer protected header declares `cty: "JWS"`. Decryption withholds all plaintext until AEAD authentication succeeds. Recipient integrity alone does not establish sender origin, identity, or request association.

## Options and bounds

Choose exact algorithm allowlists, timeout, content-encryption algorithms, and maximum plaintext. Compact envelopes are at most 1 MiB, protected JSON at most 16 KiB and depth four. Base64url is canonical and unpadded. Duplicate JSON members and floats reject. Compression, detached JWS, JSON serializations, remote/embedded key headers, `b64`, and `crit` are unsupported; choose a different protocol contract when those are required.

This is generic JOSE, with no JWT claims policy, implicit key lookup, provider profile, trust anchor, freshness, replay, or authorization. Apply those application rules separately. Tests use Node WebCrypto as an independent verifier, in addition to published vectors and local cryptography.

## Errors

`RequestSeal.JOSE.Error` carries bounded reasons and no input text. `:invalid_signature` rejects a JWS mismatch. `:decryption_failed` covers key unwrap and AEAD failure without releasing partial plaintext. `:detached_payload` rejects empty JWS payloads. `:algorithm_not_permitted`, `:invalid_options`, and `:limit` require a supported explicit contract or smaller input. Inspect the module's exact reason/layer list before implementing error handling.

Module docs: `RequestSeal.JOSE`, `RequestSeal.JOSE.JWS`, `RequestSeal.JOSE.JWE`, `RequestSeal.JOSE.Nested`, `RequestSeal.JOSE.KeyManagement`, `RequestSeal.JOSE.Error`.
