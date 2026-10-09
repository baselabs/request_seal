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

## Decrypt with a recipient key handle

For RSA-OAEP recipient custody, import an unencrypted private PEM into an
algorithm-bound unwrap handle. This example generates an RSA key locally; use
your existing PEM when provisioning a long-lived owner. The operation follows
[RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) and
[RFC 7518 Section 4.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3).
Encrypt to the handle's public key and return the handle from the resolver:

```elixir
private = :public_key.generate_key({:rsa, 2048, 65537})
pem = :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, private)])
{:ok, recipient_handle} =
  RequestSeal.Custody.Local.import({:jwe, "RSA-OAEP-256"}, pem, :pem)

# Run this health check at startup, before accepting encrypted messages.
{:ok, recipient_public} = RequestSeal.Custody.public_key(recipient_handle)
{:ok, recipient_jwe} =
  RequestSeal.JOSE.JWE.encrypt(
    [{"alg", "RSA-OAEP-256"}, {"enc", "A256GCM"}],
    "recipient payload",
    recipient_public
  )

recipient_policy = %{
  algorithms: ["RSA-OAEP-256"],
  encryption: ["A256GCM"],
  max_plaintext: 1_048_576,
  timeout: 5_000,
  key_resolver: fn %{algorithm: "RSA-OAEP-256"} ->
    {:ok, %{algorithm: "RSA-OAEP-256", key: recipient_handle}}
  end
}

{:ok, recipient_result} = RequestSeal.JOSE.JWE.decrypt(recipient_jwe, recipient_policy)
recipient_result.plaintext
# => "recipient payload"
:ok = RequestSeal.Custody.Local.release(recipient_handle)
```

The RSA private key stays in the sensitive local holder. The CEK passes through
the sensitive custody runner and middle process to JWE's sensitive worker. Those
four processes see the CEK; the outer JWE middle process and your decrypt caller
receive only the authenticated result. A direct `Custody.unwrap/3` caller receives
unwrapped bytes and owns their protection.

OAEP unwrap and GCM authentication failures return the identical complete
`%RequestSeal.JOSE.Error{reason: :decryption_failed, layer: :crypto,
correlation: nil, retryable: false}`. A released or unavailable resolved handle
makes every decrypt fail with that same error as a forged message, by design.
Use `RequestSeal.Custody.public_key(handle)` as a startup health check: successful
public resolution returns `{:ok, public_key}`; a stopped holder returns
`{:error, %RequestSeal.Custody.Error{reason: :key_not_found, retryable: false}}`.
This check reports custody availability separately from attacker-controlled
message failures. Deadline expiration remains a distinct error.

Reuse recipient handles in a long-lived owner. Release each handle when it is no
longer needed; holders also stop when their creating process exits. Recipient
integrity alone does not establish sender identity or authorization.

## Options and bounds

Choose exact algorithm allowlists, timeout, content-encryption algorithms, and maximum plaintext. Compact envelopes are at most 1 MiB, protected JSON at most 16 KiB and depth four. Base64url is canonical and unpadded. Duplicate JSON members and floats reject. Compression, detached JWS, JSON serializations, remote/embedded key headers, `b64`, and `crit` are unsupported; choose a different protocol contract when those are required.

This is generic JOSE, with no JWT claims policy, implicit key lookup, provider profile, trust anchor, freshness, replay, or authorization. Apply those application rules separately. Tests use Node WebCrypto as an independent verifier, in addition to published vectors and local cryptography.

## Errors

`RequestSeal.JOSE.Error` carries bounded reasons and no input text. `:invalid_signature` rejects a JWS mismatch. `:decryption_failed` covers key unwrap and AEAD failure without releasing partial plaintext. `:detached_payload` rejects empty JWS payloads. `:algorithm_not_permitted`, `:invalid_options`, and `:limit` require a supported explicit contract or smaller input. Inspect the module's exact reason/layer list before implementing error handling.

Module docs: `RequestSeal.JOSE`, `RequestSeal.JOSE.JWS`, `RequestSeal.JOSE.JWE`, `RequestSeal.JOSE.Nested`, `RequestSeal.JOSE.KeyManagement`, `RequestSeal.JOSE.Error`.
