<!-- Status: current · Kind: guide · Updated: 2026-10-08 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

# Keep signing keys behind a handle

**What you will build:** A local signing handle that keeps private key material in its holder process, verifies exact signed bytes, and can be explicitly released. Prerequisite: RequestSeal installed. Ed25519 follows [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html); public JWK thumbprints follow [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) and [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html).

## 1. Create an example key handle

```elixir
{_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
```

A handle exposes signing operations and public metadata, not private key export. Construction explicitly starts a sensitive holder process; loading the library starts nothing. For existing keys, `Custody.Local.import/4` accepts an explicit PEM or private JWK format, validates algorithm/key restrictions, derives the public key, and performs a real sign/verify before returning the handle.

## 2. Sign, verify, and release

```elixir
{:ok, signature} = RequestSeal.Custody.sign(handle, "exact bytes", timeout: 5_000)
RequestSeal.Custody.verify(handle, "exact bytes", signature, timeout: 5_000)
# => :ok
RequestSeal.Custody.verify(handle, "changed bytes", signature)
# => {:error, %RequestSeal.Custody.Error{reason: :invalid_signature, ...}}
```

Release the handle when its owning process no longer needs it:

```elixir
RequestSeal.Custody.Local.release(handle)
# => :ok
RequestSeal.Custody.sign(handle, "exact bytes")
# => {:error, %RequestSeal.Custody.Error{reason: :key_not_found, ...}}
```

Keep reusable handles in a long-lived owning process. Holders stop when their creating process exits, even after transfer, or when you release them; dropping a handle alone does not stop one. Long-lived owners must release handles they no longer use.

## Decryption keys

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

## Use an SSH agent

`RequestSeal.Custody.SSHAgent.new/4` takes an explicit absolute agent socket path, supported algorithm, and trusted public key. It proves possession by signing and verifying before returning a handle. It never reads SSH_AUTH_SOCK, starts an agent, or loads private files. You start and load your OpenSSH agent, then select its socket explicitly. Supported algorithms include HTTP Ed25519, RSA-v1_5-SHA256, P-256, and P-384, and their documented JWS selections; PSS and HMAC reject. See the module's cited SSH standards and public protocol.

## Deadlines and secrets

`Custody.sign/3` and `verify/4` bound work with `timeout:` (default 5,000 ms). Monitored workers terminate on deadlines and caller cancellation; cancellation cannot revoke external work already accepted by a peer. HMAC secret verification stays inside custody; key equivalence for shared secrets is an explicit nonsecret custodian value, never derived by RequestSeal. Public-key resolution does not expose private material. Custodians are trusted code and must propagate deadlines and keep secrets out of logs.

## Errors

`RequestSeal.Custody.Error` uses bounded reasons. `:key_not_found` means the holder or agent key is gone. `:key_mismatch` means the material cannot serve the selected algorithm. `:unsupported_format` includes PKCS #8 v2 containers. `:deadline_exceeded` stops the operation. Agent `:custodian_unavailable` can describe a retryable pre-send connection failure; post-send `:custodian_protocol` is nonretryable because the signing request may already have reached the agent. Verification proves mathematical validity, not identity attribution or authority.

Module docs: `RequestSeal.Custody`, `RequestSeal.Custody.Local`, `RequestSeal.Custody.SSHAgent`, `RequestSeal.KeyHandle`, `RequestSeal.PublicKey`, `RequestSeal.Custody.Error`.
