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

## Use an SSH agent

`RequestSeal.Custody.SSHAgent.new/4` takes an explicit absolute agent socket path, supported algorithm, and trusted public key. It proves possession by signing and verifying before returning a handle. It never reads SSH_AUTH_SOCK, starts an agent, or loads private files. You start and load your OpenSSH agent, then select its socket explicitly. Supported algorithms include HTTP Ed25519, RSA-v1_5-SHA256, P-256, and P-384, and their documented JWS selections; PSS and HMAC reject. See the module's cited SSH standards and public protocol.

## Deadlines and secrets

`Custody.sign/3` and `verify/4` bound work with `timeout:` (default 5,000 ms). Monitored workers terminate on deadlines and caller cancellation; cancellation cannot revoke external work already accepted by a peer. HMAC secret verification stays inside custody; key equivalence for shared secrets is an explicit nonsecret custodian value, never derived by RequestSeal. Public-key resolution does not expose private material. Custodians are trusted code and must propagate deadlines and keep secrets out of logs.

## Errors

`RequestSeal.Custody.Error` uses bounded reasons. `:key_not_found` means the holder or agent key is gone. `:key_mismatch` means the material cannot serve the selected algorithm. `:unsupported_format` includes PKCS #8 v2 containers. `:deadline_exceeded` stops the operation. Agent `:custodian_unavailable` can describe a retryable pre-send connection failure; post-send `:custodian_protocol` is nonretryable because the signing request may already have reached the agent. Verification proves mathematical validity, not identity attribution or authority.

Module docs: `RequestSeal.Custody`, `RequestSeal.Custody.Local`, `RequestSeal.Custody.SSHAgent`, `RequestSeal.KeyHandle`, `RequestSeal.PublicKey`, `RequestSeal.Custody.Error`.
