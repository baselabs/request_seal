# Generate and derive keys in custody

Create fresh signing, wrapping, and agreement keys without bringing their private
material into caller memory. Derive deterministic children from an imported root
and receive a usable handle only after atomic commitment. You own each handle's
lifetime and any cleanup obligation.

Install RequestSeal in your Mix project, then run the examples in `iex -S mix`:

```elixir
{:request_seal, "~> 2.0"}
```

## Generate a fresh key

`RequestSeal.Custody.Local.generate/2` starts a sensitive holder owned by the
calling process. It generates and validates the key inside that holder; only an
algorithm-bound `RequestSeal.KeyHandle` is returned.

```elixir
{:ok, signer} = RequestSeal.Custody.Local.generate("ed25519", [])
{:ok, public_key} = RequestSeal.Custody.public_key(signer)
{:ok, signature} = RequestSeal.Custody.sign(signer, "exact bytes")
:ok = RequestSeal.Crypto.verify("ed25519", "exact bytes", signature, public_key)
{:error, %{reason: :invalid_signature}} = RequestSeal.Custody.verify(signer, "changed bytes", signature)
:ok = RequestSeal.Custody.release(signer)
{:error, %{reason: :key_not_found}} = RequestSeal.Custody.sign(signer, "exact bytes")
```

Select the algorithm and its required options explicitly:

| Algorithm | Required options | Default capabilities |
| --- | --- | --- |
| `"rsa-pss-sha512"`, `"rsa-v1_5-sha256"`, `{:jws, "RS256"}`, `{:jws, "PS256"}`, `{:jws, "PS384"}`, `{:jws, "PS512"}` | `bits: 2048`, `3072`, or `4096` | `[:sign, :verify]` |
| `"ecdsa-p256-sha256"`, `{:jws, "ES256"}` | None; P-256 | `[:sign, :verify]` |
| `"ecdsa-p384-sha384"`, `{:jws, "ES384"}` | None; P-384 | `[:sign, :verify]` |
| `"ed25519"`, `{:jws, "EdDSA"}` | None; Ed25519 | `[:sign, :verify]` |
| `"hmac-sha256"`, `{:jws, "HS256"}` | None; 32 bytes | `[:sign, :verify]` |
| `{:jwe, "RSA-OAEP"}`, `{:jwe, "RSA-OAEP-256"}` | `bits: 2048`, `3072`, or `4096` | `[:unwrap]` |
| `{:jwe, "A128KW"}`, `{:jwe, "A256KW"}` | None; 16 or 32 bytes | `[:wrap, :unwrap]` |
| `{:jwe, "ECDH-ES"}`, `{:jwe, "ECDH-ES+A128KW"}`, `{:jwe, "ECDH-ES+A256KW"}` | `curve: "P-256"`, `"P-384"`, or `"X25519"` | `[:unwrap]` |

Every family accepts `capabilities:` as a nonempty, unique subset of its defaults.
Every family also accepts `timeout:` from 1 to 300,000 ms, default 5,000, bounding
holder startup and generation. RSA uses public exponent 65,537. Give RSA-4096
more time on loaded hosts; it can exceed the default. These examples select a
longer generation budget and a narrower signing capability:

```elixir
{:ok, recipient} = RequestSeal.Custody.Local.generate({:jwe, "RSA-OAEP-256"}, bits: 2048, timeout: 30_000)
{:ok, agreement} = RequestSeal.Custody.Local.generate({:jwe, "ECDH-ES"}, curve: "X25519")
{:ok, signing_only} = RequestSeal.Custody.Local.generate({:jws, "EdDSA"}, capabilities: [:sign])

for handle <- [recipient, agreement, signing_only] do
  :ok = RequestSeal.Custody.release(handle)
end

{:error, %{reason: :invalid_options}} = RequestSeal.Custody.Local.generate("ed25519", bits: 2048)
{:error, %{reason: :unsupported_algorithm}} = RequestSeal.Custody.Local.generate({:jwe, "dir"}, [])
```

Generation does not support GCMKW, `dir`, or derivation parents. Import an existing
key with `Local.new/3` or `Local.import/4` when the application already has its
material. Those paths do not erase copies previously held by the caller.
Symmetric generated keys have no public key and have unknown equivalence.

## Derive and commit a child

Create a parent with `{:derive, "hkdf-sha256"}` and 32 to 64 input key material
(IKM) bytes. There is no generated-parent API. The following IKM is public test
material from [RFC 3394 Section 4.3](https://www.rfc-editor.org/rfc/rfc3394.html#section-4.3),
used here only to make the example reproducible. Provision a secret root through
your application's custody owner in production.

```elixir
example_ikm = Base.decode16!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
{:ok, parent} = RequestSeal.Custody.Local.new({:derive, "hkdf-sha256"}, {:ikm, example_ikm})

{:ok, child} = RequestSeal.Custody.derive(parent, "ed25519", "example/signing/v1", timeout: 5_000)
{:ok, child_public} = RequestSeal.Custody.public_key(child)

# Parent and committed child have independent lifetimes.
:ok = RequestSeal.Custody.release(parent)
{:ok, child_signature} = RequestSeal.Custody.sign(child, "derived-key example")
:ok = RequestSeal.Crypto.verify("ed25519", "derived-key example", child_signature, child_public)
:ok = RequestSeal.Custody.release(child)
```

`Custody.derive/4` requires a `timeout:` from 1 to 300,000 ms. Domain bytes are
1 to 255 bytes, without normalization. Optional `capabilities:` narrows the
target's defaults; `curve:` is required for ECDH-ES and refused for other targets.
Supported targets are HTTP `"ed25519"`, HTTP `"hmac-sha256"`, A128KW, A256KW,
and the three ECDH-ES algorithms above. JWS signing selections, RSA, and ECDSA
signing are not derivation targets.

Derivation composes [RFC 5869 Section 2](https://www.rfc-editor.org/rfc/rfc5869.html#section-2)
with the public RequestSeal framing: extract salt `"request-seal/derive/v1"`;
expand info is that prefix followed by the family and domain, each prefixed by
its unsigned 16-bit big-endian byte length. The families are `ed25519-seed`,
`hmac-sha256-key`, `aes128-key`, `aes256-key`, `x25519-dhkem`, `p256-dhkem`, and
`p384-dhkem`. The DHKEM families then apply
[RFC 9180 Section 7.1.3](https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3)
DeriveKeyPair with the selected curve's KEM, including SHA-384 for P-384.
This framing is a RequestSeal derivation contract, not an external signing profile.

The custodian's `derive/3` callback creates an uncommitted child with its final
owner and deadline. `commit/3` atomically commits it under the same deadline.
Uncommitted children refuse operations with `:unavailable` and destroy themselves
at deadline or owner death. Only an acknowledged commit returns `{:ok, child}`.
A custodian implementing derivation must implement `derive/3`, `commit/3`, and
confirmed, idempotent `release/2` together. Callers use `Custody.derive/4`, not
those callbacks directly.

## Handle uncertain commitment and cleanup

`Custody.derive/4` has three outcomes:

| Result | Caller obligation |
| --- | --- |
| `{:ok, child}` | Use and eventually release the committed handle. |
| `{:error, error}` | No committed child can remain, or destruction was confirmed. Handle the bounded error. |
| `{:cleanup_required, cleanup, error}` | Retain the cleanup capability and retry `Custody.cleanup/2` until `:ok`. No child handle was returned. |

A lost commit result triggers one release attempt under a fresh 1,000 ms context.
Only unconfirmed destruction returns `:cleanup_required`. The redacted
`RequestSeal.Custody.Cleanup` grants release only, never key use or metadata.
Here the successful local path executes; the other branches preserve the real
result and the cleanup obligation for the application's owner process:

```elixir
{:ok, root} = RequestSeal.Custody.Local.new({:derive, "hkdf-sha256"}, {:ikm, example_ikm})

{:error, %{reason: :invalid_data}} =
  RequestSeal.Custody.derive(root, "ed25519", "", timeout: 5_000)
{:error, %{reason: :invalid_options}} =
  RequestSeal.Custody.derive(root, "ed25519", "example/signing/v1", [])

outcome =
  case RequestSeal.Custody.derive(root, {:jwe, "A256KW"}, "example/wrapping/v1", timeout: 5_000) do
    {:ok, wrapping_key} ->
      :ok = RequestSeal.Custody.release(wrapping_key)
      :ok

    {:error, error} ->
      {:error, error}

    {:cleanup_required, cleanup, error} ->
      case RequestSeal.Custody.cleanup(cleanup, timeout: 5_000) do
        :ok -> {:error, error}
        {:error, _} -> {:cleanup_required, cleanup, error}
      end
  end

:ok = outcome
:ok = RequestSeal.Custody.release(root)
```

A cleanup error leaves the obligation with the caller. Retry with an explicit
`timeout:` of 1 to 300,000 ms; a timeout does not establish destruction. Successful
cleanup is idempotent. A normal `Custody.release/1` is also idempotent; `:ok`
confirms destruction. Holders stop on the original owner's death, even if another
process has a copy of the handle. Keep reusable handles in a long-lived owner.

## Error reasons

Errors are bounded `RequestSeal.Custody.Error` structs without private diagnostics.

| Reason | Meaning here |
| --- | --- |
| `:invalid_options` | Unknown, duplicate, missing, misplaced, or out-of-range option, curve, bits, or capability selection. |
| `:unsupported_algorithm` | Generation or derivation does not implement the selected algorithm. |
| `:invalid_data` | Derivation domain is not 1 to 255 bytes. |
| `:invalid_handle`, `:unsupported_operation` | Invalid parent or cleanup capability, or an operation the handle does not grant. |
| `:invalid_key`, `:key_mismatch` | Material or cryptographic validation failed. |
| `:key_not_found`, `:unavailable` | Released parent, unusable child, or refused atomic commit state. |
| `:deadline_exceeded` | The operation exhausted its absolute deadline. |
| `:custodian_failure` | A callback failed or returned an invalid result. External custodians can also return their documented bounded failures. |

Only `:deadline_exceeded` and `:custodian_unavailable` are marked retryable. That
flag never clears an outstanding cleanup obligation. Generation emits no telemetry;
derivation and cleanup emit no key, domain, reference, identity, or commit token.
See [key custody](key-custody.md) for imports, SSH agents, and supervised owners.
