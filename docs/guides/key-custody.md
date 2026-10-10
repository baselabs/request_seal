<!-- Status: current · Kind: guide · Updated: 2026-10-09 · Governed by: public architecture and accepted ADRs · Review when: the public API or referenced standard changes -->

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

## Long-lived owner

Add `RequestSeal.Custody.Local.Owner` to your application's supervision tree.
It owns one local holder for each valid Ed25519 seed. Fetching a handle does not
transfer ownership, so the handle survives the fetching process's exit.
This uses Ed25519 as defined by [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html),
with encoding tags from [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html).

Provision a seed file separately, set its mode to 0600 or 0400, and configure
`:my_app, :signing_seed_file` with its path. Prefer `{:file, ...}` in production;
environment seed values are inherited by OS child processes. The example file
contains an unpadded Base64url encoding of exactly 32 seed bytes. Add the child
to your existing tree; this standalone example starts a supervisor:

```elixir
alias RequestSeal.Custody.Local.Owner
seed_file = Application.fetch_env!(:my_app, :signing_seed_file)
children = [
  {Owner,
   name: MyApp.Custody,
   keys: [signing: {"ed25519", {:file, seed_file, :base64url}}]}
]
{:ok, supervisor} = Supervisor.start_link(children, strategy: :one_for_one)
Owner.status(MyApp.Custody)
# => %{signing: :ready}
Owner.ready?(MyApp.Custody, :signing)
# => true
```

Source forms are explicit:

| Source | Reads |
| --- | --- |
| `{:env, "SIGNING_SEED", encoding}` | The variable's value |
| `{:file, path, encoding}` | The file at that path |
| `{:file_from_env, "SIGNING_SEED_FILE", encoding}` | A path from the variable, then its file |

Encodings are `:base64url` (padding optional), `:base64` (padded), `:hex` (either case),
or `:raw`. Only ASCII space, tab, CR, and LF are trimmed from the ends of text
encodings; interior whitespace and non-ASCII whitespace reject. Base64 encodings
must be canonical, including unused trailing bits. Standard Base64 requires
padding; Base64url accepts canonical padded or unpadded input. Raw bytes are
unchanged. Avoid `:raw` seeds in environment variables, which cannot safely
represent arbitrary binary data. No encoding is guessed. Input is limited to 4,096 bytes including whitespace; decoded seeds
must contain exactly 32 bytes. Files must be regular, not symbolic links, with
mode 0600 or stricter: execute, group, other, and special permission bits reject.
A file that disappears or changes identity after its initial checks reports
`:insecure_file`. Keep files and their parent directories under trusted control
during startup.

`status/1` reports each configured name as `:ready`, `:unconfigured` for a missing
or empty variable, a missing file, or a stopped holder, or `{:error, :invalid_seed | :insecure_file | :unreadable}`.
Bad keys leave the Owner running. `fetch/2` returns `{:ok, handle}` for a ready
key, otherwise `{:error, :unconfigured}`; no signing handle is issued for a bad
key. An empty environment seed and an empty `:file_from_env` path both report
`:unconfigured`. Calls to a stopped or busy Owner return
`{:error, :owner_unavailable}` from both `fetch/2` and `status/1`; `ready?/2`
returns false in that case. `ready?/2` returns a Boolean. No registration is supported after startup.
Configuration descriptors contain variable names or paths, never literal seeds.

The Owner sets process sensitivity before reading sources, passes each decoded
seed directly into `Local.new/2`, retains only handles and bounded statuses, and
garbage-collects after initialization. Its holders monitor the Owner. The Owner
never deletes environment variables and rereads every source on restart.

**Restart rule:** fetch per signing operation, as below. If you cache a handle,
an Owner restart makes that old handle return custody `:key_not_found`; fetch a
new handle and retry signing once. If fetching returns `:owner_unavailable`
during restart, wait for the supervised Owner to become available before
fetching again. Releasing an Owner's handle also ends that
holder and makes its status `:unconfigured` until restart; keep its lifetime
under the supervision tree's control. Readiness is a snapshot, so signing can
still encounter an unavailable holder after a successful fetch.

The explicit signature form accepts a handle without generating or reordering
your signature parameters. It follows
[RFC 9421 Section 2.3](https://www.rfc-editor.org/rfc/rfc9421.html#section-2.3):

```elixir
{:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
spec = %{
  label: "sig",
  signature_input: ~s[("@method" "@scheme" "@authority" "@path");alg="ed25519"],
  algorithm: "ed25519"
}
{:ok, handle} = RequestSeal.Custody.Local.Owner.fetch(MyApp.Custody, :signing)
{:ok, signed} = RequestSeal.sign(message, spec, handle, signing_timeout: 5_000)
Enum.map(signed.fields, & &1.name)
# => ["Signature-Input", "Signature"]
```

`signing_timeout` is 1–300,000 ms, default 5,000. `field_schemas` remains available.
The existing arity-two function signer stays synchronous; a valid timeout option
does not interrupt it. A handle's algorithm must equal `spec.algorithm`.
Mismatch returns `RequestSeal.Error` with reason `:signer_algorithm_mismatch`,
layer `:input`, and the exact message string
`"signer algorithm does not match signature specification"`.
Custody failures return `RequestSeal.Error` with reason `:signing_failed`, layer
`:crypto`, and a bounded `RequestSeal.Custody.Error` in `source`. This preserves
`:key_not_found` and `:deadline_exceeded` for explicit and generated signing specs.
`Error.retryable` is false while `source.retryable` may be true for
`:deadline_exceeded`. Malformed or excessive signing output uses custody
`:invalid_signing_output`; malformed custody errors use `:custodian_failure`.
Both signing forms return these in `source` with outer reason `:signing_failed`.
Function errors in the explicit form retain the existing `:signer_failed` reason.

Owner terminate reports keep configured key names and bounded statuses. Both
terminate and crash reports use bounded atom reasons; private reason terms are
discarded before the process exits. Unknown abnormal reasons become
`:owner_failure`; `:badarg`, `:badarith`, `:function_clause`, and `:undef` remain
recognizable. Normal and shutdown exits retain their lifecycle meaning.

Module docs: `RequestSeal.Custody`, `RequestSeal.Custody.Local`, `RequestSeal.Custody.Local.Owner`, `RequestSeal.Custody.SSHAgent`, `RequestSeal.KeyHandle`, `RequestSeal.PublicKey`, `RequestSeal.Custody.Error`.
