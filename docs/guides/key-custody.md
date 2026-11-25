# Keep keys behind a custody handle

Create signing and decryption handles, verify exact bytes, and release keys when their owner no longer needs them. Install RequestSeal as described in the [README](../../README.md#installation), then run these examples in `iex -S mix`. Ed25519 follows [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html); public JWK thumbprints follow [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638.html) and [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html).


`RequestSeal.Custody.Local.generate/2` creates fresh keys inside a sensitive
holder; the caller receives a handle. RSA requires `bits: 2048 | 3072 | 4096`;
ECDH-ES requires `curve: "P-256" | "P-384" | "X25519"`. Other supported signing
and AES-KW algorithms fix their own widths. Optional `:capabilities` narrows
that family's defaults, and optional `:timeout` (default 5,000 ms) bounds startup
and generation; give RSA-4096 a longer one. GCMKW, `dir`, and derivation parents
cannot be generated.

For deterministic children, `Local.new/3` accepts
`{:derive, "hkdf-sha256"}` with `{:ikm, bytes}` of 32–64 bytes and `[:derive]`.
`Custody.derive/4` takes the target algorithm, 1–255 domain bytes and a required
`timeout:`; ECDH-ES targets also require `:curve`. Only acknowledged atomic
commitment returns a child handle. Uncommitted children refuse use and expire at
the operation deadline or owner death. A committed child belongs to the original
caller, independently of its parent. See `RequestSeal.Custody.derive/4` for the
exact HKDF framing and seven families.

A failed derive or explicit commit refusal returns an ordinary error. A lost
commit result triggers one release under a fresh 1,000 ms deadline. If destruction
is unconfirmed, `{:cleanup_required, cleanup, error}` returns the caller's redacted
release capability. Retry `Custody.cleanup/2`, with a required `timeout:`, until
`:ok`. The capability grants no key operations. Generation and derivation never
export raw keys or identities through telemetry; symmetric equivalence stays
unknown. Key material supplied to `new/3` or `import/4` remains a caller-owned
import path. The [generation and derivation guide](key-generation-and-derivation.md)
shows the complete runnable lifecycle and error handling.

## 1. Create an example key handle

```elixir
{:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", [])
{:ok, key} = RequestSeal.Custody.public_key(handle)
{:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
```

A handle exposes signing operations and public metadata, not private key export. Construction explicitly starts a sensitive holder process; loading the library starts nothing. For existing keys, `Custody.Local.import/4` accepts an explicit `:pem`, `:der` (PKCS #8), or `:jwk` (private JWK map) format, validates algorithm/key restrictions, derives the public key, and performs a real sign/verify before returning the handle.

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

For RSA-OAEP recipient custody, generate an algorithm-bound unwrap handle.
For an existing unencrypted private PEM, use `Local.import/4` instead.
The operation follows
[RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html) and
[RFC 7518 Section 4.3](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.3).
Encrypt to the handle's public key and return the handle from the resolver:

```elixir
{:ok, recipient_handle} =
  RequestSeal.Custody.Local.generate({:jwe, "RSA-OAEP-256"}, bits: 2048, timeout: 30_000)

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
  resolve_timeout: 1000,
  unwrap_timeout: 1000,
  protected: %{expected: %{}, permitted: ~w(kid typ cty)},
  key_resolver: fn %{algorithm: "RSA-OAEP-256"} ->
    {:ok, %{algorithm: "RSA-OAEP-256", key: recipient_handle}}
  end
}

{:ok, recipient_result} = RequestSeal.JOSE.JWE.decrypt(recipient_jwe, recipient_policy)
recipient_result.plaintext
# => "recipient payload"
:ok = RequestSeal.Custody.Local.release(recipient_handle)
```

The private key stays in the sensitive local holder. Each CEK passes directly
to JWE's sensitive worker through an owner-created sink. The custody runner
and middle process receive only the summary; your decrypt caller can
receive only the authenticated result. A direct `Custody.unwrap/3` caller receives
unwrapped bytes and owns their protection. On the BEAM, binaries are immutable:
a CEK that crossed those processes cannot be zeroed and stays in their heaps
until garbage collection. The mitigation is process-level:
every CEK-bearing process marks itself sensitive, so process inspection and
tracing from outside cannot observe the CEK (exercised by the repository's JWE
tests).

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

`RequestSeal.Custody.SSHAgent.new/4` takes a supported algorithm, an explicit absolute agent socket path, a trusted public key, and optional `timeout:`. It proves possession by signing and verifying before returning a handle. It never reads SSH_AUTH_SOCK, starts an agent, or loads private files. You start and load your OpenSSH agent, then select its socket explicitly. Supported algorithms include HTTP Ed25519, RSA-v1_5-SHA256, P-256, and P-384, and their documented JWS selections; PSS and HMAC reject. See the module's cited SSH standards and public protocol.

## Deadlines and secrets

`Custody.sign/3`, `verify/4`, and `unwrap/3` bound work with `timeout:` (1–300,000 ms, default 5,000). Monitored workers terminate on deadlines and caller cancellation; cancellation cannot revoke external work already accepted by a peer. HMAC secret verification stays inside custody; key equivalence for shared secrets is an explicit nonsecret custodian value, never derived by RequestSeal. Public-key resolution does not expose private material. Custodians are trusted code and must propagate deadlines and keep secrets out of logs.

Signing and verification also accept per-call `max_bytes:`: an integer from 1
through 16,777,216, with the existing 1,048,576-byte default. Bytes over the
selected value return `:invalid_data` before the private reference is read.
Local checks the operation owner's liveness and deadline before each item of an
unwrap range. Cancellation can leave one already-running native item to finish;
its late delivery is discarded by the revoked sink. JWE tracks the unwrap
callback and its cancellation watcher directly, preserving the completion event
when the callback is killed and reaping both before finalization.

Invalid values and duplicate options return `:invalid_options`; `unwrap/3`
does not accept this option. `RequestSeal.Crypto.sign/4` and `verify/5` expose
the same option for direct primitive calls. `RequestSeal.SignatureBase` retains
its separate 1,048,576-byte ceiling. `Message.request/5` and `Message.response/4`
retain at most 1,048,576 body bytes, message fields total at most 1,048,576 bytes,
and compact JWS and JWE are at most 1,048,576 bytes. `Body.new/1` (`max_bytes:`)
and `RequestSeal.Plug.Capture` (`max_body_bytes:`) use caller-selected limits. The
custody `max_bytes:` option changes none of these.

[OpenSSH caps the whole agent message at 256 KiB](https://github.com/openssh/openssh-portable/blob/V_9_9_P1/ssh-agent.c),
including protocol overhead, so payloads slightly under 262,144 bytes are the
practical limit. Observed with OpenSSH 9.9 and Ed25519: 262,000 bytes signed
successfully; 262,200 returned `:custodian_protocol`. Raising `max_bytes:` does
not raise the agent's limit.

SSH custody keeps the agent socket path inside the holder and its operation
workers. A transferred handle remains usable while its creator is alive.
Creator exit or `Custody.release/1` ends the holder and its operations.

## Errors

`RequestSeal.Custody.Error` uses bounded reasons. `:key_not_found` means the holder or agent key is gone. `:key_mismatch` means the material cannot serve the selected algorithm. `:unsupported_format` includes PKCS #8 v2 containers. `:deadline_exceeded` stops the operation. Agent `:custodian_unavailable` can describe a retryable pre-send connection failure; post-send `:custodian_protocol` is nonretryable because the signing request may already have reached the agent. `:custodian_rejected` means the agent does not hold the trusted key; `:unsupported_algorithm` means no implementation for that selection. Only `:deadline_exceeded` and `:custodian_unavailable` are retryable. Verification proves mathematical validity, not identity attribution or authority.

## Wrap and unwrap indexed items

AES-KW handles grant a nonempty subset of `[:wrap, :unwrap]`; ECDH-ES, GCMKW, and `dir`
handles grant only `[:unwrap]`. `Custody.wrap/3` accepts a 128- or 256-bit CEK.
`Custody.unwrap/3` accepts a list of `{encrypted_key, params, content_bits}` and
returns `{:ok, results}` in that order, each `{:ok, cek}`,
`{:error, :decryption_failed}`, or `{:error, :deadline_exceeded}`. Validation
failures return one `{:error, %RequestSeal.Custody.Error{}}`. Params are `%{}` except GCMKW's decoded
`%{iv: twelve_bytes, tag: sixteen_bytes}` and ECDH's
`%{epk: public_key, apu: bytes, apv: bytes, algorithm_id: id, key_bits: bits}`.
The custodian receives decoded params and never parses a protected header. Per-item failures are closed
`:decryption_failed` or `:deadline_exceeded` values, while handle and input
validation retain bounded custody errors. Accepted items survive a later stall.
`Custody.release/1` is idempotent; `:ok` confirms destruction.

Custom custodians implement `unwrap(ref, algorithm, indexed_items, sink, context)`.
Each item is `{index, encrypted_key, params, content_bits}`. The holder calls
`RequestSeal.Custody.Sink.deliver(sink, index, {:ok, cek})` or delivers `:error`;
the callback returns only `:ok` or a bounded error. A settled index never changes,
and the sink rejects late, unknown, malformed, or wrong-width deliveries. The
runner receives no CEKs. See [the 2.0 migration](upgrading-to-2.0.md#migrate-unwrap-calls-results-and-custom-custodians)
for the former callback and result shapes.

## ECDH recipient keys

Bind a handle to `{:jwe, "ECDH-ES"}`, `{:jwe, "ECDH-ES+A128KW"}`, or
`{:jwe, "ECDH-ES+A256KW"}`. Generate one with `Local.generate/2` and an explicit
`curve:`. For existing scalars, `Local.new/3` takes
`{:ec, "P-256" | "P-384", scalar}` (32 or 48 bytes), or
`{:x25519, scalar}` (32 bytes). Construction performs an actual agreement and
recovery round trip. These handles grant only `[:unwrap]`; requesting `:wrap`
is refused at construction. Senders encrypt to the public key returned by
`Custody.public_key/1`, and decryption resolvers return the exact algorithm-bound
handle. Holders remain sensitive and refuse system state inspection.

`Local.import/4` accepts private EC or OKP X25519 JWKs and checks that their
public components match the private scalar. JWK `alg` must match the selected
member, `use` must permit encryption, and `key_ops` must permit `deriveKey`,
`deriveBits`, `decrypt`, or `unwrapKey`. An explicit capability option can only
narrow this permission. The holder validates `epk` against its curve and rejects
an all-zero X25519 shared secret; each failed item delivers only `:error` to the
sink. CEKs go directly to their owner, and the custody runner sees only a summary.
These are the public mechanisms of [RFC 7518 §4.6](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6)
and [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html).

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
Every signing entry point requires a handle whose algorithm equals `spec.algorithm`.
Mismatch returns `RequestSeal.Error` with reason `:signer_algorithm_mismatch`,
layer `:input`, and the exact message string
`"signer algorithm does not match signature specification"`, for both the
explicit and the generated signing spec. Req, Finch, and Plug report it as an
adapter `:invalid_options` error whose `source` is that core error.
Custody failures return `RequestSeal.Error` with reason `:signing_failed`, layer
`:crypto`, and a bounded `RequestSeal.Custody.Error` in `source`. This preserves
`:key_not_found` and `:deadline_exceeded` for explicit and generated signing specs.
`Error.retryable` is false while `source.retryable` may be true for
`:deadline_exceeded`. Malformed or excessive signing output uses custody
`:invalid_signing_output`; malformed custody errors use `:custodian_failure`.
Both signing forms return these in `source` with outer reason `:signing_failed`.
Key closures reject with `:invalid_options` before invocation.

Owner terminate reports keep configured key names and bounded statuses. Both
terminate and crash reports use bounded atom reasons; private reason terms are
discarded before the process exits. Unknown abnormal reasons become
`:owner_failure`; `:badarg`, `:badarith`, `:function_clause`, and `:undef` remain
recognizable. Normal and shutdown exits retain their lifecycle meaning.

Module docs: `RequestSeal.Custody`, `RequestSeal.Custody.Local`, `RequestSeal.Custody.Local.Owner`, `RequestSeal.Custody.SSHAgent`, `RequestSeal.KeyHandle`, `RequestSeal.PublicKey`, `RequestSeal.Custody.Error`.

## Bind a key purpose and approve exact covered values

Use a purpose atom when a signing key is assigned to a specific workflow.
An assigned key requires the same purpose in the signing specification.
JWS takes `:issued_for` as an option on both signing forms. HTTP and compact
JWS verification policies name `:require_issued_for` to use a bound handle.
An omitted or nil purpose only selects unassigned custody.
For Accept-Signature, set the purpose in the trusted chooser's result.
For Web Bot Auth, set it in the local signing spec. Purpose is independent
of any tag or other parameter supplied by the peer.

In direct custody calls, pass `:operation` as `:http` with a canonical RFC 9421
base or `:jws` with a compact JWS signing input. The built-in custodian checks
the operation against the retained family and checks the input format before
using an assigned key. The high-level HTTP and JWS APIs set this operation
for you. Raw bytes remain supported by unassigned, ungated keys.

Custom custodians report the retained algorithm and purpose through
`binding/2` or `signing_assignment/2` under the same deadline. The facade
prefers `binding/2` and checks requests with omitted purpose too. The signing
and verification callbacks also enforce the assignment, operation family,
and input format at key use. Assigned verification requires `verify/5`.
Without that callback, an assignment-aware provider must supply an unassigned
binding and the public key together through `binding/2`. A provider with
neither assignment interface retains legacy behavior for unassigned operations.

```elixir
alias RequestSeal.{Custody, Message, SignatureBase}
alias RequestSeal.Custody.Gate
alias RequestSeal.Replay.ETS

{:ok, store} = ETS.start_link(max_entries: 100)
{:ok, message} = Message.request("GET", "https://example.test/builds", [], "")
components = ~s[("@method" "@path")]
{:ok, digest} = Gate.commitment(message, components)
now = 1_700_000_000
decision = %Gate.Admission{
  decision: "build-approval-1",
  commitment: digest,
  not_after: now + 30,
  nonce: "build-1"
}

config = %{
  port: fn _, _ -> {:allow, decision} end,
  once: {:store, ETS.store(store), "builds"},
  required_components: [~s["@method"], ~s["@path"]],
  max_lifetime: 30,
  clock: fn -> now end,
  skew: 0,
  tag: "build"
}

{_, seed} = :crypto.generate_key(:eddsa, :ed25519)
{:ok, signer} = Gate.new("ed25519", {:ed25519, seed}, config, issued_for: :build)
params = components <> ~s[;created=1700000000;expires=1700000030;nonce="build-1";tag="build"]
{:ok, base} = SignatureBase.build(message, params)
sign_opts = [issued_for: :build, operation: :http]
{:ok, _signature} = Custody.sign(signer, base, sign_opts)
{:error, %{reason: :gate_spent}} = Custody.sign(signer, base, sign_opts)
:ok = Custody.release(signer)
:ok = GenServer.stop(store)
```

`RequestSeal.Custody.binding/2` reports the held algorithm, operation family,
purpose and public thumbprint. It observes the key at the time of the call.
For HTTP verification, resolver entries returning a public key may include
`:issued_for` from trusted configuration. A handle supplies its own purpose.
Both must match the policy's `:require_issued_for`, with omitted and nil
policies selecting unassigned keys. An assigned key used for HTTP verification
must use an HTTP algorithm, whether resolved as a handle or a public key.
For an unassigned key, a policy may explicitly select a JWS algorithm for HTTP.

The gate rejects malformed bases, including parameters of the wrong wire
type and invalid HTTP derived values, before invoking the caller port.
Verification with a gated key also
validates the HTTP base, including when the key has no assigned purpose.
The signing gate matches
the approved component digest and optional nonce, then spends the decision
through the configured store. With `:port_owned`, the port must perform the
atomic spend itself. A failure after spending requires a new decision. Set
`:record` to verify recording of the decision, base digest, and signature
digest before releasing bytes. Use `:admission` on Local key generation to
keep fresh private material inside custody from construction.

Gate work follows the key creator's lifetime as well as the signing caller's.
Either can cancel pending work. With a transferred handle, keep its creator
alive until the operation returns. The store may already have received a
request when cancellation occurs, and committed spends remain spent.

## Check a seed against a public thumbprint

Use `RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed}, expected_thumbprint: thumbprint)`
when installing a seed for a configured public key. Compute `thumbprint` using
`RequestSeal.PublicKey.thumbprint/1` on that trusted key. A source descriptor
can use the same option as `{"ed25519", source, expected_thumbprint: thumbprint}`.
A mismatched seed fails before issuing a handle.

To exclude a retired key, create a set with
`{:ok, deny} = RequestSeal.DenySet.new([retired_thumbprint])` and pass
`deny: deny` at custody import or in an HTTP, Web Bot Auth, or JWS
verification policy. The set compares the selected public key's RFC 7638
SHA-256 thumbprint, independent of its advertised key ID. An active set
requires a public key.

## Hash or authenticate framed bytes

Use `RequestSeal.Fingerprint.digest("example v1", ["ab", "c", <<0, 255>>])`
when you need a stable digest of ordered byte fields. To authenticate those
bytes, generate a dedicated handle with
`RequestSeal.Custody.Local.generate("hmac-sha256", capabilities: [:mac])`
and pass it to `RequestSeal.Custody.mac(handle, "example v1", ["ab", "c", <<0, 255>>])`.
Release the handle with `RequestSeal.Custody.release/1` when finished.

For that input, the framed byte string in hex is `6578616d706c6520763100000002616200000001630000000200ff`.
SHA-256 gives `7954fed7217396578b4f2d39f93ed01086e61b44d35492f2fbad3323827d7fab`.
With the 131-byte test key of repeated `aa` bytes in
[RFC 4231 Section 4.7](https://www.rfc-editor.org/rfc/rfc4231.html#section-4.7),
the framed HMAC-SHA256 tag is `177e8624574728c0429489b62a9730c4ca8cd4e63e926e70eeceeeee5cada356`.
The label bytes are followed by each field's four-byte big-endian length
and bytes. Fix the label and field order in your application format.

For screened handle verification, custody resolves the handle's own public
key, applies the deny set and any custodian verifier, then verifies the
signature with that key. HTTP capture retains the verified public material.

Import a signing-permitted HS256 `oct` JWK with `capabilities: [:mac]` to
produce a dedicated framed MAC handle, just as with raw HMAC material.

Public-key screening at local import compares the derived thumbprint before a
private-key possession probe. Once custody issues a handle, retire it by
withdrawing it from callers and releasing it through its owner. To reject an
already-issued key when verifying a message, update the verification policy
with its thumbprint. An active set still requires the custodian's approval
when the handle implements a verifier.
