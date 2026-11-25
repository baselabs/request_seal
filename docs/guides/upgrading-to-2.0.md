# Upgrade from RequestSeal 1.x to 2.0

Move signing and secret-bearing operations to key handles, declare protected
header policy, and split JWE deadlines into resolution, unwrap, and content
budgets. Update custom custodians and result matches together. The examples
below use the 2.0 API and run in order in `iex -S mix`.

## Install and pin the same contract

Change your dependency requirement and update your application's lock:

```elixir
{:request_seal, "~> 2.0"}
```

Run `mix deps.update request_seal`, review `mix.lock`, and commit it. The current
source version is `2.0.0-dev`; the dependency requirement describes the 2.0 release
line, not availability of a development snapshot on Hex. Stable public functions,
behaviours, results, errors, wire rules, telemetry, and `RequestSeal.Profile` stay
compatible within a major under the [compatibility contract](../reference/compatibility.md).
The 1.x line receives security fixes after 2.0.

Counterpart consumers must move their release tag, source commit, corpus index
SHA-256, error vocabulary, and reciprocal peer together. Do not reuse a 1.x
corpus pin with the 2.0 package. The corpus index's `elixir_release` must match
the package version, including pre-release suffixes. Pin the actual release
commit and index digest from its verified assets; verify the index and every
listed source and case before accepting results. See
[corpus format](../reference/corpus-format.md) and
[release verification](verifying-releases.md). Corpus assets are separate from
the Hex package.

## Migrate replay stores

Pause claim writers and cleanup before upgrading an existing durable store.
Establish a trusted upper bound on all prior sweep or prune timestamps,
including cleanup that removed zero entries. Keep admission closed if the
bound is unknown. The current database clock alone cannot establish it
after a clock rollback.

- For Postgrex, execute `RequestSeal.Replay.Postgres.cutoff_ddl(table, last_cutoff)`
  against the existing table. Open admission after the migration commits and
  every writer and sweeper is upgraded. For a new table, `ddl/1` initializes
  its cutoff.
- For AshOnetime, execute the statements from
  `RequestSeal.Replay.AshOnetime.cleanup_guard_ddl(prefix, last_cutoff)`
  in order in a single migration transaction after the ash_onetime migrations.
  Use `0` for a fresh schema with no prior pruning.

For a running ETS owner, pause claims and sweeps and suspend the owner. Use
`:sys.change_code/4` with `{:swept_through, last_cutoff}` to preserve its
table and install the trusted cutoff before resuming.
See [replay protection](replay-protection.md#choose-local-or-persistent-storage)
for store setup and transaction ownership.

## Replace every key closure

Resolver callbacks remain application functions that select trusted keys. They
return public keys or handles; they no longer return key-operation functions.
Applications backed by an external key service implement `RequestSeal.Custody`
with deadline and cancellation handling instead of wrapping the service in a
key closure.

| 1.x call or type | 2.0 form |
| --- | --- |
| `RequestSeal.sign(message, spec, signer_fun, opts)` | Pass a `RequestSeal.KeyHandle` granting `:sign` and binding `spec.algorithm`. Both explicit and generated specs require it. |
| Req `signer: fun`, `RequestSeal.Finch.sign/4` with a function, Plug response `signer: fun`, Web Bot Auth signer functions, and AshHooks signing functions | Pass the matching signing handle to each existing entry point or option. |
| HTTP/Web Bot Auth resolver `key: verify_fun` | Return `key: public_key` or `key: verify_handle`; secret verification, including HMAC, stays inside a `:verify` handle. |
| JWS `sign/4` or `sign_protected/4` with a function | Pass a handle bound to `{:jws, alg}` with `:sign`. |
| JWS resolver `key: verify_fun` | Return a `RequestSeal.PublicKey`, a `:verify` handle bound to `{:jws, alg}`, or explicitly approved `:embedded` as described below. |
| JWE `encrypt/4` recipient wrapper function | Pass an RSA/EC/X25519 public recipient key, or an A128KW/A256KW `:wrap` handle. |
| JWE resolver `unwrap: fun` | Return exactly `{:ok, %{algorithm: alg, key: handle}}`, with a `{:jwe, alg}` handle granting `:unwrap`. |
| `AcceptSignature.fulfill(message, requests, chooser, signer_fun, opts)` | Pass a nonempty list of handles with distinct HTTP algorithms as the fourth argument. The chooser still selects algorithm and times. |
| The `RequestSeal.Policy` types named `signer` and `verify_fun` | Removed; use `RequestSeal.KeyHandle.t()` or `RequestSeal.PublicKey.t()` for key parameters. |

No key-closure compatibility path remains. Malformed signing or wrapping
functions reject with `:invalid_options`; resolver function keys and `unwrap:`
entries reject with `:key_resolver_failed`. Matching handle algorithms is
explicit: HTTP `"ed25519"` and JOSE `{:jws, "EdDSA"}` are separate selections.

```elixir
{:ok, http_handle} = RequestSeal.Custody.Local.generate("ed25519", [])
{:ok, http_key} = RequestSeal.Custody.public_key(http_handle)
{:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
components = ~s[("@method" "@scheme" "@authority" "@path")]
spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60}
{:ok, signed} = RequestSeal.sign(message, spec, http_handle)

{:ok, http_policy} = RequestSeal.Policy.new(%{
  algorithms: ["ed25519"], components: components,
  key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: http_key}} end,
  freshness: :not_evaluated, content: :not_required, replay: :not_required
})
{:ok, _verification} = RequestSeal.verify(signed, http_policy, label: "sig")

{:ok, requests} = RequestSeal.AcceptSignature.parse(~s[reply=("@method" "@path")], target: :request)
chooser = fn _ -> {:ok, %{algorithm: "ed25519", created: nil, expires: nil}} end
{:ok, _negotiated} = RequestSeal.AcceptSignature.fulfill(message, requests, chooser, [http_handle], [])
:ok = RequestSeal.Custody.release(http_handle)
```

No fitting handle, an unavailable choice, or a signing failure during fulfillment
returns `:negotiation_unfulfillable` with no partially signed message.
HTTP signing with a mismatched handle returns `:signer_algorithm_mismatch` at
`:input`; custody failures return `:signing_failed` at `:crypto` with a bounded
custody error in `source`. Req, Finch, and Plug retain their adapter error
boundary. See [signing and verifying](signing-and-verifying.md).

## Rebuild in-memory custody on upgrade

Restart the processes that retain key handles and recreate the holders and
handles through their normal constructors before resuming operation. Rebuild
custom handles with the current struct and implement `signing_assignment/2`
for assigned operations. Keep SSH handle creators alive for the lifetime of
their handles, including handles transferred to another process.

Rebuild HTTP verification policies through `RequestSeal.Policy.new/1` when
selecting an assigned key. An in-memory policy with the exact previous
struct shape is interpreted with `:require_issued_for` set to nil.

## Add protected maps to JOSE policies

The 1.x JWS verification policy contained `algorithms`, `timeout`, and
`key_resolver`. Add `protected:` with exactly `expected`, `permitted`, and
`embedded_key`. JWE needs exactly `expected` and `permitted`.

```elixir
{:ok, jws_handle} = RequestSeal.Custody.Local.generate({:jws, "EdDSA"}, [])
{:ok, jws_key} = RequestSeal.Custody.public_key(jws_handle)
{:ok, token} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}, {"typ", "JOSE"}], "payload", jws_handle)

jws_policy = %{
  algorithms: ["EdDSA"], timeout: 5_000,
  protected: %{expected: %{"typ" => "JOSE"}, permitted: [], embedded_key: :refuse},
  key_resolver: fn _ -> {:ok, %{algorithm: "EdDSA", key: jws_key}} end
}
{:ok, %{payload: "payload"}} = RequestSeal.JOSE.JWS.verify(token, jws_policy)
{:error, %{reason: :protected_mismatch, layer: :input}} =
  RequestSeal.JOSE.JWS.verify(token, %{jws_policy | protected: %{jws_policy.protected | expected: %{"typ" => "other"}}})
:ok = RequestSeal.Custody.release(jws_handle)
```

`expected` maps public string names to exact decoded JSON values; missing and
different values both return `:protected_mismatch`. `permitted` names members
you accept without an expected value. A member not read by the selected
algorithm, expected, or permitted returns `:unexpected_member`. Explicitly name
`kid`, `typ`, `cty`, and `x5c` when accepting them. `x5c` gets no certificate
path validation. Reserved library-read names cannot appear in either collection,
and the collections cannot overlap. Checks run before resolution, on untrusted
headers, so resolvers must not authorize or consume replay state.

`embedded_key: :refuse` retains refusal of JWS `jwk`. To require an embedded
public signing key, select `:require`; the resolver receives the imported
`embedded_key` and must return `{:ok, %{algorithm: alg, key: :embedded}}`.
This proves the embedded key's signature only. It supplies no application trust,
JWT claims checks, or complete DPoP verification. See [JOSE](jose.md) for shapes,
reserved names, and bounds.

## Split the JWE decryption budget and replace symmetric wrapping

The 1.x `timeout:` bounded the whole open. Keep it and add required
`resolve_timeout:` and `unwrap_timeout:`. Each is 1 to 300,000 ms, and their sum
must be strictly below `timeout`. Resolution and admission end at call start
plus `resolve_timeout`; each handle group's unwrap ends at its actual resolution
completion plus `unwrap_timeout`. Content work ends at call start plus `timeout`.

| Unfinished phase | 2.0 reason / layer |
| --- | --- |
| Admission | `:deadline_exceeded` / `:input` |
| Resolution | `:key_resolver_failed` / `:key` |
| Unwrap | `:decryption_failed` / `:crypto`, after fallback authentication |
| Content authentication | `:deadline_exceeded` / `:crypto` |

1.x symmetric encryption via GCMKW or `dir` wrappers changes to AES-KW custody.
JWE encryption supports RSA-OAEP, RSA-OAEP-256, A128KW, A256KW, and ECDH-ES
(direct, +A128KW, +A256KW). GCMKW and `dir` remain decryption-only, through
matching unwrap handles created with `Local.new/3` or `Local.import/4` from
existing material. RSA senders use public keys; ECDH senders use P-256, P-384,
or X25519 public keys. `KeyManagement.wrap/4` supports only RSA-OAEP and AES-KW;
agreement uses `KeyManagement.agree/4`. There is no GCMKW encryption fallback.

```elixir
{:ok, wrapping_handle} = RequestSeal.Custody.Local.generate({:jwe, "A256KW"}, [])
{:ok, encrypted} = RequestSeal.JOSE.JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], "payload", wrapping_handle)

jwe_policy = %{
  algorithms: ["A256KW"], encryption: ["A256GCM"], max_plaintext: 4096,
  timeout: 5_000, resolve_timeout: 1_000, unwrap_timeout: 1_000,
  protected: %{expected: %{}, permitted: []},
  key_resolver: fn _ -> {:ok, %{algorithm: "A256KW", key: wrapping_handle}} end
}
{:ok, %{plaintext: "payload", object: nil}} = RequestSeal.JOSE.JWE.decrypt(encrypted, jwe_policy)

batch_policy =
  jwe_policy
  |> Map.put(:protected, %{permitted: []})
  |> Map.merge(%{max_tokens: 10, max_total_input: 65_536, max_total_plaintext: 40_960})

{:ok, [{:ok, %{plaintext: "payload"}}]} =
  RequestSeal.JOSE.JWE.decrypt_many([%{token: encrypted, expected: %{}}], batch_policy)
```

Batch items carry their own expected protected values. `{:ok, results}` is a
final ordered list of per-item success or error tuples; it does not mean every
item succeeded. Invalid policy, malformed outer input, aggregate limits, or
missing finalization return one outer error with no list. No partial batch is
returned. See [JOSE budgets and batch opens](jose.md#decryption-budgets-and-batch-opens).

## Migrate unwrap calls, results, and custom custodians

| 1.x | 2.0 |
| --- | --- |
| `Custody.unwrap(handle, encrypted_key, opts)` | `Custody.unwrap(handle, [{encrypted_key, params, content_bits}], opts)`; 1 to 10,000 items, content bits 128 or 256. |
| `{:ok, cek}` | `{:ok, [{:ok, cek}]}` for one success; results stay in input order. |
| Operation error after a partial batch | Accepted positions survive; undelivered positions settle as `{:error, :decryption_failed}` or `{:error, :deadline_exceeded}`. Validation errors remain `{:error, %Custody.Error{}}`. |
| Custodian `unwrap(ref, algorithm, encrypted_key, context)` returning key bytes | `unwrap(ref, algorithm, indexed_items, sink, context)` delivers each `{index, encrypted_key, params, content_bits}` outcome from the holder with `Custody.Sink.deliver(sink, index, {:ok, cek})` or `:error`; callback returns only `:ok` or a bounded error. |
| Custody type `unwrap_algorithm` | `key_algorithm`; `algorithm` also covers derivation selections, and `capability` includes `:wrap` and `:derive`. |
| `Local.release(handle)` for local holders | Still supported; `Custody.release(handle)` also releases through the custodian's optional `release/2` callback. Derive-capable custodians must implement it. |

```elixir
# Public, disposable example content-key bytes; never print a real CEK.
example_cek = <<0::128>>
{:ok, wrapped} = RequestSeal.Custody.wrap(wrapping_handle, example_cek)
{:ok, [{:ok, ^example_cek}]} =
  RequestSeal.Custody.unwrap(wrapping_handle, [{wrapped.encrypted_key, %{}, 128}], timeout: 5_000)
:ok = RequestSeal.Custody.release(wrapping_handle)
```

Params are decoded before custody: `%{}` for RSA-OAEP, AES-KW, and `dir`;
`%{iv: twelve_bytes, tag: sixteen_bytes}` for GCMKW;
`%{epk: public_key, apu: bytes, apv: bytes, algorithm_id: id, key_bits: bits}`
for ECDH-ES. `KeyManagement.unwrap/4` now uses these closed family params too,
rather than an arbitrary decoded header. CEKs go straight from the holder to
the receiving sink, bypassing custody runners. Direct unwrap callers receive
raw CEKs and own their protection and subsequent content authentication.

AES-KW custodians implement `wrap/4` and grant `:wrap` and/or `:unwrap`; RSA,
ECDH-ES, GCMKW, and `dir` handles grant only `:unwrap`. Custom custodians must
propagate `Context` deadlines, owner cancellation, and bounded errors. See
[key custody](key-custody.md) for availability checks and release rules.

## Generate and derive instead of exporting keys

Replace application-side random key generation followed by `Local.new/3` with
`Local.generate/2`. RSA requires `:bits`; ECDH-ES requires `:curve`; optional
`:capabilities` narrows defaults. Optional `:timeout` bounds startup and
generation, default 5,000 ms; choose a longer budget for RSA-4096 on loaded hosts.
Imports remain available for existing keys.

For deterministic children, import 32 to 64 IKM bytes into a
`{:derive, "hkdf-sha256"}` parent and call `Custody.derive/4` with target,
1 to 255 domain bytes, and required `timeout:`. Only acknowledged atomic commit
returns a child. Custom derive-capable custodians implement `derive/3`,
`commit/3`, and confirmed `release/2`. Handle `{:cleanup_required, cleanup, error}`
by retaining the redacted capability and retrying `Custody.cleanup/2` until
`:ok`. Releasing the parent does not release committed children. The
[generation and derivation guide](key-generation-and-derivation.md) gives the
complete runnable lifecycle, supported families, framing, and error rules.

## Select strict object content

Binary JWE content remains the default, with `object: nil`. Replace manual
decode-after-decrypt with `content: :object` when a JSON failure must expose
no plaintext. Success adds `result.object` and retains authenticated
`result.plaintext`; failure returns only the decoder error. The option applies
to single and batch decryption. For standalone bytes, call
`RequestSeal.JOSE.decode_object(bytes, max_bytes: limit)`.

```elixir
{:ok, %{"active" => true}} =
  RequestSeal.JOSE.decode_object(~s({"active":true}), max_bytes: 1024)
{:error, %{reason: :duplicate_member, layer: :input}} =
  RequestSeal.JOSE.decode_object(~s({"active":true,"active":false}), max_bytes: 1024)
```

The decoder requires a UTF-8 object, rejects duplicate members and floats,
and enforces byte, depth, container, string, and integer limits shared with
protected headers. See [strict JSON object content](json-object-content.md)
for authenticated examples, batch results, and every rejection bound.
