# Sign JWS and encrypt JWE envelopes

Sign a compact JWS, encrypt it inside a JWE, and authenticate both envelopes before reading the payload. Install RequestSeal from the [README](../../README.md#installation), then run these blocks in `iex -S mix`; no framework is needed. Sources: [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515.html), [RFC 7516](https://www.rfc-editor.org/rfc/rfc7516.html), and [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html).

## 1. Sign and verify JWS

```elixir
{:ok, jose_handle} = RequestSeal.Custody.Local.generate({:jws, "EdDSA"}, [])
{:ok, jose_key} = RequestSeal.Custody.public_key(jose_handle)
{:ok, token} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}], "signed payload", jose_handle)
```

Trust the public key and allow only EdDSA when verifying:

```elixir
jws_policy = %{
  algorithms: ["EdDSA"],
  timeout: 5_000,
  protected: %{expected: %{}, permitted: ~w(kid typ cty x5c), embedded_key: :refuse},
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
{:ok, wrapping_handle} = RequestSeal.Custody.Local.generate({:jwe, "A256KW"}, [])

{:ok, encrypted} =
  RequestSeal.JOSE.JWE.encrypt(
    [{"alg", "A256KW"}, {"enc", "A256GCM"}],
    token,
    wrapping_handle
  )
```

Select the trusted wrapping key and verify the inner signature after decryption:

```elixir
jwe_policy = %{
  algorithms: ["A256KW"],
  encryption: ["A256GCM"],
  max_plaintext: 1_048_576,
  timeout: 5_000,
  resolve_timeout: 1000,
  unwrap_timeout: 1000,
  protected: %{expected: %{}, permitted: ~w(kid typ cty)},
  key_resolver: fn %{algorithm: "A256KW"} ->
    {:ok,
     %{
       algorithm: "A256KW",
       key: wrapping_handle
     }}
  end
}

{:ok, decrypted} = RequestSeal.JOSE.JWE.decrypt(encrypted, jwe_policy)
{:ok, inner} = RequestSeal.JOSE.JWS.verify(decrypted.plaintext, jws_policy)
inner.payload
# => "signed payload"
:ok = RequestSeal.Custody.release(wrapping_handle)
:ok = RequestSeal.Custody.release(jose_handle)
```

The wrapping key stays in its sensitive custody holder. Encryption uses fresh content-encryption keys and IVs from the CSPRNG. `RequestSeal.JOSE.Nested.verify/4` also supports one-level JWS-in-JWE verification with explicit outer/inner policies and `content_types: ["JWS"]` when the outer protected header declares `cty: "JWS"`.
The envelope above omits `cty`; add `{"cty", "JWS"}` to the JWE header before using
`Nested.verify/4`, or it rejects with `:content_type_mismatch`. The inner JWS may
itself carry a non-JOSE `cty` such as `application/json`; only values that name
another JOSE envelope (`application/jose`, `application/jose+json`,
`application/jws`, `application/jwe`, or RFC 7519's `application/jwt`, with RFC
7515 Section 4.1.10's abbreviation rule) reject as `:nesting_depth`, because
`Nested` verifies exactly one level. Decryption withholds all plaintext until AEAD authentication succeeds. Recipient integrity alone does not establish sender origin, identity, or request association.

## Decrypt with a recipient key handle

For RSA-OAEP or ECDH-ES, keep the recipient's private key in an algorithm-bound custody
handle and return that handle from the key resolver. [Decryption keys](key-custody.md#decryption-keys)
shows generation, the import alternative, the startup health check, and why a released handle fails
exactly like a forged message.

## ECDH recipients

The ECDH-ES family accepts `RequestSeal.PublicKey` recipients on P-256, P-384,
or X25519 ([RFC 7518 §4.6](https://www.rfc-editor.org/rfc/rfc7518.html#section-4.6),
[RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html)). Import EC JWKs or
OKP JWKs with `crv: "X25519"`; raw X25519 material is `{:x25519, public_bytes}`
with exactly 32 bytes. X25519 cannot verify a signature.

For encryption, supply the public key to `JWE.encrypt/3`. Each call generates a
fresh ephemeral private key inside its sensitive worker. Direct `ECDH-ES`
derives the CEK; the +KW variants derive a KEK and wrap a separately generated
CEK with RFC 3394. The protected header gains the public `epk`, and additions
cannot replace any caller member. Function recipients are refused for this family.

Optional protected `apu` and `apv` remain canonical Base64url in the header.
Their decoded values are each at most 1,024 bytes and must differ when both
members are supplied. On decryption, malformed points or parties reject as
`:invalid_header` before resolution. The resolver returns a handle bound to the
exact selected ECDH family member; a wrong curve, released handle, zero X25519
agreement, or failed unwrap ends `:decryption_failed`, with no plaintext.

`KeyManagement.agree/4` is the primitive for caller-owned protocol work.
It accepts decoded parties and returns the CEK, encrypted key, and public header
additions. `KeyManagement.wrap/4` continues to admit only RSA-OAEP and AES-KW.
Primitive support for published CBC agreement stages does not enable CBC in JWE.

## Options and bounds

JWS algorithms are `RS256`, `PS256`, `PS384`, `PS512`, `HS256`, `ES256`, `ES384`, and `EdDSA`. JWE encryption uses `RSA-OAEP-256`, `RSA-OAEP`, `A128KW`, `A256KW`, `ECDH-ES`, `ECDH-ES+A128KW`, or `ECDH-ES+A256KW`; decryption also admits `A128GCMKW`, `A256GCMKW`, and `dir`; content encryption is `A128GCM` or `A256GCM`.

Choose exact algorithm allowlists, explicit protected-member choices, timeout,
resolve and unwrap budgets, content-encryption algorithms, and maximum plaintext. Compact envelopes are at most 1 MiB, protected JSON at most 16 KiB and depth four. Base64url is canonical and unpadded. Duplicate JSON members and floats reject. Compression, detached JWS, JSON serializations, the `jku` and `x5u` key headers, `b64`, and `crit` are unsupported. An embedded
signature `jwk` requires explicit JWS policy; `x5c` is uninterpreted and must be
named by the protected-member policy.

This is generic JOSE, with no JWT claims policy, implicit key lookup, provider profile, trust anchor, freshness, replay, or authorization. Apply those application rules separately. Tests use Node WebCrypto as an independent verifier, in addition to published vectors and local cryptography.

## Explicit protected context

Verification/decryption policies require `protected`. For JWE it is exactly
`%{expected: public_context, permitted: names}`; JWS also requires
`embedded_key: :refuse | :require`. Each expected member must be present and
exactly equal as decoded JSON. Absence and difference both produce
`:protected_mismatch`, layer `:input`. Every member must be read by RequestSeal
for the selected algorithm, expected, or permitted; others produce
`:unexpected_member`, layer `:input`. In particular, name `kid`, `typ`, `cty`,
and `x5c` when the application accepts them. `x5c` is passed to the resolver
without certificate path validation.

Expected context is at most 64 string keys and 16,384 serialized bytes;
permitted is a unique list of at most 64 strings. Overlap and naming library-read
members are invalid policy. JWE reserves `alg`, `enc`, `iv`, `tag`, `epk`, `apu`,
and `apv`; JWS reserves `alg` and `jwk`. Empty expectations are valid; selecting
complete public context is the consumer's responsibility.

Admission checks compact/header refusals and algorithm selection first. JWE then
checks content structure and public key-management params, followed by member
set and expected values. Encrypted-key width is recorded here. Width failures
still receive the member and expectation checks, then bypass resolution and
unwrap (including every RFC 3394 round). They run content authentication under
a fresh random CEK and end `:decryption_failed`/`:crypto`. Malformed GCMKW iv/tag
retain their input reason even with a wrong encrypted-key width.

All checks before authentication read untrusted data. A forged header matching
every expectation can reach the resolver and custody. Resolvers must have no
authorization, replay-consumption, or other trusted side effects. Expected
values are public context; a boundary that considers the mismatch predicate
sensitive must normalize that refusal. Plaintext stays private until AEAD and
key-management success both hold.

## Embedded signature keys

Under `embedded_key: :refuse`, `jwk` rejects, and resolvers may return only a
public key or a `:verify` custody handle. Resolver key closures are removed.
For the RFC 9449 DPoP key primitive, select `:require`. The protected `jwk` must
be a public RSA object (only `kty`, `n`, `e`, 2,048–8,192 bits), EC object (only
`kty`, `crv`, `x`, `y`, P-256/P-384), or OKP Ed25519 object (only `kty`, `crv`,
`x`). Private fields, extra metadata, oct, X25519, missing fields, nonobjects,
and import failures give `:invalid_header`/`:input`. Shape is checked before
algorithm binding; a valid incompatible key gives `:algorithm_mismatch`/`:key`.
Both precede resolution.

The resolver receives the imported `embedded_key` in addition to `algorithm`
and `header`. Return exactly `{:ok, %{algorithm: alg, key: :embedded}}` to accept
it, or `:error` to reject. Under `:require` every other resolver key is refused;
under `:refuse` the `:embedded` sentinel is refused. The signature uses the
embedded key over the unchanged protected bytes. This supplies only DPoP's key
primitive ([RFC 9449 §4.2–4.3](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.3));
the application still checks method, URI, timestamps, identifiers, token binding,
and replay.

## Decryption budgets and batch opens

All three budgets are required integers, 1–300,000 ms, with
`resolve_timeout + unwrap_timeout < timeout`. At call start t0, R is
`t0 + resolve_timeout`, D is `t0 + timeout`, and each group's U is actual
resolution completion plus `unwrap_timeout`. Size the reserve before D for the
maximum ciphertext and workload.

| Unfinished work | Deadline | Reason / layer |
| --- | --- | --- |
| Admission | R | `:deadline_exceeded` / `:input` |
| Resolver | R | `:key_resolver_failed` / `:key` |
| Unwrap | U | `:decryption_failed` / `:crypto`, after fallback AEAD |
| Content authentication | D | `:deadline_exceeded` / `:crypto` |

`JWE.decrypt_many/2` accepts a list of exactly `%{token: bytes, expected: map}`
items. Its policy contains the decryption choices above, `protected` with only
`permitted`, and required `max_tokens` (1–10,000), `max_total_input`, and
`max_total_plaintext` (1–67,108,864 bytes each). Expected context belongs to each
item. Aggregate limits are checked across the whole batch before key work;
input includes serialized expectations and plaintext limits count ciphertext
widths. Empty input returns `{:ok, []}`.

A guard owns the cancellation boundary and creates the registry with itself as
heir. A coordinator processes bounded control messages; sensitive preflight and
range workers hold input, handles and content keys. The range count is at most
min(n, 32, online schedulers). Each admitted width-valid token starts its resolver
immediately. All resolver end notices precede custody creation. Groups use a
handle digest and full handle equality, and each group unwraps once into
range-owned aliases. Accepted deliveries survive later group failure; unsettled
positions authenticate under their prepared fallback. The public result remains
withheld until finalization.

The policy excluding single-open `protected.expected` is at most 4,096 words,
including function environments. Each expectation is at most 4,096 words and
16,384 bytes of binaries in total. Each permitted UTF-8 name is at most 16,384
bytes, checked before scanning it. Exceeding an expectation bound is positional
`:invalid_policy` in a batch; exceeding a policy or name bound is outer
`:invalid_policy`. Single open reports all three as `:invalid_policy`. Shared
occurrences count individually. A resolver with a large keyring captures a
registered name, ETS table or `persistent_term` key. A returned handle also has
4,096-word and 16,384-binary-byte bounds, including any reference closure environment;
an oversized answer is that item's `:key_resolver_failed`.

F is D + 100 ms. Teardown has B(n) = 20 ms + 15 microseconds per item, with
n initially zero and published when cardinality is accepted. The caller's
wait-end is bounded by F + B(n), even with a suspended guard. Cleanup and
caller-owned telemetry handlers follow that stamp. The guard reacts to caller
notice ownership or F before dequeuing another message, kills the coordinator,
and sweeps the inherited registry once. Private heir notices observe callback
completion without copying callback exit reasons. Children check caller
ownership and their deadline immediately before invoking callbacks. Arbitrary
unlinked descendants created by caller code remain its responsibility.

At most n + 35 library-owned processes are alive simultaneously, 2n + 35 are
created over a call, and n + 3 ETS tables coexist, with one two-cell atomics
array. Single open uses six processes and five tables over its lifetime. These
are transient costs of isolating cancellation and custody.

Malformed items and invalid expectations are positional errors. Invalid policy,
a nonproper list, aggregate limits, or missing finalization are outer errors
with no result list. See `RequestSeal.JOSE.JWE.decrypt_many/2` for the complete
reason lists. When no deadline or custodian lifecycle change occurs, batch
results equal individual decryption under the corresponding item policies.

`[:request_seal, :jose, :content_authentication]` records once when each real AEAD returns and emits after teardown, with only `outcome: :ok | :failed` and no measurements.
`[:request_seal, :jose, :decrypt_many]` has only `count`, `groups`, `failed`, and
`deadline_exceeded` measurements and empty metadata. Every custody unwrap event
has only `duration` and `items` measurements, with no per-item outcome.

## Errors

`RequestSeal.JOSE.Error` carries bounded reasons and no input text. `:invalid_signature` rejects a JWS mismatch. `:decryption_failed` covers key unwrap and AEAD failure without releasing partial plaintext. `:unexpected_member` and `:protected_mismatch` reject public context before resolution.
`:detached_payload` rejects empty JWS payloads. `:algorithm_not_permitted`, `:invalid_options`, and `:limit` require a supported explicit contract or smaller input. `:unknown_key` and `:key_resolver_failed` come from your resolver; `Nested` adds `:content_type_mismatch` and `:nesting_depth`; a failing custody wrap operation is `:signer_failed`. Only `:deadline_exceeded` is retryable. Each function's documentation lists the exact reasons it can return.

Module docs: `RequestSeal.JOSE`, `RequestSeal.JOSE.JWS`, `RequestSeal.JOSE.JWE`, `RequestSeal.JOSE.Nested`, `RequestSeal.JOSE.KeyManagement`, `RequestSeal.JOSE.Error`.

## Decode an object

`RequestSeal.JOSE.decode_object(bytes, max_bytes: limit)` parses decoded JSON
bytes as one strict UTF-8 object. It does not authenticate bytes. Use an
explicit byte limit from 1 through 1,048,576. Duplicate members and floats
reject, containers have at most 64 entries and four levels, strings and member
names have at most 16,384 bytes, and integers are within
±999,999,999,999,999. Invalid options return `:invalid_options`, malformed
objects return `:invalid_header`, duplicate names return `:duplicate_member`,
and exceeded bounds return `:limit`, all at layer `:input`.

Set `content: :object` on a JWE decryption policy to decode after authentication.
A successful result keeps `plaintext` and adds `object`; a decode failure
returns only the decoder error. It applies to single and batch decryption. Omitting `content:` or selecting
`:binary` leaves `object: nil`. The object byte budget is `max_plaintext`.
[Strict object content](json-object-content.md) shows runnable success and
rejection examples, including batch positions.

For fresh keys use [generation and derivation](key-generation-and-derivation.md);
for changed 1.x call shapes see [the 2.0 upgrade](upgrading-to-2.0.md).
