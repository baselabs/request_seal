<!-- Status: current · Kind: reference · Updated: 2026-11-11 · Governed by: public architecture · Review when: the public API, a supported standard revision, or the release policy changes -->

# Compatibility and deprecation

RequestSeal follows [Semantic Versioning](https://semver.org/) from 1.0.0. This page
says what a 1.x release keeps stable, what may change in a minor release, and how a
public API is deprecated. Security support for released versions is in
[SECURITY.md](../../SECURITY.md).

## What 1.x keeps stable

Within 1.x, a release never removes or incompatibly changes:

- **Functions:** every documented public function, its arities, and its required and
  optional option names, defaults and accepted values.
- **Results and errors:** documented structs and their documented fields, nested result
  shapes (`RequestSeal.Verification`, the JOSE results, `RequestSeal.WebBotAuth.Verification`,
  `RequestSeal.Quorum.Verification`), and the meaning of each documented error reason
  and layer. `authorization: :not_evaluated` stays in every verification result:
  a valid signature is never an authorization decision.
- **Wire behavior:** the bytes RequestSeal signs and emits for a given input, algorithm
  tokens, and which inputs verification accepts or rejects, except for security fixes
  (below).
- **Behaviours:** the `RequestSeal.Custody` and `RequestSeal.Replay` callbacks,
  including their timeout and cancellation context.
- **Telemetry:** the events in `RequestSeal.Telemetry`, their measurement keys and
  units, their metadata keys, and the meaning of each value.
- **Standard revisions:** a supported draft revision (for example Web Bot Auth
  protocol-00) stays selectable and keeps its result stamp. A newer revision arrives as
  a separate, explicit selection; the default never changes silently.

`RequestSeal.Profile`, the extension surface for profiles owned by other packages, is
covered by the same promise. RequestSeal ships only standards-derived profiles; any
other named profile lives in its own extension package.

## What a minor release may add

- New functions, modules, and optional options whose defaults keep existing behavior.
- New algorithms, standard revisions, and component support, each selected explicitly.
- New error reasons and `detail` values. Match the reasons you handle and keep a
  catch-all clause: a 1.x release may return a reason your code has not seen, always as
  an error, never as success.
- New telemetry events, measurement keys, and metadata keys.
- New fields in result structs. Pattern-match the fields you use, not whole structs.

## Security fixes

A security fix may reject input that an earlier 1.x release accepted, in a minor or
patch release. Its changelog entry says what is rejected and why, and names the
standard or advisory behind it.

## What is not part of the contract

- Functions and modules marked `@doc false`, and anything named internal.
- Implementation state inside documented structs: the `ref` field of
  `RequestSeal.KeyHandle`, the hash contexts inside `RequestSeal.Digest`, and the
  fields of `RequestSeal.KeyIdentity`. Use the documented functions that operate on
  them.
- `Inspect` output and exception message text.
- Dependency versions inside the published ranges, and the development lock.

## Deprecation

A public API is deprecated in a minor release: its documentation says what replaces
it, and a compile-time or runtime warning names the replacement where Elixir supports
one. It keeps working for the rest of 1.x and is removed only in 2.0.

## Supported runtimes

RequestSeal declares `elixir: "~> 1.18"`: Elixir 1.18 or newer, below 2.0, on
Erlang/OTP 27 or newer. CI tests three pairs: Elixir 1.18.4 with OTP 27.3.4,
1.19.5 with OTP 28.5.0.7, and 1.20.4 with OTP 29.1.1. The optional ash_onetime and
ash_hooks integrations need Elixir 1.20. Raising the minimum Elixir or OTP version
happens only in a minor release, with a changelog entry.
