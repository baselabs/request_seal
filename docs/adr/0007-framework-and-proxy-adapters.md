# ADR 0007: Keep adapters optional and byte-preserving

- Status: Accepted
- Date: 2026-10-06

## Context

RequestSeal must integrate with Req, Finch, Plug, Phoenix, Ash, and reverse proxies while retaining a framework-free core. Signing must occur after final transformations; verification must happen before parsers discard evidence. Retries, redirects, body consumption, response association, and trusted proxy reconstruction can each invalidate otherwise correct cryptography.

## Decision

Ship optional adapters that translate actual framework runtime values to and from the lossless core model:

- Req signs each final attempt after serialization and verifies responses with the exact associated request.
- Finch translates finalized request/response values but does not start or own a pool.
- Plug/Phoenix captures raw target, ordered field occurrences, body, and trailers before destructive parsing and signs responses after bytes settle.
- Ash maps only an authenticated principal/provenance into caller-selected actor/context; policies remain caller-owned.
- Reverse-proxy reconstruction uses an explicit trusted-hop/origin policy and retains original ingress facts beside reconstructed values.

Adapters refuse missing required evidence. They do not invent raw bytes, trust forwarded headers by default, reuse a signature across attempts, or start a process/network service.

## Strongest alternatives

1. **Framework-specific packages only.** Each integration can be idiomatic. Core/profile semantics and errors drift across packages and cross-language corpus mapping becomes harder.
2. **One universal middleware behavior.** It gives a single setup call. Framework lifecycle points differ; one hook cannot safely cover final outbound bytes, inbound body capture, trailers, and response signing.
3. **Document recipes without adapters.** It keeps dependencies out. Every caller must rebuild high-risk ordering and proxy logic.
4. **Require Phoenix/Plug as the primary API.** It improves one common path but violates the plain-library contract and excludes clients/jobs/other servers.

## Deciding evidence and deletion test

Delete the lossless adapter and every consumer relearns framework lifecycle and byte extraction; adapters are deep when they hide those decisions. Delete an adapter that only renames a core call and callers get simpler; such adapters are rejected. Actual runtime probes, not framework source reads alone, decide whether each required fact is available.

## Consequences

Framework dependencies are optional and do not start with the base application. Some framework configurations are rejected unless capture/reconstruction is configured earlier. Guides must name hook ordering and retry/redirect behavior exactly.

## Acceptance

- Real Req/Finch flows exercise serialization, retry, same- and cross-origin redirects, cancellation, and response association.
- Real Plug/Phoenix flows exercise body capture, duplicates, trailers where supported, rejection, and signed response bytes.
- Trusted/untrusted reverse-proxy paths prove origin/target reconstruction.
- Real Ash policy tests prove authenticated identity does not imply authorization.
- A consumer compiles and runs the core with none of these framework dependencies installed.


## Plug reader and response-cookie contract

### Amendment — October 8, 2026

This amendment supersedes the Decision bullet's "raw target" and "trailers"
claims for Plug/Phoenix. Plug reconstructs the target from `request_path` and
`query_string`; it does not retain evidence of the exact original target form or
an empty query delimiter. Coverage of `@request-target`, `@target-uri`, and
`@query`, including request-bound response components, fails closed with
`:unsupported_component`. Request and response trailers are unavailable; required
trailer coverage fails closed.

Retained request bytes replay at the Plug adapter, including multipart readers
that bypass `Plug.Parsers`' `body_reader` option. Replay tracks its offset and
handed-out SHA-256 digest. Verification requires the same captured replay to
remain installed, including its request-local identity; replacing or rewrapping
that adapter rejects. Once any bytes have been requested through replay, it must
be fully drained and the digest of all handed-out bytes must equal the digest of
the full captured body before resolving keys. An unread suffix is never excluded
from that comparison. Negative or non-integer replay lengths return a bounded
`:invalid_options` error without moving the offset. A wrapper reader must return
those bytes unchanged. Its later transformations are outside the adapter's observation, so
this digest does not establish parser-output integrity.

Response signing executes after registered callbacks, including earlier callbacks
that mutate signed facts. Those changes are included before signing; the former
warning about earlier callbacks running after signing no longer applies. Absent
or nil callback state is valid; malformed callback state produces an empty unsigned
failure with bounded `:unsupported_delivery`. Server transformations after Plug's
callbacks, such as compression, still must be disabled when covering body bytes.
Plug merges `resp_cookies` into response headers after callbacks, so coverage of response `set-cookie` with
pending cookies rejects with `:unsupported_delivery`. Explicit final cookie
headers are supported. This keeps failure replacement in the existing transport
wrapper and avoids mutable signing context at send time. Full signing after Plug's
cookie merge remains an alternative; it would need request-local transfer of the
final callback context and error back to the connection.

Sources: [Plug.Conn](https://hexdocs.pm/plug/Plug.Conn.html) and
[Plug.Parsers](https://hexdocs.pm/plug/Plug.Parsers.html). OBSERVED by
`mix test test/plug_transport_test.exs --seed 1`: live Bandit HTTP/1.1, h2c, and
TLS HTTP/2 with Finch/Mint exercised multipart replay, cookies, and read limits.

## Pass-through parsing and mapped proxy ranges

Verification uses the adapter's actual replay reads and handed-out digest, rather
than treating fetched body params as evidence of consumption. Pass-through parsing
can leave retained bytes unread for the application, including when no content
type is supplied and Plug fetches empty params. Capture still precedes parsing;
a consuming parser before Capture rejects before key resolution.

`Capture.read_body/2` records reader invocation separately from the adapter's
read signal. Multipart and default Plug readers can read through the adapter
without invoking that configured reader. A wrapper that returns substitute bytes
without invoking either entry point leaves both signals unset. Fetched params
cannot safely supply a third signal: no-content-type pass-through requests also
fetch empty params without reading. Generic Plug integration cannot infer whether
a caller's custom parser or reader consumed different bytes from this connection
state. Therefore the caller must configure a reader that uses the RequestSeal
reader or adapter and returns its bytes unchanged. Verification authenticates the
captured request, not parser outputs or the caller's reader configuration.

OBSERVED in the live Plug transport tests:
a substitute reader parsed `earth` while captured `world` verified, with both read
signals unset, on live Bandit HTTP/1.1, h2c, and TLS HTTP/2. The same run retained
verification for unread text/plain, octet-stream, XML, and no-content-type parsing.
This characterization is a caller-configuration boundary, not a claim of parser
output integrity.

Native IPv4 peers are compared in their IPv4-mapped representation against IPv6
ranges of at most 96 bits that contain that representation. Narrower explicitly
mapped subnets retain their host-bit restrictions. IPv4 trust never normalizes
6to4, NAT64, or IPv4-compatible IPv6 peers into native IPv4.

OBSERVED by `mix test test/plug_phoenix_test.exs test/plug_transport_test.exs
--seed 1 --warnings-as-errors`: all four Phoenix raw-body routes verified and
replayed exact bytes; native and dual-stack Bandit listeners accepted `::/0` and
`::ffff:0:0/96`; real-matcher tests retained transition-form rejection.
