# 0007 — Keep adapters optional and byte-preserving

## Context

RequestSeal must integrate with Req, Finch, Plug, Phoenix, Ash, and reverse proxies while retaining a framework-free core. Signing must occur after final transformations; verification must happen before parsers discard evidence. Retries, redirects, body consumption, response association, and trusted proxy reconstruction can each invalidate otherwise correct cryptography.

## Decision

Optional adapters preserve framework facts in the lossless core model:
- Req signs final attempts and binds responses to their associated requests.
- Finch translates finalized values without starting a pool.
- Plug/Phoenix retains body and ordered fields; unavailable exact targets or trailers reject.
- Ash maps authenticated identity into explicit caller actor/context; policies stay caller-owned.
- Trusted-proxy reconstruction retains ingress facts under explicit hop/origin policy.
Missing evidence rejects; adapters neither invent bytes nor start mandatory services.

## Consequences

Framework dependencies are optional and do not start with the base application. Some framework configurations are rejected unless capture/reconstruction is configured earlier. Guides must name hook ordering and retry/redirect behavior exactly.

## Acceptance

- Real Req/Finch flows cover serialization, retries, redirects, cancellation, and response association.
- Real Plug/Phoenix flows cover capture, duplicates, rejection, and final response bytes.
- Required unavailable exact targets and trailers reject.
- Trusted/untrusted proxy tests and Ash policy tests preserve caller authority boundaries.
- Core consumers compile and run without framework dependencies.

## Plug reader and response-cookie contract

Plug reconstructs targets from `request_path` and `query_string`; exact target form
and an empty query delimiter are unavailable. Required `@request-target`, `@target-uri`,
and `@query` coverage, including request-bound response components, rejects with
`:unsupported_component`. Request and response trailers are unavailable.
Retained bytes replay through the Plug adapter, including multipart readers.
Replay tracks offset, request-local identity, and a digest of handed-out bytes.
Verification requires the captured replay adapter to remain installed unchanged.
Once replay is read, it must drain fully and its handed-out digest must match the captured body.
Negative or noninteger lengths reject with `:invalid_options` without advancing offset.
Wrapper readers must return unchanged bytes; later transformations are outside observation.
The digest authenticates the captured body, not parser-output integrity.

Response signing runs after registered callbacks and includes their changes.
Absent/nil callback state is valid; malformed state produces an empty unsigned failure
with `:unsupported_delivery`. Disable later server transformations such as compression
when covering body bytes. Plug merges response cookies after callbacks, so pending
cookies reject `set-cookie` coverage with `:unsupported_delivery`; explicit final headers work.
Failure replacement stays in the transport wrapper without mutable signing context.

Sources: [Plug.Conn](https://hexdocs.pm/plug/Plug.Conn.html) and
[Plug.Parsers](https://hexdocs.pm/plug/Plug.Parsers.html).
`test/plug_transport_test.exs` exercises live Bandit HTTP/1.1, h2c, TLS HTTP/2,
multipart replay, cookies, and read limits with Finch/Mint.

## Pass-through parsing and mapped proxy ranges

Verification uses actual replay reads and handed-out digests, not fetched params,
as consumption evidence. Pass-through parsing may leave bytes unread, including
requests without content type. Capture precedes consuming parsers or rejects before key resolution.

`Capture.read_body/2` records invocation separately from adapter reads.
Multipart and default readers can use the adapter without invoking that reader.
A substitute reader can leave both signals unset; fetched params cannot disambiguate
it from legitimate pass-through parsing. Configure custom readers to use the
RequestSeal reader or adapter and return its bytes unchanged.
Verification authenticates captured requests, not parser output or reader configuration.

Native IPv4 peers compare in IPv4-mapped form against IPv6 ranges of at most
96 bits that contain that form. Narrower explicitly mapped subnets retain host restrictions.
IPv4 trust never normalizes 6to4, NAT64, or IPv4-compatible IPv6 into native IPv4.

`test/plug_phoenix_test.exs` and `test/plug_transport_test.exs` cover raw-body routes,
exact replay bytes, substitute readers and unread pass-through bodies across
HTTP/1.1, h2c, and TLS HTTP/2. Native and dual-stack listeners exercise `::/0`
and `::ffff:0:0/96`, while real matcher tests retain transition-form rejection.
