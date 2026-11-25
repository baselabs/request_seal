# 0035 — Check freshness across trusted clock intervals

Status: Accepted.

## Context

A trusted clock can provide a bounded uncertainty interval in Unix seconds.

## Decision

Both interval endpoints must satisfy freshness. An integer clock is a singleton
interval. The verification result reports the upper endpoint as `now`. Web Bot
Auth samples once per selected signature and uses that same sample throughout.

## Reasons

The earliest possible time is strictest for future creation. The latest is
strictest for expiration and maximum age. Endpoint checks cover every second
in between and preserve the configured skew and boundary semantics.

## Consequences

The caller supplies the clock and its uncertainty bounds. Discovery and replay
store clocks retain their existing interfaces.
See [RFC 9421 Section 3.2.1](https://www.rfc-editor.org/rfc/rfc9421.html#section-3.2.1).

Discovery checks key and proof starts at the lower endpoint and expirations
at the upper endpoint. Resolved entries retain the latest start and earliest
expiration for lookup and conditional refresh. Keep future key starts in
the snapshot so a later lookup can establish key validity using its own
bounds. For an older entry without start facts, use its original fetch time.

Fetch timestamps use the upper endpoint for reporting. Reuse deadlines for
200 and 304 responses use the earliest possible request and response times
when applying [RFC 9111 Section 4.2.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2.3).
A 304 without freshness directives inherits the stored HTTP lifetime and
recomputes its deadline within the retained key and proof lifetimes.
