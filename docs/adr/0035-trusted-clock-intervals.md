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
expiration for lookup and conditional refresh. Fetch timestamps use the upper
endpoint.
