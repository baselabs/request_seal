# 0037 — Frame byte sequences for hashing and custody MAC

Status: Accepted.

## Context

A byte commitment must distinguish the boundaries of its input fields. A caller
may also need to authenticate those bytes with a dedicated custody key.

## Decision

Hash or MAC a printable domain followed by each field's unsigned 32-bit
big-endian byte count and exact bytes. SHA-256 is unkeyed. HMAC-SHA256 uses a
dedicated custody capability and returns a 32-byte tag.

## Reasons

The lengths disambiguate concatenation. The first count starts with a
nonprinting byte, so it also separates the domain from the field sequence. The
MAC label is restricted to a syntax distinct from HTTP signature bases and
compact JWS inputs. Operation capabilities constrain the use of local keys.

## Consequences

The application chooses and versions the domain and field order. These are
RequestSeal byte contracts using [RFC 6234](https://www.rfc-editor.org/rfc/rfc6234.html)
algorithms. The corpus publishes independently calculated framing vectors.

Local import assesses admission before issuing capabilities. Applications
withdraw and release an existing handle to retire it.
