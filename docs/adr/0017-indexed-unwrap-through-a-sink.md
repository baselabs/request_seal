<!-- Status: accepted · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0017 — Unwrap indexed items into a caller-created sink
Status: Accepted

## Context

The RSA-OAEP custody path in [ADR 0004](0004-key-custody-and-discovery.md) returned one
content key's bytes from the holder through the custody runner and a middle process to
the JWE worker, so four processes saw the key. Batch decryption needs many unwraps under
one handle, and a holder process must never run caller code.

## Decision

1. The optional `RequestSeal.Custody` callback is
   `unwrap(term(), key_algorithm(), [item()], Sink.t(), Context.t())`, returning `:ok` or a
   bounded error. An item is `{index, encrypted_key, params, content_bits}` with content
   bits of 128 or 256.
2. The custodian delivers each outcome with `RequestSeal.Custody.Sink.deliver/3`, directly
   from the process that holds the key, as `{:ok, cek}` or `:error`. A sink is an opaque,
   revocable address created by the receiving process. That process accepts only
   deliveries dequeued strictly before one absolute monotonic deadline, discards unknown
   indexes, and settles each index once; malformed outcomes and wrong-width keys settle as
   `:error`. Expiry revokes the address. The custody runner reports only a call summary
   and never carries a key.
3. `RequestSeal.Custody.unwrap/3` takes 1 to 10,000 `{encrypted_key, params, content_bits}`
   tuples and returns `{:ok, results}` in input order, each `{:ok, cek}`,
   `{:error, :decryption_failed}` or `{:error, :deadline_exceeded}`. An accepted prefix
   survives a later failure. Direct callers receive key bytes and protect them.
4. Params are closed per key-management family and decoded before custody: `%{}` for
   RSA-OAEP, AES-KW and `dir`; `%{iv: _, tag: _}` for AES-GCMKW; and the agreement params for
   ECDH-ES ([ADR 0018](0018-ecdh-es-key-agreement.md)).
5. The `[:request_seal, :custody, :unwrap]` telemetry event carries no key data.

## Alternatives

1. **Keep the single-key byte return.** Simple for one token. Every batch item repeats a
   custody round trip, and the runner and middle processes keep seeing the key.
2. **Pass a caller function for the holder to call.** Flexible. The holder would run
   caller code with key material in scope.
3. **Return all keys in one runner reply.** One message. The runner, which is not the
   holder or the receiver, sees every key.

## Consequences

The callback change is breaking for custodians written against 1.x and lands in 2.0. A
custodian that does not implement `unwrap/5` cannot serve JWE decryption. The batch
coordinator in [ADR 0016](0016-bounded-jwe-open-coordinator.md) builds on the sink, and the
TypeScript package adopts the same delivery model in its next minor line.
