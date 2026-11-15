<!-- Status: proposed · Kind: decision record · Updated: 2026-11-15 · Governed by: public API, compatibility contract, and cited decisions · Review when: the implementation or a governing decision changes -->

# 0028 — Decode JSON objects strictly and only after authentication
Status: Proposed

## Context

JOSE headers and many JWE payloads are JSON objects. A general JSON decoder accepts
duplicate members, unbounded nesting, very long strings and integers outside the range
other languages represent exactly, so two implementations can read the same bytes
differently. Applications that decode a decrypted payload themselves also see plaintext
even when decoding fails.

## Decision

1. RequestSeal.JOSE.decode_object(bytes, opts) takes decoded JSON bytes and exactly the required :max_bytes option, an integer from 1 to 1,048,576. Missing, unknown, duplicate or invalid options return {:error, %JOSE.Error{reason: :invalid_options, layer: :input}}. It accepts only a UTF-8 object, with no duplicate members or floats, at most 64 members per object and 64 elements per array, at most four container levels, valid UTF-8 strings and member names of at most 16,384 bytes, and integers within ±999,999,999,999,999. It returns {:ok, map} or {:error, %JOSE.Error{}} with :invalid_header, :duplicate_member or :limit according to those rules.
2. JWE decryption with `content: :object` returns the decoded object in the result. The
   payload is decoded only after authentication, and no plaintext is returned when decoding
   fails.

## Alternatives

1. **Use the general decoder and document the hazards.** No new function. Duplicate members
   and large integers still read differently across implementations.
2. **Return plaintext and the decode error together.** Easier debugging. The caller holds
   plaintext from a payload it is about to refuse.

## Consequences

Header parsing and object payloads share one set of bounds, and the corpus carries the
boundary cases. Payloads larger than the bounds use binary content and the application's
own decoder. This record stays Proposed until the change lands on the main branch.
