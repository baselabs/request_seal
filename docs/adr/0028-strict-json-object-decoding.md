# 0028 — Proposed: Decode JSON objects strictly and only after authentication

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

## Consequences

Header parsing and object payloads share one set of bounds, and the corpus carries the
boundary cases. Payloads larger than the bounds use binary content and the application's
own decoder. This record stays Proposed until the change lands on the main branch.
