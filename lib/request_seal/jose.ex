defmodule RequestSeal.JOSE do
  @moduledoc """
  Bounded compact JOSE envelopes over OTP cryptography.

  `RequestSeal.JOSE.JWS` signs and verifies compact RFC 7515 envelopes;
  `RequestSeal.JOSE.JWE` encrypts and decrypts compact RFC 7516 envelopes.
  `RequestSeal.JOSE.Nested` verifies one JWS inside one JWE. Each call selects
  algorithms explicitly. There is no JWT claims policy, provider profile,
  automatic key lookup, trust anchor, authorization, or network operation.

  Algorithm identifiers are exact wire tokens. Results expose protected bytes
  and payload/plaintext only through explicit field access; inspection hides them.
  All errors use `RequestSeal.JOSE.Error`, with no input or exception text.
  Compact bytes are limited to 1,048,576. Protected JSON is at most 16,384 bytes,
  64 members per object, depth four, and 64 entries per array. Integers are within
  ±999,999,999,999,999; floats and duplicate members reject at every depth.
  Base64url is canonical and unpadded. Compression, detached JWS, JSON
  serializations, remote/embedded key headers, `b64`, and `crit` are unsupported.

  Key-management functions are custodian-side primitives. Decryption callbacks
  own private keys and return a CEK only inside the bounded sensitive worker.
  Successful recipient integrity does not establish origin or a principal.
  """
  @type jws_alg :: binary()
  @type jwe_alg :: binary()
  @type enc :: binary()
  @type header :: [{binary(), term()}]
end
