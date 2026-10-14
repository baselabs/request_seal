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
  Base64url is canonical and unpadded. Compression (`zip`), detached JWS, JSON
  serializations, the `jku`, `x5u`, and `jwk` key headers, `b64`, and `crit` are
  unsupported; `kid` and `x5c` are accepted only as untrusted header data.

  Key-management functions are custodian-side primitives. Decryption callbacks
  own private keys and return a CEK only inside the bounded sensitive worker.
  Successful recipient integrity does not establish origin or a principal.
  """
  @typedoc "JWS algorithm wire name, such as `\"EdDSA\"` or `\"ES256\"`."
  @type jws_alg :: binary()
  @typedoc "JWE key-management algorithm wire name, such as `\"A256GCMKW\"`."
  @type jwe_alg :: binary()
  @typedoc "JWE content-encryption wire name: `\"A128GCM\"` or `\"A256GCM\"`."
  @type enc :: binary()
  @typedoc """
  Ordered protected header pairs: `{member_name, json_value}`.

  Names are strings and must be unique. Values are JSON terms: strings (valid
  UTF-8), integers, `true`, `false`, `nil` (JSON null), lists, and maps with
  string keys. Floats, other atoms, and structs reject.
  """
  @type header :: [{binary(), term()}]
end
