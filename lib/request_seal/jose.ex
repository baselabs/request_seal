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
  serializations, `jku`, `x5u`, `b64`, and `crit` are unsupported. JWS can
  require an embedded public `jwk` under explicit policy; otherwise it is
  refused. Every unread member, including `kid` and `x5c`, must be explicitly
  expected or permitted and remains untrusted before authentication.

  Key-management functions are custodian-side primitives. Decryption resolves
  custody handles; CEKs travel directly to sensitive sink owners. Single and
  batch opens share explicit admission, resolution, unwrap, and AEAD budgets.
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

  @doc """
  Decode JSON bytes as one bounded UTF-8 object.

  `opts` must contain exactly `max_bytes: limit`, an integer from 1 through
  1,048,576. This parses decoded bytes, not a compact or Base64url segment,
  and does not authenticate them. Objects and arrays have at most 64 entries
  and four container levels. Strings and member names have at most 16,384
  UTF-8 bytes. Integers are within ±999,999,999,999,999; floats reject.

  Returns `{:ok, map}` or `{:error, %RequestSeal.JOSE.Error{}}`, always at
  layer `:input`: `:invalid_options` for invalid options, `:invalid_header`
  for malformed JSON, invalid UTF-8, floats or a non-object root,
  `:duplicate_member` for repeated member names at any depth, and `:limit`
  for any exceeded size, depth, width, string or integer bound.

  ## Examples

      iex> RequestSeal.JOSE.decode_object(~s({"active":true}), max_bytes: 1024)
      {:ok, %{"active" => true}}
      iex> {:error, error} = RequestSeal.JOSE.decode_object(~s({"n":1,"n":2}), max_bytes: 1024)
      iex> {error.reason, error.layer}
      {:duplicate_member, :input}
  """
  @spec decode_object(binary(), keyword()) :: {:ok, map()} | {:error, RequestSeal.JOSE.Error.t()}
  def decode_object(bytes, opts) do
    RequestSeal.JOSE.Support.safe(fn ->
      RequestSeal.JOSE.Support.ensure(
        match?([max_bytes: limit] when is_integer(limit) and limit in 1..1_048_576, opts),
        :invalid_options
      )

      RequestSeal.JOSE.JWE.Codec.object(bytes, opts[:max_bytes])
    end)
  end
end
