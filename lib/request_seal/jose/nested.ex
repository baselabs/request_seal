defmodule RequestSeal.JOSE.Nested do
  @moduledoc """
  Verify exactly one compact JWS inside one authenticated compact JWE.

  Both policies are explicit; no recursive dispatch or fallback occurs. Failure
  returns a redacted `RequestSeal.JOSE.Error`, never a decrypted partial result.
  These are envelope facts, not JWT claims validation or authorization.
  """
  alias RequestSeal.JOSE.{JWE, JWS, Support}
  import Support

  @doc """
  Decrypt one compact JWE, then verify the compact JWS it carries.

  The outer protected `cty` must be one of the selected content types. Inner
  envelopes (plaintext that is not a three-segment compact JWS) or an inner JWS
  with a `cty` header reject as `:nesting_depth`. Only complete success returns a
  result. Each policy supplies its own stage timeout; there is no combined timeout
  option.

  ## Parameters

    * `compact` - the outer compact JWE, as accepted by
      `RequestSeal.JOSE.JWE.decrypt/2`.
    * `jwe_policy` - the decryption policy map for `RequestSeal.JOSE.JWE.decrypt/2`.
    * `jws_policy` - the verification policy map for `RequestSeal.JOSE.JWS.verify/2`.
    * `opts` - keyword list; required (there is no default).

  ## Options

    * `:content_types` - required. Unique nonempty list of at most 64 nonempty
      strings, each at most 256 bytes, compared exactly with the outer `cty`.

  ## Returns

    * `{:ok, %{jwe: %RequestSeal.JOSE.JWE.Result{}, jws: %RequestSeal.JOSE.JWS.Result{}}}`.
    * `{:error, %RequestSeal.JOSE.Error{}}` - `:invalid_options` (missing, unknown,
      duplicate, or invalid option), `:content_type_mismatch` (outer `cty` absent
      or not selected), `:nesting_depth`, and every reason
      `RequestSeal.JOSE.JWE.decrypt/2` and `RequestSeal.JOSE.JWS.verify/2` return.
      Meanings: `RequestSeal.JOSE.Error`.

  ## Examples

      iex> {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
      iex> {:ok, key} = RequestSeal.Custody.public_key(handle)
      iex> {:ok, jws} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}], ~s({"order":"A-1001","status":"shipped"}), handle)
      iex> kek = {:aes, :crypto.strong_rand_bytes(32)}
      iex> wrap = fn algorithm, cek -> RequestSeal.JOSE.KeyManagement.wrap(algorithm, cek, %{}, kek) end
      iex> {:ok, jwe} = RequestSeal.JOSE.JWE.encrypt([{"alg", "A256GCMKW"}, {"enc", "A256GCM"}, {"cty", "JWT"}], jws, wrap)
      iex> unwrap = fn bytes, header -> RequestSeal.JOSE.KeyManagement.unwrap("A256GCMKW", bytes, header, kek) end
      iex> jwe_policy = %{algorithms: ["A256GCMKW"], encryption: ["A256GCM"], max_plaintext: 4_096, timeout: 5_000, key_resolver: fn _ -> {:ok, %{algorithm: "A256GCMKW", unwrap: unwrap}} end}
      iex> jws_policy = %{algorithms: ["EdDSA"], timeout: 5_000, key_resolver: fn _ -> {:ok, %{algorithm: "EdDSA", key: key}} end}
      iex> {:ok, %{jws: inner}} = RequestSeal.JOSE.Nested.verify(jwe, jwe_policy, jws_policy, content_types: ["JWT"])
      iex> inner.payload
      ~s({"order":"A-1001","status":"shipped"})
      iex> {:error, error} = RequestSeal.JOSE.Nested.verify(jwe, jwe_policy, jws_policy, content_types: ["application/example+jws"])
      iex> error.reason
      :content_type_mismatch
      iex> RequestSeal.Custody.Local.release(handle)
      :ok
  """
  @spec verify(binary(), map(), map(), keyword()) ::
          {:ok, map()} | {:error, RequestSeal.JOSE.Error.t()}
  def verify(compact, jwe_policy, jws_policy, opts) do
    safe(fn ->
      options(opts, [:content_types])
      types = Keyword.get(opts, :content_types)

      ensure(
        is_list(types) and length(types) in 1..64 and Enum.uniq(types) == types and
          Enum.all?(types, &(is_binary(&1) and byte_size(&1) in 1..256)),
        :invalid_options
      )

      case JWE.decrypt(compact, jwe_policy) do
        {:ok, jwe} ->
          ensure(jwe.header["cty"] in types, :content_type_mismatch, :nesting)

          ensure(
            Support.segment_count?(jwe.plaintext, 3),
            :nesting_depth,
            :nesting
          )

          case JWS.verify(jwe.plaintext, jws_policy) do
            {:ok, jws} ->
              ensure(not Map.has_key?(jws.header, "cty"), :nesting_depth, :nesting)
              {:ok, %{jwe: jwe, jws: jws}}

            error ->
              error
          end

        error ->
          error
      end
    end)
  end
end
