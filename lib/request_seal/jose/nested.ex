defmodule RequestSeal.JOSE.Nested do
  @moduledoc """
  Verify exactly one compact JWS inside one authenticated compact JWE.

  `verify/4` requires `content_types: [binary]`, a unique nonempty list of at
  most 64 nonempty strings (each at most 256 bytes). The outer protected `cty`
  must be selected. Inner envelopes or an inner JWS with `cty` reject as
  `:nesting_depth`. Both policies are explicit; no recursive dispatch or fallback
  occurs. Only complete success returns `%{jwe: JWE.Result, jws: JWS.Result}`.
  Failure returns a redacted `JOSE.Error`, never a decrypted partial result.
  Each policy supplies its own stage timeout; there is no combined timeout option.
  These are envelope facts, not JWT claims validation or authorization.
  """
  alias RequestSeal.JOSE.{JWE, JWS, Support}
  import Support

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
            length(:binary.split(jwe.plaintext, ".", [:global])) == 3,
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
