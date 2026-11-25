defmodule RequestSeal.Custody.Support do
  @moduledoc false
  alias RequestSeal.Custody.Error
  def ensure(true, _), do: :ok
  def ensure(_, reason), do: fail(reason)

  @spec fail(term()) :: no_return()
  def fail(reason), do: throw({:custody_error, reason})

  def safe(fun, fallback \\ :invalid_key) do
    fun.()
  rescue
    _ -> {:error, Error.new(fallback)}
  catch
    {tag, reason} when tag in [:custody_error, :crypto_error] -> {:error, Error.new(reason)}
    _, _ -> {:error, Error.new(fallback)}
  end

  def unwrap({:ok, value}), do: value
  def unwrap(:ok), do: :ok
  def unwrap({:error, %{reason: reason}}), do: fail(reason)
  def unwrap({:error, reason}) when is_atom(reason), do: fail(reason)

  def check_public_key(public, opts) do
    ensure(RequestSeal.DenySet.valid_admission_options?(opts), :invalid_options)

    case RequestSeal.DenySet.check(opts[:deny], public) do
      :ok -> :ok
      {:error, :key_denied} -> fail(:key_denied)
      {:error, :key_fingerprint_unknown} -> fail(:key_fingerprint_unknown)
    end

    if expected = opts[:expected_thumbprint] do
      case RequestSeal.PublicKey.thumbprint(public) do
        {:ok, ^expected} -> :ok
        {:ok, _} -> fail(:key_mismatch)
        _ -> fail(:key_fingerprint_unknown)
      end
    end

    :ok
  end

  # OTP 27/28 decode PrivateKeyInfo; OTP 29 aliases it to OneAsymmetricKey.
  # Normalize both supported decoder contracts without admitting v2 containers.
  @spec pkcs8_components(tuple()) :: {term(), term(), term()}
  def pkcs8_components(info) do
    case info do
      {:PrivateKeyInfo, :v1, {:PrivateKeyInfo_privateKeyAlgorithm, oid, params}, private, _} ->
        {oid, params, private}

      {:OneAsymmetricKey, :v1, {:PrivateKeyAlgorithmIdentifier, oid, params}, private, _,
       :asn1_NOVALUE} ->
        {oid, params, private}

      _ ->
        fail(:unsupported_format)
    end
  end

  def options(opts, allowed) do
    ensure(is_list(opts) and Keyword.keyword?(opts), :invalid_options)
    keys = Keyword.keys(opts)

    ensure(
      length(keys) == length(Enum.uniq(keys)) and Enum.all?(keys, &(&1 in allowed)),
      :invalid_options
    )

    opts
  end

  def timeout(opts, allowed \\ [:timeout]) do
    options(opts, allowed)
    value = Keyword.get(opts, :timeout, 5_000)
    ensure(is_integer(value) and value in 1..300_000, :invalid_options)
    value
  end

  def max_bytes(opts) do
    value = Keyword.get(opts, :max_bytes, 1_048_576)

    ensure(
      is_integer(value) and value in 1..RequestSeal.Crypto.max_bytes_ceiling(),
      :invalid_options
    )

    value
  end

  # An operation context presents the requested use and the outer metadata
  # separately. Only the custodian's retained state supplies the comparison.
  def held_binding!(algorithm, purpose, context) do
    ensure(
      context.handle_purpose == purpose and
        context.operation_family in [nil, RequestSeal.KeyHandle.family(algorithm)],
      :key_mismatch
    )
  end

  def signing_binding!(algorithm, purpose, context, gated?) do
    held_binding!(algorithm, purpose, context)
    ensure(context.issued_for == purpose, :issued_for_mismatch)

    if purpose != nil or gated? do
      family = RequestSeal.KeyHandle.family(algorithm)
      ensure(context.operation == family and family in [:http, :jws], :unsupported_operation)
    end
  end

  def signing_bytes!(bytes, algorithm) when is_binary(algorithm) do
    case RequestSeal.SignatureBase.parse(bytes) do
      {:ok, %{inner_list: input}} ->
        ensure(
          RequestSeal.SignatureFields.parameters(input)["alg"] in [nil, algorithm],
          :invalid_data
        )

      _ ->
        fail(:invalid_data)
    end
  end

  def signing_bytes!(bytes, {:jws, algorithm}) do
    result =
      RequestSeal.JOSE.Support.safe(fn ->
        [protected, payload] = RequestSeal.JOSE.Support.compact(bytes, 2)
        header = RequestSeal.JOSE.Header.parse(protected)
        ensure(payload != "" and header["alg"] == algorithm, :invalid_data)
        _ = RequestSeal.JOSE.Support.decode(payload)
        :ok
      end)

    ensure(result == :ok, :invalid_data)
  end
end
