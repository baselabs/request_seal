defmodule RequestSeal.JOSE.Support do
  @moduledoc false
  alias RequestSeal.{Custody, KeyHandle}
  alias RequestSeal.JOSE.Error
  @jws ~w(RS256 PS256 PS384 PS512 HS256 ES256 ES384 EdDSA)
  @wrap ~w(RSA-OAEP-256 RSA-OAEP A128KW A256KW)
  @encrypt @wrap ++ ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW)
  @jwe @encrypt ++ ~w(A128GCMKW A256GCMKW dir)
  @enc ~w(A128GCM A256GCM)
  def json_object(bytes) do
    case RequestSeal.JOSE.JWE.Codec.object(bytes, 16_384) do
      {:ok, object} -> object
      {:error, %Error{reason: reason, layer: layer}} -> fail(reason, layer)
    end
  end

  def tree(value), do: RequestSeal.JOSE.JWE.Codec.tree(value)

  @spec ensure(term(), term(), atom()) :: :ok | no_return()
  def ensure(true, _, _), do: :ok
  def ensure(_, reason, layer), do: fail(reason, layer)
  @spec ensure(term(), term()) :: :ok | no_return()
  def ensure(value, reason), do: ensure(value, reason, :input)
  @spec fail(term()) :: no_return()
  @spec fail(term(), atom()) :: no_return()
  def fail(reason, layer \\ :input), do: throw({:jose_error, reason, layer})

  def safe(fun, fallback \\ :invalid_header, layer \\ :input) do
    fun.()
  rescue
    _ -> {:error, Error.new(fallback, layer)}
  catch
    {:jose_error, reason, selected} -> {:error, Error.new(reason, selected)}
    # Keep all catchable exits, including shutdown-class exits, closed. Callback
    # exit reasons may contain secrets or depend on attacker input; propagating
    # them would expose an oracle and break the redacted result contract.
    # Untrappable process termination remains the caller supervisor's concern.
    _, _ -> {:error, Error.new(fallback, layer)}
  end

  def timeout(opts, allowed \\ [:timeout]) do
    options(opts, allowed)
    t = Keyword.get(opts, :timeout, 5000)
    ensure(is_integer(t) and t in 1..300_000, :invalid_options)
    t
  end

  def options(opts, allowed) do
    ensure(is_list(opts) and Keyword.keyword?(opts), :invalid_options)
    keys = Keyword.keys(opts)

    ensure(
      length(keys) == length(Enum.uniq(keys)) and Enum.all?(keys, &(&1 in allowed)),
      :invalid_options
    )
  end

  def policy(p, kind) do
    common = [:algorithms, :timeout, :key_resolver, :protected]

    keys =
      case kind do
        :jws ->
          common

        :jwe ->
          common ++ [:encryption, :max_plaintext, :resolve_timeout, :unwrap_timeout]

        :batch ->
          common ++
            [
              :encryption,
              :max_plaintext,
              :resolve_timeout,
              :unwrap_timeout,
              :max_tokens,
              :max_total_input,
              :max_total_plaintext
            ]
      end

    ensure(is_map(p) and Enum.sort(Map.keys(p)) == Enum.sort(keys), :invalid_policy)

    ensure(
      is_integer(p.timeout) and p.timeout in 1..300_000 and is_function(p.key_resolver, 1),
      :invalid_policy
    )

    list(p.algorithms, if(kind == :jws, do: @jws, else: @jwe))
    protected_policy!(p.protected, kind)

    if kind != :jws do
      list(p.encryption, @enc)
      ensure(is_integer(p.max_plaintext) and p.max_plaintext in 1..1_048_576, :invalid_policy)

      ensure(
        is_integer(p.resolve_timeout) and p.resolve_timeout in 1..300_000 and
          is_integer(p.unwrap_timeout) and p.unwrap_timeout in 1..300_000 and
          p.resolve_timeout + p.unwrap_timeout < p.timeout,
        :invalid_policy
      )
    end

    if kind == :batch do
      ensure(is_integer(p.max_tokens) and p.max_tokens in 1..10_000, :invalid_policy)

      for k <- [:max_total_input, :max_total_plaintext] do
        ensure(is_integer(p[k]) and p[k] in 1..67_108_864, :invalid_policy)
      end
    end

    p
  end

  defp list(xs, allowed) do
    ensure(
      proper_list?(xs) and length(xs) in 1..length(allowed) and Enum.uniq(xs) == xs and
        Enum.all?(xs, &(&1 in allowed)),
      :invalid_policy
    )
  end

  def proper_list?([]), do: true
  def proper_list?([_ | tail]), do: proper_list?(tail)
  def proper_list?(_), do: false

  defp protected_policy!(p, kind) do
    keys =
      case kind do
        :jws -> [:embedded_key, :expected, :permitted]
        :jwe -> [:expected, :permitted]
        :batch -> [:permitted]
      end

    ensure(is_map(p) and Enum.sort(Map.keys(p)) == keys, :invalid_policy)
    reserved = if kind == :jws, do: ~w(alg jwk), else: ~w(alg enc iv tag epk apu apv)
    if kind == :jws, do: ensure(p.embedded_key in [:refuse, :require], :invalid_policy)
    expected = Map.get(p, :expected, %{})
    expected!(expected, p.permitted, reserved)
  end

  # Shared by both JOSE policies and each batch item's public expectations.
  def expected!(
        expected,
        permitted,
        reserved \\ ~w(alg enc iv tag epk apu apv),
        encoded_size \\ nil
      ) do
    ensure(
      proper_list?(permitted) and length(permitted) <= 64 and Enum.uniq(permitted) == permitted and
        Enum.all?(permitted, &(is_binary(&1) and String.valid?(&1))),
      :invalid_policy
    )

    ensure(
      is_map(expected) and not is_struct(expected) and map_size(expected) <= 64,
      :invalid_policy
    )

    ensure(
      Enum.all?(
        Map.keys(expected),
        &(is_binary(&1) and &1 not in reserved and &1 not in permitted)
      ) and
        Enum.all?(permitted, &(&1 not in reserved)),
      :invalid_policy
    )

    case safe(fn ->
           tree(expected)
           size = encoded_size || byte_size(json_encode(expected))
           ensure(size <= 16_384, :invalid_policy)
           {:ok, size}
         end) do
      {:ok, size} -> size
      _ -> fail(:invalid_policy)
    end
  end

  def json_encode(value), do: value |> json_null() |> :json.encode() |> IO.iodata_to_binary()
  defp json_null(nil), do: :null
  defp json_null(v) when is_map(v), do: Map.new(v, fn {k, x} -> {k, json_null(x)} end)
  defp json_null(v) when is_list(v), do: Enum.map(v, &json_null/1)
  defp json_null(v), do: v

  def protected!(header, expected, permitted, read) do
    ensure(
      Enum.all?(Map.keys(header), &(&1 in read or is_map_key(expected, &1) or &1 in permitted)),
      :unexpected_member
    )

    ensure(
      Enum.all?(expected, fn {k, v} -> Map.has_key?(header, k) and header[k] === v end),
      :protected_mismatch
    )

    :ok
  end

  def selected(header, kind, algorithms, encryption \\ nil) do
    ensure(header["alg"] in algorithms, :algorithm_not_permitted)
    ensure(header["alg"] in if(kind == :jws, do: @jws, else: @jwe), :algorithm_not_permitted)

    if kind == :jwe do
      ensure(header["enc"] in @enc and header["enc"] in encryption, :algorithm_not_permitted)
    end

    header["alg"]
  end

  def algorithms(:jws), do: @jws
  def algorithms(:jwe), do: @jwe
  def algorithms(:jwe_encrypt), do: @encrypt
  def algorithms(:jwe_wrap), do: @wrap
  def encryption, do: @enc

  def bytes(bytes) do
    ensure(is_binary(bytes), :invalid_serialization)
    ensure(byte_size(bytes) <= 1_048_576, :limit)
    bytes
  end

  def compact(bytes, count) do
    bytes(bytes)

    ensure(
      not String.starts_with?(String.trim_leading(bytes), ["{", "["]),
      :unsupported_serialization
    )

    segments(bytes, count, [])
  end

  def segment_count?(bytes, count) do
    match?(
      {:ok, _},
      safe(fn ->
        bytes(bytes)
        {:ok, segments(bytes, count, [])}
      end)
    )
  end

  defp segments(bytes, remaining, acc) do
    case :binary.split(bytes, ".") do
      [segment, rest] ->
        ensure(remaining > 1, :invalid_serialization)
        segments(rest, remaining - 1, [segment | acc])

      [segment] ->
        ensure(remaining == 1, :invalid_serialization)
        Enum.reverse([segment | acc])
    end
  end

  def b64(bytes), do: Base.url_encode64(bytes, padding: false)

  def decode(encoded) do
    ensure(is_binary(encoded), :invalid_base64)

    # RFC 4648 §3.5: the final sextet's unused bits must be zero.
    # The decoder checks the alphabet; check padding and the tail directly
    # instead of allocating a second encoding of every ciphertext/payload.
    ensure(canonical64?(encoded), :invalid_base64)

    case Base.url_decode64(encoded, padding: false) do
      {:ok, value} ->
        value

      _ ->
        fail(:invalid_base64)
    end
  end

  defp canonical64?(encoded) do
    :binary.match(encoded, "=") == :nomatch and
      case rem(byte_size(encoded), 4) do
        0 -> true
        2 -> :binary.last(encoded) in ~c"AQgw"
        3 -> :binary.last(encoded) in ~c"AEIMQUYcgkosw048"
        _ -> false
      end
  end

  def random(size) do
    :crypto.strong_rand_bytes(size)
  rescue
    _ -> fail(:entropy_failure, :crypto)
  catch
    _, _ -> fail(:entropy_failure, :crypto)
  end

  def worker(timeout, fun, fallback, layer) do
    context = %Custody.Context{
      owner: self(),
      deadline: System.monotonic_time(:millisecond) + timeout
    }

    case Custody.run(context, fn ->
           Process.flag(:sensitive, true)
           safe(fun, fallback, layer)
         end) do
      {:error, %Custody.Error{reason: :deadline_exceeded}} -> fail(:deadline_exceeded, layer)
      {:error, %Custody.Error{}} -> fail(fallback, layer)
      result -> result
    end
  end

  def callback(fun, fallback, layer) do
    fun.()
  rescue
    _ -> fail(fallback, layer)
  catch
    _, _ -> fail(fallback, layer)
  end

  def resolve(fun, request) do
    case callback(fn -> fun.(request) end, :key_resolver_failed, :key) do
      :error ->
        fail(:unknown_key, :key)

      {:ok, entry} when is_map(entry) ->
        # An entry without an authoritative algorithm is an invalid entry;
        # :algorithm_mismatch stays reserved for a present, different algorithm.
        ensure(is_map_key(entry, :algorithm), :key_resolver_failed, :key)
        ensure(entry[:algorithm] == request.algorithm, :algorithm_mismatch, :key)
        entry

      _ ->
        fail(:key_resolver_failed, :key)
    end
  end

  def sign(%KeyHandle{} = handle, alg, bytes, timeout) do
    ensure(handle.algorithm == {:jws, alg}, :algorithm_mismatch, :key)

    case Custody.sign(handle, bytes, timeout: timeout) do
      {:ok, signature} -> signature
      {:error, %{reason: :deadline_exceeded}} -> fail(:deadline_exceeded, :crypto)
      _ -> fail(:signer_failed, :crypto)
    end
  end

  def sign(_, _, _, _), do: fail(:invalid_options)
end
