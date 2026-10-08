defmodule RequestSeal.JOSE.Support do
  @moduledoc false
  alias RequestSeal.{Custody, KeyHandle}
  alias RequestSeal.JOSE.Error
  @jws ~w(RS256 PS256 PS384 PS512 HS256 ES256 ES384 EdDSA)
  @jwe ~w(RSA-OAEP-256 RSA-OAEP A128GCMKW A256GCMKW dir)
  @enc ~w(A128GCM A256GCM)
  def json_object(bytes) do
    ensure(byte_size(bytes) <= 16_384, :limit)
    depth(bytes, 0, false, false)

    decoders = %{
      null: nil,
      object_push: fn k, v, acc ->
        ensure(length(acc) < 64, :limit)
        ensure(not List.keymember?(acc, k, 0), :duplicate_member)
        [{k, v} | acc]
      end,
      array_push: fn v, acc ->
        ensure(length(acc) < 64, :limit)
        [v | acc]
      end
    }

    {h, _, rest} = :json.decode(bytes, nil, decoders)
    ensure(json_whitespace?(rest) and is_map(h), :invalid_header)
    tree(h)
    h
  rescue
    _ -> fail(:invalid_header)
  end

  defp json_whitespace?(<<>>), do: true

  defp json_whitespace?(<<b, rest::binary>>) when b in [32, 9, 10, 13],
    do: json_whitespace?(rest)

  defp json_whitespace?(_), do: false

  def tree(v) when is_map(v) do
    ensure(not is_struct(v) and map_size(v) <= 64, :limit)

    Enum.each(v, fn {k, x} ->
      ensure(is_binary(k), :invalid_header)
      tree(x)
    end)
  end

  def tree(v) when is_list(v) do
    ensure(length(v) <= 64, :limit)
    Enum.each(v, &tree/1)
  end

  def tree(v) when is_integer(v),
    do: ensure(v in -999_999_999_999_999..999_999_999_999_999, :limit)

  def tree(v) when is_binary(v), do: ensure(String.valid?(v), :invalid_header)
  def tree(v) when v in [nil, true, false], do: :ok
  def tree(_), do: fail(:invalid_header)
  defp depth(<<>>, d, string, _), do: ensure(d == 0 and not string, :invalid_header)
  defp depth(<<_, r::binary>>, d, true, true), do: depth(r, d, true, false)
  defp depth(<<92, r::binary>>, d, true, false), do: depth(r, d, true, true)
  defp depth(<<34, r::binary>>, d, s, false), do: depth(r, d, not s, false)

  defp depth(<<b, r::binary>>, d, false, false) when b in [123, 91] do
    ensure(d < 4, :limit)
    depth(r, d + 1, false, false)
  end

  defp depth(<<b, r::binary>>, d, false, false) when b in [125, 93] do
    ensure(d > 0, :invalid_header)
    depth(r, d - 1, false, false)
  end

  defp depth(<<_, r::binary>>, d, s, e), do: depth(r, d, s, e)

  def ensure(true, _, _), do: :ok
  def ensure(_, reason, layer), do: fail(reason, layer)
  def ensure(value, reason), do: ensure(value, reason, :input)
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
    keys =
      if kind == :jws,
        do: [:algorithms, :timeout, :key_resolver],
        else: [:algorithms, :encryption, :max_plaintext, :timeout, :key_resolver]

    ensure(is_map(p) and Enum.sort(Map.keys(p)) == Enum.sort(keys), :invalid_policy)

    ensure(
      is_integer(p.timeout) and p.timeout in 1..300_000 and is_function(p.key_resolver, 1),
      :invalid_policy
    )

    list(p.algorithms, if(kind == :jws, do: @jws, else: @jwe))

    if kind == :jwe do
      list(p.encryption, @enc)
      ensure(is_integer(p.max_plaintext) and p.max_plaintext in 1..1_048_576, :invalid_policy)
    end

    p
  end

  defp list(xs, allowed) do
    ensure(
      is_list(xs) and length(xs) in 1..8 and Enum.uniq(xs) == xs and
        Enum.all?(xs, &(&1 in allowed)),
      :invalid_policy
    )
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

    case Base.url_decode64(encoded, padding: false) do
      {:ok, value} ->
        ensure(b64(value) == encoded, :invalid_base64)
        value

      _ ->
        fail(:invalid_base64)
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
        ensure(entry[:algorithm] == request.algorithm, :algorithm_mismatch, :key)
        entry

      _ ->
        fail(:key_resolver_failed, :key)
    end
  end

  defmodule FunctionCustodian do
    @moduledoc false
    @behaviour RequestSeal.Custody
    @impl true
    def sign(ref, alg, bytes, _context) do
      Process.flag(:sensitive, true)
      ref.().(alg, bytes)
    end

    @impl true
    def public_key(_), do: {:error, :unsupported_operation}
    @impl true
    def identity(_), do: {:error, :unsupported_operation}
  end

  def sign(signer, alg, bytes, timeout) do
    handle =
      case signer do
        %KeyHandle{} = h ->
          ensure(h.algorithm == {:jws, alg}, :algorithm_mismatch, :key)
          h

        fun when is_function(fun, 2) ->
          %KeyHandle{
            custodian: FunctionCustodian,
            algorithm: {:jws, alg},
            ref: fn -> fun end,
            capabilities: [:sign]
          }

        _ ->
          fail(:invalid_options)
      end

    case Custody.sign(handle, bytes, timeout: timeout) do
      {:ok, signature} -> signature
      {:error, %{reason: :deadline_exceeded}} -> fail(:deadline_exceeded, :crypto)
      _ -> fail(:signer_failed, :crypto)
    end
  end
end
