defmodule RequestSeal.JOSE.JWE.Codec do
  @moduledoc false
  alias RequestSeal.JOSE.Error
  alias RequestSeal.JOSE.JWE.Bounds

  @algorithms ~w(RSA-OAEP RSA-OAEP-256 A128KW A256KW A128GCMKW A256GCMKW dir ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW)
  @reserved ~w(alg enc iv tag epk apu apv)

  @spec fail(atom()) :: no_return()
  @spec fail(atom(), atom()) :: no_return()
  def fail(reason, layer \\ :input), do: throw({:jose_error, reason, layer})
  def ensure(true, _), do: :ok
  def ensure(_, reason), do: fail(reason)

  def error(reason, layer \\ :input),
    do: {:error, %Error{reason: reason, layer: layer, retryable: reason == :deadline_exceeded}}

  def policy(p, batch, flag, deadline) do
    unit(flag, deadline)

    keys = [
      :algorithms,
      :encryption,
      :max_plaintext,
      :timeout,
      :resolve_timeout,
      :unwrap_timeout,
      :key_resolver,
      :protected
    ]

    keys = if batch, do: [:max_tokens, :max_total_input, :max_total_plaintext | keys], else: keys
    unit(flag, deadline)
    ensure(is_map(p) and not is_map_key(p, :__struct__) and map_size(p) <= 12, :invalid_policy)

    unit(flag, deadline)

    ensure(
      :lists.sort(:maps.keys(:maps.remove(:content, p))) == :lists.sort(keys),
      :invalid_policy
    )

    unit(flag, deadline)
    ensure(:maps.get(:content, p, :binary) in [:binary, :object], :invalid_policy)

    unit(flag, deadline)

    ensure(
      is_integer(:erlang.map_get(:timeout, p)) and :erlang.map_get(:timeout, p) in 1..300_000,
      :invalid_policy
    )

    unit(flag, deadline)

    ensure(
      is_integer(:erlang.map_get(:resolve_timeout, p)) and
        :erlang.map_get(:resolve_timeout, p) in 1..300_000,
      :invalid_policy
    )

    unit(flag, deadline)

    ensure(
      is_integer(:erlang.map_get(:unwrap_timeout, p)) and
        :erlang.map_get(:unwrap_timeout, p) in 1..300_000,
      :invalid_policy
    )

    unit(flag, deadline)

    ensure(
      :erlang.map_get(:resolve_timeout, p) + :erlang.map_get(:unwrap_timeout, p) <
        :erlang.map_get(:timeout, p),
      :invalid_policy
    )

    unit(flag, deadline)
    ensure(is_function(:erlang.map_get(:key_resolver, p), 1), :invalid_policy)

    unit(flag, deadline)

    ensure(
      is_integer(:erlang.map_get(:max_plaintext, p)) and
        :erlang.map_get(:max_plaintext, p) in 1..1_048_576,
      :invalid_policy
    )

    unit(flag, deadline)
    selection(:erlang.map_get(:algorithms, p), @algorithms, [])
    selection(:erlang.map_get(:encryption, p), ~w(A128GCM A256GCM), [])
    protected = :erlang.map_get(:protected, p)

    unit(flag, deadline)

    ensure(
      is_map(protected) and not is_map_key(protected, :__struct__) and map_size(protected) <= 2,
      :invalid_policy
    )

    unit(flag, deadline)

    ensure(
      :lists.sort(:maps.keys(protected)) ==
        [:permitted],
      :invalid_policy
    )

    names(:erlang.map_get(:permitted, protected), [], flag, deadline)

    if batch do
      unit(flag, deadline)

      ensure(
        is_integer(:erlang.map_get(:max_tokens, p)) and
          :erlang.map_get(:max_tokens, p) in 1..10_000,
        :invalid_policy
      )

      unit(flag, deadline)

      ensure(
        is_integer(:erlang.map_get(:max_total_input, p)) and
          :erlang.map_get(:max_total_input, p) in 1..67_108_864,
        :invalid_policy
      )

      unit(flag, deadline)

      ensure(
        is_integer(:erlang.map_get(:max_total_plaintext, p)) and
          :erlang.map_get(:max_total_plaintext, p) in 1..67_108_864,
        :invalid_policy
      )
    end

    :maps.put(:content, :maps.get(:content, p, :binary), p)
  end

  def unit(flag, deadline) do
    if RequestSeal.JOSE.JWE.Bounds.now() >= deadline do
      :atomics.put(flag, 1, 1)
      throw(:preflight_deadline)
    end
  end

  def expected(value, permitted) do
    try do
      ensure(is_map(value), :invalid_policy)
      tree(value)

      ensure(
        :lists.all(fn k -> expected_key?(k, permitted) end, :maps.keys(value)),
        :invalid_policy
      )

      encoded = :erlang.iolist_to_binary(:json.encode(value))
      ensure(byte_size(encoded) <= 16_384, :invalid_policy)
      depth(encoded, 0, false, false)
      {:ok, encoded}
    catch
      :throw, {:jose_error, _, _} -> error(:invalid_policy)
    end
  end

  defp selection([], _, []), do: fail(:invalid_policy)
  defp selection([], _, _), do: :ok

  defp selection([x | xs], allowed, seen) when length(seen) < 16 do
    ensure(:lists.member(x, allowed) and not :lists.member(x, seen), :invalid_policy)
    selection(xs, allowed, [x | seen])
  end

  defp selection(_, _, _), do: fail(:invalid_policy)

  defp names([], _, _, _), do: :ok

  defp names([x | xs], seen, flag, deadline) when is_binary(x) and length(seen) < 64 do
    unit(flag, deadline)
    ensure(byte_size(x) <= Bounds.permitted_name_bytes(), :invalid_policy)

    ensure(
      utf8?(x) and not :lists.member(x, seen) and not :lists.member(x, @reserved),
      :invalid_policy
    )

    names(xs, [x | seen], flag, deadline)
  end

  defp names(_, _, _, _), do: fail(:invalid_policy)

  def expected_key?(key, permitted) when is_binary(key),
    do: not :lists.member(key, @reserved) and not :lists.member(key, permitted)

  def expected_key?(_, _), do: false

  def utf8?(<<>>), do: true
  def utf8?(<<_::utf8, rest::binary>>), do: utf8?(rest)
  def utf8?(_), do: false

  def object(bytes, max_bytes) do
    try do
      ensure(is_binary(bytes), :invalid_header)
      ensure(byte_size(bytes) <= max_bytes, :limit)
      ensure(utf8?(bytes), :invalid_header)
      depth(bytes, 0, false, false)

      {value, _, rest} =
        :json.decode(bytes, nil, %{
          null: nil,
          object_push: fn k, v, acc ->
            ensure(length(acc) < 64, :limit)
            ensure(not :lists.keymember(k, 1, acc), :duplicate_member)
            [{k, v} | acc]
          end,
          array_push: fn v, acc ->
            ensure(length(acc) < 64, :limit)
            [v | acc]
          end
        })

      ensure(whitespace?(rest) and is_map(value), :invalid_header)
      tree(value)
      {:ok, value}
    catch
      :throw, {:jose_error, reason, layer} -> error(reason, layer)
      :error, :unexpected_end -> error(:invalid_header)
      :error, {:invalid_byte, _} -> error(:invalid_header)
      :error, {:unexpected_sequence, _} -> error(:invalid_header)
    end
  end

  def tree(v) when is_map(v) do
    ensure(map_size(v) <= 64 and not is_map_key(v, :__struct__), :limit)
    tree_pairs(:maps.to_list(v))
  end

  def tree(v) when is_list(v) do
    tree_list(v, 0)
  end

  def tree(v) when is_binary(v) do
    ensure(utf8?(v), :invalid_header)
    ensure(byte_size(v) <= 16_384, :limit)
  end

  def tree(v) when is_integer(v),
    do: ensure(v in -999_999_999_999_999..999_999_999_999_999, :limit)

  def tree(v) when v in [nil, true, false], do: :ok
  def tree(_), do: fail(:invalid_header)
  defp tree_pairs([]), do: :ok

  defp tree_pairs([{k, v} | rest]) when is_binary(k) do
    tree(k)
    tree(v)
    tree_pairs(rest)
  end

  defp tree_pairs(_), do: fail(:invalid_header)

  defp tree_list([], _), do: :ok
  defp tree_list([_ | _], n) when n >= 64, do: fail(:limit)

  defp tree_list([v | rest], n) do
    tree(v)
    tree_list(rest, n + 1)
  end

  defp tree_list(_, _), do: fail(:invalid_header)

  defp whitespace?(bytes), do: first_non_whitespace(bytes, 0) == :nomatch

  # Validate one word before skipping a repeated run in native code. The
  # common prefix of bytes and its eight-byte tail proves repetition of that
  # validated word, including a partial final repetition. Nonperiodic input
  # still advances eight bytes; no prefix is copied or pattern set compiled.
  defp first_non_whitespace(<<a, b, c, d, e, f, g, h, rest::binary>> = bytes, at)
       when a in [32, 9, 10, 13] and b in [32, 9, 10, 13] and c in [32, 9, 10, 13] and
              d in [32, 9, 10, 13] and e in [32, 9, 10, 13] and f in [32, 9, 10, 13] and
              g in [32, 9, 10, 13] and h in [32, 9, 10, 13] do
    case rest do
      <<^a, ^b, ^c, ^d, ^e, ^f, ^g, ^h, _::binary>> ->
        skip = 8 + :binary.longest_common_prefix([bytes, rest])
        tail = :binary.part(bytes, skip, byte_size(bytes) - skip)
        first_non_whitespace(tail, at + skip)

      _ ->
        first_non_whitespace(rest, at + 8)
    end
  end

  defp first_non_whitespace(<<byte, rest::binary>>, at) when byte in [32, 9, 10, 13],
    do: first_non_whitespace(rest, at + 1)

  defp first_non_whitespace(<<byte, _::binary>>, at), do: {at, byte}
  defp first_non_whitespace(<<>>, _), do: :nomatch

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

  def split(token) do
    try do
      ensure(is_binary(token), :invalid_serialization)
      ensure(byte_size(token) <= 1_048_576, :limit)
      {:ok, separators(token)}
    catch
      :throw, {:jose_error, reason, layer} -> error(reason, layer)
    end
  end

  # Classify leading whitespace in words and native repeated runs, then find at most five
  # dots. Native binary search needs no pattern-set compilation or backtracking and
  # allocates at most five part references, even for a token made only of dots.
  # Each native search returns into Codec, retaining its continuation while OTP
  # yields. The complete token and preflight accounting remain one bounded unit.
  defp separators(token) do
    case first_non_whitespace(token, 0) do
      {at, byte} ->
        ensure(byte not in [123, 91], :unsupported_serialization)
        separators(token, 0, at, 4, [])

      :nomatch ->
        fail(:invalid_serialization)
    end
  end

  defp separators(token, start, search, left, parts) do
    size = byte_size(token) - start

    case :binary.match(token, ".", scope: {search, byte_size(token) - search}) do
      :nomatch when left == 0 ->
        :lists.reverse([:binary.part(token, start, size) | parts])

      {at, 1} when left > 0 ->
        part = :binary.part(token, start, at - start)
        separators(token, at + 1, at + 1, left - 1, [part | parts])

      _ ->
        fail(:invalid_serialization)
    end
  end

  def decode(value) when is_binary(value) do
    ensure(base64url?(value) and canonical?(value), :invalid_base64)
    :base64.decode(value, %{mode: :urlsafe, padding: false})
  end

  def decode(_), do: fail(:invalid_base64)
  defp base64url?(<<>>), do: true

  defp base64url?(<<c, rest::binary>>)
       when c in ?A..?Z or c in ?a..?z or c in ?0..?9 or c in [?-, ?_],
       do: base64url?(rest)

  defp base64url?(_), do: false

  defp canonical?(v) do
    case rem(byte_size(v), 4) do
      0 -> true
      2 -> :lists.member(:binary.last(v), ~c"AQgw")
      3 -> :lists.member(:binary.last(v), ~c"AEIMQUYcgkosw048")
      _ -> false
    end
  end

  def admit({:error, _} = error, _, _), do: error

  # Admission and successful results decode the same authenticated protected bytes.
  def header(protected), do: object(decode(protected), 16_384)

  def admit({:ok, parts}, expected, p) do
    try do
      # Preflight validated this plain tree. Keep its exact JSON values through
      # the bounded per-row handoff instead of decoding an encoding a second time.
      [protected, ek, iv, ct, tag] = parts
      ensure(byte_size(protected) <= 21_846, :limit)

      h =
        case header(protected) do
          {:ok, h} -> h
          {:error, e} -> fail(:erlang.map_get(:reason, e), :erlang.map_get(:layer, e))
        end

      ensure(not is_map_key(h, "zip"), :compression_unsupported)
      ensure(not is_map_key(h, "crit"), :unsupported_critical_header)

      ensure(
        not :lists.any(fn k -> is_map_key(h, k) end, ~w(jku x5u jwk b64)),
        :unsupported_header
      )

      alg = :maps.get("alg", h, nil)
      enc = :maps.get("enc", h, nil)
      ensure(is_binary(alg), :invalid_header)

      ensure(
        :lists.member(alg, :erlang.map_get(:algorithms, p)) and
          :lists.member(enc, :erlang.map_get(:encryption, p)),
        :algorithm_not_permitted
      )

      ek = decode(ek)
      iv = decode(iv)
      ensure(byte_size(iv) == 12, :invalid_iv)
      tag = decode(tag)
      ensure(byte_size(tag) == 16, :invalid_tag)
      ct = decode(ct)
      ensure(byte_size(ct) <= :erlang.map_get(:max_plaintext, p), :limit)
      {params, read} = params(alg, h)

      ensure(
        :lists.all(
          fn k ->
            :lists.member(k, read) or is_map_key(expected, k) or
              :lists.member(k, :erlang.map_get(:permitted, :erlang.map_get(:protected, p)))
          end,
          :maps.keys(h)
        ),
        :unexpected_member
      )

      ensure(
        :lists.all(
          fn {k, v} -> is_map_key(h, k) and :maps.get(k, h) === v end,
          :maps.to_list(expected)
        ),
        :protected_mismatch
      )

      {:ok,
       %{
         protected: protected,
         h: h,
         alg: alg,
         enc: enc,
         ek: ek,
         iv: iv,
         ct: ct,
         tag: tag,
         params: params,
         width_valid: width_valid?(alg, ek, enc)
       }}
    catch
      :throw, {:jose_error, reason, layer} -> error(reason, layer)
    end
  end

  defp params(alg, h) when alg in ~w(A128GCMKW A256GCMKW) do
    iv = decode(:maps.get("iv", h, nil))
    ensure(byte_size(iv) == 12, :invalid_iv)
    tag = decode(:maps.get("tag", h, nil))
    ensure(byte_size(tag) == 16, :invalid_tag)
    {%{iv: iv, tag: tag}, ~w(alg enc iv tag)}
  end

  defp params(alg, h) when alg in ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW),
    do: {ecdh_params(alg, h), ~w(alg enc epk apu apv)}

  defp params(_, _), do: {%{}, ~w(alg enc)}

  def ecdh_params(alg, h) do
    parties = parties(h)
    key = epk(:maps.get("epk", h, nil))

    bits =
      case alg do
        "ECDH-ES" -> width(:maps.get("enc", h)) * 8
        "ECDH-ES+A128KW" -> 128
        "ECDH-ES+A256KW" -> 256
      end

    id = if alg == "ECDH-ES", do: :maps.get("enc", h), else: alg
    :maps.merge(parties, %{epk: key, algorithm_id: id, key_bits: bits})
  end

  def parties(h) do
    try do
      apu = if is_map_key(h, "apu"), do: decode(:maps.get("apu", h)), else: ""
      apv = if is_map_key(h, "apv"), do: decode(:maps.get("apv", h)), else: ""
      ensure(byte_size(apu) <= 1024 and byte_size(apv) <= 1024, :invalid_header)
      ensure(not (is_map_key(h, "apu") and is_map_key(h, "apv") and apu == apv), :invalid_header)
      %{apu: apu, apv: apv}
    catch
      :throw, {:jose_error, _, _} -> fail(:invalid_header)
    end
  end

  def epk(jwk) do
    ensure(is_map(jwk), :invalid_header)

    material =
      case jwk do
        %{"kty" => "OKP", "crv" => "X25519", "x" => x} when map_size(jwk) == 3 ->
          x = decode(x)
          ensure(byte_size(x) == 32, :invalid_header)
          {:x25519, x}

        %{"kty" => "EC", "crv" => crv, "x" => x, "y" => y}
        when crv in ["P-256", "P-384"] and map_size(jwk) == 4 ->
          {curve, size, prime, b} = curve(crv)
          x = decode(x)
          y = decode(y)
          ensure(byte_size(x) == size and byte_size(y) == size, :invalid_header)
          xi = :binary.decode_unsigned(x)
          yi = :binary.decode_unsigned(y)
          rhs = rem(xi * xi * xi - 3 * xi + b, prime)
          rhs = if rhs < 0, do: rhs + prime, else: rhs
          ensure(xi < prime and yi < prime and rem(yi * yi, prime) == rhs, :invalid_header)
          point = <<4, x::binary, y::binary>>

          try do
            :crypto.compute_key(:ecdh, point, <<1::unsigned-big-size(size * 8)>>, curve)
          catch
            :error, :badarg -> fail(:invalid_header)
            :error, {:badarg, _, _} -> fail(:invalid_header)
          end

          {:ec, crv, point}

        _ ->
          fail(:invalid_header)
      end

    %RequestSeal.PublicKey{material: material}
  end

  defp curve("P-256"),
    do:
      {:secp256r1, 32, 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
       0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B}

  defp curve("P-384"),
    do:
      {:secp384r1, 48,
       0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
       0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF}

  defp width_valid?(alg, ek, enc) when alg in ~w(A128KW A256KW ECDH-ES+A128KW ECDH-ES+A256KW),
    do: byte_size(ek) == width(enc) + 8

  defp width_valid?(alg, ek, _) when alg in ["dir", "ECDH-ES"], do: ek == ""

  defp width_valid?(alg, ek, enc) when alg in ~w(A128GCMKW A256GCMKW),
    do: byte_size(ek) == width(enc)

  defp width_valid?(_, ek, _), do: byte_size(ek) in 256..1024
  def width("A128GCM"), do: 16
  def width("A256GCM"), do: 32
  def cipher("A128GCM"), do: :aes_128_gcm
  def cipher("A256GCM"), do: :aes_256_gcm
end
