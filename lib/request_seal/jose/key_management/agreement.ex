defmodule RequestSeal.JOSE.KeyManagement.Agreement do
  @moduledoc false
  import RequestSeal.JOSE.Support
  alias RequestSeal.{PublicKey, Crypto.Algorithm}
  alias RequestSeal.JOSE.KeyManagement
  @family ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW)

  # Deterministic protocol stage. Production supplies CSPRNG material, never a
  # caller-selected ephemeral scalar; corpus adapters can reproduce public vectors.
  def run(alg, enc, recipient, params, ephemeral, cek) do
    safe(
      fn ->
        recipient!(alg, recipient)
        {id, bits} = selection(alg, enc)
        {apu, apv} = parties!(params)
        material = private_material(recipient, ephemeral)
        {public, _} = :crypto.generate_key(:ecdh, native(recipient), ephemeral)
        epk = public_material(recipient, public)
        {:ok, epk} = PublicKey.import(epk, :raw)
        {:ok, jwk} = PublicKey.export(epk, :jwk)
        key = kdf!(shared_secret(recipient, material), id, apu, apv, bits)

        {cek, encrypted} =
          if alg == "ECDH-ES" do
            ensure(cek == nil, :invalid_header)
            {key, ""}
          else
            ensure(
              is_binary(cek) and bit_size(cek) == content_bits(enc),
              :algorithm_mismatch,
              :key
            )

            {:ok, wrapped} = KeyManagement.wrap(wrap_algorithm(alg), cek, %{}, {:aes, key})
            {cek, wrapped.encrypted_key}
          end

        {:ok, %{cek: cek, encrypted_key: encrypted, header: %{"epk" => jwk}}}
      end,
      :decryption_failed,
      :crypto
    )
  end

  def recipient!(alg, %PublicKey{} = key) do
    ensure(alg in @family, :algorithm_not_permitted)
    validated!(key, :algorithm_mismatch, :key)

    ensure(
      key.algorithm in [nil, alg] and key.use in [nil, "enc"] and
        (key.operations == nil or Enum.any?(key.operations, &(&1 in ~w(deriveKey deriveBits)))),
      :algorithm_mismatch,
      :key
    )

    key
  end

  def recipient!(_, _), do: fail(:algorithm_mismatch, :key)

  def native(%PublicKey{material: {:x25519, _}}), do: :x25519
  def native(%PublicKey{material: {:ec, crv, _}}), do: elem(Algorithm.curve(crv), 0)
  defp public_material(%PublicKey{material: {:x25519, _}}, public), do: {:x25519, public}
  defp public_material(%PublicKey{material: {:ec, crv, _}}, public), do: {:ec, crv, public}
  defp private_material(%PublicKey{material: {:x25519, _}}, scalar), do: {:x25519, scalar}
  defp private_material(%PublicKey{material: {:ec, crv, _}}, scalar), do: {:ec, crv, scalar}

  def shared_secret(%PublicKey{} = key, material) do
    validated!(key, :invalid_header, :input)

    {point, scalar, curve, width} =
      case {key.material, material} do
        {{:x25519, point}, {:x25519, scalar}} ->
          {point, scalar, :x25519, 32}

        {{:ec, crv, point}, {:ec, crv, scalar}} ->
          {curve, width, order} = Algorithm.curve(crv)

          ensure(is_binary(scalar) and byte_size(scalar) == width, :decryption_failed, :crypto)
          value = :binary.decode_unsigned(scalar)
          ensure(value > 0 and value < order, :decryption_failed, :crypto)

          {point, scalar, curve, width}

        _ ->
          fail(:decryption_failed, :crypto)
      end

    ensure(is_binary(scalar) and byte_size(scalar) == width, :decryption_failed, :crypto)
    z = :crypto.compute_key(:ecdh, point, scalar, curve)
    ensure(byte_size(z) == width, :decryption_failed, :crypto)

    if curve == :x25519,
      do: ensure(not :crypto.hash_equals(z, <<0::256>>), :decryption_failed, :crypto)

    z
  end

  def kdf(z, id, apu, apv, bits), do: safe(fn -> {:ok, kdf!(z, id, apu, apv, bits)} end)

  defp kdf!(z, id, apu, apv, bits) do
    ensure(is_binary(z) and byte_size(z) in [32, 48], :invalid_header)

    ensure(
      is_binary(id) and byte_size(id) > 0 and byte_size(id) <= 64 and
        Enum.all?(:binary.bin_to_list(id), &(&1 >= 0x21 and &1 <= 0x7E)),
      :invalid_header
    )

    ensure(bits in [128, 256], :invalid_header)
    parties!(%{apu: apu, apv: apv})
    other = field(id) <> field(apu) <> field(apv) <> <<bits::32>>
    binary_part(:crypto.hash(:sha256, <<1::32>> <> z <> other), 0, div(bits, 8))
  end

  defp field(bytes), do: <<byte_size(bytes)::32, bytes::binary>>

  def parties!(params) do
    ensure(
      is_map(params) and not is_struct(params) and
        Enum.all?(Map.keys(params), &(&1 in [:apu, :apv])),
      :invalid_header
    )

    apu = Map.get(params, :apu, "")
    apv = Map.get(params, :apv, "")

    ensure(
      is_binary(apu) and byte_size(apu) <= 1024 and is_binary(apv) and byte_size(apv) <= 1024,
      :invalid_header
    )

    # Empty decoded values also represent absent parties in the closed params.
    ensure(apu == "" or apv == "" or apu != apv, :invalid_header)
    {apu, apv}
  end

  def header_parties!(h) do
    case safe(fn ->
           apu = if Map.has_key?(h, "apu"), do: decode(h["apu"]), else: ""
           apv = if Map.has_key?(h, "apv"), do: decode(h["apv"]), else: ""

           ensure(
             not (Map.has_key?(h, "apu") and Map.has_key?(h, "apv") and apu == apv),
             :invalid_header
           )

           parties!(%{apu: apu, apv: apv})
         end) do
      {:error, _} -> fail(:invalid_header)
      {apu, apv} -> %{apu: apu, apv: apv}
    end
  end

  def header_params!(alg, h) do
    parties = header_parties!(h)
    epk = parse_epk!(h["epk"])
    {id, bits} = selection(alg, h["enc"])
    Map.merge(parties, %{epk: epk, algorithm_id: id, key_bits: bits})
  end

  def parse_epk!(jwk) do
    ensure(is_map(jwk) and not is_struct(jwk), :invalid_header)

    keys =
      case jwk do
        %{"kty" => "EC", "crv" => crv} when crv in ["P-256", "P-384"] -> ~w(crv kty x y)
        %{"kty" => "OKP", "crv" => "X25519"} -> ~w(crv kty x)
        _ -> fail(:invalid_header)
      end

    ensure(Enum.sort(Map.keys(jwk)) == keys, :invalid_header)

    case PublicKey.import(jwk, :jwk) do
      {:ok, key} -> validated!(key, :invalid_header, :input)
      _ -> fail(:invalid_header)
    end
  end

  def validate_params!(alg, params) do
    ensure(
      is_map(params) and not is_struct(params) and
        Enum.sort(Map.keys(params)) == [:algorithm_id, :apu, :apv, :epk, :key_bits],
      :invalid_header
    )

    ensure(params.key_bits in [128, 256], :invalid_header)

    if alg == "ECDH-ES" do
      ensure(
        params.algorithm_id in ["A128GCM", "A256GCM", "A128CBC-HS256"] and
          content_bits(params.algorithm_id) == params.key_bits,
        :invalid_header
      )
    else
      ensure(
        params.algorithm_id == alg and
          params.key_bits == if(alg == "ECDH-ES+A128KW", do: 128, else: 256),
        :invalid_header
      )
    end

    parties!(Map.take(params, [:apu, :apv]))
    key = validated!(params.epk, :invalid_header, :input)
    ensure(key.algorithm == nil and key.use == nil and key.operations == nil, :invalid_header)
    :ok
  end

  def unwrap(alg, encrypted, params, material) do
    validate_params!(alg, params)

    key =
      kdf!(
        shared_secret(params.epk, material),
        params.algorithm_id,
        params.apu,
        params.apv,
        params.key_bits
      )

    if alg == "ECDH-ES" do
      ensure(encrypted == "", :decryption_failed, :crypto)
      key
    else
      case KeyManagement.unwrap(wrap_algorithm(alg), encrypted, %{}, {:aes, key}) do
        {:ok, cek} -> cek
        _ -> fail(:decryption_failed, :crypto)
      end
    end
  end

  def selection(alg, enc) do
    ensure(alg in @family, :algorithm_not_permitted)
    content = content_bits(enc)

    {if(alg == "ECDH-ES", do: enc, else: alg),
     case alg do
       "ECDH-ES" -> content
       "ECDH-ES+A128KW" -> 128
       "ECDH-ES+A256KW" -> 256
     end}
  end

  def content_bits("A128GCM"), do: 128
  def content_bits(enc) when enc in ["A256GCM", "A128CBC-HS256"], do: 256
  def content_bits(_), do: fail(:algorithm_not_permitted)
  defp wrap_algorithm("ECDH-ES+A128KW"), do: "A128KW"
  defp wrap_algorithm("ECDH-ES+A256KW"), do: "A256KW"

  defp validated!(key, reason, layer) do
    case safe(
           fn ->
             PublicKey.validate!(key)

             case key.material do
               {:ec, crv, <<4, point::binary>>} when crv in ["P-256", "P-384"] ->
                 {_, size, _} = Algorithm.curve(crv)
                 <<x::unsigned-big-size(^size * 8), y::unsigned-big-size(^size * 8)>> = point
                 {p, b} = field_parameters(crv)

                 ensure(
                   x < p and y < p and rem(y * y, p) == Integer.mod(x * x * x - 3 * x + b, p),
                   reason,
                   layer
                 )

               {:x25519, x} ->
                 ensure(byte_size(x) == 32, reason, layer)

               _ ->
                 fail(reason, layer)
             end

             key
           end,
           reason,
           layer
         ) do
      {:error, _} -> fail(reason, layer)
      valid -> valid
    end
  end

  defp field_parameters("P-256"),
    do: {
      0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
      0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    }

  defp field_parameters("P-384"),
    do: {
      0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
      0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF
    }
end
