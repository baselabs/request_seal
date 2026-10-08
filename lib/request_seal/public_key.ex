defmodule RequestSeal.PublicKey do
  @moduledoc """
  Public-only RSA, P-256, P-384, and Ed25519 key formats and algorithm binding.

  Formats follow [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517.html),
  [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html),
  [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html),
  [RFC 4055](https://www.rfc-editor.org/rfc/rfc4055.html),
  [RFC 5480](https://www.rfc-editor.org/rfc/rfc5480.html), and
  [RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html).

  `import/2` and `export/2` support public JWK maps (`:jwk`), PEM (`:pem`), DER
  SubjectPublicKeyInfo (`:der`), and explicit components (`:raw`):
  `{:rsa, n, e}`, `{:rsa_pss, n, e}`, `{:ec, "P-256" | "P-384", uncompressed_point}`,
  or `{:ed25519, public_bytes}`. PEM also accepts PKCS #1 RSA public keys.
  Private and symmetric JWK/PEM material rejects. No secret or key ID is retained.

  JWK `alg`, `use`, and `key_ops` are retained and checked on every verification.
  Algorithm names are printable ASCII; simultaneous use/operation restrictions must agree.
  JWK `alg` uses exact JOSE identifiers even for an HTTP algorithm. Absent metadata
  imposes no additional restriction; it does not establish trust. Export preserves
  restrictions; restricted JWKs cannot export to formats without metadata.
  RSA-PSS SubjectPublicKeyInfo with absent parameters retains its PSS-only type;
  parameter-constrained PSS keys reject instead of discarding constraints. PSS-only
  keys cannot export to JWK, which has no equivalent key-type restriction.

  RSA moduli are odd, 2048–8192 bits; public exponents are odd, 3–2^32-1 and
  smaller than the modulus. EC points must have the exact uncompressed width and
  pass OTP point validation. Ed25519 keys are 32 bytes with canonical encoded y
  and reject all eight small-order points with `:invalid_key` in every format.
  The check ignores the encoded x sign, following the
  libsodium small-order blocklist (`ge25519_has_small_order` in
  [ed25519_ref10.c at tag 1.0.18](https://github.com/jedisct1/libsodium/blob/1.0.18/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c)).
  PEM/DER inputs are limited to 16,384 bytes. JWK maps have at most 32 entries;
  encoded components are bounded. Supplied structs are revalidated at each use.
  """
  alias RequestSeal.Crypto.{Algorithm, Support}
  import Support, only: [ensure: 2, bounded_binary?: 3]
  defstruct [:material, :algorithm, :use, :operations]

  @type t :: %__MODULE__{
          material: tuple(),
          algorithm: binary() | nil,
          use: binary() | nil,
          operations: [binary()] | nil
        }
  @rsa {1, 2, 840, 113_549, 1, 1, 1}
  @pss {1, 2, 840, 113_549, 1, 1, 10}
  @ec {1, 2, 840, 10045, 2, 1}
  @ed {1, 3, 101, 112}
  # Canonical y values from the published libsodium blocklist linked above.
  # Its sign-bit mask covers both encodings of the order-4 and order-8 points.
  @ed25519_small_order_y [
    0,
    1,
    0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEC,
    0x05FC536D880238B13933C6D305ACDFD5F098EFF289F4C345B027B2C28F95E826,
    0x7A03AC9277FDC74EC6CC392CFA53202A0F67100D760B3CBA4FD84D3D706A17C7
  ]

  @doc "Import bounded, explicit public key material, preserving JWK restrictions."
  @spec import(term(), :jwk | :pem | :der | :raw) ::
          {:ok, t()} | {:error, RequestSeal.Crypto.Error.t()}
  def import(value, format),
    do: Support.safe(:invalid_key, fn -> {:ok, decode(value, format)} end)

  @doc "Export a validated public key without dropping algorithm or operation restrictions."
  @spec export(t(), :jwk | :pem | :der | :raw) ::
          {:ok, term()} | {:error, RequestSeal.Crypto.Error.t()}
  def export(key, format) do
    Support.safe(:invalid_key, fn ->
      validate!(key)
      ensure(format in [:jwk, :pem, :der, :raw], :unsupported_format)

      ensure(
        format == :jwk or (key.algorithm == nil and key.use == nil and key.operations == nil),
        :unsupported_format
      )

      {:ok, encode(key, format)}
    end)
  end

  @doc "Compute the RFC 7638 / RFC 8037 SHA-256 thumbprint of required public members."
  @spec thumbprint(t()) :: {:ok, binary()} | {:error, RequestSeal.Crypto.Error.t()}
  def thumbprint(key) do
    Support.safe(:invalid_key, fn ->
      validate!(key)

      members =
        case key.material do
          {type, n, e} when type in [:rsa, :rsa_pss] ->
            [
              {"e", Base.url_encode64(:binary.encode_unsigned(e), padding: false)},
              {"kty", "RSA"},
              {"n", Base.url_encode64(:binary.encode_unsigned(n), padding: false)}
            ]

          {:ed25519, public} ->
            [{"crv", "Ed25519"}, {"kty", "OKP"}, {"x", Base.url_encode64(public, padding: false)}]

          {:ec, curve, <<4, point::binary>>} ->
            width = div(byte_size(point), 2)
            <<x::binary-size(^width), y::binary-size(^width)>> = point

            [
              {"crv", curve},
              {"kty", "EC"},
              {"x", Base.url_encode64(x, padding: false)},
              {"y", Base.url_encode64(y, padding: false)}
            ]
        end

      # Ordered, required ASCII members only; metadata is not thumbprint material.
      json =
        "{" <>
          Enum.map_join(members, ",", fn {name, value} ->
            "\"" <> name <> "\":\"" <> value <> "\""
          end) <> "}"

      {:ok, Base.url_encode64(:crypto.hash(:sha256, json), padding: false)}
    end)
  end

  @doc false
  def validate!(%__MODULE__{} = key) do
    ensure(map_size(key) == 5, :invalid_key)
    material!(key.material)
    metadata!(key.algorithm, key.use, key.operations)
    key
  end

  def validate!(_), do: ensure(false, :invalid_key)

  @doc false
  def bind!(key, {jose, {type, _, curve, _}}) do
    validate!(key)

    compatible =
      case {key.material, type} do
        {{:rsa, _, _}, :rsa} -> true
        {{:rsa_pss, _, _}, :rsa} -> jose in ["PS256", "PS384", "PS512"]
        {{:ec, ^curve, _}, :ec} -> true
        {{:ed25519, _}, :ed25519} -> true
        _ -> false
      end

    ensure(
      compatible and key.algorithm in [nil, jose] and key.use in [nil, "sig"] and
        (key.operations == nil or "verify" in key.operations),
      :key_mismatch
    )

    key.material
  end

  defp decode(value, :raw), do: %__MODULE__{material: material!(value)}

  defp decode(value, :jwk) do
    ensure(is_map(value) and not is_struct(value) and map_size(value) <= 32, :invalid_key)
    ensure(not Enum.any?(~w(d p q dp dq qi oth k), &Map.has_key?(value, &1)), :invalid_key)

    material =
      case value do
        %{"kty" => "RSA", "n" => n, "e" => e} ->
          {:rsa, uint(n), uint(e)}

        %{"kty" => "EC", "crv" => crv, "x" => x, "y" => y} ->
          {_, size, _} = Algorithm.curve(crv)
          x = b64(x)
          y = b64(y)
          ensure(byte_size(x) == size and byte_size(y) == size, :invalid_key)
          {:ec, crv, <<4, x::binary, y::binary>>}

        %{"kty" => "OKP", "crv" => "Ed25519", "x" => x} ->
          {:ed25519, b64(x)}

        _ ->
          ensure(false, :invalid_key)
      end

    alg = value["alg"]
    use = value["use"]
    ops = value["key_ops"]
    # Explicit null is not absent in a JWK.
    ensure(
      Enum.all?(~w(alg use key_ops), &(not Map.has_key?(value, &1) or value[&1] != nil)),
      :invalid_key
    )

    metadata!(alg, use, ops)
    %__MODULE__{material: material!(material), algorithm: alg, use: use, operations: ops}
  end

  defp decode(value, :pem) do
    ensure(bounded_binary?(value, 1, 16_384), :invalid_key)
    entries = :public_key.pem_decode(value)
    ensure(length(entries) == 1, :invalid_key)

    case hd(entries) do
      {:SubjectPublicKeyInfo, der, :not_encrypted} ->
        decode(der, :der)

      {:RSAPublicKey, der, :not_encrypted} ->
        {:RSAPublicKey, n, e} = canonical_der(:RSAPublicKey, der)
        decode({:rsa, n, e}, :raw)

      _ ->
        ensure(false, :invalid_key)
    end
  end

  defp decode(value, :der) do
    ensure(bounded_binary?(value, 1, 16_384), :invalid_key)

    {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, oid, params}, bytes} =
      canonical_der(:SubjectPublicKeyInfo, value)

    # OTP 27 exposes open-type parameter DER; OTP 28+ decodes its value.
    # Normalize only the selected algorithm after the container's canonical check.
    params =
      case {oid, params} do
        {@rsa, <<5, 0>>} -> :NULL
        {@ec, der} when is_binary(der) -> canonical_der(:EcpkParameters, der)
        _ -> params
      end

    material =
      case oid do
        oid when oid in [@rsa, @pss] ->
          ensure(
            if(oid == @rsa,
              do: params in [:asn1_NOVALUE, :NULL],
              else: params == :asn1_NOVALUE
            ),
            :invalid_key
          )

          {:RSAPublicKey, n, e} = canonical_der(:RSAPublicKey, bytes)
          {if(oid == @rsa, do: :rsa, else: :rsa_pss), n, e}

        @ec ->
          crv =
            case params do
              {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}} -> "P-256"
              {:namedCurve, {1, 3, 132, 0, 34}} -> "P-384"
              _ -> ensure(false, :invalid_key)
            end

          {:ec, crv, bytes}

        @ed ->
          ensure(params == :asn1_NOVALUE, :invalid_key)
          {:ed25519, bytes}

        _ ->
          ensure(false, :invalid_key)
      end

    decode(material, :raw)
  end

  defp decode(_, _), do: ensure(false, :unsupported_format)

  defp canonical_der(type, bytes) do
    decoded = :public_key.der_decode(type, bytes)
    ensure(:public_key.der_encode(type, decoded) == bytes, :invalid_key)
    decoded
  end

  defp b64(value) do
    ensure(bounded_binary?(value, 1, 1366), :invalid_key)
    {:ok, bytes} = Base.url_decode64(value, padding: false)
    ensure(Base.url_encode64(bytes, padding: false) == value, :invalid_key)
    bytes
  end

  defp uint(value) do
    bytes = b64(value)
    ensure(:binary.first(bytes) != 0, :invalid_key)
    :binary.decode_unsigned(bytes)
  end

  defp metadata!(alg, use, ops) do
    ensure(alg == nil or bounded_binary?(alg, 1, 64), :invalid_key)
    ensure(alg == nil or Enum.all?(:binary.bin_to_list(alg), &(&1 in 0x20..0x7E)), :invalid_key)
    ensure(use == nil or use in ["sig", "enc"], :invalid_key)

    ensure(
      ops == nil or
        (is_list(ops) and length(ops) in 0..8 and length(Enum.uniq(ops)) == length(ops) and
           Enum.all?(
             ops,
             &(&1 in ~w(sign verify encrypt decrypt wrapKey unwrapKey deriveKey deriveBits))
           )),
      :invalid_key
    )

    ensure(
      use == nil or ops == nil or
        Enum.all?(
          ops,
          &(&1 in if(use == "sig",
              do: ~w(sign verify),
              else: ~w(encrypt decrypt wrapKey unwrapKey deriveKey deriveBits)
            ))
        ),
      :invalid_key
    )
  end

  defp material!({type, n, e} = material) when type in [:rsa, :rsa_pss] do
    ensure(
      is_integer(n) and n >= Bitwise.bsl(1, 2047) and n < Bitwise.bsl(1, 8192) and rem(n, 2) == 1 and
        is_integer(e) and e >= 3 and e <= 0xFFFFFFFF and e < n and rem(e, 2) == 1,
      :invalid_key
    )

    material
  end

  defp material!({:ec, crv, point} = material) do
    {curve, size, _} = Algorithm.curve(crv)

    ensure(
      bounded_binary?(point, 1 + size * 2, 1 + size * 2) and :binary.first(point) == 4,
      :invalid_key
    )

    # OTP validates the supplied point; the scalar is public and fixed, not a key.
    :crypto.compute_key(:ecdh, point, <<1::unsigned-big-size(size * 8)>>, curve)
    material
  end

  defp material!({:ed25519, bytes} = material) do
    ensure(bounded_binary?(bytes, 32, 32), :invalid_key)
    <<encoded::little-unsigned-256>> = bytes
    y = Bitwise.band(encoded, Bitwise.bsl(1, 255) - 1)

    ensure(
      y < Bitwise.bsl(1, 255) - 19 and y not in @ed25519_small_order_y,
      :invalid_key
    )

    material
  end

  defp material!(_), do: ensure(false, :invalid_key)

  defp encode(key, :raw), do: key.material

  defp encode(key, :jwk) do
    jwk =
      case key.material do
        {:rsa, n, e} ->
          %{
            "kty" => "RSA",
            "n" => Base.url_encode64(:binary.encode_unsigned(n), padding: false),
            "e" => Base.url_encode64(:binary.encode_unsigned(e), padding: false)
          }

        {:ec, crv, <<4, rest::binary>>} ->
          {_, size, _} = Algorithm.curve(crv)
          <<x::binary-size(^size), y::binary>> = rest

          %{
            "kty" => "EC",
            "crv" => crv,
            "x" => Base.url_encode64(x, padding: false),
            "y" => Base.url_encode64(y, padding: false)
          }

        {:ed25519, x} ->
          %{"kty" => "OKP", "crv" => "Ed25519", "x" => Base.url_encode64(x, padding: false)}

        _ ->
          ensure(false, :unsupported_format)
      end

    Enum.reduce(
      [{"alg", key.algorithm}, {"use", key.use}, {"key_ops", key.operations}],
      jwk,
      fn {name, value}, acc -> if value == nil, do: acc, else: Map.put(acc, name, value) end
    )
  end

  defp encode(key, :der) do
    {oid, params, bytes} =
      case key.material do
        {type, n, e} when type in [:rsa, :rsa_pss] ->
          {if(type == :rsa, do: @rsa, else: @pss),
           if(type == :rsa, do: :NULL, else: :asn1_NOVALUE),
           :public_key.der_encode(:RSAPublicKey, {:RSAPublicKey, n, e})}

        {:ec, crv, point} ->
          params =
            if crv == "P-256",
              do: {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}},
              else: {:namedCurve, {1, 3, 132, 0, 34}}

          {@ec, params, point}

        {:ed25519, bytes} ->
          {@ed, :asn1_NOVALUE, bytes}
      end

    try do
      :public_key.der_encode(
        :SubjectPublicKeyInfo,
        {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, oid, params}, bytes}
      )
    rescue
      _ ->
        encoded_params =
          case params do
            :NULL -> <<5, 0>>
            {:namedCurve, _} -> :public_key.der_encode(:EcpkParameters, params)
            :asn1_NOVALUE -> :asn1_NOVALUE
          end

        :public_key.der_encode(
          :SubjectPublicKeyInfo,
          {:SubjectPublicKeyInfo, {:AlgorithmIdentifier, oid, encoded_params}, bytes}
        )
    end
  end

  defp encode(key, :pem),
    do: :public_key.pem_encode([{:SubjectPublicKeyInfo, encode(key, :der), :not_encrypted}])
end
