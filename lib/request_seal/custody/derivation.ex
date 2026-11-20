defmodule RequestSeal.Custody.Derivation do
  @moduledoc false
  alias RequestSeal.Crypto.Algorithm
  alias RequestSeal.Custody.Support
  import Support, only: [ensure: 2, fail: 1]
  @prefix "request-seal/derive/v1"
  @ecdh ~w(ECDH-ES ECDH-ES+A128KW ECDH-ES+A256KW)

  def target(algorithm, opts) do
    curve = Keyword.get(opts, :curve)

    if match?({:jwe, alg} when alg in @ecdh, algorithm) do
      ensure(curve in ["P-256", "P-384", "X25519"], :invalid_options)
    else
      ensure(not Keyword.has_key?(opts, :curve), :invalid_options)
    end

    target = %{algorithm: algorithm, curve: curve}
    {_, _, defaults} = family(target)
    capabilities = capabilities(opts, defaults)
    {target, capabilities}
  end

  def capabilities(opts, defaults) do
    selected = Keyword.get(opts, :capabilities, defaults)

    ensure(
      is_list(selected) and selected != [] and Enum.uniq(selected) == selected and
        Enum.all?(selected, &(&1 in defaults)),
      :invalid_options
    )

    selected
  end

  def family(%{algorithm: {:jwe, alg}, curve: curve}) when alg in @ecdh do
    case curve do
      "X25519" -> {"x25519-dhkem", 32, [:unwrap]}
      "P-256" -> {"p256-dhkem", 32, [:unwrap]}
      "P-384" -> {"p384-dhkem", 48, [:unwrap]}
      _ -> fail(:invalid_options)
    end
  end

  def family(%{algorithm: "ed25519", curve: nil}), do: {"ed25519-seed", 32, [:sign, :verify]}
  def family(%{algorithm: "hmac-sha256", curve: nil}), do: {"hmac-sha256-key", 32, [:sign, :verify]}
  def family(%{algorithm: {:jwe, "A128KW"}, curve: nil}), do: {"aes128-key", 16, [:wrap, :unwrap]}
  def family(%{algorithm: {:jwe, "A256KW"}, curve: nil}), do: {"aes256-key", 32, [:wrap, :unwrap]}
  def family(_), do: fail(:unsupported_algorithm)

  # This function is called only in the parent holder. No derived material is
  # returned across a custody boundary, including the HKDF intermediate values.
  def material(ikm, target, domain) do
    {family, width, _} = family(target)
    ensure(is_binary(domain) and byte_size(domain) in 1..255, :invalid_data)
    prk = :crypto.mac(:hmac, :sha256, @prefix, ikm)
    info = @prefix <> lp(family) <> lp(domain)
    okm = expand(:sha256, prk, info, width)

    case family do
      "ed25519-seed" -> {:ed25519, okm}
      "hmac-sha256-key" -> {:hmac, okm}
      "aes128-key" -> {:aes, okm}
      "aes256-key" -> {:aes, okm}
      "x25519-dhkem" -> {:x25519, elem(key_pair(0x0020, okm), 0)}
      "p256-dhkem" -> {:ec, "P-256", elem(key_pair(0x0010, okm), 0)}
      "p384-dhkem" -> {:ec, "P-384", elem(key_pair(0x0011, okm), 0)}
    end
  end

  # Internal RFC 9180 Section 7.1.3 stage, also exercised by independently
  # published DeriveKeyPair vectors. It is not a key-export API.
  def key_pair(kem, ikm) when kem in [0x0010, 0x0011, 0x0020] and is_binary(ikm) do
    {hash, width, curve} =
      case kem do
        0x0010 -> {:sha256, 32, :secp256r1}
        0x0011 -> {:sha384, 48, :secp384r1}
        0x0020 -> {:sha256, 32, :x25519}
      end

    suite = <<"KEM", kem::16>>
    prk = :crypto.mac(:hmac, hash, <<>>, "HPKE-v1" <> suite <> "dkp_prk" <> ikm)

    scalar =
      if kem == 0x0020 do
        labeled_expand(hash, prk, suite, "sk", <<>>, width)
      else
        {_, _, order} = Algorithm.curve(if(kem == 0x0010, do: "P-256", else: "P-384"))
        candidate(hash, prk, suite, width, order, 0)
      end

    {public, _} = :crypto.generate_key(:ecdh, curve, scalar)
    {scalar, public}
  end

  defp candidate(hash, prk, suite, width, order, counter) when counter <= 255 do
    bytes = labeled_expand(hash, prk, suite, "candidate", <<counter>>, width)
    scalar = :binary.decode_unsigned(bytes)

    if scalar > 0 and scalar < order,
      do: bytes,
      else: candidate(hash, prk, suite, width, order, counter + 1)
  end

  defp candidate(_, _, _, _, _, _), do: fail(:invalid_key)

  defp labeled_expand(hash, prk, suite, label, info, width),
    do: expand(hash, prk, <<width::16>> <> "HPKE-v1" <> suite <> label <> info, width)

  defp expand(hash, prk, info, width) do
    first = :crypto.mac(:hmac, hash, prk, info <> <<1>>)

    bytes =
      if byte_size(first) >= width,
        do: first,
        else: first <> :crypto.mac(:hmac, hash, prk, first <> info <> <<2>>)

    binary_part(bytes, 0, width)
  end

  defp lp(bytes), do: <<byte_size(bytes)::16, bytes::binary>>
end
