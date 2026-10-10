defmodule RequestSeal.Custody.SSHAgent.Wire do
  @moduledoc false
  alias RequestSeal.Crypto
  alias RequestSeal.Crypto.Algorithm
  alias RequestSeal.PublicKey
  import RequestSeal.Custody.Support, only: [ensure: 2]

  def string(bytes), do: <<byte_size(bytes)::32, bytes::binary>>

  def key_blob(%PublicKey{material: {:ed25519, public}}),
    do: string("ssh-ed25519") <> string(public)

  def key_blob(%PublicKey{material: {:rsa, n, e}}),
    do: string("ssh-rsa") <> mpint(e) <> mpint(n)

  def key_blob(%PublicKey{material: {:ec, crv, point}}) do
    curve = if crv == "P-256", do: "nistp256", else: "nistp384"
    string("ecdsa-sha2-" <> curve) <> string(curve) <> string(point)
  end

  def identities(response) do
    safe(fn ->
      case response do
        <<5>> ->
          {:error, :custodian_rejected}

        <<12, count::32, rest::binary>> ->
          ensure(count <= 256, :custodian_protocol)
          {keys, ""} = identities(rest, count, [])
          {:ok, keys}

        _ ->
          {:error, :custodian_protocol}
      end
    end)
  end

  defp identities(rest, 0, keys), do: {Enum.reverse(keys), rest}

  defp identities(rest, count, keys) do
    {blob, rest} = read_string(rest, 16_384)
    {_, rest} = read_string(rest, 16_384)
    identities(rest, count - 1, [blob | keys])
  end

  # This is the single acceptance boundary for actual agent replies. Even a
  # correctly framed signature is untrusted until bound to the requested bytes.
  def signature(response, algorithm, bytes, public) do
    safe(fn ->
      case response do
        <<5>> ->
          {:error, :custodian_rejected}

        <<14, rest::binary>> ->
          {packet, ""} = read_string(rest, 16_384)
          {type, rest} = read_string(packet, 64)
          {raw, ""} = read_string(rest, 16_384)
          {jose, _} = Algorithm.resolve(algorithm)
          signature = signature_bytes(jose, type, raw, public)

          case Crypto.verify(algorithm, bytes, signature, public,
                 max_bytes: Crypto.max_bytes_ceiling()
               ) do
            :ok -> {:ok, signature}
            {:error, _} -> {:error, :custodian_rejected}
          end

        _ ->
          {:error, :custodian_protocol}
      end
    end)
  end

  defp signature_bytes("EdDSA", "ssh-ed25519", raw, _) do
    ensure(byte_size(raw) == 64, :custodian_protocol)
    raw
  end

  defp signature_bytes("RS256", "rsa-sha2-256", raw, %PublicKey{material: {:rsa, n, _}}) do
    width = byte_size(:binary.encode_unsigned(n))
    ensure(byte_size(raw) > 0 and byte_size(raw) <= width, :custodian_protocol)
    :binary.copy(<<0>>, width - byte_size(raw)) <> raw
  end

  defp signature_bytes("ES256", "ecdsa-sha2-nistp256", raw, _), do: ecdsa(raw, 32)
  defp signature_bytes("ES384", "ecdsa-sha2-nistp384", raw, _), do: ecdsa(raw, 48)
  defp signature_bytes(_, _, _, _), do: ensure(false, :custodian_protocol)

  defp ecdsa(raw, width) do
    {r, rest} = read_string(raw, width + 1)
    {s, ""} = read_string(rest, width + 1)
    fixed_mpint(r, width) <> fixed_mpint(s, width)
  end

  defp fixed_mpint(bytes, width) do
    # Positive mpints need one sign byte precisely when the magnitude's high bit
    # is set. Never trim arbitrary zeroes or accept negative/oversized scalars.
    magnitude =
      case bytes do
        <<0, first, rest::binary>> when first >= 128 -> <<first, rest::binary>>
        <<first, _::binary>> when first in 1..127 -> bytes
        _ -> ensure(false, :custodian_protocol)
      end

    ensure(byte_size(magnitude) <= width, :custodian_protocol)
    :binary.copy(<<0>>, width - byte_size(magnitude)) <> magnitude
  end

  defp mpint(value) do
    bytes = :binary.encode_unsigned(value)
    if :binary.first(bytes) >= 128, do: string(<<0, bytes::binary>>), else: string(bytes)
  end

  defp read_string(<<size::32, rest::binary>>, limit)
       when size <= limit and byte_size(rest) >= size do
    <<bytes::binary-size(^size), tail::binary>> = rest
    {bytes, tail}
  end

  defp read_string(_, _), do: ensure(false, :custodian_protocol)

  defp safe(fun) do
    fun.()
  rescue
    _ -> {:error, :custodian_protocol}
  catch
    _, _ -> {:error, :custodian_protocol}
  end
end
