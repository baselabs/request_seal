defmodule RequestSeal.JOSEVectors do
  @moduledoc false
  def fixture(name), do: File.read!("test/fixtures/jose/" <> name) |> :json.decode()
  def b64(s), do: Base.url_decode64!(s, padding: false)
  def enc(s), do: Base.url_encode64(s, padding: false)
  def hex(s), do: Base.decode16!(s, case: :mixed)

  def rsa(j) do
    [n, e, d, p, q, dp, dq, qi] =
      Enum.map(~w(n e d p q dp dq qi), &:binary.decode_unsigned(b64(j[&1])))

    {:rsa, {:RSAPrivateKey, :"two-prime", n, e, d, p, q, dp, dq, qi, :asn1_NOVALUE}}
  end

  def public(j),
    do: RequestSeal.PublicKey.import(Map.drop(j, ~w(d p q dp dq qi k)), :jwk) |> elem(1)

  def material(%{"kty" => "RSA"} = j), do: rsa(j)
  def material(%{"kty" => "OKP", "d" => d}), do: {:ed25519, b64(d)}
  def material(%{"kty" => "oct", "k" => k}), do: {:hmac, b64(k)}
  def material(%{"kty" => "EC", "crv" => c, "d" => d}), do: {:ec, c, b64(d)}

  def jws_policy(j, alg) do
    key =
      if j["kty"] == "oct",
        do: fn a, b, s -> RequestSeal.Crypto.verify(a, b, s, material(j)) end,
        else: public(j)

    %{
      algorithms: [alg],
      timeout: 5000,
      key_resolver: fn _ -> {:ok, %{algorithm: alg, key: key}} end
    }
  end

  def jwe_policy(j, alg, enc) do
    descriptor = if j["kty"] == "RSA", do: rsa(j), else: {:cek, b64(j["k"])}

    %{
      algorithms: [alg],
      encryption: [enc],
      max_plaintext: 1_048_576,
      timeout: 5000,
      key_resolver: fn _ ->
        {:ok,
         %{
           algorithm: alg,
           unwrap: fn ek, h -> RequestSeal.JOSE.KeyManagement.unwrap(alg, ek, h, descriptor) end
         }}
      end
    }
  end

  def replace(compact, index, value),
    do: compact |> String.split(".") |> List.replace_at(index, value) |> Enum.join(".")

  def header(compact, json), do: replace(compact, 0, enc(json))
end
