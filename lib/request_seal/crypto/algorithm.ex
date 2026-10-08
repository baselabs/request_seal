defmodule RequestSeal.Crypto.Algorithm do
  @moduledoc false
  @http ~w(rsa-pss-sha512 rsa-v1_5-sha256 hmac-sha256 ecdsa-p256-sha256 ecdsa-p384-sha384 ed25519)
  @jws %{
    "RS256" => {:rsa, :sha256, :pkcs1, 0},
    "PS256" => {:rsa, :sha256, :pss, 32},
    "PS384" => {:rsa, :sha384, :pss, 48},
    "PS512" => {:rsa, :sha512, :pss, 64},
    "ES256" => {:ec, :sha256, "P-256", 32},
    "ES384" => {:ec, :sha384, "P-384", 48},
    "HS256" => {:hmac, :sha256, nil, 32},
    "EdDSA" => {:ed25519, :none, nil, 64}
  }
  @mapping Enum.zip(@http, ~w(PS512 RS256 HS256 ES256 ES384 EdDSA)) |> Map.new()
  def http, do: @http
  def resolve({:jws, name}) when is_map_key(@jws, name), do: {name, Map.fetch!(@jws, name)}

  def resolve(name) when is_map_key(@mapping, name),
    do: resolve({:jws, Map.fetch!(@mapping, name)})

  def resolve(_), do: throw({:crypto_error, :unsupported_algorithm})

  def curve("P-256"),
    do: {:secp256r1, 32, 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551}

  def curve("P-384"),
    do:
      {:secp384r1, 48,
       0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973}

  def curve(_), do: throw({:crypto_error, :invalid_key})
end
