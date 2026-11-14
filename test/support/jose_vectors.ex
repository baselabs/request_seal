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
        do: local({:jws, "HS256"}, material(j)),
        else: public(j)

    %{
      algorithms: [alg],
      timeout: 5000,
      protected: %{
        expected: %{},
        permitted: ~w(kid typ cty x5c n a s x padding),
        embedded_key: :refuse
      },
      key_resolver: fn _ -> {:ok, %{algorithm: alg, key: key}} end
    }
  end

  def jwe_policy(j, alg, enc) do
    descriptor =
      if j["kty"] == "RSA",
        do: rsa(j),
        else: {if(alg == "dir", do: :cek, else: :aes), b64(j["k"])}

    handle = local({:jwe, alg}, descriptor)

    %{
      algorithms: [alg],
      encryption: [enc],
      max_plaintext: 1_048_576,
      timeout: 5000,
      resolve_timeout: 1000,
      unwrap_timeout: 1000,
      protected: %{expected: %{}, permitted: ~w(kid typ cty x5c)},
      key_resolver: fn _ -> {:ok, %{algorithm: alg, key: handle}} end
    }
  end

  def local(alg, descriptor) do
    # Caller-owned real holders are torn down when this test/corpus owner exits.
    case Process.get({__MODULE__, alg, descriptor}) do
      nil ->
        {:ok, handle} = RequestSeal.Custody.Local.new(alg, descriptor)
        Process.put({__MODULE__, alg, descriptor}, handle)
        handle

      handle ->
        handle
    end
  end

  def params(alg, header) when alg in ~w(A128GCMKW A256GCMKW),
    do: %{iv: b64(header["iv"]), tag: b64(header["tag"])}

  def params(_, _), do: %{}

  def replace(compact, index, value),
    do: compact |> String.split(".") |> List.replace_at(index, value) |> Enum.join(".")

  def header(compact, json), do: replace(compact, 0, enc(json))
end
