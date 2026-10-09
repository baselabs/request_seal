defmodule RequestSeal.JOSEReciprocalTest do
  use ExUnit.Case, async: false
  alias RequestSeal.JOSE.{JWE, JWS, KeyManagement}
  import RequestSeal.JOSEVectors
  @moduletag timeout: 300_000
  defp peer(request) do
    input = request |> :json.encode() |> IO.iodata_to_binary()

    RequestSeal.JOSEPeer.with_input(input, fn path ->
      assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600
      assert Bitwise.band(File.stat!(Path.dirname(path)).mode, 0o777) == 0o700
      {out, status} = RequestSeal.JOSEPeer.run(path)
      assert status == 0, out
      :json.decode(out)
    end)
  end

  test "32 fresh random rounds per direction with independent Node WebCrypto" do
    {tool, 0} = System.cmd("node", ["--version"])
    IO.puts("RECIPROCAL TOOL Node #{String.trim(tool)} WebCrypto")
    jwe_algs = ~w(RSA-OAEP-256 RSA-OAEP A128GCMKW A256GCMKW dir)
    jws_algs = ~w(RS256 PS256 PS384 PS512 HS256 ES256 ES384 EdDSA)

    for round <- 0..31 do
      alg = Enum.at(jwe_algs, rem(round, 5))
      sig = Enum.at(jws_algs, rem(round, 8))
      enc = if rem(round, 2) == 0, do: "A128GCM", else: "A256GCM"
      length = if round == 0, do: 0, else: if(round == 31, do: 65536, else: :rand.uniform(65536))

      IO.puts("RECIPROCAL ROUND #{round} #{sig} #{alg} #{enc}")

      v =
        peer(%{
          operation: "make",
          algorithm: alg,
          encryption: enc,
          signature_algorithm: sig,
          length: length
        })

      desc =
        if alg == "dir",
          do: {:cek, b64(v["key"]["k"])},
          else:
            if(alg in ~w(A128GCMKW A256GCMKW),
              do: {:aes, b64(v["key"]["k"])},
              else: rsa(v["key"])
            )

      jp = %{
        algorithms: [alg],
        encryption: [enc],
        max_plaintext: 1_048_576,
        timeout: 5000,
        key_resolver: fn _ ->
          {:ok, %{algorithm: alg, unwrap: fn ek, h -> KeyManagement.unwrap(alg, ek, h, desc) end}}
        end
      }

      assert {:ok, decrypted} = JWE.decrypt(v["jwe"], jp)
      assert decrypted.plaintext == b64(v["plaintext"])
      assert {:ok, verified} = JWS.verify(v["jws"], jws_policy(v["verification_key"], sig))
      assert verified.payload == b64(v["payload"])
      # Fresh Elixir keys and plaintext for the other direction.
      secret =
        case sig do
          a when a in ~w(RS256 PS256 PS384 PS512) ->
            {:rsa, :public_key.generate_key({:rsa, 2048, 65537})}

          "HS256" ->
            {:hmac, :crypto.strong_rand_bytes(32)}

          "EdDSA" ->
            {:ed25519, :crypto.strong_rand_bytes(32)}

          a ->
            {_, scalar} =
              :crypto.generate_key(:ecdh, if(a == "ES256", do: :secp256r1, else: :secp384r1))

            {:ec, if(a == "ES256", do: "P-256", else: "P-384"), scalar}
        end

      assert {:ok, handle} = RequestSeal.Custody.Local.new({:jws, sig}, secret)

      try do
        payload = :crypto.strong_rand_bytes(max(1, length))
        assert {:ok, compact} = JWS.sign([{"alg", sig}], payload, handle, timeout: 5000)

        key =
          if sig == "HS256",
            do: %{"kty" => "oct", "k" => enc(elem(secret, 1))},
            else:
              RequestSeal.Custody.public_key(handle)
              |> elem(1)
              |> RequestSeal.PublicKey.export(:jwk)
              |> elem(1)

        assert peer(%{operation: "verify", algorithm: sig, key: key, compact: compact})["valid"] ==
                 true

        [p, b, s] = String.split(compact, ".")
        <<f, rest::binary>> = b64(s)

        assert peer(%{
                 operation: "verify",
                 algorithm: sig,
                 key: key,
                 compact: Enum.join([p, b, enc(<<Bitwise.bxor(f, 1), rest::binary>>)], ".")
               })["valid"] == false
      after
        RequestSeal.Custody.Local.release(handle)
      end

      plaintext = :crypto.strong_rand_bytes(length)

      {recipient, recipient_key} =
        if alg in ~w(RSA-OAEP RSA-OAEP-256) do
          {:rsa, k} = desc = rsa_key()
          {:ok, pub} = RequestSeal.PublicKey.import({:rsa, elem(k, 2), elem(k, 3)}, :raw)
          {pub, private_jwk(desc)}
        else
          owner = self()
          k = :crypto.strong_rand_bytes(if alg == "A128GCMKW", do: 16, else: 32)

          recipient = fn a, cek ->
            if a == "dir" do
              send(owner, {:direct_key, cek})
              KeyManagement.wrap(a, cek, %{}, {:cek, cek})
            else
              KeyManagement.wrap(a, cek, %{}, {:aes, k})
            end
          end

          {recipient, %{"kty" => "oct", "k" => enc(k)}}
        end

      assert {:ok, compact} =
               JWE.encrypt([{"alg", alg}, {"enc", enc}], plaintext, recipient, timeout: 5000)

      recipient_key =
        if alg == "dir",
          do:
            (receive do
               {:direct_key, k} -> %{"kty" => "oct", "k" => enc(k)}
             after
               1000 -> flunk("direct custody provisioning failed")
             end),
          else: recipient_key

      assert peer(%{
               operation: "decrypt",
               algorithm: alg,
               encryption: enc,
               key: recipient_key,
               compact: compact
             })["plaintext"] == enc(plaintext)
    end

    IO.puts("RECIPROCAL TOOL 32 Node-to-Elixir and 32 Elixir-to-Node rounds passed")
  end

  defp rsa_key, do: {:rsa, :public_key.generate_key({:rsa, 2048, 65537})}

  defp private_jwk({:rsa, k}) do
    values = for i <- [2, 3, 4, 5, 6, 7, 8, 9], do: enc(:binary.encode_unsigned(elem(k, i)))
    Map.new(Enum.zip(~w(n e d p q dp dq qi), values)) |> Map.put("kty", "RSA")
  end

  test "OpenSSL RSA OAEP SHA-256 and MGF1 SHA-256 both directions; SHA-1 MGF1 rejects" do
    {tool, 0} = System.cmd("openssl", ["version"])
    IO.puts("RECIPROCAL TOOL " <> String.trim(tool))
    desc = {:rsa, k} = rsa_key()
    assert {:ok, unwrap_handle} = RequestSeal.Custody.Local.new({:jwe, "RSA-OAEP-256"}, desc)
    {:ok, pub} = RequestSeal.PublicKey.import({:rsa, elem(k, 2), elem(k, 3)}, :raw)
    dir = Path.join(System.tmp_dir!(), "requestseal-oaep-#{System.unique_integer([:positive])}")
    File.mkdir!(dir)

    try do
      File.write!(
        Path.join(dir, "private.pem"),
        :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, k)])
      )

      File.write!(
        Path.join(dir, "public.pem"),
        RequestSeal.PublicKey.export(pub, :pem) |> elem(1)
      )

      cek = :crypto.strong_rand_bytes(32)
      File.write!(Path.join(dir, "cek"), cek)

      options = [
        "-pkeyopt",
        "rsa_padding_mode:oaep",
        "-pkeyopt",
        "rsa_oaep_md:sha256",
        "-pkeyopt",
        "rsa_mgf1_md:sha256"
      ]

      {out, code} =
        System.cmd(
          "openssl",
          [
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            Path.join(dir, "public.pem"),
            "-in",
            Path.join(dir, "cek"),
            "-out",
            Path.join(dir, "wrapped") | options
          ],
          stderr_to_stdout: true
        )

      assert code == 0, out

      assert RequestSeal.Custody.unwrap(unwrap_handle, File.read!(Path.join(dir, "wrapped"))) ==
               {:ok, cek}

      assert KeyManagement.unwrap(
               "RSA-OAEP-256",
               File.read!(Path.join(dir, "wrapped")),
               %{},
               desc
             ) == {:ok, cek}

      assert {:ok, %{encrypted_key: ek}} =
               KeyManagement.wrap(
                 "RSA-OAEP-256",
                 cek,
                 %{},
                 {:rsa, {:RSAPublicKey, elem(k, 2), elem(k, 3)}}
               )

      File.write!(Path.join(dir, "wrapped"), ek)

      {out, code} =
        System.cmd(
          "openssl",
          [
            "pkeyutl",
            "-decrypt",
            "-inkey",
            Path.join(dir, "private.pem"),
            "-in",
            Path.join(dir, "wrapped"),
            "-out",
            Path.join(dir, "decrypted") | options
          ],
          stderr_to_stdout: true
        )

      assert code == 0, out
      assert File.read!(Path.join(dir, "decrypted")) == cek
      options = List.replace_at(options, length(options) - 1, "rsa_mgf1_md:sha1")

      {out, code} =
        System.cmd(
          "openssl",
          [
            "pkeyutl",
            "-encrypt",
            "-pubin",
            "-inkey",
            Path.join(dir, "public.pem"),
            "-in",
            Path.join(dir, "cek"),
            "-out",
            Path.join(dir, "wrapped") | options
          ],
          stderr_to_stdout: true
        )

      assert code == 0, out

      assert {:error, %{reason: :decryption_failed}} =
               RequestSeal.Custody.unwrap(unwrap_handle, File.read!(Path.join(dir, "wrapped")))

      assert {:error, %{reason: :decryption_failed}} =
               KeyManagement.unwrap(
                 "RSA-OAEP-256",
                 File.read!(Path.join(dir, "wrapped")),
                 %{},
                 desc
               )
    after
      RequestSeal.Custody.Local.release(unwrap_handle)
      File.rm_rf!(dir)
    end
  end

  test "HS256 peer requires exactly 256 bits of key material" do
    key = :crypto.strong_rand_bytes(32)
    payload = "key-length-boundary"
    {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "HS256"}, {:hmac, key})
    on_exit(fn -> RequestSeal.Custody.Local.release(handle) end)
    {:ok, compact} = JWS.sign([{"alg", "HS256"}], payload, handle)

    for bytes <- [1, 16, 31, 33, 64] do
      jwk = %{kty: "oct", k: Base.url_encode64(:crypto.strong_rand_bytes(bytes), padding: false)}
      request = %{operation: "verify", algorithm: "HS256", key: jwk, compact: compact}
      input = request |> :json.encode() |> IO.iodata_to_binary()

      RequestSeal.JOSEPeer.with_input(input, fn path ->
        {out, status} = RequestSeal.JOSEPeer.run(path)
        assert status == 1
        assert :json.decode(out) == %{"error" => "rejected"}
      end)
    end

    assert peer(%{
             operation: "verify",
             algorithm: "HS256",
             key: %{kty: "oct", k: Base.url_encode64(key, padding: false)},
             compact: compact
           }) == %{"valid" => true}
  end
end
