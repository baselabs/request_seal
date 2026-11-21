defmodule RequestSeal.ReasonAlignmentTest do
  use ExUnit.Case, async: true
  alias RequestSeal.JOSE.{JWE, JWS}

  setup do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, jws} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
    {:ok, http} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})

    on_exit(fn ->
      RequestSeal.Custody.Local.release(jws)
      RequestSeal.Custody.Local.release(http)
    end)

    %{jws: jws, http: http}
  end

  test "a header that is not a list of pairs is an invalid header, not a limit", c do
    kek = {:aes, :crypto.strong_rand_bytes(32)}
    wrap = RequestSeal.JOSEVectors.local({:jwe, "A256KW"}, kek)

    for header <- [%{"alg" => "EdDSA"}, nil, "alg", {"alg", "EdDSA"}] do
      assert {:error, %RequestSeal.JOSE.Error{reason: :invalid_header}} =
               JWS.sign(header, "sensor reading", c.jws)

      assert {:error, %RequestSeal.JOSE.Error{reason: :invalid_header}} =
               JWE.encrypt(header, "sensor reading", wrap)
    end

    too_many = [{"alg", "EdDSA"} | for(i <- 1..64, do: {"x#{i}", i})]
    assert {:error, %RequestSeal.JOSE.Error{reason: :limit}} = JWS.sign(too_many, "r", c.jws)
  end

  test "unwrap keeps the corpus-pinned KEK size reason and decryption stays uniform" do
    alias RequestSeal.JOSE.{JWE, KeyManagement}

    vector =
      RequestSeal.JOSEVectors.fixture(
        "5_7.key_wrap_using_aes-gcm_keywrap_with_aes-cbc-hmac-sha2.json"
      )

    cek = RequestSeal.JOSEVectors.b64(vector["generated"]["cek"])
    kek = {:aes, RequestSeal.JOSEVectors.b64(vector["input"]["key"]["k"])}
    wrapped = RequestSeal.JOSEVectors.b64(vector["encrypting_key"]["encrypted_key"])
    header = vector["encrypting_content"]["protected"]

    short = {:aes, :crypto.strong_rand_bytes(16)}

    assert {:error, %{reason: :algorithm_mismatch}} =
             KeyManagement.unwrap(
               "A256GCMKW",
               wrapped,
               RequestSeal.JOSEVectors.params("A256GCMKW", header),
               short
             )

    for material <- [{:cek, cek}, {:rsa, :none}, :none] do
      assert {:error, %{reason: :decryption_failed}} =
               KeyManagement.unwrap(
                 "A256GCMKW",
                 wrapped,
                 RequestSeal.JOSEVectors.params("A256GCMKW", header),
                 material
               )
    end

    for material <- [short, {:cek, cek}, {:rsa, :none}, :none] do
      assert {:error, %{reason: :algorithm_not_permitted, layer: :input}} =
               KeyManagement.wrap("A256GCMKW", cek, %{}, material)
    end

    {:ok, handle} = RequestSeal.Custody.Local.new({:jwe, "A256KW"}, kek)
    on_exit(fn -> RequestSeal.Custody.release(handle) end)
    {:ok, token} = JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], "reading", handle)

    # 2.0 unwrap failures come from custody, never resolver closures.
    {:ok, wrong} =
      RequestSeal.Custody.Local.new({:jwe, "A256KW"}, {:aes, :crypto.strong_rand_bytes(32)})

    on_exit(fn -> RequestSeal.Custody.release(wrong) end)
    refused = %{handle | ref: fn -> raise "custody unavailable" end}

    for recipient <- [wrong, refused] do
      policy = %{
        algorithms: ["A256KW"],
        encryption: ["A256GCM"],
        max_plaintext: 1024,
        timeout: 5000,
        resolve_timeout: 1000,
        unwrap_timeout: 1000,
        protected: %{expected: %{}, permitted: []},
        key_resolver: fn _ -> {:ok, %{algorithm: "A256KW", key: recipient}} end
      }

      assert {:error, %{reason: :decryption_failed, layer: :crypto}} = JWE.decrypt(token, policy)
    end
  end

  test "a Web Bot Auth signing agent URL the caller supplies is checked as an option", c do
    {:ok, key} = RequestSeal.Custody.public_key(c.http)
    {:ok, message} = RequestSeal.Message.request("GET", "https://docs.example.org/", [], nil)
    signer = c.http

    for location <- ["http://crawler.example", "https://user@crawler.example", "crawler.example"] do
      spec = %{
        label: "agent",
        agent: %{location: location, type: :jwks_uri},
        key: key,
        algorithm: "ed25519",
        created: 1_760_000_000,
        expires: 1_760_000_060,
        nonce: nil
      }

      assert {:error, %RequestSeal.Error{reason: :invalid_options, layer: :input}} =
               RequestSeal.WebBotAuth.sign(message, spec, signer)
    end
  end
end
