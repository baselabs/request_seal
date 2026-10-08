# Run only as a child with an explicitly unavailable OpenSSL DRBG.
v = File.read!("test/fixtures/jose/rfc7516.json") |> :json.decode()

try do
  :crypto.strong_rand_bytes(16)
  raise "CSPRNG did not fail"
rescue
  error -> if error.__struct__ != ErlangError, do: reraise(error, __STACKTRACE__)
catch
  :error, :low_entropy -> :ok
end

[protected, _, iv, ct, tag] = String.split(v["compact"], ".")
decode = &Base.url_decode64!(&1, padding: false)

plaintext =
  :crypto.crypto_one_time_aead(
    :aes_256_gcm,
    :binary.list_to_bin(v["cek"]),
    decode.(iv),
    decode.(ct),
    protected,
    decode.(tag),
    false
  )

true = plaintext == v["plaintext"]

{:error, %RequestSeal.JOSE.Error{reason: :entropy_failure}} =
  RequestSeal.JOSE.JWE.encrypt([{"alg", "dir"}, {"enc", "A128GCM"}], "", fn _, cek ->
    RequestSeal.JOSE.KeyManagement.wrap("dir", cek, %{}, {:cek, cek})
  end)

direct =
  File.read!("test/fixtures/jose/5_6.direct_encryption_using_aes-gcm.json") |> :json.decode()

key = decode.(direct["input"]["key"]["k"])

policy = %{
  algorithms: ["dir"],
  encryption: ["A128GCM"],
  timeout: 5000,
  max_plaintext: 1_048_576,
  key_resolver: fn _ ->
    {:ok,
     %{
       algorithm: "dir",
       unwrap: fn bytes, h ->
         RequestSeal.JOSE.KeyManagement.unwrap("dir", bytes, h, {:cek, key})
       end
     }}
  end
}

{:error, %RequestSeal.JOSE.Error{reason: :entropy_failure}} =
  RequestSeal.JOSE.JWE.decrypt(direct["output"]["compact"], policy)

IO.puts("CSPRNG FAILED; PUBLISHED AES WORKS; ENCRYPT/DECRYPT ENTROPY FAILURE")
