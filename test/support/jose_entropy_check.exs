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

{:ok, recipient} = RequestSeal.PublicKey.import(Map.drop(v["key"], ~w(d p q dp dq qi)), :jwk)

{:error, %RequestSeal.JOSE.Error{reason: :entropy_failure}} =
  RequestSeal.JOSE.JWE.encrypt([{"alg", "RSA-OAEP"}, {"enc", "A128GCM"}], "", recipient)

direct =
  File.read!("test/fixtures/jose/5_6.direct_encryption_using_aes-gcm.json") |> :json.decode()

handle =
  RequestSeal.Test.JOSEBatchCustodian.start(
    "dir",
    {:cek, decode.(direct["input"]["key"]["k"])},
    :all,
    self()
  )

policy = %{
  algorithms: ["dir"],
  encryption: ["A128GCM"],
  timeout: 5000,
  max_plaintext: 1_048_576,
  resolve_timeout: 1000,
  unwrap_timeout: 1000,
  protected: %{expected: %{}, permitted: ~w(kid)},
  key_resolver: fn _ -> {:ok, %{algorithm: "dir", key: handle}} end
}

{:error, %RequestSeal.JOSE.Error{reason: :entropy_failure}} =
  RequestSeal.JOSE.JWE.decrypt(direct["output"]["compact"], policy)

RequestSeal.Custody.release(handle)

IO.puts("CSPRNG FAILED; PUBLISHED AES WORKS; ENCRYPT/DECRYPT ENTROPY FAILURE")
