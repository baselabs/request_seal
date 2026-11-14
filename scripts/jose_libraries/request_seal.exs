# Check peer-produced envelopes and create fresh output for both peers to open.
alias RequestSeal.{Custody, PublicKey}
alias RequestSeal.Custody.Local
alias RequestSeal.JOSE.JWE
[input, output] = System.argv()
rows = :json.decode(File.read!(input))

outputs =
  Enum.flat_map(rows, fn row ->
    alg = row["alg"]
    {:ok, handle} = Local.import({:jwe, alg}, row["key"], :jwk)

    try do
      policy = %{
        algorithms: [alg],
        encryption: [row["enc"]],
        max_plaintext: 1024,
        timeout: 5000,
        key_resolver: fn _ -> {:ok, %{algorithm: alg, key: handle}} end
      }

      {:ok, result} = JWE.decrypt(row["token"], policy)
      plaintext = Base.url_decode64!(row["plaintext"], padding: false)
      true = result.plaintext == plaintext

      if alg in ~w(A128GCMKW A256GCMKW dir) do
        []
      else
        recipient =
          if String.starts_with?(alg, "ECDH-ES") do
            {:ok, key} = PublicKey.import(Map.drop(row["key"], ["d"]), :jwk)
            key
          else
            handle
          end

        {:ok, token} = JWE.encrypt([{"alg", alg}, {"enc", row["enc"]}], plaintext, recipient)
        [Map.put(row, "token", token)]
      end
    after
      Custody.release(handle)
    end
  end)

File.write!(output, :json.encode(outputs))

IO.puts(
  "PASS RequestSeal decrypted #{length(rows)} peer envelopes; produced #{length(outputs)} fresh reciprocal envelopes"
)
