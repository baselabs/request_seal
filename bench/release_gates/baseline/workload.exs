Code.require_file("../benchmark.exs", __DIR__)

alias RequestSeal.JOSE.{JWE, KeyManagement}

[mode, output] = System.argv()

report =
  RequestSeal.ReleaseGateBenchmark.run(mode, fn kek, tokens, single, object ->
    unwrap = fn encrypted, header ->
      KeyManagement.unwrap("A256GCMKW", encrypted, header, {:aes, kek})
    end

    policy = %{
      algorithms: ["A256GCMKW"],
      encryption: ["A256GCM"],
      max_plaintext: 16_384,
      timeout: 5_000,
      key_resolver: fn _ -> {:ok, %{algorithm: "A256GCMKW", unwrap: unwrap}} end
    }

    open = fn token ->
      {:ok, result} = JWE.decrypt(token, policy)
      result.plaintext
    end

    page = fn ->
      tokens
      |> Task.async_stream(fn token -> :json.decode(open.(token)) end, ordered: true)
      |> Enum.to_list()
    end

    valid_page? = fn results ->
      length(results) == 100 and Enum.all?(results, &(&1 == {:ok, object}))
    end

    {page, fn -> open.(single) end, valid_page?, fn -> :ok end}
  end)

File.write!(output, :json.encode(report))
