Code.require_file("../benchmark.exs", __DIR__)

alias RequestSeal.Custody
alias RequestSeal.JOSE.JWE

[mode, output] = System.argv()

report =
  RequestSeal.ReleaseGateBenchmark.run(mode, fn kek, tokens, single, object ->
    {:ok, handle} = Custody.Local.new({:jwe, "A256GCMKW"}, {:aes, kek})

    policy = %{
      algorithms: ["A256GCMKW"],
      encryption: ["A256GCM"],
      max_plaintext: 16_384,
      timeout: 5_000,
      resolve_timeout: 1_000,
      unwrap_timeout: 1_000,
      protected: %{expected: %{}, permitted: ["cty", "padding"]},
      key_resolver: fn _ -> {:ok, %{algorithm: "A256GCMKW", key: handle}} end
    }

    batch_policy =
      %{policy | protected: %{permitted: ["cty", "padding"]}}
      |> Map.merge(%{
        max_tokens: 100,
        max_total_input: 1_000_000,
        max_total_plaintext: 1_000_000,
        content: :object
      })

    items = Enum.map(tokens, &%{token: &1, expected: %{}})
    expected = %{object | "archived_at" => nil, "parent" => nil}

    page = fn ->
      {:ok, results} = JWE.decrypt_many(items, batch_policy)
      results
    end

    valid_page? = fn results ->
      length(results) == 100 and
        Enum.all?(results, fn
          {:ok, result} -> result.object == expected
          _ -> false
        end)
    end

    one = fn ->
      {:ok, result} = JWE.decrypt(single, policy)
      result.plaintext
    end

    {page, one, valid_page?, fn -> Custody.release(handle) end}
  end)

File.write!(output, :json.encode(report))
