# Isolated independent producer/consumer, pinned by version and Hex checksum (mix.lock). No runtime dependency.
Mix.install([{:jose, "== 1.11.13"}], lockfile: Path.join(__DIR__, "mix.lock"))
:jose.json_module(:jose_json_otp)
[mode, input, output] = System.argv()
decode = fn value -> Base.url_decode64!(value, padding: false) end
encode = fn value -> Base.url_encode64(value, padding: false) end

if mode == "make" do
  configurations =
    for curve <- [:secp256r1, :X25519], alg <- ~w(ECDH-ES ECDH-ES+A256KW), do: {alg, curve}

  configurations =
    configurations ++ Enum.map(~w(A128KW A256KW A128GCMKW A256GCMKW dir), &{&1, nil})

  rows =
    for {alg, curve} <- configurations, enc <- ~w(A128GCM A256GCM) do
      key =
        cond do
          curve == :secp256r1 ->
            JOSE.JWK.generate_key({:ec, :secp256r1})

          curve == :X25519 ->
            JOSE.JWK.generate_key({:okp, :X25519})

          true ->
            width =
              if String.starts_with?(alg, "A128") or (alg == "dir" and enc == "A128GCM"),
                do: 16,
                else: 32

            JOSE.JWK.from_oct(:crypto.strong_rand_bytes(width))
        end

      {_, jwk} = JOSE.JWK.to_map(key)
      plaintext = :crypto.strong_rand_bytes(53)

      encryption_key =
        if curve do
          ephemeral =
            JOSE.JWK.generate_key(
              if(curve == :X25519, do: {:okp, :X25519}, else: {:ec, :secp256r1})
            )

          {JOSE.JWK.to_public(key), ephemeral}
        else
          key
        end

      {_, token} =
        JOSE.JWE.block_encrypt(encryption_key, plaintext, %{"alg" => alg, "enc" => enc})
        |> JOSE.JWE.compact()

      {^plaintext, _} = JOSE.JWE.block_decrypt(key, token)

      %{
        "provider" => "erlang-jose-1.11.13",
        "alg" => alg,
        "enc" => enc,
        "key" => jwk,
        "token" => token,
        "plaintext" => encode.(plaintext)
      }
    end

  File.write!(output, :json.encode(rows))
else
  rows = :json.decode(File.read!(input))

  for row <- rows do
    expected = decode.(row["plaintext"])
    {^expected, _} = JOSE.JWE.block_decrypt(JOSE.JWK.from_map(row["key"]), row["token"])
  end

  IO.puts("PASS Erlang jose 1.11.13 decrypted #{length(rows)} RequestSeal envelopes")
end
