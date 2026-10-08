Code.require_file("support/discovery_peer_helper.exs", __DIR__)

defmodule RequestSeal.DiscoveryFetchTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  alias RequestSeal.{Discovery, PublicKey}
  alias RequestSeal.Discovery.{Source, KeySet}
  alias RequestSeal.DiscoveryPeer, as: Peer

  defp source(peer, attrs \\ %{}) do
    defaults = %{
      type: :directory,
      location: "https://localhost:#{peer.port}",
      cacerts: peer.cacerts,
      permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]
    }

    {:ok, source} = Source.new(Map.merge(defaults, attrs))
    source
  end

  defp peer(fun, hostname \\ ~c"localhost") do
    p = Peer.start(fun, hostname)
    on_exit(fn -> Peer.stop(p) end)
    p
  end

  defp unsigned(socket, _),
    do:
      Peer.reply(socket, Peer.directory(), [
        {"Content-Type", "application/http-message-signatures-directory+json"},
        {"Cache-Control", "max-age=30"}
      ])

  defp reason(source, expected, opts \\ []) do
    assert {:error, %{reason: ^expected} = error} = Discovery.fetch(source, opts)
    refute inspect(error) =~ "localhost"
    refute inspect(error) =~ "canary"
  end

  test "real TLS directory proof binds key, body and authority with a resolver bridge" do
    p = peer(fn socket, req -> Peer.signed(socket, req, Peer.directory()) end)
    s = source(p)
    assert {:ok, set} = Discovery.fetch(s, [])
    assert set.proof == :signed
    assert set.origin == "https://localhost:#{p.port}"
    assert set.expires_at > set.fetched_at
    assert map_size(set.keys) == 1
    {:ok, public} = PublicKey.import(Peer.public_jwk(), :jwk)
    {:ok, kid} = PublicKey.thumbprint(public)
    assert {:ok, resolution} = KeySet.lookup(set, kid, ["ed25519"])
    assert resolution.thumbprint == kid
    resolver = Discovery.resolver(set, algorithms: ["ed25519"])

    assert {:ok, %{key: ^public, algorithm: "ed25519"}} =
             resolver.(%{keyid: kid, label: "ignored", tag: "ignored"})

    assert :error = resolver.(%{keyid: s.location})
    assert :error = KeySet.lookup(set, kid, ["rsa-pss-sha512"])
    refute inspect(set) =~ "localhost"
    refute inspect(resolution) =~ kid
  end

  test "directory proof labels use the configured bound beyond the generic policy default" do
    p =
      peer(fn socket, req ->
        body = Peer.directory()
        messages = for n <- 1..17, do: Peer.signed_message(req, body, nil, label: "directory#{n}")

        common =
          hd(messages).fields
          |> Enum.reject(&(String.downcase(&1.name) in ["signature", "signature-input"]))

        signatures =
          Enum.flat_map(messages, fn m ->
            Enum.filter(m.fields, &(String.downcase(&1.name) in ["signature", "signature-input"]))
          end)

        Peer.reply(socket, body, Enum.map(common ++ signatures, &{&1.name, &1.value}))
      end)

    assert {:ok, %{proof: :signed}} = Discovery.fetch(source(p), [])
  end

  test "directory proof can cover the actual related request Host field" do
    p =
      peer(fn socket, req ->
        Peer.signed(socket, req, Peer.directory(), nil,
          components: "\"@authority\";req \"content-digest\" \"host\";req"
        )
      end)

    assert {:ok, %{proof: :signed}} = Discovery.fetch(source(p), [])
  end

  test "RSA directory proof allows each key-compatible HTTP algorithm without sender selection" do
    {:ok, rsa} = PublicKey.import(File.read!("test/fixtures/crypto/rsa_public.pem"), :pem)
    {:ok, jwk} = PublicKey.export(rsa, :jwk)

    for algorithm <- ["rsa-v1_5-sha256", "rsa-pss-sha512"] do
      p =
        peer(fn socket, req ->
          Peer.signed(socket, req, Peer.directory([jwk]), nil, algorithm: algorithm)
        end)

      assert {:ok, %{proof: :signed}} = Discovery.fetch(source(p), [])
    end
  end

  test "gzip possession proof authenticates encoded HTTP content, then parses decoded JSON" do
    body = :zlib.gzip(Peer.directory())
    p = peer(fn socket, req -> Peer.signed(socket, req, body, nil, gzip: true) end)
    assert {:ok, %{proof: :signed}} = Discovery.fetch(source(p), [])
  end

  for encoding <- ["GZIP", "Gzip", " gzip ", "x-gzip", " X-GZip "] do
    @tag finding: :f1
    test "gzip coding #{inspect(encoding)} preserves the encoded possession proof" do
      encoding = unquote(encoding)
      body = :zlib.gzip(Peer.directory())

      p =
        peer(fn socket, req ->
          message = Peer.signed_message(req, body)

          headers = [
            {"Content-Encoding", encoding} | Enum.map(message.fields, &{&1.name, &1.value})
          ]

          Peer.reply(socket, body, headers)
        end)

      assert {:ok, %{proof: :signed}} = Discovery.fetch(source(p), [])
    end
  end

  @tag finding: :f1
  test "unknown and stacked content codings fail closed" do
    for encoding <- ["br", "X-Unknown", "gzip, identity", "gzip, gzip"] do
      p =
        peer(fn socket, req ->
          body = :zlib.gzip(Peer.directory())
          message = Peer.signed_message(req, body)

          headers = [
            {"Content-Encoding", encoding} | Enum.map(message.fields, &{&1.name, &1.value})
          ]

          Peer.reply(socket, body, headers)
        end)

      reason(source(p), :invalid_response)
    end
  end

  @tag finding: :f3
  test "directory proof ignores unrelated signature dictionary members" do
    for label <- ["directory", "possession"],
        extra <- [
          [{"Signature", "other=:AAAA:"}],
          [{"Signature-Input", "other=(\"@status\");tag=\"unrelated\""}],
          [
            {"Signature-Input", "other=(\"@status\");tag=\"unrelated\""},
            {"Signature", "other=:AAAA:"}
          ]
        ] do
      p =
        peer(fn socket, req ->
          body = Peer.directory()
          # The expected member can use a different label: its keyid names a directory key.
          message = Peer.signed_message(req, body, nil, label: label)
          Peer.reply(socket, body, Enum.map(message.fields, &{&1.name, &1.value}) ++ extra)
        end)

      assert {:ok, %{proof: :signed}} = Discovery.fetch(source(p), [])
    end
  end

  @tag finding: :f3
  test "missing or invalid expected directory members fail closed despite unrelated labels" do
    for mutation <- [:missing_signature, :invalid_signature, :missing_input, :wrong_tag] do
      p =
        peer(fn socket, req ->
          body = Peer.directory()
          parameters = if mutation == :wrong_tag, do: [tag: "unrelated"], else: []
          message = Peer.signed_message(req, body, nil, parameters)

          headers =
            Enum.flat_map(message.fields, fn field ->
              case {String.downcase(field.name), mutation} do
                {"signature", :missing_signature} -> []
                {"signature", :invalid_signature} -> [{field.name, "directory=:AAAA:"}]
                {"signature-input", :missing_input} -> []
                _ -> [{field.name, field.value}]
              end
            end)

          Peer.reply(
            socket,
            body,
            headers ++
              [
                {"Signature-Input", "other=(\"@status\");tag=\"unrelated\""},
                {"Signature", "other=:AAAA:"}
              ]
          )
        end)

      reason(source(p), :directory_signature_invalid)
    end
  end

  @tag finding: :f2
  test "CIMD origin normalization permits equivalent JWKS origins but preserves exact client ID" do
    p =
      peer(fn socket, req ->
        host = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, req) |> Enum.at(1)
        [_, port] = String.split(host, ":")

        if String.starts_with?(req, "GET /card ") do
          doc = %{
            "client_id" => "https://#{host}/card",
            "jwks_uri" => "HTTPS://LOCALHOST.:#{port}/keys"
          }

          Peer.reply(socket, :json.encode(doc) |> IO.iodata_to_binary(), [
            {"Content-Type", "application/json"}
          ])
        else
          Peer.reply(socket, Peer.directory(), [{"Content-Type", "application/jwk-set+json"}])
        end
      end)

    s = source(p, %{type: :cimd, location: "https://localhost:#{p.port}/card"})
    assert {:ok, %{origin: origin}} = Discovery.fetch(s, [])
    assert origin == "https://localhost:#{p.port}"

    spelling = "HTTPS://LOCALHOST.:#{p.port}/card"
    differently_spelled = source(p, %{type: :cimd, location: spelling})
    assert differently_spelled.location == spelling
    reason(differently_spelled, :client_id_mismatch)
  end

  @tag finding: :f2
  test "CIMD origin normalization retains literal IP, different host and HTTP denials" do
    for target <- [
          "https://127.0.0.1/keys",
          "https://[::1]/keys",
          "https://other.canary/keys",
          "http://localhost/keys"
        ] do
      p =
        peer(fn socket, req ->
          host = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, req) |> Enum.at(1)
          doc = %{"client_id" => "https://#{host}/card", "jwks_uri" => target}

          Peer.reply(socket, :json.encode(doc) |> IO.iodata_to_binary(), [
            {"Content-Type", "application/json"}
          ])
        end)

      expected =
        if String.starts_with?(target, "http:"), do: :invalid_source, else: :redirect_denied

      reason(source(p, %{type: :cimd, location: "https://localhost:#{p.port}/card"}), expected)
    end
  end

  test "unsigned directories require an explicit relaxation" do
    p = peer(&unsigned/2)
    reason(source(p), :directory_unsigned)

    assert {:ok, %{proof: :unsigned}} =
             Discovery.fetch(source(p, %{require_signed_directory: false}), [])
  end

  test "signed proof rejects another authority, future creation, stale expiration and wrong tag" do
    for {authority, params} <- [
          {"different.canary", []},
          {nil, [created: System.system_time(:second) + 60]},
          {nil, [expires: System.system_time(:second) - 1]},
          {nil, [tag: "canary"]}
        ] do
      p =
        peer(fn socket, req -> Peer.signed(socket, req, Peer.directory(), authority, params) end)

      reason(source(p), :directory_signature_invalid)
    end
  end

  test "thumbprint IDs and HTTP algorithm restrictions reject malformed sets" do
    for jwk <- [
          Map.put(Peer.public_jwk(), "kid", "aPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"),
          Map.put(Peer.public_jwk(), "alg", "EdDSA"),
          Map.put(Peer.public_jwk(), "nbf", "tomorrow"),
          Map.put(Peer.public_jwk(), "d", "canary")
        ] do
      p =
        peer(fn socket, _ ->
          Peer.reply(socket, Peer.directory([jwk]), [
            {"Content-Type", "application/http-message-signatures-directory+json"}
          ])
        end)

      reason(source(p, %{require_signed_directory: false}), :invalid_key_set)
    end

    jwk = Map.put(Peer.public_jwk(), "alg", "ed25519")

    p =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory([jwk]), [
          {"Content-Type", "application/http-message-signatures-directory+json"}
        ])
      end)

    assert {:ok, set} = Discovery.fetch(source(p, %{require_signed_directory: false}), [])
    [resolution] = Map.values(set.keys)
    assert resolution.key.algorithm == "EdDSA"
    assert resolution.asserted_algorithm == "ed25519"
  end

  test "source revocation excludes a still-published key from fetched snapshots" do
    p = peer(&unsigned/2)
    {:ok, key} = PublicKey.import(Peer.public_jwk(), :jwk)
    {:ok, kid} = PublicKey.thumbprint(key)

    assert {:ok, %{keys: keys}} =
             Discovery.fetch(source(p, %{require_signed_directory: false, revoked: [kid]}), [])

    refute Map.has_key?(keys, kid)
  end

  test "key validity and encryption-only restrictions never resolve" do
    for extra <- [
          %{"use" => "enc"},
          %{"key_ops" => ["sign"]},
          %{"nbf" => System.system_time(:second) + 60},
          %{"exp" => System.system_time(:second) - 1}
        ] do
      p =
        peer(fn socket, _ ->
          Peer.reply(socket, Peer.directory([Map.merge(Peer.public_jwk(), extra)]), [
            {"Content-Type", "application/http-message-signatures-directory+json"}
          ])
        end)

      assert {:ok, set} = Discovery.fetch(source(p, %{require_signed_directory: false}), [])
      assert set.keys == %{}
    end
  end

  test "JWKS and CIMD use configured locations and exact client IDs" do
    p =
      peer(fn socket, req ->
        host = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, req) |> Enum.at(1)

        if String.starts_with?(req, "GET /card ") do
          body =
            :json.encode(%{
              "client_id" => "https://#{host}/card",
              "jwks" => %{"keys" => [Peer.public_jwk()]}
            })
            |> IO.iodata_to_binary()

          Peer.reply(socket, body, [{"Content-Type", "application/json;charset=utf-8"}])
        else
          Peer.reply(socket, Peer.directory(), [{"Content-Type", "application/jwk-set+json"}])
        end
      end)

    assert {:ok, %{proof: :not_applicable}} =
             Discovery.fetch(
               source(p, %{type: :jwks_uri, location: "https://localhost:#{p.port}/keys"}),
               []
             )

    assert {:ok, %{proof: :not_applicable}} =
             Discovery.fetch(
               source(p, %{type: :cimd, location: "https://localhost:#{p.port}/card"}),
               []
             )

    for doc <- [
          %{"client_id" => "https://localhost:443/card", "jwks" => %{"keys" => []}},
          %{"client_id" => "https://localhost/card-drift", "jwks" => %{"keys" => []}}
        ] do
      p =
        peer(fn socket, _ ->
          Peer.reply(socket, :json.encode(doc) |> IO.iodata_to_binary(), [
            {"Content-Type", "application/json"}
          ])
        end)

      reason(
        source(p, %{type: :cimd, location: "https://localhost:#{p.port}/card"}),
        :client_id_mismatch
      )
    end

    p =
      peer(fn socket, req ->
        host = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, req) |> Enum.at(1)

        doc = %{
          "client_id" => "https://#{host}/card",
          "jwks" => %{"keys" => []},
          "jwks_uri" => "https://#{host}/keys"
        }

        Peer.reply(socket, :json.encode(doc) |> IO.iodata_to_binary(), [
          {"Content-Type", "application/json"}
        ])
      end)

    reason(
      source(p, %{type: :cimd, location: "https://localhost:#{p.port}/card"}),
      :ambiguous_key_source
    )
  end

  test "CIMD nested JWKS stays within the configured origin and shares freshness bounds" do
    p =
      peer(fn socket, req ->
        host = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, req) |> Enum.at(1)

        if String.starts_with?(req, "GET /card ") do
          doc = %{"client_id" => "https://#{host}/card", "jwks_uri" => "https://#{host}/keys"}

          Peer.reply(socket, :json.encode(doc) |> IO.iodata_to_binary(), [
            {"Content-Type", "application/json"},
            {"Cache-Control", "max-age=60"}
          ])
        else
          Peer.reply(socket, Peer.directory(), [
            {"Content-Type", "application/jwk-set+json"},
            {"Cache-Control", "max-age=10"}
          ])
        end
      end)

    assert {:ok, set} =
             Discovery.fetch(
               source(p, %{type: :cimd, location: "https://localhost:#{p.port}/card"}),
               []
             )

    assert set.expires_at - set.fetched_at == 10
    [resolution] = Map.values(set.keys)
    assert resolution.source_type == :cimd
    assert resolution.location == "https://localhost:#{p.port}/keys"

    p =
      peer(fn socket, req ->
        host = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, req) |> Enum.at(1)
        doc = %{"client_id" => "https://#{host}/card", "jwks_uri" => "https://other.canary/keys"}

        Peer.reply(socket, :json.encode(doc) |> IO.iodata_to_binary(), [
          {"Content-Type", "application/json"}
        ])
      end)

    reason(
      source(p, %{type: :cimd, location: "https://localhost:#{p.port}/card"}),
      :redirect_denied
    )
  end

  test "private DNS results reject without an exact permit and TLS trusts the configured hostname" do
    p = peer(&unsigned/2)
    reason(source(p, %{permitted_addresses: []}), :address_denied)
    reason(source(p, %{permitted_addresses: [{127, 0, 0, 1}]}), :address_denied)
    wrong = peer(&unsigned/2, ~c"different.canary")
    logs = capture_log(fn -> reason(source(wrong), :tls_failed) end)
    refute logs =~ "canary"
    refute logs =~ "localhost"
    alien = peer(&unsigned/2)
    reason(source(p, %{cacerts: alien.cacerts}), :tls_failed)
    Peer.stop(p)
    reason(source(p), :connect_failed)
  end

  test "deadline and caller cancellation close the owned TLS socket" do
    owner = self()

    p =
      peer(fn socket, _ ->
        send(owner, {:connected, self()})
        send(owner, {:closed, :ssl.recv(socket, 0, 5_000)})
      end)

    started = System.monotonic_time(:millisecond)
    reason(source(p), :deadline_exceeded, timeout: 100)
    assert System.monotonic_time(:millisecond) - started < 1_000
    assert_receive {:closed, {:error, :closed}}, 1_000
    caller = spawn(fn -> Discovery.fetch(source(p), timeout: 5_000) end)
    assert_receive {:connected, _}, 1_000
    # Drain the first connection notification before waiting for the second.
    assert_receive {:connected, _}, 1_000
    Process.exit(caller, :kill)
    assert_receive {:closed, {:error, :closed}}, 1_000
  end
end
