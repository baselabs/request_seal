Code.require_file("support/discovery_peer_helper.exs", __DIR__)

defmodule RequestSeal.DiscoveryFetchTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  alias RequestSeal.{Discovery, PublicKey}
  alias RequestSeal.Discovery.{Cache, KeySet, Source}
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

  test "stopping a publisher joins its acceptor and every accepted handler" do
    owner = self()

    p =
      peer(fn _, _ ->
        send(owner, {:blocked_handler, self()})
        receive do: (:release -> :ok)
      end)

    task =
      Task.async(fn ->
        Discovery.fetch(source(p, %{require_signed_directory: false}), [])
      end)

    try do
      assert_receive {:blocked_handler, handler}, 5_000
      acceptor_ref = Process.monitor(p.pid)
      handler_ref = Process.monitor(handler)
      assert Process.alive?(p.pid)
      assert Process.alive?(handler)
      assert :ok = Peer.stop(p)
      assert_receive {:DOWN, ^acceptor_ref, :process, _, _}, 5_000
      assert_receive {:DOWN, ^handler_ref, :process, ^handler, _}, 5_000
      assert {:error, _} = Task.await(task, 5_000)
    after
      Task.shutdown(task, :brutal_kill)
    end
  end

  # A JWKS set legitimately carries keys for algorithms this library does not
  # verify with (encryption keys, unsupported signing names): those keys are
  # skipped, and the rest of the set still resolves.
  test "out-of-registry alg values skip that key instead of rejecting the set" do
    encryption_key = %{
      "kty" => "RSA",
      "n" =>
        "0vx7agoebGcQSuuPi1J6nRC05LiY_gEtBednLWZ3EuFhbcuVF3njD_5Bd5abFxdbFiXorSAkyNBI2dyIvdhWx1w-G2shZ8RlUTz3VBHUeGdZs7pW5z7KiW4Xyzp3fl9EMnI6yq6zUFxLKzhlSr-uQe2o0Cofgzg4mkZJz6qKBXsBBA"
        |> String.slice(0..255),
      "e" => "AQAB",
      "alg" => "RSA-OAEP",
      "use" => "enc"
    }

    unsupported = Map.put(Peer.public_jwk(), "alg", "ES512")
    usable = Peer.public_jwk()
    {:ok, usable_public} = PublicKey.import(usable, :jwk)
    {:ok, usable_kid} = PublicKey.thumbprint(usable_public)

    p =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory([encryption_key, unsupported, usable]), [
          {"Content-Type", "application/http-message-signatures-directory+json"}
        ])
      end)

    assert {:ok, set} = Discovery.fetch(source(p, %{require_signed_directory: false}), [])
    [resolution] = Map.values(set.keys)
    assert resolution.key_id == usable_kid
    assert resolution.asserted_algorithm == nil
    assert {:ok, _} = KeySet.lookup(set, resolution.key_id, ["ed25519"])

    # A well-formed key of an unsupported kty is skipped the same way (RFC
    # 7517 Section 5); leaked private members still reject the whole set
    # loudly, before any skip decision.
    x25519 = %{
      "kty" => "OKP",
      "crv" => "X25519",
      "x" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    }

    leaked = Map.put(usable, "d", Base.url_encode64(:crypto.strong_rand_bytes(32)))

    mixed =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory([encryption_key, unsupported, x25519, usable]), [
          {"Content-Type", "application/http-message-signatures-directory+json"}
        ])
      end)

    assert {:ok, set} = Discovery.fetch(source(mixed, %{require_signed_directory: false}), [])
    [resolution] = Map.values(set.keys)
    assert resolution.key_id == usable_kid

    for body <- [[leaked], [Map.put(Peer.public_jwk(), "d", "canary")]] do
      leaky =
        peer(fn socket, _ ->
          Peer.reply(socket, Peer.directory([usable | body] ++ [Peer.public_jwk()]), [
            {"Content-Type", "application/http-message-signatures-directory+json"}
          ])
        end)

      reason(source(leaky, %{require_signed_directory: false}), :invalid_key_set)
    end

    # A set where every key is skipped resolves to an empty set, and lookups
    # fail closed.
    all_skipped =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory([encryption_key, unsupported]), [
          {"Content-Type", "application/http-message-signatures-directory+json"}
        ])
      end)

    assert {:ok, empty} =
             Discovery.fetch(source(all_skipped, %{require_signed_directory: false}), [])

    assert empty.keys == %{}
    assert :error = KeySet.lookup(empty, usable_kid, ["ed25519"])

    # Skipped keys still count toward the source's max_keys bound.
    limited =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory([encryption_key, unsupported, usable]), [
          {"Content-Type", "application/http-message-signatures-directory+json"}
        ])
      end)

    reason(source(limited, %{require_signed_directory: false, max_keys: 2}), :limit)

    # A :jwks_uri source shares the same key parser and the same skip.
    jwks =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory([encryption_key, usable]), [
          {"Content-Type", "application/json"},
          {"Cache-Control", "max-age=30"}
        ])
      end)

    assert {:ok, set} =
             Discovery.fetch(
               source(jwks, %{type: :jwks_uri, require_signed_directory: false}),
               []
             )

    [resolution] = Map.values(set.keys)
    assert resolution.key_id == usable_kid

    # A malformed (non-string) alg still rejects the whole set.
    malformed = Map.put(Peer.public_jwk(), "alg", 42)

    bad =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory([usable, malformed]), [
          {"Content-Type", "application/http-message-signatures-directory+json"}
        ])
      end)

    reason(source(bad, %{require_signed_directory: false}), :invalid_key_set)
  end

  # RFC 2606 reserves the .invalid TLD: the real resolver returns an
  # authoritative NXDOMAIN, separating a config error from resolver trouble.
  test "NXDOMAIN is a nonretryable config error distinct from resolver failures" do
    {:ok, source} =
      Source.new(%{type: :directory, location: "https://request-seal-nxdomain.invalid"})

    assert {:error, %{reason: :domain_not_found, retryable: false} = error} =
             Discovery.fetch(source, [])

    refute inspect(error) =~ "invalid"
  end

  # RFC 9110 Section 15.4.5: 304 only follows a conditional request this
  # client made; unsolicited 304 rejects like any other unexpected status.
  test "an unsolicited 304 response rejects" do
    p =
      peer(fn socket, _ ->
        Peer.reply(
          socket,
          "",
          [
            {"Content-Type", "application/http-message-signatures-directory+json"}
          ],
          304
        )
      end)

    reason(source(p, %{require_signed_directory: false}), :unexpected_status)
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

  test "fetch and cached lookup require key and proof validity across the interval" do
    start = System.system_time(:second)
    {:ok, proof_key} = PublicKey.import(Peer.public_jwk(), :jwk)
    {:ok, proof_thumbprint} = PublicKey.thumbprint(proof_key)
    {:ok, rsa} = PublicKey.import(File.read!("test/fixtures/crypto/rsa_public.pem"), :pem)
    {:ok, jwk} = PublicKey.export(rsa, :jwk)
    {:ok, thumbprint} = PublicKey.thumbprint(rsa)
    algorithms = ["rsa-pss-sha512"]

    for {nbf, created, reason} <- [
          {start + 1, start, :unknown_key},
          {start, start + 1, :directory_signature_invalid}
        ] do
      leaf = Map.merge(jwk, %{"nbf" => nbf, "exp" => start + 20})
      body = Peer.directory([Peer.public_jwk(), leaf])

      p =
        peer(fn socket, req ->
          Peer.signed(socket, req, body, nil, created: created, expires: start + 20)
        end)

      s = source(p)
      cache = start_supervised!({Cache, clock: fn -> start + 2 end}, id: make_ref())

      assert {:error, %{reason: ^reason}} =
               Cache.resolve(cache, s, thumbprint,
                 algorithms: algorithms,
                 clock: fn -> {start, start + 2} end
               )

      if reason == :unknown_key do
        assert {:ok, entry} = Cache.resolve(cache, s, thumbprint, algorithms: algorithms)
        assert entry.not_before == start + 1
        assert entry.proof_signers == [proof_thumbprint]
        assert_received {:accepted, _}
        refute_received {:accepted, _}
      end

      # Warm a different cache while both the key and proof are valid.
      ready = start_supervised!({Cache, clock: fn -> start + 2 end}, id: make_ref())
      assert {:ok, set} = Cache.refresh(ready, s)
      assert {:ok, entry} = KeySet.lookup_at(set, thumbprint, algorithms, start + 2)
      assert entry.proof_signers == [proof_thumbprint]
      assert entry.not_before == start + 1

      assert {:error, %{reason: :unknown_key}} =
               Cache.resolve(ready, s, thumbprint,
                 algorithms: algorithms,
                 clock: fn -> {start, start + 2} end
               )

      assert :error = KeySet.lookup_at(set, thumbprint, algorithms, {start + 1, start + 20})
      assert {:ok, _} = KeySet.lookup_at(set, thumbprint, algorithms, {start + 1, start + 3})
    end
  end

  test "a legacy resolution establishes no validity before its original fetch" do
    now = System.system_time(:second)
    p = peer(fn socket, req -> Peer.signed(socket, req, Peer.directory(), nil, created: now) end)
    assert {:ok, set} = Discovery.fetch(source(p), clock: fn -> now end)
    [{kid, entry}] = Map.to_list(set.keys)
    persisted = Map.delete(entry, :not_before)
    reconstructed = struct(RequestSeal.Discovery.Resolution, Map.from_struct(persisted))
    assert reconstructed.not_before == nil
    assert entry.not_before == now

    for old <- [persisted, reconstructed] do
      legacy = put_in(set.keys[kid], old)
      assert :error = KeySet.lookup_at(legacy, kid, ["ed25519"], now - 1)
      assert :error = KeySet.lookup_at(legacy, kid, ["ed25519"], {now - 1, now + 1})
      assert {:ok, _} = KeySet.lookup_at(legacy, kid, ["ed25519"], now)
      assert {:ok, _} = KeySet.lookup_at(legacy, kid, ["ed25519"], {now, now + 1})
    end
  end

  test "proofs and body lookup refuse a partially overlapping signer in either order" do
    now = System.system_time(:second)
    interval = {now, now + 10}
    signer = Peer.public_jwk()
    {:ok, signer_key} = PublicKey.import(signer, :jwk)
    {:ok, signer_id} = PublicKey.thumbprint(signer_key)
    {:ok, leaf} = PublicKey.import(File.read!("test/fixtures/crypto/rsa_public.pem"), :pem)
    {:ok, leaf_jwk} = PublicKey.export(leaf, :jwk)
    {:ok, leaf_id} = PublicKey.thumbprint(leaf)

    for offset <- [5, 11], reversed? <- [false, true] do
      future = Map.put(signer, "nbf", now + offset)
      signers = if reversed?, do: [future, signer], else: [signer, future]
      body = Peer.directory([leaf_jwk | signers])

      p =
        peer(fn socket, request ->
          Peer.signed(socket, request, body, nil, created: now, expires: now + 60)
        end)

      s = source(p)
      unsigned = %{s | require_signed_directory: false}

      if offset == 5 do
        assert {:error, %{reason: :directory_signature_invalid}} =
                 Discovery.fetch(s, clock: fn -> interval end)

        assert {:error, %{reason: :invalid_key_set}} =
                 Discovery.parse_body(body, unsigned, interval)
      else
        assert {:ok, set} = Discovery.fetch(s, clock: fn -> interval end)

        assert {:ok, %{proof_signers: [^signer_id]}} =
                 KeySet.lookup_at(set, leaf_id, ["rsa-pss-sha512"], interval)

        assert {:ok, %{^signer_id => %{not_before: 0}}} =
                 Discovery.parse_body(body, unsigned, interval)
      end
    end
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
          Map.put(Peer.public_jwk(), "alg", 42),
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

    # RFC 7517 JWKS sources assert "alg" with standard JOSE names; either
    # spelling normalizes once at import to the standard JOSE name.
    for asserted <- ["ed25519", "EdDSA"] do
      jwk = Map.put(Peer.public_jwk(), "alg", asserted)

      p =
        peer(fn socket, _ ->
          Peer.reply(socket, Peer.directory([jwk]), [
            {"Content-Type", "application/http-message-signatures-directory+json"}
          ])
        end)

      assert {:ok, set} = Discovery.fetch(source(p, %{require_signed_directory: false}), [])
      [resolution] = Map.values(set.keys)
      assert resolution.key.algorithm == "EdDSA"
      assert resolution.asserted_algorithm == "EdDSA"

      # Either allowlist spelling selects the same key, and the tuple spelling
      # selects PS256 too when the key fits it.
      for allowlist <- [["ed25519"], [{:jws, "EdDSA"}]] do
        assert {:ok, selected} = KeySet.lookup(set, resolution.key_id, allowlist)
        assert selected.algorithm in ["ed25519", {:jws, "EdDSA"}]
        assert selected.asserted_algorithm == "EdDSA"
      end
    end

    # A JOSE-tuple allowlist also matches an HTTP-asserted set.
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
    assert resolution.asserted_algorithm == "EdDSA"
    assert {:ok, selected} = KeySet.lookup(set, resolution.key_id, [{:jws, "EdDSA"}])
    assert selected.asserted_algorithm == "EdDSA"
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
      {:ok, key} = PublicKey.import(Peer.public_jwk(), :jwk)
      {:ok, kid} = PublicKey.thumbprint(key)
      assert :error = KeySet.lookup(set, kid, ["ed25519"])
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

    # One pinned instant: no response delay, so the span is exactly max-age.
    now = System.system_time(:second)

    assert {:ok, set} =
             Discovery.fetch(
               source(p, %{type: :cimd, location: "https://localhost:#{p.port}/card"}),
               clock: fn -> now end
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

  test "nested CIMD responses never expose or replay a composite validator" do
    owner = self()
    media = {"Content-Type", "application/json"}

    for mode <- [:distinct, :outer_only, :redirected] do
      p =
        peer(fn socket, request ->
          [_, path] = Regex.run(~r/\AGET (\S+) /, request)
          [_, host] = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, request)
          send(owner, {:cimd_request, path, String.contains?(request, "If-None-Match:")})
          root = "https://" <> host

          case path do
            "/card" ->
              body = :json.encode(%{"client_id" => root <> path, "jwks_uri" => root <> "/keys"})
              Peer.reply(socket, IO.iodata_to_binary(body), [media, {"ETag", ~s("card")}])

            "/keys" when mode == :redirected ->
              Peer.reply(socket, "", [{"Location", "/published"}, {"ETag", ~s("hop")}], 302)

            _ ->
              fields = if mode == :outer_only, do: [media], else: [media, {"ETag", ~s("keys")}]
              Peer.reply(socket, Peer.directory(), fields)
          end
        end)

      location = "https://localhost:#{p.port}/card"
      s = source(p, %{type: :cimd, location: location, max_redirects: 1})
      cache = start_supervised!({Cache, clock: fn -> 100 end}, id: make_ref())

      for _ <- 1..2 do
        assert {:ok, %{etag: nil, validator_uri: nil, freshness_fields: nil}} =
                 Cache.refresh(cache, s)

        assert_receive {:cimd_request, "/card", false}
        assert_receive {:cimd_request, "/keys", false}
        if mode == :redirected, do: assert_received({:cimd_request, "/published", false})
      end
    end
  end

  test "unresponsive request and response clocks obey the fetch timeout" do
    p = peer(&unsigned/2)
    s = source(p, %{require_signed_directory: false})

    for blocked_sample <- [1, 2] do
      calls = :atomics.new(1, [])

      clock = fn ->
        if :atomics.add_get(calls, 1, 1) == blocked_sample, do: Process.sleep(:infinity)
        100
      end

      assert {:error, %{reason: :deadline_exceeded}} =
               Discovery.fetch(s, timeout: 1_000, clock: clock)

      assert :atomics.get(calls, 1) == blocked_sample
    end
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
    monitor = Process.monitor(caller)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^monitor, :process, ^caller, :killed}, 1_000
    assert_receive {:closed, {:error, :closed}}, 1_000
  end
end
