Code.require_file("support/discovery_peer_helper.exs", __DIR__)

defmodule RequestSeal.DiscoveryTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{PublicKey, Discovery}
  alias RequestSeal.Discovery.{Source, Address}

  test "published RFC thumbprints and RSA-PSS identity" do
    rsa =
      :json.decode(File.read!("test/fixtures/custody/rfc7517.json"))["keys"]
      |> Enum.at(1)
      |> Map.take(~w(kty n e))

    {:ok, key} = PublicKey.import(rsa, :jwk)
    assert PublicKey.thumbprint(key) == {:ok, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"}
    {:rsa, n, e} = key.material
    {:ok, pss} = PublicKey.import({:rsa_pss, n, e}, :raw)
    assert PublicKey.thumbprint(pss) == PublicKey.thumbprint(key)
    okp = :json.decode(File.read!("test/fixtures/custody/rfc8037.json")) |> Map.delete("d")
    {:ok, key} = PublicKey.import(okp, :jwk)
    assert PublicKey.thumbprint(key) == {:ok, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"}

    {:ok, key} =
      PublicKey.import(
        %{
          "kty" => "OKP",
          "crv" => "Ed25519",
          "x" => "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
        },
        :jwk
      )

    assert PublicKey.thumbprint(key) == {:ok, "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U"}
    assert {:error, _} = PublicKey.thumbprint(%{key | material: {:ed25519, <<0::256>>}})
  end

  test "EC thumbprints use an independent local construction and metadata does not change identity" do
    {:ok, key} = PublicKey.import(File.read!("test/fixtures/crypto/p256_public.pem"), :pem)
    {:ok, jwk} = PublicKey.export(key, :jwk)
    bytes = :json.encode(Map.take(jwk, ~w(crv kty x y))) |> IO.iodata_to_binary()

    script =
      "import sys,json,hashlib,base64;print(base64.urlsafe_b64encode(hashlib.sha256(json.dumps(json.loads(sys.argv[1]),sort_keys=True,separators=(',',':')).encode()).digest()).decode().rstrip('='))"

    {expected, 0} = System.cmd("python3", ["-c", script, bytes])
    assert PublicKey.thumbprint(key) == {:ok, String.trim(expected)}

    {:ok, restricted} =
      PublicKey.import(Map.merge(jwk, %{"use" => "enc", "key_ops" => ["encrypt"]}), :jwk)

    assert PublicKey.thumbprint(restricted) == PublicKey.thumbprint(key)
  end

  test "caller sources are HTTPS, bounded and redacted" do
    assert {:ok, source} = Source.new(%{type: :directory, location: "https://example.com"})
    assert source.location == "https://example.com/.well-known/http-message-signatures-directory"
    assert source.require_signed_directory
    refute inspect(source) =~ "example.com"

    for attrs <- [
          %{type: :unknown, location: "https://example.com"},
          %{type: :jwks_uri, location: "http://example.com/keys"},
          %{type: :cimd, location: "https://user@example.com/keys"},
          %{type: :cimd, location: "https://example.com/a/../keys"},
          %{type: :cimd, location: "https://example.com/%2e/keys"},
          %{type: :cimd, location: "https://example.com/#secret"},
          %{type: :cimd, location: "https://example.com"},
          %{type: :directory, location: "https://example.com", max_redirects: 4},
          %{type: :directory, location: "https://example.com", timeout: 0},
          %{type: :directory, location: "https://example.com", unknown: true}
        ] do
      assert {:error, %{reason: :invalid_source}} = Source.new(attrs)
    end

    assert {:error, %{reason: :invalid_source}} =
             Source.new(type: :directory, type: :directory, location: "https://example.com")

    assert {:error, %{reason: :invalid_options}} = Discovery.fetch(source, timeout: 0)
    assert {:error, %{reason: :invalid_source}} = Discovery.fetch(%{source | max_keys: 257}, [])
  end

  test "directory proof sources require thumbprint key IDs" do
    attrs = %{type: :directory, location: "https://example.com", key_id: :directory}
    assert {:error, %{reason: :invalid_source}} = Source.new(attrs)

    {:ok, source} = Source.new(Map.delete(attrs, :key_id))

    assert catch_throw(Source.validate!(%{source | key_id: :directory})) ==
             {:discovery_error, :invalid_source}

    for type <- [:jwks_uri, :cimd] do
      assert {:ok, _} =
               Source.new(%{type: type, location: "https://example.com/keys", key_id: :directory})
    end
  end

  @tag finding: :f2
  test "origin normalization drops only the HTTPS default port and one trailing host dot" do
    for location <- ["HTTPS://EXAMPLE.COM:443/card", "https://example.com./card"] do
      assert Source.origin(Source.url!(location)) == "https://example.com"
      assert {:ok, source} = Source.new(%{type: :cimd, location: location})
      assert source.location == location
    end

    assert Source.origin(Source.url!("https://EXAMPLE.COM.:8443/card")) ==
             "https://example.com:8443"

    assert Source.origin(Source.url!("https://example.com../card")) == "https://example.com."
    assert Source.origin(Source.url!("https://[::1]:443/card")) == "https://[::1]"
  end

  test "all source and fetch option bounds reject unknown or excessive configuration" do
    base = %{type: :jwks_uri, location: "https://example.com/keys"}

    for {key, value} <- [
          {:max_bytes, 0},
          {:max_bytes, 1_048_577},
          {:max_decoded_bytes, 0},
          {:max_decoded_bytes, 1_048_577},
          {:max_keys, 0},
          {:max_keys, 257},
          {:timeout, 300_001},
          {:max_redirects, -1},
          {:min_ttl, -1},
          {:max_ttl, 604_801},
          {:redirect_scope, :all},
          {:require_signed_directory, :yes},
          {:permitted_addresses, [{256, 0, 0, 0}]},
          {:permitted_addresses, List.duplicate({127, 0, 0, 1}, 17)},
          {:revoked, ["canary"]},
          {:revoked, List.duplicate("kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k", 257)},
          {:cacerts, []},
          {:cacerts, [""]},
          {:cacerts, List.duplicate("DER", 33)},
          {:location, "https://example.com/" <> String.duplicate("x", 2048)},
          {:location, "https://example.com:443:80/keys"},
          {:location, "https://example.com/%xz"},
          {:location, "https://example.com/\\keys"},
          {:location, "https://example.com/%0a"}
        ] do
      assert {:error, %{reason: :invalid_source}} = Source.new(Map.put(base, key, value)),
             inspect(key)
    end

    assert {:error, %{reason: :invalid_source}} =
             Source.new(Map.merge(base, %{min_ttl: 20, max_ttl: 10}))

    assert {:ok, s} = Source.new(base)

    for opts <- [
          [unknown: true],
          [timeout: 10, timeout: 10],
          [clock: nil],
          [clock: fn -> -1 end],
          [clock: fn -> raise "canary" end]
        ] do
      assert {:error, %{reason: :invalid_options}} = Discovery.fetch(s, opts)
    end

    assert :error = Discovery.resolver(:invalid, algorithms: ["unknown"]).(%{keyid: "canary"})
  end

  @tag fix2: true
  test "negative freshness is bounded to five minutes at construction and fetch" do
    base = %{type: :jwks_uri, location: "https://example.com/keys"}

    for ttl <- [0, 30, 300] do
      assert {:ok, source} = Source.new(Map.put(base, :negative_ttl, ttl))
      assert source.negative_ttl == ttl
    end

    {:ok, source} = Source.new(base)

    for ttl <- [301, 604_800, 604_801, -1, 1.0, nil] do
      assert {:error, %{reason: :invalid_options, retryable: false}} =
               Source.new(Map.put(base, :negative_ttl, ttl))

      assert {:error, %{reason: :invalid_options, retryable: false}} =
               Discovery.fetch(%{source | negative_ttl: ttl})
    end
  end

  test "without a caller-started SSL application discovery fails safely" do
    script =
      "Application.ensure_all_started(:request_seal); {:ok,s}=RequestSeal.Discovery.Source.new(%{type: :directory,location: \"https://example.com\"}); IO.inspect(RequestSeal.Discovery.fetch(s,[]))"

    {output, status} =
      System.cmd(
        "elixir",
        ["-pa", Path.expand("_build/test/lib/request_seal/ebin"), "-e", script],
        stderr_to_stdout: true
      )

    assert status == 0, output
    assert output =~ "reason: :transport_unavailable"
    refute output =~ "example.com"
  end

  test "special-purpose ranges and embedded IPv4 are denied unless explicitly permitted" do
    for addr <-
          ~w(0.1.2.3 10.0.0.1 100.64.0.1 127.0.0.1 169.254.1.1 172.16.0.1 192.0.0.9 192.0.2.1 192.88.99.1 192.168.0.1 198.18.0.1 198.51.100.1 203.0.113.1 224.0.0.1 240.0.0.1 :: ::1 ::ffff:127.0.0.1 64:ff9b::7f00:1 64:ff9b:1::1 100::1 100:0:0:1::1 2001:2::1 2001:db8::1 2002:7f00:1::1 3fff::1 5f00::1 fc00::1 fe80::1 ff00::1) do
      {:ok, ip} = :inet.parse_address(String.to_charlist(addr))
      refute Address.allowed?(ip, []), addr
      assert Address.allowed?(ip, [ip]), addr
    end

    for addr <-
          ~w(8.8.8.8 9.9.9.9 100.63.255.255 100.128.0.0 172.15.255.255 172.32.0.0 198.17.255.255 198.20.0.0 223.255.255.255 2606:4700::1111 2002:808:808::1 64:ff9b::808:808) do
      {:ok, ip} = :inet.parse_address(String.to_charlist(addr))
      assert Address.allowed?(ip, []), addr
    end

    refute Address.allowed?({256, 0, 0, 1}, [])
  end

  test "IANA allocation boundaries include their last address and exclude their neighbors" do
    # Independently transcribed IANA special-purpose allocations; boundary inputs
    # are local adverse constructions, not claimed published test vectors.
    blocks = [
      {"0.0.0.0", "0.255.255.255", "1.0.0.0"},
      {"10.0.0.0", "10.255.255.255", "11.0.0.0"},
      {"100.64.0.0", "100.127.255.255", "100.128.0.0"},
      {"127.0.0.0", "127.255.255.255", "128.0.0.0"},
      {"169.254.0.0", "169.254.255.255", "169.255.0.0"},
      {"172.16.0.0", "172.31.255.255", "172.32.0.0"},
      {"192.0.0.0", "192.0.0.255", "192.0.1.0"},
      {"192.0.2.0", "192.0.2.255", "192.0.3.0"},
      {"192.31.196.0", "192.31.196.255", "192.31.197.0"},
      {"192.52.193.0", "192.52.193.255", "192.52.194.0"},
      {"192.88.99.0", "192.88.99.255", "192.88.100.0"},
      {"192.168.0.0", "192.168.255.255", "192.169.0.0"},
      {"192.175.48.0", "192.175.48.255", "192.175.49.0"},
      {"198.18.0.0", "198.19.255.255", "198.20.0.0"},
      {"198.51.100.0", "198.51.100.255", "198.51.101.0"},
      {"203.0.113.0", "203.0.113.255", "203.0.114.0"},
      {"2001::", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", "2001:200::"},
      {"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", "2001:db9::"},
      {"2620:4f:8000::", "2620:4f:8000:ffff:ffff:ffff:ffff:ffff", "2620:4f:8001::"},
      {"3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", "3fff:1000::"}
    ]

    for {first, last, outside} <- blocks do
      for address <- [first, last] do
        {:ok, ip} = :inet.parse_address(String.to_charlist(address))
        refute Address.allowed?(ip, []), address
      end

      {:ok, ip} = :inet.parse_address(String.to_charlist(outside))
      assert Address.allowed?(ip, []), outside
    end
  end

  test "directory-assigned IDs preserve thumbprint identity and revocation" do
    {:ok, key} = PublicKey.import(File.read!("test/fixtures/crypto/ed25519_public.pem"), :pem)
    {:ok, thumbprint} = PublicKey.thumbprint(key)
    now = System.system_time(:second)

    assert {:ok, source} =
             Source.new(%{
               type: :jwks_uri,
               location: "https://example.com/keys",
               key_id: :directory
             })

    assert {:error, %{reason: :invalid_source}} =
             Source.new(%{type: :jwks_uri, location: "https://example.com/keys", key_id: :other})

    entry = %RequestSeal.Discovery.Resolution{
      key: key,
      key_id: "directory-assigned",
      thumbprint: thumbprint,
      algorithm: "ed25519",
      expires_at: now + 3600
    }

    set = %RequestSeal.Discovery.KeySet{
      source: source,
      keys: %{entry.key_id => entry},
      expires_at: now + 3600
    }

    assert {:ok, resolution} = RequestSeal.Discovery.KeySet.lookup(set, entry.key_id, ["ed25519"])
    assert resolution.key_id == "directory-assigned"
    assert resolution.thumbprint == thumbprint

    assert :error =
             RequestSeal.Discovery.KeySet.lookup(
               %{set | source: %{source | revoked: [thumbprint]}},
               entry.key_id,
               ["ed25519"]
             )

    assert :error =
             RequestSeal.Discovery.KeySet.lookup(
               %{set | keys: %{entry.key_id => %{entry | thumbprint: "other"}}},
               entry.key_id,
               ["ed25519"]
             )

    assert :error =
             RequestSeal.Discovery.KeySet.lookup(
               %{set | keys: %{entry.key_id => %{entry | key_id: "other"}}},
               entry.key_id,
               ["ed25519"]
             )

    assert {:ok, %{key: ^key, algorithm: "ed25519"}} =
             Discovery.resolver(set, algorithms: ["ed25519"]).(%{keyid: entry.key_id})

    for kid <- ["", String.duplicate("x", 257), "bad\n"] do
      assert :error = RequestSeal.Discovery.KeySet.lookup(set, kid, ["ed25519"])
      malformed = %{set | keys: %{kid => %{entry | key_id: kid}}}
      assert :error = RequestSeal.Discovery.KeySet.lookup(malformed, kid, ["ed25519"])

      assert {:error, %{reason: :unknown_key}} =
               RequestSeal.Discovery.Cache.resolve(:unavailable_cache, source, kid,
                 algorithms: ["ed25519"]
               )
    end
  end

  test "local TLS publisher enforces directory ID uniqueness, key time, and thumbprint removals" do
    alias RequestSeal.DiscoveryPeer, as: Peer
    alias RequestSeal.Discovery.{Cache, KeySet}
    # Local construction from the published RFC 8037 key; actual TLS and discovery.
    jwk = Peer.public_jwk() |> Map.put("kid", "directory-assigned")
    {:ok, public} = PublicKey.import(jwk, :jwk)
    {:ok, thumbprint} = PublicKey.thumbprint(public)
    now = System.system_time(:second)

    for {keys, reason} <- [
          {[jwk, jwk], :invalid_key_set},
          {[Map.delete(jwk, "kid")], :invalid_key_set},
          {[Map.put(jwk, "kid", "")], :invalid_key_set},
          {[Map.put(jwk, "kid", String.duplicate("x", 257))], :invalid_key_set},
          {[Map.put(jwk, "kid", "bad\n")], :invalid_key_set}
        ] do
      p =
        Peer.start(fn socket, _ ->
          Peer.reply(socket, Peer.directory(keys), [
            {"Content-Type", "application/jwk-set+json"},
            {"Cache-Control", "max-age=3600"}
          ])
        end)

      try do
        {:ok, source} =
          Source.new(%{
            type: :jwks_uri,
            location: "https://localhost:#{p.port}/keys",
            key_id: :directory,
            cacerts: p.cacerts,
            permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]
          })

        assert {:error, %{reason: ^reason}} = Discovery.fetch(source)
      after
        Peer.stop(p)
      end
    end

    for key <- [jwk, Map.put(jwk, "exp", now - 1), Map.put(jwk, "nbf", now + 3600)] do
      p =
        Peer.start(fn socket, _ ->
          Peer.reply(socket, Peer.directory([key]), [
            {"Content-Type", "application/jwk-set+json"},
            {"Cache-Control", "max-age=3600"}
          ])
        end)

      try do
        {:ok, source} =
          Source.new(%{
            type: :jwks_uri,
            location: "https://localhost:#{p.port}/keys",
            key_id: :directory,
            cacerts: p.cacerts,
            permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]
          })

        assert {:ok, set} = Discovery.fetch(source)

        if key == jwk do
          assert {:ok, r} = KeySet.lookup(set, "directory-assigned", ["ed25519"])
          assert r.thumbprint == thumbprint
          assert {:ok, revoked} = Discovery.fetch(%{source | revoked: [thumbprint]})
          refute Map.has_key?(revoked.keys, "directory-assigned")
          assert :error = KeySet.lookup(revoked, "directory-assigned", ["ed25519"])
          cache = start_supervised!({Cache, []})

          assert {:ok, _} =
                   Cache.resolve(cache, source, "directory-assigned", algorithms: ["ed25519"])

          assert :ok = Cache.remove(cache, source, thumbprint)

          assert {:error, %{reason: :unknown_key}} =
                   Cache.resolve(cache, source, "directory-assigned", algorithms: ["ed25519"])

          assert {:ok, _} = Cache.refresh(cache, source)

          assert {:error, %{reason: :unknown_key}} =
                   Cache.resolve(cache, source, "directory-assigned", algorithms: ["ed25519"])

          assert :ok = Cache.invalidate(cache, source)

          assert {:error, %{reason: :unknown_key}} =
                   Cache.resolve(cache, source, "directory-assigned", algorithms: ["ed25519"])

          stop_supervised(Cache)
        else
          assert :error = KeySet.lookup(set, "directory-assigned", ["ed25519"])
        end
      after
        Peer.stop(p)
      end
    end
  end

  test "rotating directory IDs count only eligible keys in either order" do
    alias RequestSeal.DiscoveryPeer, as: Peer
    alias RequestSeal.Discovery.KeySet
    current = Peer.public_jwk() |> Map.put("kid", "rotating")
    {:ok, public} = PublicKey.import(current, :jwk)
    {:ok, thumbprint} = PublicKey.thumbprint(public)
    {:ok, old_key} = PublicKey.import(File.read!("test/fixtures/crypto/ed25519_public.pem"), :pem)
    {:ok, old} = PublicKey.export(old_key, :jwk)
    {:ok, old_thumbprint} = PublicKey.thumbprint(old_key)
    now = System.system_time(:second)

    excluded = [
      {Map.put(current, "exp", now - 1), []},
      {Map.put(current, "nbf", now + 3600), []},
      {Map.put(old, "kid", "rotating"), [old_thumbprint]},
      {Map.put(current, "use", "enc"), []}
    ]

    for {previous, revoked} <- excluded, keys <- [[previous, current], [current, previous]] do
      peer =
        Peer.start(fn socket, _ ->
          Peer.reply(socket, Peer.directory(keys), [
            {"Content-Type", "application/jwk-set+json"},
            {"Cache-Control", "max-age=3600"}
          ])
        end)

      try do
        {:ok, source} =
          Source.new(%{
            type: :jwks_uri,
            location: "https://localhost:#{peer.port}/keys",
            key_id: :directory,
            revoked: revoked,
            cacerts: peer.cacerts,
            permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]
          })

        assert {:ok, set} = Discovery.fetch(source)
        assert map_size(set.keys) == 1
        assert {:ok, %{thumbprint: ^thumbprint}} = KeySet.lookup(set, "rotating", ["ed25519"])
      after
        Peer.stop(peer)
      end
    end
  end

  test "a directory ID colliding with another thumbprint cannot transfer revocation" do
    alias RequestSeal.Discovery.{Cache, KeySet}
    alias RequestSeal.DiscoveryPeer, as: Peer
    {:ok, first} = PublicKey.import(File.read!("test/fixtures/crypto/ed25519_public.pem"), :pem)
    {:ok, first_jwk} = PublicKey.export(first, :jwk)
    {:ok, first_thumbprint} = PublicKey.thumbprint(first)
    second_jwk = Peer.public_jwk()
    {:ok, second} = PublicKey.import(second_jwk, :jwk)
    {:ok, second_thumbprint} = PublicKey.thumbprint(second)

    body =
      Peer.directory([
        Map.put(first_jwk, "kid", "first"),
        Map.put(second_jwk, "kid", first_thumbprint)
      ])

    peer =
      Peer.start(fn socket, _ ->
        Peer.reply(socket, body, [
          {"Content-Type", "application/jwk-set+json"},
          {"Cache-Control", "max-age=3600"}
        ])
      end)

    try do
      {:ok, source} =
        Source.new(%{
          type: :jwks_uri,
          location: "https://localhost:#{peer.port}/keys",
          key_id: :directory,
          cacerts: peer.cacerts,
          permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]
        })

      assert {:ok, set} = Discovery.fetch(%{source | revoked: [first_thumbprint]})
      assert :error = KeySet.lookup(set, "first", ["ed25519"])

      assert {:ok, %{thumbprint: ^second_thumbprint}} =
               KeySet.lookup(set, first_thumbprint, ["ed25519"])

      cache = start_supervised!({Cache, []})

      assert {:ok, %{thumbprint: ^second_thumbprint}} =
               Cache.resolve(cache, %{source | revoked: [first_thumbprint]}, first_thumbprint,
                 algorithms: ["ed25519"]
               )

      assert {:ok, _} = Cache.resolve(cache, source, "first", algorithms: ["ed25519"])
      assert {:ok, _} = Cache.resolve(cache, source, first_thumbprint, algorithms: ["ed25519"])
      assert :ok = Cache.remove(cache, source, first_thumbprint)

      assert {:error, %{reason: :unknown_key}} =
               Cache.resolve(cache, source, "first", algorithms: ["ed25519"])

      assert {:ok, %{thumbprint: ^second_thumbprint}} =
               Cache.resolve(cache, source, first_thumbprint, algorithms: ["ed25519"])

      assert {:ok, _} = Cache.refresh(cache, source)

      assert {:ok, %{thumbprint: ^second_thumbprint}} =
               Cache.resolve(cache, source, first_thumbprint, algorithms: ["ed25519"])

      assert :ok = Cache.invalidate(cache, source)

      assert {:ok, %{thumbprint: ^second_thumbprint}} =
               Cache.resolve(cache, source, first_thumbprint, algorithms: ["ed25519"])
    after
      Peer.stop(peer)
    end
  end

  test "published RFC 7517 key IDs require explicit directory mode over the local TLS publisher" do
    alias RequestSeal.Discovery.{KeySet}
    alias RequestSeal.DiscoveryPeer, as: Peer

    keys =
      :json.decode(File.read!("test/fixtures/custody/rfc7517.json"))["keys"]
      |> Enum.map(&Map.take(&1, ~w(kty crv x y n e kid)))

    # Retain published public material and IDs, excluding private components and
    # JOSE algorithm/encryption restrictions from this HTTP signing directory.
    body = Peer.directory(keys)

    peer =
      Peer.start(fn socket, _ ->
        Peer.reply(socket, body, [
          {"Content-Type", "application/json"},
          {"Cache-Control", "public, max-age=3600"}
        ])
      end)

    try do
      {:ok, source} =
        Source.new(%{
          type: :jwks_uri,
          location: "https://localhost:#{peer.port}/keys",
          key_id: :directory,
          cacerts: peer.cacerts,
          permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]
        })

      assert {:ok, set} = Discovery.fetch(source)

      for {kid, algorithm} <- [{"1", "ecdsa-p256-sha256"}, {"2011-04-29", "rsa-v1_5-sha256"}] do
        jwk = Enum.find(keys, &(&1["kid"] == kid))
        assert {:ok, public} = PublicKey.import(jwk, :jwk)
        assert {:ok, thumbprint} = PublicKey.thumbprint(public)
        refute kid == thumbprint
        assert {:ok, r} = KeySet.lookup(set, kid, [algorithm])
        assert r.thumbprint == thumbprint
        assert r.key.material == public.material
      end

      assert {:error, %{reason: :invalid_key_set}} =
               Discovery.fetch(%{source | key_id: :thumbprint})
    after
      Peer.stop(peer)
    end
  end

  test "thumbprint mode retains its existing handling of expired duplicate entries" do
    alias RequestSeal.Discovery.{KeySet}
    alias RequestSeal.DiscoveryPeer, as: Peer
    jwk = Peer.public_jwk()
    {:ok, public} = PublicKey.import(jwk, :jwk)
    {:ok, thumbprint} = PublicKey.thumbprint(public)
    body = Peer.directory([Map.put(jwk, "exp", System.system_time(:second) - 1), jwk])

    peer =
      Peer.start(fn socket, _ ->
        Peer.reply(socket, body, [
          {"Content-Type", "application/json"},
          {"Cache-Control", "max-age=3600"}
        ])
      end)

    try do
      {:ok, source} =
        Source.new(%{
          type: :jwks_uri,
          location: "https://localhost:#{peer.port}/keys",
          cacerts: peer.cacerts,
          permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}]
        })

      assert source.key_id == :thumbprint
      assert {:ok, set} = Discovery.fetch(source)
      assert {:ok, %{thumbprint: ^thumbprint}} = KeySet.lookup(set, thumbprint, ["ed25519"])
    after
      Peer.stop(peer)
    end
  end
end
