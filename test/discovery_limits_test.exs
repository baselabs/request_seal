Code.require_file("support/discovery_peer_helper.exs", __DIR__)

defmodule RequestSeal.DiscoveryLimitsTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  alias RequestSeal.Discovery
  alias RequestSeal.Discovery.{Source, KeySet}
  alias RequestSeal.DiscoveryPeer, as: Peer

  defp peer(fun) do
    p = Peer.start(fun)
    on_exit(fn -> Peer.stop(p) end)
    p
  end

  defp source(p, opts \\ %{}) do
    {:ok, source} =
      Source.new(
        Map.merge(
          %{
            type: :directory,
            location: "https://localhost:#{p.port}",
            cacerts: p.cacerts,
            permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}],
            require_signed_directory: false
          },
          opts
        )
      )

    source
  end

  defp reason(source, expected) do
    assert {:error, %{reason: ^expected} = error} = Discovery.fetch(source, [])
    refute inspect(error) =~ "canary"
    refute inspect(error) =~ "localhost"
  end

  defp media,
    do: {"Content-Type", "application/http-message-signatures-directory+json;charset=utf-8"}

  test "encoded and decoded byte caps apply at the boundary for length, chunked and close bodies" do
    body = Peer.directory()
    p = peer(fn socket, _ -> Peer.reply(socket, body, [media()]) end)
    assert {:ok, _} = Discovery.fetch(source(p, %{max_bytes: byte_size(body)}), [])
    reason(source(p, %{max_bytes: byte_size(body) - 1}), :limit)

    for framing <- [:chunked, :close] do
      p =
        peer(fn socket, _ ->
          header = if framing == :chunked, do: "Transfer-Encoding: chunked\r\n", else: ""

          encoded =
            if framing == :chunked,
              do: [
                Integer.to_string(byte_size(body), 16),
                ";public=key\r\n",
                body,
                "\r\n0\r\n\r\n"
              ],
              else: body

          :ssl.send(socket, [
            "HTTP/1.1 200 OK\r\nContent-Type: application/http-message-signatures-directory+json\r\n",
            header,
            "Connection: close\r\n\r\n",
            encoded
          ])
        end)

      assert {:ok, _} = Discovery.fetch(source(p, %{max_bytes: byte_size(body)}), [])
      reason(source(p, %{max_bytes: byte_size(body) - 1}), :limit)
    end

    large = body <> String.duplicate(" ", 65_536)
    compressed = :zlib.gzip(large)

    p =
      peer(fn socket, _ ->
        Peer.reply(socket, compressed, [media(), {"Content-Encoding", "gzip"}])
      end)

    reason(source(p), :limit)
    assert {:ok, _} = Discovery.fetch(source(p, %{max_decoded_bytes: byte_size(large)}), [])
    reason(source(p, %{max_decoded_bytes: byte_size(large) - 1}), :limit)
  end

  test "gzip trailing members and malformed streams cannot hide decoded bytes" do
    compressed = :zlib.gzip(Peer.directory())

    for body <- [
          compressed <> :zlib.gzip(String.duplicate("x", 65_536)),
          binary_part(compressed, 0, byte_size(compressed) - 4),
          compressed <> "canary"
        ] do
      p =
        peer(fn socket, _ ->
          Peer.reply(socket, body, [media(), {"Content-Encoding", "gzip"}])
        end)

      reason(source(p), :invalid_response)
    end
  end

  test "framing ambiguity, malformed chunks and oversized headers reject before parsing JSON" do
    body = Peer.directory()

    for {head, tail, expected} <- [
          {"Transfer-Encoding: chunked\r\nContent-Length: #{byte_size(body)}\r\n", body,
           :invalid_response},
          {"Transfer-Encoding: gzip\r\n", body, :invalid_response},
          {"Content-Length: #{byte_size(body)}\r\nContent-Length: #{byte_size(body)}\r\n", body,
           :invalid_response},
          {"Content-Length: -1\r\n", body, :invalid_response},
          {"Transfer-Encoding: chunked\r\n", "ffffffffffffffffffffffff\r\n", :invalid_response},
          {"Transfer-Encoding: chunked\r\n", "G\r\n", :invalid_response},
          {"Transfer-Encoding: chunked\r\n", "1\r\nx!!", :invalid_response},
          {"X-Canary: " <> String.duplicate("x", 16_384) <> "\r\n", body, :limit},
          {"X-Canary: folded\r\n more\r\n", body, :invalid_response}
        ] do
      p =
        peer(fn socket, _ ->
          :ssl.send(socket, [
            "HTTP/1.1 200 OK\r\nContent-Type: application/http-message-signatures-directory+json\r\n",
            head,
            "Connection: close\r\n\r\n",
            tail
          ])
        end)

      reason(source(p), expected)
    end
  end

  test "status, media, JSON nesting/duplicates and key-count are bounded" do
    body = Peer.directory()

    for status <- [204, 404, 500] do
      p = peer(fn socket, _ -> Peer.reply(socket, body, [media()], status) end)
      reason(source(p), :unexpected_status)
    end

    p = peer(fn socket, _ -> Peer.reply(socket, body, [{"Content-Type", "text/canary"}]) end)
    reason(source(p), :unexpected_media_type)

    {:ok, rsa} =
      RequestSeal.PublicKey.import(File.read!("test/fixtures/crypto/rsa_public.pem"), :pem)

    {:ok, jwk} = RequestSeal.PublicKey.export(rsa, :jwk)

    p =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory([Peer.public_jwk(), jwk]), [media()])
      end)

    reason(source(p, %{max_keys: 1}), :limit)
    assert {:ok, %{keys: keys}} = Discovery.fetch(source(p, %{max_keys: 2}), [])
    assert map_size(keys) == 2

    for {json, expected} <- [
          {"{\"keys\":[],\"keys\":[#{:json.encode(Peer.public_jwk()) |> IO.iodata_to_binary()}]}",
           :invalid_response},
          {"{\"extra\":" <>
             String.duplicate("[", 33) <> "0" <> String.duplicate("]", 33) <> ",\"keys\":[]}",
           :limit},
          {"{\"keys\":\"canary\"}", :invalid_key_set},
          {"not JSON canary", :invalid_response}
        ] do
      p = peer(fn socket, _ -> Peer.reply(socket, json, [media()]) end)
      reason(source(p), expected)
    end
  end

  test "CIMD has a decoded 5 KB cap independent of configured larger limits" do
    for {size, expected} <- [{5120, :ok}, {5121, :limit}] do
      p =
        peer(fn socket, req ->
          host = Regex.run(~r/\r\nHost: ([^\r]+)\r\n/, req) |> Enum.at(1)

          doc = %{
            "client_id" => "https://#{host}/card",
            "jwks" => %{"keys" => [Peer.public_jwk()]}
          }

          json = :json.encode(doc) |> IO.iodata_to_binary()
          body = json <> String.duplicate(" ", size - byte_size(json))
          Peer.reply(socket, body, [{"Content-Type", "application/json"}])
        end)

      s = source(p, %{type: :cimd, location: "https://localhost:#{p.port}/card"})

      if expected == :ok,
        do: assert(match?({:ok, _}, Discovery.fetch(s, []))),
        else: reason(s, expected)
    end
  end

  test "redirects need explicit bounded same-origin permission and revalidate every destination" do
    for status <- [301, 302, 307, 308] do
      p =
        peer(fn socket, req ->
          if String.starts_with?(req, "GET /keys "),
            do: Peer.reply(socket, Peer.directory(), [media()]),
            else: Peer.reply(socket, "", [{"Location", "/keys"}], status)
        end)

      reason(source(p), :redirect_denied)
      assert {:ok, set} = Discovery.fetch(source(p, %{max_redirects: 1}), [])
      assert set.origin == "https://localhost:#{p.port}"
    end

    for target <- [
          "http://localhost/keys",
          "https://other.canary/keys",
          "https://127.0.0.1/keys",
          "/%2e%2e/keys"
        ] do
      p = peer(fn socket, _ -> Peer.reply(socket, "", [{"Location", target}], 302) end)
      reason(source(p, %{max_redirects: 1}), :redirect_denied)
    end

    p = peer(fn socket, _ -> Peer.reply(socket, "", [{"Location", "/again"}], 302) end)
    reason(source(p, %{max_redirects: 1}), :redirect_limit)

    p =
      peer(fn socket, _ ->
        Peer.reply(socket, "", [{"Location", "https://127.0.0.2/keys"}], 302)
      end)

    reason(source(p, %{max_redirects: 1, redirect_scope: :any_https}), :address_denied)
  end

  @tag finding: :f2
  test "same-origin redirects normalize scheme and host case and one trailing dot" do
    for host <- ["LOCALHOST", "localhost.", "LOCALHOST."] do
      p =
        peer(fn socket, req ->
          if String.starts_with?(req, "GET /keys ") do
            Peer.reply(socket, Peer.directory(), [media()])
          else
            port = Regex.run(~r/\r\nHost: localhost:([0-9]+)\r\n/, req) |> Enum.at(1)
            Peer.reply(socket, "", [{"Location", "HTTPS://#{host}:#{port}/keys"}], 302)
          end
        end)

      assert {:ok, %{origin: origin}} = Discovery.fetch(source(p, %{max_redirects: 1}), [])
      assert origin == "https://localhost:#{p.port}"
    end
  end

  test "trailer-injected signature fields cannot become a directory proof" do
    body = Peer.directory()

    p =
      peer(fn socket, _ ->
        :ssl.send(socket, [
          "HTTP/1.1 200 OK\r\nContent-Type: application/http-message-signatures-directory+json\r\nTransfer-Encoding: chunked\r\n\r\n",
          Integer.to_string(byte_size(body), 16),
          "\r\n",
          body,
          "\r\n0\r\nSignature-Input: attacker=(\"@authority\";req \"content-digest\")\r\nSignature: attacker=:YWJj:\r\n\r\n"
        ])
      end)

    reason(source(p, %{require_signed_directory: true}), :directory_unsigned)
  end

  test "cache freshness honors age, no-store and directory signature expiry" do
    body = Peer.directory()

    p =
      peer(fn socket, _ ->
        Peer.reply(socket, body, [media(), {"Cache-Control", "max-age=30"}, {"Age", "10"}])
      end)

    assert {:ok, set} = Discovery.fetch(source(p), [])
    assert set.expires_at - set.fetched_at == 20

    p =
      peer(fn socket, req ->
        Peer.signed(socket, req, body, nil, expires: System.system_time(:second) + 2)
      end)

    assert {:ok, set} = Discovery.fetch(source(p), [])
    assert set.expires_at - set.fetched_at <= 2
    [kid] = Map.keys(set.keys)

    assert :error =
             KeySet.lookup(%{set | expires_at: System.system_time(:second)}, kid, ["ed25519"])

    p =
      peer(fn socket, _ ->
        Peer.reply(socket, body, [media(), {"Cache-Control", "max-age=1"}])
      end)

    assert {:ok, set} = Discovery.fetch(source(p, %{min_ttl: 10}), [])
    assert set.expires_at - set.fetched_at == 1
  end

  defp http_date(seconds),
    do: Calendar.strftime(DateTime.from_unix!(seconds), "%a, %d %b %Y %H:%M:%S GMT")

  @tag fix2: true
  test "Expires freshness uses Date and Age while max-age takes precedence" do
    now = System.system_time(:second)
    expires = DateTime.from_unix!(now + 120)

    asctime =
      Calendar.strftime(expires, "%a %b ") <>
        String.pad_leading(Integer.to_string(expires.day), 2) <>
        Calendar.strftime(expires, " %H:%M:%S %Y")

    for {headers, expected} <- [
          {[{"Expires", http_date(now + 120)}], 120},
          {[
             {"Expires",
              Calendar.strftime(DateTime.from_unix!(now + 120), "%A, %d-%b-%y %H:%M:%S GMT")}
           ], 120},
          {[{"Expires", asctime}], 120},
          {[{"Expires", http_date(now + 120)}, {"Age", "20"}], 100},
          {[{"Date", http_date(now - 60)}, {"Expires", http_date(now + 120)}, {"Age", "80"}],
           100},
          {[{"Date", http_date(now - 60)}, {"Expires", http_date(now + 120)}], 120},
          {[{"Cache-Control", "max-age=10"}, {"Expires", http_date(now + 120)}], 10},
          {[{"Cache-Control", "max-age=10"}, {"Expires", "invalid"}], 10},
          {[{"Expires", http_date(now - 1)}], 0},
          {[{"Expires", "0"}], 0},
          {[{"Expires", "invalid"}], 0},
          {[{"Expires", "Thu, 31 Feb 2026 00:00:00 GMT"}], 0},
          {[{"Expires", "Thu, 08 Xxx 2026 00:00:00 GMT"}], 0},
          {[{"Cache-Control", "no-cache"}, {"Expires", http_date(now + 120)}], 0},
          {[{"Cache-Control", "no-store"}, {"Expires", http_date(now + 120)}], 0},
          {[{"Cache-Control", "max-age=0"}, {"Expires", http_date(now + 120)}], 0}
        ] do
      p = peer(fn socket, _ -> Peer.reply(socket, Peer.directory(), [media() | headers]) end)
      assert {:ok, set} = Discovery.fetch(source(p), clock: fn -> now end)
      assert set.expires_at == now + expected, inspect(headers)
    end
  end

  @tag fix2: true
  test "fallback freshness is configurable and all freshness remains capped" do
    now = System.system_time(:second)
    p = peer(fn socket, _ -> Peer.reply(socket, Peer.directory(), [media()]) end)

    for {attrs, ttl} <- [{%{}, 300}, {%{min_ttl: 20}, 20}, {%{min_ttl: 0}, 0}] do
      assert {:ok, set} = Discovery.fetch(source(p, attrs), clock: fn -> now end)
      assert set.expires_at == now + ttl
    end

    p =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory(), [media(), {"Expires", http_date(now + 600)}])
      end)

    assert {:ok, set} =
             Discovery.fetch(source(p, %{min_ttl: 0, max_ttl: 60}), clock: fn -> now end)

    assert set.expires_at == now + 60

    p =
      peer(fn socket, _ ->
        Peer.reply(socket, Peer.directory([Map.put(Peer.public_jwk(), "exp", now + 30)]), [
          media(),
          {"Expires", http_date(now + 600)}
        ])
      end)

    assert {:ok, set} = Discovery.fetch(source(p), clock: fn -> now end)
    assert set.expires_at == now + 30
  end

  @tag fix2: true
  test "5xx statuses are retryable but 4xx statuses are not" do
    for status <- [400, 401, 404, 429, 499, 500, 502, 503, 504, 599] do
      p = peer(fn socket, _ -> Peer.reply(socket, "", [], status) end)

      assert {:error, %{reason: :unexpected_status, retryable: retryable}} =
               Discovery.fetch(source(p))

      assert retryable == status in 500..599, inspect(status)
    end
  end

  test "failure outputs and captured logs exclude sensitive peer data" do
    logs =
      capture_log(fn ->
        for {bytes, reason} <- [
              {"canary invalid JSON", :invalid_response},
              {Peer.directory(), :invalid_key_set}
            ] do
          body =
            if reason == :invalid_key_set,
              do: Peer.directory([Map.put(Peer.public_jwk(), "kid", "canary")]),
              else: bytes

          p =
            peer(fn socket, _ ->
              Peer.reply(socket, body, [media(), {"X-Canary", "peer canary"}])
            end)

          source = source(p)
          assert {:error, error} = Discovery.fetch(source, [])
          assert error.reason == reason
          assert error.retryable == false
          refute inspect(error) =~ "canary"
          refute inspect(source) =~ "localhost"
        end
      end)

    refute logs =~ "canary"
    refute logs =~ "localhost"
  end
end
