defmodule RequestSeal.ClockBoundsTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Conformance, Crypto, Message, Replay}
  alias RequestSeal.Discovery.{Cache, Source}
  alias RequestSeal.Custody.Context
  @max 253_402_300_799

  defp context do
    %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5000}
  end

  test "generic verify rejects outside clocks and accepts both bounds before freshness" do
    c = Conformance.json(File.read!("corpus/cases/verify/rfc9421-sig-b26.json"))

    c =
      put_in(c, ["policy", "freshness"], %{
        "max_age" => Conformance.number(60),
        "skew" => Conformance.number(0),
        "require_expires" => false
      })

    for {now, reason} <- [
          {-1, :invalid_clock},
          {0, :created_in_future},
          {@max, :too_old},
          {@max + 1, :invalid_clock}
        ] do
      c = Map.put(c, "now", Conformance.number(now))
      assert {:error, %{reason: ^reason}} = Conformance.Surfaces.verify("corpus", c)
    end
  end

  test "claim retention bounds fail closed through validation and stores" do
    pid = start_supervised!({Replay.ETS, max_entries: 16})

    for until <- [0, @max] do
      claim = %Replay.Claim{
        namespace: "bounds",
        key: Integer.to_string(until),
        retain_until: until
      }

      assert Replay.Claim.valid?(claim)
      assert :claimed = Replay.ETS.claim(pid, claim, context())
      expired = %{context() | deadline: System.monotonic_time(:millisecond) - 1}
      assert {:error, :timeout} = Replay.Postgres.claim({self(), "replay"}, claim, expired)
    end

    assert {:ok, 1} = Replay.ETS.sweep(pid, 0, context())
    assert {:ok, 1} = Replay.ETS.sweep(pid, @max, context())

    for until <- [@max + 1, -9_223_372_036_854_775_809] do
      claim = %Replay.Claim{namespace: "bounds", key: "invalid", retain_until: until}
      refute Replay.Claim.valid?(claim)
      assert {:error, :failure} = Replay.ETS.claim(pid, claim, context())
      assert {:error, :failure} = GenServer.call(pid, {:claim, claim, context()})

      assert {:error, %{reason: :invalid_claim}} =
               Replay.claim(Replay.ETS.store(pid), claim, timeout: 5000)

      assert {:error, :failure} = Replay.Postgres.claim({self(), "replay"}, claim, context())
    end
  end

  test "Postgres sweep clock guard precedes queries at both edges" do
    expired = context()
    # An expired real operation context reaches the query deadline guard,
    # proving accepted clocks without a connection or a database.
    expired = %{expired | deadline: System.monotonic_time(:millisecond) - 1}

    for now <- [0, @max],
        do: assert({:error, :timeout} = Replay.Postgres.sweep({self(), "replay"}, now, expired))

    for now <- [-1, @max + 1],
        do: assert({:error, :failure} = Replay.Postgres.sweep({self(), "replay"}, now, expired))
  end

  test "Discovery body and cache clocks use the same inclusive bounds" do
    {:ok, source} = Source.new(%{type: :jwks_uri, location: "https://example.com/keys"})

    body =
      Conformance.bytes(
        Conformance.json(File.read!("corpus/cases/discovery/rfc8037-jwks.json"))["inputs"]["body"]
      )

    for now <- [0, @max] do
      assert {:ok, _} = RequestSeal.Discovery.parse_body(body, source, now)
      assert {:ok, pid} = Cache.start_link(clock: fn -> now end)
      {:ok, denied} = Source.new(%{type: :jwks_uri, location: "https://127.0.0.1/keys"})

      assert {:error, %{reason: :address_denied}} =
               Cache.resolve(pid, denied, String.duplicate("A", 43), clock: fn -> now end)

      GenServer.stop(pid)
    end

    for now <- [-1, @max + 1] do
      assert {:error, %{reason: :invalid_options}} =
               RequestSeal.Discovery.parse_body(body, source, now)

      assert {:error, %{reason: :invalid_options}} = Cache.start_link(clock: fn -> now end)

      assert {:error, %{reason: :invalid_options}} =
               RequestSeal.Discovery.fetch(source, clock: fn -> now end)

      assert {:error, %{reason: :invalid_options}} =
               Cache.resolve(self(), source, String.duplicate("A", 43), clock: fn -> now end)
    end
  end

  test "generic and Finch signing accept bounds and reject outside clocks" do
    {:ok, message} = Message.request("GET", "https://example.com/", [], nil)
    key = File.read!("test/fixtures/crypto/ed25519_private.pem")
    [entry] = :public_key.pem_decode(key)
    key = {:ed25519, elem(:public_key.pem_entry_decode(entry), 2)}
    signer = fn a, b -> Crypto.sign(a, b, key) end

    spec = %{
      label: "s",
      algorithm: "ed25519",
      components: ~s[("@method")],
      parameters: %{created: true, expires_in: nil, nonce: nil, keyid: nil, tag: nil, alg: false},
      digest: nil,
      field_schemas: %{}
    }

    for now <- [0, @max] do
      assert {:ok, _} = RequestSeal.sign(message, spec, signer, clock: fn -> now end)

      assert {:ok, _} =
               RequestSeal.Finch.sign(Finch.build(:get, "https://example.com/"), spec, signer,
                 clock: fn -> now end
               )
    end

    for now <- [-1, @max + 1] do
      assert {:error, %{reason: :invalid_options}} =
               RequestSeal.sign(message, spec, signer, clock: fn -> now end)

      assert {:error, %{reason: :invalid_options}} =
               RequestSeal.Finch.sign(Finch.build(:get, "https://example.com/"), spec, signer,
                 clock: fn -> now end
               )
    end
  end

  test "Web Bot Auth clock bounds precede freshness evaluation" do
    c = Conformance.json(File.read!("corpus/cases/web_bot_auth/directory.json"))

    for {now, reason} <- [
          {-1, :invalid_clock},
          {0, :created_in_future},
          {@max, :expired},
          {@max + 1, :invalid_clock}
        ] do
      assert {:error, %{reason: ^reason}} =
               Conformance.Surfaces.web_bot_auth(
                 "corpus",
                 Map.put(c, "now", Conformance.number(now))
               )
    end
  end

  test "Discovery fetch accepts edge clocks before address policy, without a connection" do
    {:ok, source} = Source.new(%{type: :jwks_uri, location: "https://127.0.0.1/keys"})

    for now <- [0, @max] do
      assert {:error, %{reason: :address_denied}} =
               RequestSeal.Discovery.fetch(source, clock: fn -> now end)
    end
  end

  test "Req signing samples edge clocks on the request step without transport" do
    signer = fn a, b -> Crypto.sign(a, b, {:hmac, String.duplicate("k", 32)}) end

    spec = %{
      label: "s",
      algorithm: "hmac-sha256",
      components: ~s[("@method")],
      parameters: %{created: true, expires_in: nil, nonce: nil, keyid: nil, tag: nil, alg: false},
      digest: nil,
      field_schemas: %{}
    }

    for now <- [0, @max, -1, @max + 1] do
      assert {:ok, request} =
               RequestSeal.Req.attach(Req.new(url: "https://example.com/"),
                 sign: spec,
                 signer: signer,
                 verify: :none,
                 clock: fn -> now end
               )

      result = RequestSeal.Req.sign_attempt(request)

      if now in 0..@max do
        assert %Req.Request{} = result
        assert Enum.any?(result.headers, fn {name, _} -> name == "signature" end)
      else
        assert {%Req.Request{}, %{reason: :invalid_options}} = result
      end
    end
  end

  test "Plug response signing applies edge clocks with and without generated Date" do
    {:ok, request} = Message.request("GET", "https://example.com/", [], nil)
    signer = fn a, b -> Crypto.sign(a, b, {:hmac, String.duplicate("k", 32)}) end

    for components <- [~s[("@status")], ~s[("@status" "date")]], now <- [0, @max, -1, @max + 1] do
      spec = %{
        label: "s",
        algorithm: "hmac-sha256",
        components: components,
        parameters: %{
          created: true,
          expires_in: nil,
          nonce: nil,
          keyid: nil,
          tag: nil,
          alg: false
        },
        digest: nil,
        field_schemas: %{}
      }

      opts =
        RequestSeal.Plug.SignResponse.init(
          sign: spec,
          signer: signer,
          clock: fn -> now end,
          signing_timeout: 5000,
          on_failure: {:respond, 500}
        )

      conn = %Plug.Conn{
        state: :set,
        status: 200,
        resp_body: "",
        private: %{
          request_seal: %RequestSeal.Plug.State{
            capture: %RequestSeal.Plug.Capture{message: request}
          }
        }
      }

      conn = RequestSeal.Plug.SignResponse.call(conn, opts)
      [callback] = conn.private.before_send
      result = callback.(conn)

      if now in 0..@max do
        assert Enum.any?(result.resp_headers, fn {name, _} -> name == "signature" end)
        assert result.private.request_seal.error == nil
      else
        assert %{reason: :invalid_options} = result.private.request_seal.error
      end
    end
  end
end
