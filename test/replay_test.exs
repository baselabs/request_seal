defmodule RequestSeal.ReplayTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Body, FieldOccurrence, Message, Policy, PublicKey, Replay, TransportFacts}
  alias RequestSeal.Replay.ETS
  alias RequestSeal.Custody.Context
  @root Path.join(__DIR__, "fixtures")
  @vectors :json.decode(File.read!(Path.join(@root, "verification/rfc9421.json")))
  @bases :json.decode(File.read!(Path.join(@root, "signature_base/rfc9421.json")))
  @created 1_618_884_473

  setup do
    # Supervised so ExUnit stops it after the test process exits; an alive check followed by
    # GenServer.stop races the linked exit.
    pid = start_supervised!({ETS, max_entries: 256})
    %{pid: pid, store: ETS.store(pid)}
  end

  test "sweep bounds protect claims through both public and direct entry points", ctx do
    claim = claim("scope", "bound", 253_402_300_799)
    assert :claimed = ETS.claim(ctx.pid, claim, context())

    for now <- [-1, 253_402_300_800] do
      assert {:error, :failure} = ETS.sweep(ctx.pid, now, context())
      assert {:error, :failure} = GenServer.call(ctx.pid, {:sweep, now, context()})
      assert :already_claimed = ETS.claim(ctx.pid, claim, context())
    end

    assert {:ok, 1} = ETS.sweep(ctx.pid, 253_402_300_799, context())
  end

  test "64 concurrent claims have one winner and namespaces are independent", %{store: store} do
    claim = claim("scope", "identifier", 100)

    results =
      1..64
      |> Task.async_stream(fn _ -> Replay.claim(store, claim, timeout: 2000) end,
        max_concurrency: 64
      )
      |> Enum.map(fn {:ok, x} -> x end)

    assert Enum.count(results, &(&1 == :claimed)) == 1
    assert Enum.count(results, &(&1 == :already_claimed)) == 63
    assert :claimed = Replay.claim(store, %{claim | namespace: "other"}, timeout: 2000)
  end

  test "malformed direct GenServer calls preserve the owner and existing claims", ctx do
    Process.unlink(ctx.pid)
    claim = claim("scope", "existing", 100)
    context = context()
    assert :claimed = ETS.claim(ctx.pid, claim, context)

    for request <- [
          :unexpected,
          {:claim, :garbage, context},
          {:claim, claim, :garbage},
          {:sweep, :garbage, context},
          {:sweep, 100, :garbage}
        ] do
      assert {:error, :failure} = GenServer.call(ctx.pid, request)
      assert Process.alive?(ctx.pid)
      assert :already_claimed = ETS.claim(ctx.pid, claim, context)
    end

    assert {:ok, 1} = ETS.sweep(ctx.pid, 100, context)
  end

  test "direct claim rejects malformed claim and context before calling the owner", ctx do
    Process.unlink(ctx.pid)
    claim = claim("scope", "existing", 100)
    context = context()
    assert :claimed = ETS.claim(ctx.pid, claim, context)

    for {candidate, operation} <- [{:garbage, context}, {claim, :garbage}] do
      assert {:error, :failure} = ETS.claim(ctx.pid, candidate, operation)
      assert Process.alive?(ctx.pid)
      assert :already_claimed = ETS.claim(ctx.pid, claim, context)
    end
  end

  test "direct sweep rejects malformed time and context before calling the owner", ctx do
    Process.unlink(ctx.pid)
    claim = claim("scope", "existing", 100)
    context = context()
    assert :claimed = ETS.claim(ctx.pid, claim, context)

    for {now, operation} <- [{100, :garbage}, {:garbage, context}] do
      assert {:error, :failure} = ETS.sweep(ctx.pid, now, operation)
      assert Process.alive?(ctx.pid)
      assert :already_claimed = ETS.claim(ctx.pid, claim, context)
    end
  end

  test "the protected table rejects external writes while owner claims and sweeps work", ctx do
    table = :sys.get_state(ctx.pid).table
    assert :ets.info(table, :protection) == :protected
    claim = claim("scope", "existing", 100)
    assert :claimed = Replay.claim(ctx.store, claim, timeout: 2000)
    assert_raise ArgumentError, fn -> :ets.delete(table, {:claim, "scope", "existing"}) end
    assert_raise ArgumentError, fn -> :ets.insert(table, {:count, 0}) end
    assert :already_claimed = Replay.claim(ctx.store, claim, timeout: 2000)
    assert {:ok, 1} = ETS.sweep(ctx.pid, 100)
    assert :claimed = Replay.claim(ctx.store, claim, timeout: 2000)
  end

  test "published nonce yields a receipt; relabeling and retention changes cannot bypass replay",
       ctx do
    owner = self()

    commitment = fn facts ->
      send(owner, {:facts, facts})
      {:ok, facts.identifier}
    end

    policy = policy(ctx.store, commitment)
    assert {:ok, result} = verify(message(), policy)
    assert result.replay == struct(Replay.Receipt, store: ETS, retain_until: @created + 63)
    assert_receive {:facts, facts}

    assert facts == %{
             identifier: "b3k2pp5k7z-50gnwp.yemd",
             algorithm: "rsa-pss-sha512",
             keyid: "test-key-rsa-pss",
             tag: nil,
             created: @created,
             expires: nil,
             profile: %{name: :rfc9421}
           }

    refute_received {:facts, _}
    error(verify(message(), policy), :replayed, :replay)
    assert_receive {:facts, ^facts}

    relabeled =
      message()
      |> rewrite(
        "signature-input",
        String.replace(vector()["signature_input"], "sig-b21=", "sig-x=")
      )
      |> rewrite("signature", String.replace(vector()["signature"], "sig-b21=", "sig-x="))

    error(RequestSeal.verify(relabeled, policy, label: "sig-x"), :replayed, :replay)

    error(
      verify(message(), %{policy | freshness: %{policy.freshness | max_age: 120}}),
      :replayed,
      :replay
    )

    assert {:ok, _} = verify(message(), %{policy | replay: %{policy.replay | namespace: "other"}})
    refute inspect(policy) =~ "b3k2"
    refute inspect(ctx.store) =~ "scope"
    refute inspect(claim("sensitive-namespace", "sensitive-key", 100)) =~ "sensitive"
  end

  test "sweep preserves the last accepted second and next second fails before commitment", ctx do
    owner = self()

    p =
      policy(ctx.store, fn f ->
        send(owner, :committed)
        {:ok, f.identifier}
      end)

    assert {:ok, _} = verify(message(), p)
    assert_receive :committed
    last = @created + 62
    swept = ETS.sweep(ctx.pid, last)
    p = %{p | freshness: %{p.freshness | clock: fn -> last end}}
    error(verify(message(), p), :replayed, :replay)
    assert swept == {:ok, 0}
    assert_receive :committed
    assert {:ok, 1} = ETS.sweep(ctx.pid, last + 1)

    error(
      verify(message(), %{p | freshness: %{p.freshness | clock: fn -> last + 1 end}}),
      :too_old,
      :freshness
    )

    refute_received :committed
  end

  test "exclusive expiration and combined bounds have exact retention", ctx do
    for {age, expiry, expected} <- [
          {nil, @created + 40, @created + 42},
          {60, @created + 40, @created + 42},
          {20, @created + 40, @created + 23}
        ] do
      m = resign(message(), ";expires=#{expiry}")
      p = policy(ctx.store, fn f -> {:ok, :erlang.term_to_binary({age, f.identifier})} end)
      p = %{p | freshness: %{p.freshness | max_age: age, require_expires: true}}
      assert {:ok, r} = verify(m, p)
      assert r.replay.retain_until == expected
    end
  end

  test "missing empty and oversized authenticated nonce rejects without a claim", ctx do
    owner = self()

    p =
      policy(ctx.store, fn f ->
        send(owner, :committed)
        {:ok, f.identifier}
      end)

    for value <- [nil, ""] do
      error(verify(resign(message(), "", value), p), :missing_replay_identifier, :replay)
    end

    error(verify(resign(message(), "", String.duplicate("n", 1025)), p), :limit, :input)
    refute_received :committed
    assert {:ok, 0} = ETS.sweep(ctx.pid, @created + 1000)
  end

  test "nonce bound precedes coverage freshness and key callbacks even without required replay",
       ctx do
    owner = self()

    p =
      policy(ctx.store, fn f ->
        send(owner, :committed)
        {:ok, f.identifier}
      end)

    p = %{
      p
      | components: ~s[("@method")],
        freshness: %{
          p.freshness
          | clock: fn ->
              send(owner, :clock_read)
              1_618_884_473
            end
        },
        key_resolver: fn _ ->
          send(owner, :resolved)
          :error
        end
    }

    oversized = resign(message(), "", String.duplicate("n", 1025))

    for replay <- [p.replay, :not_required] do
      error(verify(oversized, %{p | replay: replay}), :limit, :input)
      refute_received :clock_read
      refute_received :resolved
      refute_received :committed
      assert {:ok, 0} = ETS.sweep(ctx.pid, 1_618_885_000)
    end
  end

  test "callback faults malformed and oversized keys fail closed without storage", ctx do
    for fun <- [
          fn _ -> :error end,
          fn _ -> raise "secret" end,
          fn _ -> exit(:secret) end,
          fn _ -> throw(:secret) end,
          fn _ -> {:ok, 10} end,
          fn _ -> {:ok, ""} end,
          fn _ -> {:ok, String.duplicate("x", 257)} end
        ] do
      error(verify(message(), policy(ctx.store, fun)), :commitment_failed, :replay)
      assert {:ok, 0} = ETS.sweep(ctx.pid, @created + 1000)
    end
  end

  test "missing required coverage never invokes commitment or stores a replay claim", ctx do
    owner = self()

    p =
      policy(ctx.store, fn f ->
        send(owner, :committed)
        {:ok, f.identifier}
      end)

    result = verify(message(), %{p | components: ~s[("@method")]})
    refute_received :committed
    assert :ets.tab2list(:sys.get_state(ctx.pid).table) == [{:count, 0}]
    error(result, :missing_required_component, :policy)

    # The same signed message and real store accept a policy with satisfied coverage.
    assert {:ok, _} = verify(message(), p)
    assert_receive :committed
    assert {:ok, 1} = ETS.sweep(ctx.pid, @created + 1000)
  end

  test "invalid cryptography never invokes commitment or stores a replay claim", ctx do
    owner = self()

    p =
      policy(ctx.store, fn f ->
        send(owner, :committed)
        {:ok, f.identifier}
      end)

    [_, encoded] = String.split(vector()["signature"], "=:", parts: 2)
    <<b, rest::binary>> = encoded |> String.trim_trailing(":") |> Base.decode64!()

    bad =
      rewrite(
        message(),
        "signature",
        "sig-b21=:" <> Base.encode64(<<Bitwise.bxor(b, 1), rest::binary>>) <> ":"
      )

    result = verify(bad, p)
    refute_received :committed
    assert :ets.tab2list(:sys.get_state(ctx.pid).table) == [{:count, 0}]
    error(result, :invalid_signature, :crypto)

    assert {:ok, _} = verify(message(), p)
    assert_receive :committed
    assert {:ok, 1} = ETS.sweep(ctx.pid, @created + 1000)
  end

  test "invalid keys freshness digest and HMAC never invoke commitment", ctx do
    owner = self()

    p =
      policy(ctx.store, fn f ->
        send(owner, :committed)
        {:ok, f.identifier}
      end)

    error(verify(message(), %{p | key_resolver: fn _ -> :error end}), :unknown_key, :key)

    error(
      verify(message(), %{p | freshness: %{p.freshness | clock: fn -> @created + 100 end}}),
      :too_old,
      :freshness
    )

    v = Enum.find(@vectors, &(&1["section"] == "B.2.3"))
    m = message(v)
    {:ok, body} = Body.new(%{state: :retained, bytes: "altered actual body"})

    error(
      RequestSeal.verify(
        %{m | body: body},
        %{p | content: %{kind: :content, algorithms: ["sha-512"], section: :headers}},
        label: v["label"]
      ),
      :digest_mismatch,
      :content
    )

    h = Enum.find(@vectors, &(&1["section"] == "B.2.5"))

    p = %{
      p
      | algorithms: ["hmac-sha256"],
        key_resolver: fn _ ->
          {:ok,
           %{
             algorithm: "hmac-sha256",
             key: fn a, b, s -> RequestSeal.Crypto.verify(a, b, s, {:hmac, "wrong secret"}) end
           }}
        end
    }

    error(RequestSeal.verify(message(h), p, label: h["label"]), :invalid_signature, :crypto)
    refute_received :committed
    assert {:ok, 0} = ETS.sweep(ctx.pid, @created + 1000)
  end

  test "policy rejects unbounded malformed ambiguous scope store and timeout", ctx do
    p = policy(ctx.store, fn f -> {:ok, f.identifier} end)
    attrs = Map.from_struct(p)

    for replay <- [
          Map.delete(p.replay, :commitment),
          Map.put(p.replay, :unknown, true),
          %{p.replay | identifier: :challenge},
          %{p.replay | namespace: ""},
          %{p.replay | namespace: String.duplicate("n", 257)},
          %{p.replay | store: struct(Replay.Store, adapter: "wrong", ref: nil)},
          %{p.replay | store: struct(Replay.Store, adapter: Enum, ref: nil)},
          %{p.replay | timeout: 0},
          %{p.replay | timeout: 300_001},
          %{p.replay | commitment: fn -> :error end}
        ] do
      error(Policy.new(%{attrs | replay: replay}), :invalid_policy, :input)
      error(verify(message(), %{p | replay: replay}), :invalid_policy, :input)
    end

    for key <- Map.keys(p.replay) do
      error(Policy.new(%{attrs | replay: Map.delete(p.replay, key)}), :invalid_policy, :input)
    end

    for freshness <- [:not_evaluated, %{p.freshness | max_age: nil}] do
      error(Policy.new(%{attrs | freshness: freshness}), :invalid_policy, :input)
    end

    assert {:ok, _} =
             Policy.new(%{
               attrs
               | replay: %{p.replay | namespace: String.duplicate("n", 256), timeout: 300_000}
             })
  end

  test "exact capacity unavailable owner and boundary validation", ctx do
    {:ok, pid} = ETS.start_link(max_entries: 1)
    store = ETS.store(pid)
    assert :claimed = Replay.claim(store, claim("scope", "one", 100), timeout: 2000)
    assert :already_claimed = Replay.claim(store, claim("scope", "one", 200), timeout: 2000)

    assert {:error, %{reason: :store_full, retryable: false}} =
             Replay.claim(store, claim("scope", "two", 100), timeout: 2000)

    error(
      verify(message(), policy(store, fn f -> {:ok, f.identifier} end)),
      :store_failed,
      :replay
    )

    assert {:ok, 1} = ETS.sweep(pid, 100)
    assert :claimed = Replay.claim(store, claim("scope", "two", 101), timeout: 2000)
    GenServer.stop(pid)

    assert {:error, %{reason: :store_unavailable}} =
             Replay.claim(store, claim("scope", "one", 100), timeout: 2000)

    error(
      verify(message(), policy(store, fn f -> {:ok, f.identifier} end)),
      :store_unavailable,
      :replay
    )

    for invalid <- [
          nil,
          claim("", "key", 100),
          claim("scope", "", 100),
          claim(String.duplicate("n", 257), "key", 100),
          claim("scope", "key", -9_223_372_036_854_775_809),
          claim("scope", "key", 9_223_372_036_854_775_808),
          claim("scope", String.duplicate("k", 257), 100),
          claim("scope", "key", :bad)
        ] do
      assert {:error, %{reason: :invalid_claim}} = Replay.claim(ctx.store, invalid, timeout: 100)
    end

    for opts <- [
          [],
          [timeout: 0],
          [timeout: 300_001],
          [timeout: 10, timeout: 10],
          [timeout: 10, other: true],
          [{:timeout, 1} | :tail]
        ] do
      assert {:error, %{reason: :invalid_options}} =
               Replay.claim(ctx.store, claim("s", "k", 100), opts)
    end

    assert {:error, %{reason: :invalid_store}} =
             Replay.claim(nil, claim("s", "k", 100), timeout: 100)
  end

  test "one shared deadline kills callback and caller death cancels its runner", ctx do
    owner = self()

    fun = fn f ->
      Process.flag(:trap_exit, true)
      send(owner, {:runner, self()})

      receive do
        :continue -> {:ok, f.identifier}
      end
    end

    p = policy(ctx.store, fun)

    assert {:error, %{reason: :store_timeout, layer: :replay}} =
             verify(message(), %{p | replay: %{p.replay | timeout: 30}})

    assert_receive {:runner, expired}
    refute Process.alive?(expired)
    caller = spawn(fn -> verify(message(), p) end)
    assert_receive {:runner, runner}, 1000
    ref = Process.monitor(runner)
    {:monitored_by, [middle]} = Process.info(caller, :monitored_by)
    middle_ref = Process.monitor(middle)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^ref, :process, ^runner, :killed}, 1000
    assert_receive {:DOWN, ^middle_ref, :process, ^middle, _}, 1000
    assert {:ok, 0} = ETS.sweep(ctx.pid, @created + 1000)
    refute_received {_, {:ok, _}}
  end

  test "caller adapter contract violation fails closed after its real ETS operation", ctx do
    store = %{ctx.store | adapter: RequestSeal.ReplayContractViolation}

    error(
      verify(message(), policy(store, fn f -> {:ok, f.identifier} end)),
      :store_failed,
      :replay
    )

    assert {:ok, 1} = ETS.sweep(ctx.pid, @created + 1000)
  end

  test "concurrent capacity reservations and duplicate rollback preserve the exact bound" do
    {:ok, pid} = ETS.start_link(max_entries: 1)
    store = ETS.store(pid)

    results =
      1..64
      |> Task.async_stream(
        fn n -> Replay.claim(store, claim("s", Integer.to_string(n), 100), timeout: 2000) end,
        max_concurrency: 64
      )
      |> Enum.map(fn {:ok, r} -> r end)

    assert Enum.count(results, &(&1 == :claimed)) == 1
    assert Enum.count(results, &match?({:error, %{reason: :store_full}}, &1)) == 63
    assert {:ok, 1} = ETS.sweep(pid, 100)
    assert :claimed = Replay.claim(store, claim("s", "first", 100), timeout: 2000)
    assert :already_claimed = Replay.claim(store, claim("s", "first", 100), timeout: 2000)

    assert {:error, %{reason: :store_full}} =
             Replay.claim(store, claim("s", "second", 100), timeout: 2000)

    GenServer.stop(pid)
    {:ok, roomy} = ETS.start_link(max_entries: 2)
    roomy_store = ETS.store(roomy)
    assert :claimed = Replay.claim(roomy_store, claim("s", "first", 100), timeout: 2000)

    for _ <- 1..8 do
      assert :already_claimed = Replay.claim(roomy_store, claim("s", "first", 100), timeout: 2000)
    end

    assert :claimed = Replay.claim(roomy_store, claim("s", "second", 100), timeout: 2000)
    GenServer.stop(roomy)

    for opts <- [[], [max_entries: 0], [max_entries: 10_000_001], [max_entries: 10, other: true]] do
      assert {:error, :invalid_options} = ETS.start_link(opts)
    end
  end

  test "queued store work honors the expired deadline and never inserts", ctx do
    :sys.suspend(ctx.pid)

    try do
      assert {:error, %{reason: :store_timeout}} =
               Replay.claim(ctx.store, claim("scope", "queued", 100), timeout: 30)
    after
      :sys.resume(ctx.pid)
    end

    assert {:ok, 0} = ETS.sweep(ctx.pid, 100)
    refute_received {_, :claimed}
  end

  test "just inside key and nonce bounds are accepted", ctx do
    m = resign(message(), "", String.duplicate("n", 1024))
    assert {:ok, _} = verify(m, policy(ctx.store, fn _ -> {:ok, String.duplicate("k", 256)} end))

    assert :already_claimed =
             Replay.claim(ctx.store, claim("scope", String.duplicate("k", 256), 100),
               timeout: 2000
             )
  end

  @tag :postgres
  test "Postgres published nonce protects the final accepted second after sweep" do
    alias RequestSeal.Replay.Postgres
    {:ok, _} = Application.ensure_all_started(:postgrex)
    uri = URI.parse(System.fetch_env!("REQUESTSEAL_REPLAY_PG_URL"))
    [username, password] = String.split(uri.userinfo, ":", parts: 2)

    {:ok, conn} =
      Postgrex.start_link(
        hostname: uri.host,
        port: uri.port,
        username: username,
        password: password,
        database: String.trim_leading(uri.path, "/")
      )

    table = "replay_nonce_" <> Integer.to_string(System.unique_integer([:positive]))
    Postgrex.query!(conn, Postgres.ddl(table), [])

    try do
      owner = self()
      store = Postgres.store(conn, table: table)

      p =
        policy(store, fn f ->
          send(owner, :committed)
          {:ok, f.identifier}
        end)

      assert {:ok, r} = verify(message(), p)
      assert r.replay.store == Postgres
      assert r.replay.retain_until == @created + 63
      assert_receive :committed
      last = @created + 62

      context = %RequestSeal.Custody.Context{
        owner: self(),
        deadline: System.monotonic_time(:millisecond) + 2000
      }

      assert {:ok, 0} = Postgres.sweep(store.ref, last, context)
      p = %{p | freshness: %{p.freshness | clock: fn -> last end}}
      error(verify(message(), p), :replayed, :replay)
      assert_receive :committed

      error(
        verify(message(), %{p | freshness: %{p.freshness | clock: fn -> last + 1 end}}),
        :too_old,
        :freshness
      )

      refute_received :committed
      assert {:ok, 1} = Postgres.sweep(store.ref, last + 1, context)
    after
      Postgrex.query!(conn, "DROP TABLE #{table}", [])
      GenServer.stop(conn)
    end
  end

  test "the core application never starts a replay dependency" do
    refute :postgrex in Application.spec(:request_seal, :applications)
    refute :db_connection in Application.spec(:request_seal, :applications)
  end

  defp claim(namespace, key, retain_until),
    do: struct(Replay.Claim, namespace: namespace, key: key, retain_until: retain_until)

  defp context,
    do: %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 2000}

  defp policy(store, commitment) do
    {:ok, public} =
      PublicKey.import(File.read!(Path.join(@root, "crypto/rsa_pss_public.pem")), :pem)

    {:ok, p} =
      Policy.new(%{
        algorithms: ["rsa-pss-sha512"],
        components: "()",
        key_resolver: fn _ -> {:ok, %{algorithm: "rsa-pss-sha512", key: public}} end,
        freshness: %{clock: fn -> @created end, max_age: 60, skew: 2, require_expires: false},
        content: :not_required,
        replay: %{
          identifier: :nonce,
          namespace: "scope",
          commitment: commitment,
          store: store,
          timeout: 2000
        }
      })

    p
  end

  defp vector, do: Enum.find(@vectors, &(&1["section"] == "B.2.1"))

  defp message(v \\ vector()) do
    b = Enum.find(@bases, &(&1["section"] == v["section"]))["message"]
    {:ok, body} = Body.new(%{state: :retained, bytes: ~s[{"hello": "world"}]})
    {:ok, transport} = TransportFacts.new(%{})

    {:ok, m} =
      Message.new(%{
        kind: :request,
        method: b["method"],
        raw_target: b["raw_target"],
        target_form: :origin,
        scheme: b["scheme"],
        authority: b["authority"],
        fields: Enum.map(b["fields"], fn [n, v] -> field(n, v) end),
        body: body,
        transport: transport,
        trailers: :unavailable
      })

    m |> rewrite("signature-input", v["signature_input"]) |> rewrite("signature", v["signature"])
  end

  defp field(n, v) do
    {:ok, f} = FieldOccurrence.new(%{name: n, value: v, section: :headers, provenance: :caller})
    f
  end

  defp rewrite(m, n, v),
    do: %{m | fields: Enum.reject(m.fields, &(String.downcase(&1.name) == n)) ++ [field(n, v)]}

  defp verify(m, p), do: RequestSeal.verify(m, p, label: "sig-b21")

  defp error(result, reason, layer),
    do: assert(match?({:error, %{reason: ^reason, layer: ^layer, retryable: false}}, result))

  # Locally signed mutations test input rules, never external conformance.
  defp resign(m, suffix, nonce \\ "b3k2pp5k7z-50gnwp.yemd") do
    params =
      vector()["signature_input"]
      |> String.split("=", parts: 2)
      |> List.last()
      |> String.replace(
        ~s[;nonce="b3k2pp5k7z-50gnwp.yemd"],
        if(nonce == nil, do: "", else: ~s[;nonce="#{nonce}"])
      )

    m = %{
      m
      | fields:
          Enum.reject(m.fields, &(String.downcase(&1.name) in ["signature-input", "signature"]))
    }

    [entry] = :public_key.pem_decode(File.read!(Path.join(@root, "crypto/rsa_pss_private.pem")))
    key = :public_key.pem_entry_decode(entry) |> elem(0)

    {:ok, signed} =
      RequestSeal.sign(
        m,
        %{label: "sig-b21", signature_input: params <> suffix, algorithm: "rsa-pss-sha512"},
        fn a, b -> RequestSeal.Crypto.sign(a, b, {:rsa, key}) end
      )

    signed
  end
end

# Caller-authored adapter deliberately violates the contract after touching the real store.
# This tests boundary rejection, not a substitute for backend conformance.
defmodule RequestSeal.ReplayContractViolation do
  @behaviour RequestSeal.Replay
  @impl true
  def claim(ref, claim, context) do
    RequestSeal.Replay.ETS.claim(ref, claim, context)
    :ok
  end

  @impl true
  def sweep(ref, now, context), do: RequestSeal.Replay.ETS.sweep(ref, now, context)
end
