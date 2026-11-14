defmodule RequestSeal.JOSEDecryptManyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties
  alias RequestSeal.{Custody, JOSE}
  alias JOSE.{Error, Header, JWE, KeyManagement, Support}
  alias RequestSeal.Test.JOSEBatchCustodian, as: Controlled
  @kek Base.decode16!("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")

  setup do
    {:ok, handle} = Custody.Local.new({:jwe, "A256KW"}, {:aes, @kek})
    on_exit(fn -> Custody.release(handle) end)

    tokens =
      for i <- 0..2 do
        {:ok, t} =
          JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}, {"page", i}], "payload#{i}", handle)

        %{token: t, expected: %{"page" => i}}
      end

    {:ok, handle: handle, items: tokens, p: policy(handle)}
  end

  defp policy(handle) do
    %{
      algorithms: ["A256KW"],
      encryption: ["A256GCM"],
      max_plaintext: 1_048_576,
      max_tokens: 10_000,
      max_total_input: 67_108_864,
      max_total_plaintext: 67_108_864,
      timeout: 5000,
      resolve_timeout: 1000,
      unwrap_timeout: 1000,
      protected: %{permitted: []},
      key_resolver: fn %{algorithm: a} -> {:ok, %{algorithm: a, key: handle}} end
    }
  end

  defp single(p, expected),
    do:
      p
      |> Map.drop([:max_tokens, :max_total_input, :max_total_plaintext])
      |> Map.put(:protected, %{expected: expected, permitted: p.protected.permitted})

  defp failure(r, reason, layer \\ :input), do: assert(r == {:error, Error.new(reason, layer)})

  defp observe do
    id = make_ref()

    :ok =
      :telemetry.attach_many(
        id,
        [
          [:request_seal, :jose, :decrypt_many],
          [:request_seal, :jose, :content_authentication],
          [:request_seal, :custody, :unwrap]
        ],
        fn e, m, md, pid -> send(pid, {:event, List.last(e), m, md}) end,
        self()
      )

    on_exit(fn -> :telemetry.detach(id) end)
  end

  test "batch empty list returns empty positional results", %{p: p} do
    assert JWE.decrypt_many([], p) == {:ok, []}
  end

  test "batch nonlist and improper list are outer invalid_serialization", %{p: p} do
    for xs <- [nil, %{}, "token", [1 | 2]],
        do: failure(JWE.decrypt_many(xs, p), :invalid_serialization)
  end

  test "batch exact policy keys and all positive resource bounds", %{p: p, items: xs} do
    for k <- Map.keys(p), do: failure(JWE.decrypt_many(xs, Map.delete(p, k)), :invalid_policy)
    failure(JWE.decrypt_many(xs, Map.put(p, :extra, true)), :invalid_policy)

    for {k, upper} <- [
          max_tokens: 10_000,
          max_total_input: 67_108_864,
          max_total_plaintext: 67_108_864
        ],
        v <- [0, upper + 1, :infinity] do
      failure(JWE.decrypt_many(xs, Map.put(p, k, v)), :invalid_policy)
    end
  end

  test "batch protected policy is exactly permitted with unique nonreserved names", %{
    p: p,
    items: xs
  } do
    for protected <- [
          nil,
          %{},
          %{permitted: [], expected: %{}},
          %{permitted: ["x", "x"]},
          %{permitted: ["epk"]},
          %{permitted: [:x]}
        ] do
      failure(JWE.decrypt_many(xs, %{p | protected: protected}), :invalid_policy)
    end
  end

  for {name, expected} <- [
        {"reserved key", %{"alg" => "A256KW"}},
        {"too many keys", Map.new(1..65, &{"x#{&1}", 0})},
        {"too many bytes", %{"x" => String.duplicate("x", 16_384)}},
        {"non JSON value", %{"x" => :atom}}
      ] do
    test "batch item expected #{name} is positional invalid_policy", %{p: p, items: [item | _]} do
      assert {:ok, [result]} =
               JWE.decrypt_many([%{item | expected: unquote(Macro.escape(expected))}], p)

      failure(result, :invalid_policy)
    end
  end

  test "batch strict budget sum refuses equality and above and largest accepted sum completes", %{
    p: p,
    items: xs
  } do
    for t <- [1999, 2000], do: failure(JWE.decrypt_many(xs, %{p | timeout: t}), :invalid_policy)

    assert {:ok, results} =
             JWE.decrypt_many(xs, %{
               p
               | timeout: 300_000,
                 resolve_timeout: 149_999,
                 unwrap_timeout: 150_000
             })

    assert Enum.all?(results, &match?({:ok, _}, &1))
  end

  test "batch outer limits include serialized expectations and actual total ciphertext before resolver",
       %{p: p, items: xs} do
    owner = self()

    p = %{
      p
      | key_resolver: fn _ ->
          send(owner, :resolved)
          :error
        end
    }

    for limited <- [
          %{p | max_tokens: 2},
          %{p | max_total_input: Enum.sum(Enum.map(xs, &byte_size(&1.token)))},
          %{p | max_total_plaintext: 23}
        ] do
      failure(JWE.decrypt_many(xs, limited), :limit)
      refute_receive :resolved
    end
  end

  test "batch malformed items and invalid expectations are positional", %{p: p, items: [good | _]} do
    bad = [nil, %{token: good.token}, Map.put(good, :extra, 1), %{good | expected: []}]
    assert {:ok, results} = JWE.decrypt_many(bad ++ [good], p)

    assert Enum.take(results, 3) ==
             List.duplicate({:error, Error.new(:invalid_serialization, :input)}, 3)

    failure(Enum.at(results, 3), :invalid_policy)
    assert {:ok, _} = List.last(results)
  end

  test "single and batch malformed handle capabilities authenticate as item failures", %{
    p: p,
    handle: h,
    items: xs
  } do
    observe()

    for capabilities <- [[:sign | :invalid], [:unwrap | :invalid], nil, %{}] do
      invalid = %{h | capabilities: capabilities}

      resolver = fn request ->
        key = if request.header["page"] == 1, do: invalid, else: h
        {:ok, %{algorithm: request.algorithm, key: key}}
      end

      assert {:ok, [a, b, c]} = JWE.decrypt_many(xs, %{p | key_resolver: resolver})
      assert {:ok, %{plaintext: "payload0"}} = a
      failure(b, :decryption_failed, :crypto)
      assert {:ok, %{plaintext: "payload2"}} = c

      outcomes =
        for _ <- 1..3 do
          assert_receive {:event, :content_authentication, measurements, metadata}
          assert measurements == %{}
          assert Map.keys(metadata) == [:outcome]
          metadata.outcome
        end

      assert Enum.sort(outcomes) == [:failed, :ok, :ok]
      item = Enum.at(xs, 1)

      failure(
        JWE.decrypt(item.token, single(%{p | key_resolver: resolver}, item.expected)),
        :decryption_failed,
        :crypto
      )

      assert_receive {:event, :content_authentication, %{}, %{outcome: :failed}}
      refute_receive {:event, :content_authentication, _, _}
    end
  end

  test "batch binds every item before grouping even when a mismatched handle can recover its CEK",
       %{p: p, handle: h, items: [good | _]} do
    observe()
    cek = :crypto.strong_rand_bytes(32)
    iv = :crypto.strong_rand_bytes(12)
    {protected, _} = Header.serialize([{"alg", "A128KW"}, {"enc", "A256GCM"}, {"page", 1}])
    # The tag is valid, but the claimed A128KW key is actually wrapped with the
    # neighbouring A256KW handle. Grouping must never substitute its algorithm.
    {:ok, %{encrypted_key: ek}} = KeyManagement.wrap("A256KW", cek, %{}, {:aes, @kek})

    {ct, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, cek, iv, "wrong binding", protected, 16, true)

    token =
      Enum.join(
        [protected, Support.b64(ek), Support.b64(iv), Support.b64(ct), Support.b64(tag)],
        "."
      )

    bad = %{token: token, expected: %{"page" => 1}}

    p = %{
      p
      | algorithms: ["A128KW", "A256KW"],
        key_resolver: fn request -> {:ok, %{algorithm: request.algorithm, key: h}} end
    }

    failure(JWE.decrypt(bad.token, single(p, bad.expected)), :decryption_failed, :crypto)
    assert_receive {:event, :content_authentication, %{}, %{outcome: :failed}}

    for items <- [[good, bad], [bad, good]] do
      assert {:ok, results} = JWE.decrypt_many(items, p)

      for {item, result} <- Enum.zip(items, results) do
        if item == bad,
          do: failure(result, :decryption_failed, :crypto),
          else: assert(match?({:ok, %{plaintext: "payload0"}}, result))
      end

      assert_receive {:event, :unwrap, %{duration: _, items: 1}, %{}}

      outcomes =
        for _ <- 1..2 do
          assert_receive {:event, :content_authentication, measurements, metadata}
          assert measurements == %{}
          assert Map.keys(metadata) == [:outcome]
          metadata.outcome
        end

      assert Enum.sort(outcomes) == [:failed, :ok]
    end
  end

  test "batch forged token among good ones and one custody round trip", %{p: p, items: xs} do
    observe()

    forged =
      update_in(
        xs,
        [Access.at(1), :token],
        &RequestSeal.JOSEVectors.replace(&1, 4, Support.b64(<<0::128>>))
      )

    assert {:ok, [a, b, c]} = JWE.decrypt_many(forged, p)
    assert {:ok, %{plaintext: "payload0"}} = a
    failure(b, :decryption_failed, :crypto)
    assert {:ok, %{plaintext: "payload2"}} = c
    assert_receive {:event, :unwrap, measurements, metadata}
    assert Enum.sort(Map.keys(measurements)) == [:duration, :items]
    assert is_integer(measurements.duration) and measurements.items == 3
    assert metadata == %{}
    refute_receive {:event, :unwrap, _, _}

    assert_receive {:event, :decrypt_many, measurements, metadata}
    assert measurements == %{count: 3, groups: 1, failed: 1, deadline_exceeded: 0}
    assert metadata == %{}

    events =
      for _ <- 1..3 do
        assert_receive {:event, :content_authentication, measurements, metadata}
        assert measurements == %{}
        assert Map.keys(metadata) == [:outcome]
        metadata.outcome
      end

    assert Enum.sort(events) == [:failed, :ok, :ok]
  end

  test "batch resolver blocked past R fails key while other results survive", %{
    p: p,
    handle: h,
    items: xs
  } do
    owner = self()

    p = %{
      p
      | resolve_timeout: 200,
        key_resolver: fn %{header: header, algorithm: a} ->
          if header["page"] == 1 do
            send(owner, {:blocked, self()})
            receive do: (:never -> :error)
          else
            {:ok, %{algorithm: a, key: h}}
          end
        end
    }

    task = Task.async(fn -> JWE.decrypt_many(xs, p) end)
    assert_receive {:blocked, pid}
    mon = Process.monitor(pid)
    assert {:ok, [{:ok, _}, middle, {:ok, _}]} = Task.await(task)
    failure(middle, :key_resolver_failed, :key)
    assert_receive {:DOWN, ^mon, _, ^pid, _}
  end

  for mode <- [:partial_error, :stall] do
    test "batch #{mode} preserves delivered prefix and authenticates unsettled items", %{
      items: xs
    } do
      observe()
      h = Controlled.start("A256KW", {:aes, @kek}, unquote(mode), self())
      on_exit(fn -> Custody.release(h) end)
      p = %{policy(h) | unwrap_timeout: 250}
      task = Task.async(fn -> JWE.decrypt_many(xs, p) end)
      assert_receive {:batch_holder, holder, _, sink, _, 3}
      # The coordinator, rather than an intermediate collector, owns each sink.
      assert is_pid(sink.owner) and sink.owner != task.pid
      send(holder, :continue)
      assert_receive {:batch_prefix, ^holder}
      assert {:ok, [first, second, third]} = Task.await(task)
      assert {:ok, %{plaintext: "payload0"}} = first
      failure(second, :decryption_failed, :crypto)
      failure(third, :decryption_failed, :crypto)
      for _ <- 1..3, do: assert_receive({:event, :content_authentication, %{}, %{outcome: _}})
      refute_receive {:event, :content_authentication, _, _}
      assert_receive {:event, :unwrap, %{duration: duration, items: 3}, %{}}
      assert is_integer(duration)
      refute_receive {:event, :unwrap, _, _}
    end
  end

  for count <- [1, 3] do
    test "unwrap telemetry survives cancellation with #{count} delivered-or-pending items", %{
      items: xs
    } do
      observe()
      h = Controlled.start("A256KW", {:aes, @kek}, :stubborn, self())
      on_exit(fn -> Custody.release(h) end)

      task =
        Task.async(fn ->
          JWE.decrypt_many(Enum.take(xs, unquote(count)), %{policy(h) | unwrap_timeout: 300})
        end)

      assert_receive {:batch_holder, holder, runner, _, _, unquote(count)}
      monitor = Process.monitor(runner)
      send(holder, :continue)
      assert {:ok, [first | rest]} = Task.await(task, 10_000)
      assert {:ok, %{plaintext: "payload0"}} = first
      for result <- rest, do: failure(result, :decryption_failed, :crypto)
      assert_receive {:DOWN, ^monitor, _, ^runner, _}
      assert_receive {:event, :unwrap, %{duration: duration, items: unquote(count)}, %{}}
      assert is_integer(duration) and duration >= 0
      refute_receive {:event, :unwrap, _, _}
    end
  end

  test "batch width failures skip resolvers and run AEAD while resolver is blocked", %{
    items: [a, b, c],
    handle: h
  } do
    observe()
    {public, _scalar} = :crypto.generate_key(:ecdh, :x25519)
    {:ok, public} = RequestSeal.PublicKey.import({:x25519, public}, :raw)
    {:ok, direct} = JWE.encrypt([{"alg", "ECDH-ES"}, {"enc", "A256GCM"}], "direct", public)
    owner = self()

    p = %{
      policy(h)
      | algorithms: ["A256KW", "ECDH-ES"],
        key_resolver: fn request ->
          send(owner, {:resolved, self(), request.algorithm})
          receive do: (:continue -> {:ok, %{algorithm: request.algorithm, key: h}})
        end
    }

    bad_kw = %{b | token: RequestSeal.JOSEVectors.replace(b.token, 1, Support.b64(<<0::256>>))}
    bad_direct = %{token: RequestSeal.JOSEVectors.replace(direct, 1, "AA"), expected: %{}}
    task = Task.async(fn -> JWE.decrypt_many([a, bad_kw, bad_direct, c], p) end)
    assert_receive {:event, :content_authentication, %{}, %{outcome: :failed}}
    assert_receive {:event, :content_authentication, %{}, %{outcome: :failed}}

    for _ <- 1..2 do
      assert_receive {:resolved, resolver, "A256KW"}
      send(resolver, :continue)
    end

    assert {:ok, [{:ok, _}, kw, dh_result, {:ok, _}]} = Task.await(task)
    failure(kw, :decryption_failed, :crypto)
    failure(dh_result, :decryption_failed, :crypto)
    refute_receive {:resolved, _, _}
  end

  test "batch two handles one released mid batch preserves the other group", %{
    items: xs,
    handle: h
  } do
    controlled = Controlled.start("A256KW", {:aes, @kek}, :all, self())
    on_exit(fn -> Custody.release(controlled) end)

    p = %{
      policy(h)
      | key_resolver: fn %{header: header} ->
          {:ok, %{algorithm: "A256KW", key: if(header["page"] == 1, do: controlled, else: h)}}
        end
    }

    task = Task.async(fn -> JWE.decrypt_many(xs, p) end)
    assert_receive {:batch_holder, _, _, _, _, 1}
    assert :ok = Custody.release(controlled)
    assert {:ok, [{:ok, _}, middle, {:ok, _}]} = Task.await(task)
    failure(middle, :decryption_failed, :crypto)
  end

  test "unwrap callback is a directly tracked coordinator child with no nested runners", %{
    items: xs
  } do
    h = Controlled.start("A256KW", {:aes, @kek}, :all, self())
    on_exit(fn -> Custody.release(h) end)
    task = Task.async(fn -> JWE.decrypt_many(xs, policy(h)) end)
    assert_receive {:batch_holder, holder, runner, sink, _, _}
    {:links, links} = Process.info(runner, :links)
    assert sink.owner in links
    monitor = Process.monitor(runner)
    send(holder, :continue)
    assert {:ok, results} = Task.await(task)
    assert Enum.all?(results, &match?({:ok, _}, &1))
    assert_receive {:DOWN, ^monitor, _, ^runner, _}
    refute Process.alive?(runner)
  end

  test "lost unwrap watcher is retired before normal finalization and preserves accepted prefix",
       %{
         items: xs
       } do
    observe()
    h = Controlled.start("A256KW", {:aes, @kek}, :stall, self())
    on_exit(fn -> Custody.release(h) end)
    p = %{policy(h) | timeout: 30_000, resolve_timeout: 5000, unwrap_timeout: 10_000}
    task = Task.async(fn -> JWE.decrypt_many(xs, p) end)

    try do
      assert_receive {:batch_holder, holder, runner, sink, _, 3}
      on_exit(fn -> if Process.alive?(sink.owner), do: Process.exit(sink.owner, :kill) end)
      {:monitored_by, monitors} = Process.info(runner, :monitored_by)
      [watcher] = List.delete(monitors, sink.owner)
      tracked = children(sink.owner)
      refs = for pid <- tracked, do: {pid, Process.monitor(pid)}
      send(holder, :continue)
      assert_receive {:event, :content_authentication, %{}, %{outcome: :ok}}
      Process.exit(watcher, :kill)

      assert {:ok, [{:ok, %{plaintext: "payload0"}}, second, third]} = Task.await(task, 10_000)
      failure(second, :decryption_failed, :crypto)
      failure(third, :decryption_failed, :crypto)

      for {pid, ref} <- refs do
        assert_receive {:DOWN, ^ref, :process, ^pid, _}
        refute Process.alive?(pid)
      end
    after
      Task.shutdown(task, :brutal_kill)
    end
  end

  test "batch no plaintext reaches caller mailbox before finalization", %{items: xs} do
    observe()
    h = Controlled.start("A256KW", {:aes, @kek}, :stall, self())
    on_exit(fn -> Custody.release(h) end)
    task = Task.async(fn -> JWE.decrypt_many(xs, %{policy(h) | unwrap_timeout: 300}) end)
    assert_receive {:batch_holder, holder, _, _, _, _}
    send(holder, :continue)
    assert_receive {:batch_prefix, ^holder}
    assert_receive {:event, :content_authentication, %{}, %{outcome: :ok}}
    assert Process.info(task.pid, :messages) == {:messages, []}
    assert {:ok, [{:ok, _}, _, _]} = Task.await(task)
  end

  test "batch caller exit stops coordinator and all active workers", %{items: xs} do
    h = Controlled.start("A256KW", {:aes, @kek}, :all, self())
    on_exit(fn -> Custody.release(h) end)
    task = Task.async(fn -> JWE.decrypt_many(xs, policy(h)) end)
    assert_receive {:batch_holder, _, runner, sink, _, _}
    monitors = for pid <- [runner, sink.owner], do: {pid, Process.monitor(pid)}
    Task.shutdown(task, :brutal_kill)
    for {pid, monitor} <- monitors, do: assert_receive({:DOWN, ^monitor, _, ^pid, _})
  end

  test "caller death cancels tracked children while unwrap telemetry and AEAD both block", %{
    items: [item | _],
    p: p
  } do
    observer = self()
    id = make_ref()

    :ok =
      :telemetry.attach_many(
        id,
        [[:request_seal, :custody, :unwrap], [:request_seal, :jose, :content_authentication]],
        fn event, _, _, _ ->
          {:links, links} = Process.info(self(), :links)
          send(observer, {:blocked_event, List.last(event), self(), links})
          receive do: (:never -> :ok)
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(id) end)
    task = Task.async(fn -> JWE.decrypt_many([item], %{p | timeout: 300_000}) end)
    assert_receive {:blocked_event, :unwrap, _, [coordinator]}
    assert_receive {:blocked_event, :content_authentication, _, _}
    tracked = children(coordinator)
    monitors = for pid <- [coordinator | tracked], do: {pid, Process.monitor(pid)}
    Task.shutdown(task, :brutal_kill)

    for {pid, ref} <- monitors do
      assert_receive {:DOWN, ^ref, _, ^pid, _}
      refute Process.alive?(pid)
    end
  end

  test "batch cancellation stops every concurrent resolver and its coordinator", %{
    items: xs,
    p: p
  } do
    owner = self()

    p = %{
      p
      | key_resolver: fn _ ->
          sensitive = Process.flag(:sensitive, true)
          send(owner, {:resolver_wait, self(), sensitive})
          receive do: (:never -> :error)
        end
    }

    task = Task.async(fn -> JWE.decrypt_many(xs, p) end)

    resolvers =
      for _ <- 1..3 do
        assert_receive {:resolver_wait, pid, true}
        {pid, Process.monitor(pid)}
      end

    [{pid, _} | _] = resolvers
    {:links, [coordinator]} = Process.info(pid, :links)
    monitor = Process.monitor(coordinator)
    Task.shutdown(task, :brutal_kill)
    assert_receive {:DOWN, ^monitor, _, ^coordinator, _}
    for {pid, monitor} <- resolvers, do: assert_receive({:DOWN, ^monitor, _, ^pid, _})
  end

  test "batch AEAD pool is bounded and sensitive", %{items: [item | _], p: p} do
    count = System.schedulers_online()
    items = List.duplicate(item, count + 2)
    owner = self()
    id = make_ref()

    :ok =
      :telemetry.attach(
        id,
        [:request_seal, :jose, :content_authentication],
        fn _, _, _, _ ->
          sensitive = Process.flag(:sensitive, true)
          send(owner, {:pool_worker, self(), sensitive})
          receive do: (:continue -> :ok)
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(id) end)
    task = Task.async(fn -> JWE.decrypt_many(items, %{p | timeout: 20_000}) end)

    workers =
      for _ <- 1..count do
        assert_receive {:pool_worker, pid, true}
        pid
      end

    refute_receive {:pool_worker, _, _}
    Enum.each(workers, &send(&1, :continue))

    for _ <- 1..2 do
      assert_receive {:pool_worker, pid, true}
      send(pid, :continue)
    end

    assert {:ok, results} = Task.await(task)
    assert length(results) == count + 2
    assert Enum.all?(results, &match?({:ok, _}, &1))
  end

  test "batch completed results survive queued worker DOWN signals", %{items: xs, p: p} do
    owner = self()
    id = make_ref()

    :ok =
      :telemetry.attach(
        id,
        [:request_seal, :jose, :content_authentication],
        fn _, _, _, _ ->
          {:links, [coordinator]} = Process.info(self(), :links)
          send(owner, {:completed_aead, self(), coordinator})
          receive do: (:continue -> :ok)
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(id) end)
    task = Task.async(fn -> JWE.decrypt_many(xs, p) end)

    workers =
      for _ <- 1..3 do
        assert_receive {:completed_aead, pid, coordinator}
        {pid, Process.monitor(pid), coordinator}
      end

    [{_, _, coordinator} | _] = workers
    assert :erlang.suspend_process(coordinator)

    try do
      for {pid, _, _} <- workers do
        send(pid, :continue)
        send(pid, :stop)
      end

      for {pid, ref, _} <- workers, do: assert_receive({:DOWN, ^ref, _, ^pid, :normal})
    after
      :erlang.resume_process(coordinator)
    end

    assert {:ok, results} = Task.await(task)
    assert Enum.all?(results, &match?({:ok, _}, &1))
  end

  test "batch large admission tail expires at R with input layer", %{items: [item | _], p: p} do
    xs = List.duplicate(item, 10_000)
    assert {:ok, results} = JWE.decrypt_many(xs, %{p | resolve_timeout: 1})
    assert Enum.any?(results, &(&1 == {:error, Error.new(:deadline_exceeded, :input)}))
  end

  test "batch AEAD response past D keeps completed results and marks crypto deadline", %{
    items: xs,
    p: p
  } do
    # A synchronous telemetry handler delays an actual AEAD response, never fakes crypto.
    owner = self()
    id = make_ref()

    :ok =
      :telemetry.attach(
        id,
        [:request_seal, :jose, :content_authentication],
        fn _, _, _, _ ->
          send(owner, {:aead_returned, self()})
          receive do: (:finish -> :ok)
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(id) end)

    task =
      Task.async(fn ->
        JWE.decrypt_many(xs, %{p | timeout: 600, resolve_timeout: 100, unwrap_timeout: 100})
      end)

    assert_receive {:aead_returned, worker}
    mon = Process.monitor(worker)
    assert {:ok, results} = Task.await(task)
    assert Enum.all?(results, &(&1 == {:error, Error.new(:deadline_exceeded, :crypto)}))
    assert_receive {:DOWN, ^mon, _, ^worker, _}
  end

  test "batch coordinator past F returns outer deadline and cancels workers", %{items: xs} do
    h = Controlled.start("A256KW", {:aes, @kek}, :all, self())
    on_exit(fn -> Custody.release(h) end)
    p = %{policy(h) | timeout: 600, resolve_timeout: 100, unwrap_timeout: 100}
    task = Task.async(fn -> JWE.decrypt_many(xs, p) end)
    assert_receive {:batch_holder, _, runner, sink, _, _}
    monitor = Process.monitor(runner)
    assert :erlang.suspend_process(sink.owner)

    try do
      failure(Task.await(task), :deadline_exceeded, :crypto)
      assert_receive {:DOWN, ^monitor, _, ^runner, _}
    after
      if Process.alive?(sink.owner), do: :erlang.resume_process(sink.owner)
    end
  end

  property "batch equivalence with single decrypt without deadline or custody lifecycle changes",
           %{items: xs, p: p} do
    check all(count <- integer(1..3), forged <- boolean(), mismatch <- boolean(), max_runs: 100) do
      items =
        xs
        |> Enum.take(count)
        |> Enum.map(fn item ->
          item =
            if forged,
              do: %{
                item
                | token: RequestSeal.JOSEVectors.replace(item.token, 4, Support.b64(<<0::128>>))
              },
              else: item

          if mismatch, do: %{item | expected: %{"page" => 100}}, else: item
        end)

      singles = Enum.map(items, &JWE.decrypt(&1.token, single(p, &1.expected)))
      assert JWE.decrypt_many(items, p) == {:ok, singles}
    end
  end

  test "batch real large AEAD work exhausts the one ms reserve and keeps the completed prefix" do
    observe()
    {:ok, wrapping} = Custody.Local.new({:jwe, "A256KW"}, {:aes, @kek})
    on_exit(fn -> Custody.release(wrapping) end)

    {:ok, token} =
      JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], :binary.copy(<<0>>, 700_000), wrapping)

    items = for _ <- 0..63, do: %{token: token, expected: %{}}
    holder_handle = Controlled.start("A256KW", {:aes, @kek}, :stall, self())
    on_exit(fn -> Custody.release(holder_handle) end)
    owner = self()

    p = %{
      policy(holder_handle)
      | timeout: 3301,
        resolve_timeout: 3000,
        unwrap_timeout: 300,
        key_resolver: fn request ->
          send(owner, {:large_resolver, self()})
          receive do: (:continue -> {:ok, %{algorithm: request.algorithm, key: holder_handle}})
        end
    }

    task = Task.async(fn -> JWE.decrypt_many(items, p) end)
    # Keep one real resolver past R so U ends one ms before D; release the rest.
    assert_receive {:large_resolver, blocked}

    for _ <- 1..63 do
      assert_receive {:large_resolver, pid}
      send(pid, :continue)
    end

    assert_receive {:batch_holder, holder, _, _, _, 63}
    send(holder, :continue)
    assert_receive {:event, :content_authentication, %{}, %{outcome: :ok}}
    assert {:ok, results} = Task.await(task, 10_000)
    assert Enum.any?(results, &match?({:ok, _}, &1))
    assert Enum.any?(results, &(&1 == {:error, Error.new(:deadline_exceeded, :crypto)}))
    refute Process.alive?(blocked)
  end

  # Inspect the real process tree. Sensitive processes retain their links and
  # initial_call metadata; no keys, messages or dictionaries are inspected.
  defp children(coordinator) do
    {:links, links} = Process.info(coordinator, :links)
    Enum.filter(links, &is_pid/1)
  end

  defp admission_workers(coordinator) do
    Enum.filter(children(coordinator), fn pid ->
      Process.info(pid, :initial_call) ==
        {:initial_call, {RequestSeal.JOSE.JWE.Open, :admission_worker, 4}}
    end)
  end

  defp held_admission(p, items) do
    observer = self()
    table = :ets.new(:admission_gate, [:public])
    on_exit(fn -> if :ets.info(table) != :undefined, do: :ets.delete(table) end)
    resolver = p.key_resolver

    p = %{
      p
      | key_resolver: fn request ->
          if :ets.insert_new(table, {:first, true}) do
            {:links, [coordinator]} = Process.info(self(), :links)
            :erlang.suspend_process(coordinator)

            workers =
              Enum.reduce(admission_workers(coordinator), [], fn pid, held ->
                try do
                  :erlang.suspend_process(pid)
                  [pid | held]
                rescue
                  ArgumentError -> held
                end
              end)

            send(observer, {:admission_held, coordinator, self(), workers})
            receive do: (:handoff -> :ok)
            for pid <- workers, do: :erlang.resume_process(pid)
            :erlang.resume_process(coordinator)
            send(observer, :admission_transferred)
          end

          send(observer, {:admission_resolver, self()})
          receive do: (:continue -> :ok)
          resolver.(request)
        end
    }

    earliest_r = System.monotonic_time(:millisecond) + p.resolve_timeout
    task = Task.async(fn -> JWE.decrypt_many(items, p) end)
    assert_receive {:admission_held, coordinator, resolver_pid, workers}
    # Suspension belongs to the suspending process. Acquire our own holds
    # before the resolver releases its holds or exits.
    :erlang.suspend_process(coordinator)
    for pid <- workers, do: :erlang.suspend_process(pid)
    send(resolver_pid, :handoff)
    assert_receive :admission_transferred
    on_exit(fn -> if Process.alive?(coordinator), do: Process.exit(coordinator, :kill) end)
    {task, coordinator, resolver_pid, workers, earliest_r}
  end

  defp finish_admission_task(task) do
    ref = task.ref

    receive do
      {:admission_resolver, pid} ->
        send(pid, :continue)
        finish_admission_task(task)

      {^ref, result} ->
        Process.demonitor(ref, [:flush])
        result
    after
      20_000 -> flunk("batch did not finalize")
    end
  end

  defp slow_admissions(handle, p) do
    {:ok, token} =
      JWE.encrypt(
        [{"alg", "A256KW"}, {"enc", "A256GCM"}, {"padding", String.duplicate("p", 12_000)}],
        "range item",
        handle
      )

    {List.duplicate(%{token: token, expected: %{}}, 1024),
     %{p | protected: %{permitted: ["padding"]}, timeout: 15_000, resolve_timeout: 5000}}
  end

  defp until_deadline(ms) do
    ref = make_ref()
    Process.send_after(self(), ref, ms)
    receive do: (^ref -> :ok)
  end

  test "admission outcome dequeued after R is rejected even when sent before R", %{
    p: p,
    handle: h
  } do
    {items, p} = slow_admissions(h, p)
    p = %{p | resolve_timeout: 5000}
    {task, coordinator, resolver, workers, earliest_r} = held_admission(p, items)
    assert workers != []
    accepted = length(children(coordinator)) - length(admission_workers(coordinator))
    assert accepted > 0 and accepted < length(items)
    # Workers finish and send their outcomes while the owner is suspended.
    # DOWN establishes completion; the envelopes remain queued at the owner.
    for pid <- workers do
      monitor = Process.monitor(pid)
      if Process.alive?(pid), do: :erlang.resume_process(pid)
      assert_receive {:DOWN, ^monitor, _, ^pid, _}
    end

    assert System.monotonic_time(:millisecond) < earliest_r
    until_deadline(5100)
    send(resolver, :continue)
    :erlang.resume_process(coordinator)
    assert {:ok, results} = Task.await(task, 20_000)

    assert Enum.count(results, &(&1 == {:error, Error.new(:deadline_exceeded, :input)})) ==
             length(items) - accepted

    assert Enum.count(results, &(&1 == {:error, Error.new(:key_resolver_failed, :key)})) ==
             accepted

    refute Enum.any?(results, &match?({:ok, _}, &1))
  end

  test "admission duplicates and outcomes outside a worker range cannot change settlement", %{
    p: p,
    handle: h
  } do
    previous = :erlang.system_flag(:schedulers_online, 1)

    try do
      {items, p} = slow_admissions(h, p)
      {task, coordinator, resolver, [worker], _} = held_admission(p, items)
      poisoned = {:error, Error.new(:protected_mismatch, :input)}
      send(coordinator, {:admitted, worker, 0, poisoned})
      send(coordinator, {:admitted, worker, -1, poisoned})
      send(coordinator, {:admitted, worker, 1024, poisoned})
      send(coordinator, {:admitted, self(), 1, poisoned})
      send(resolver, :continue)
      :erlang.resume_process(coordinator)
      :erlang.resume_process(worker)
      assert {:ok, results} = finish_admission_task(task)
      assert length(results) == 1024
      assert Enum.all?(results, &match?({:ok, _}, &1))
    after
      :erlang.system_flag(:schedulers_online, previous)
    end
  end

  test "admission worker killed mid-item leaves its unaccepted indices at input deadline", %{
    p: p,
    handle: h
  } do
    {items, p} = slow_admissions(h, p)
    {task, coordinator, resolver, active, _} = held_admission(p, items)
    assert active != []
    # Only workers still processing their range are killed; idle range owners
    # are kept. Neighbouring ranges and accepted admissions must survive.
    for pid <- active, do: Process.exit(pid, :kill)
    send(resolver, :continue)
    :erlang.resume_process(coordinator)
    assert {:ok, results} = finish_admission_task(task)
    assert length(results) == length(items)
    assert Enum.any?(results, &(&1 == {:error, Error.new(:deadline_exceeded, :input)}))
    assert Enum.any?(results, &match?({:ok, _}, &1))
  end

  test "admitted item whose resolver cannot start before R skips callback and fails key", %{
    p: p,
    items: [item | _]
  } do
    observer = self()
    [protected | _] = Support.compact(item.token, 5)
    header = Header.parse(protected)
    request = %{algorithm: "A256KW", encryption: "A256GCM", header: header}

    resolver = fn r ->
      send(observer, :callback_invoked)
      p.key_resolver.(r)
    end

    # A real resolver worker held before its entry point starts. Expiry must
    # prevent the callback even when this worker has never been scheduled.
    deadline = System.monotonic_time(:millisecond) - 1

    pid =
      spawn(fn ->
        receive do
          :start ->
            RequestSeal.JOSE.JWE.Open.resolver_worker(observer, 0, request, resolver, deadline)
        end
      end)

    send(pid, :start)
    assert_receive {:resolved, ^pid, 0, result}
    failure(result, :key_resolver_failed, :key)
    refute_receive :callback_invoked
  end

  test "late admissions sharing an earlier resolved handle form exactly one custody call", %{
    p: p,
    handle: h
  } do
    observe()
    {items, p} = slow_admissions(h, p)
    {task, coordinator, resolver, active, _} = held_admission(p, items)
    assert active != []
    send(resolver, :continue)
    :erlang.resume_process(coordinator)
    # Free the accepted prefix's resolvers while later range items cannot be
    # admitted. Only after that gap can the remaining range owners continue.
    ref = make_ref()
    Process.send_after(self(), ref, 100)

    release = fn release ->
      receive do
        {:admission_resolver, pid} ->
          send(pid, :continue)
          release.(release)

        ^ref ->
          :ok
      end
    end

    release.(release)
    refute_receive {:event, :unwrap, _, _}, 0
    for pid <- active, do: :erlang.resume_process(pid)
    assert {:ok, results} = finish_admission_task(task)
    assert Enum.all?(results, &match?({:ok, _}, &1))
    assert_receive {:event, :unwrap, %{items: 1024}, %{}}
    refute_receive {:event, :unwrap, _, _}
  end

  for ending <- [:normal, :deadline, :caller_death] do
    test "no live child including idle pool workers after #{ending}", %{p: p, items: [item | _]} do
      observer = self()
      id = make_ref()

      :ok =
        :telemetry.attach(
          id,
          [:request_seal, :jose, :content_authentication],
          fn _, _, _, _ ->
            {:links, [coordinator]} = Process.info(self(), :links)
            send(observer, {:at_authentication, self(), coordinator})
            receive do: (:continue -> :ok)
          end,
          nil
        )

      on_exit(fn -> :telemetry.detach(id) end)
      p = %{p | timeout: 5000, resolve_timeout: 1000, unwrap_timeout: 1000}
      task = Task.async(fn -> JWE.decrypt_many([item, item], p) end)
      assert_receive {:at_authentication, idle, coordinator}
      assert_receive {:at_authentication, busy, ^coordinator}
      send(idle, :continue)
      await_idle(idle)
      tracked = children(coordinator)
      assert idle in tracked and busy in tracked
      monitors = for pid <- tracked, do: {pid, Process.monitor(pid)}

      case unquote(ending) do
        :normal ->
          send(busy, :continue)
          assert {:ok, [{:ok, _}, {:ok, _}]} = Task.await(task, 10_000)

        :deadline ->
          assert {:ok, results} = Task.await(task, 10_000)
          assert Enum.count(results, &match?({:ok, _}, &1)) == 1

          assert Enum.count(results, &(&1 == {:error, Error.new(:deadline_exceeded, :crypto)})) ==
                   1

        :caller_death ->
          Task.shutdown(task, :brutal_kill)
      end

      for {pid, ref} <- monitors do
        assert_receive {:DOWN, ^ref, _, ^pid, _}
        refute Process.alive?(pid)
      end
    end
  end

  defp await_idle(pid, attempts \\ 100_000)
  defp await_idle(_, 0), do: flunk("worker did not become idle")

  defp await_idle(pid, attempts) do
    if Process.info(pid, :current_function) ==
         {:current_function, {RequestSeal.JOSE.JWE.Open, :authentication_loop, 1}} do
      :ok
    else
      :erlang.yield()
      await_idle(pid, attempts - 1)
    end
  end

  test "malformed item inside an admission worker range does not stop its neighbours", %{
    p: p,
    items: [item | _]
  } do
    # One range on one scheduler proves both neighbours share the malformed
    # item's exception boundary owner, without relying on page partition size.
    previous = :erlang.system_flag(:schedulers_online, 1)

    try do
      assert {:ok, [{:ok, _}, bad, {:ok, _}]} = JWE.decrypt_many([item, nil, item], p)
      failure(bad, :invalid_serialization)
    after
      :erlang.system_flag(:schedulers_online, previous)
    end
  end

  test "multi-item AEAD worker resets success flag around a width-failed item", %{
    p: p,
    handle: handle,
    items: [item | _]
  } do
    previous = :erlang.system_flag(:schedulers_online, 1)
    observer = self()
    id = make_ref()

    :ok =
      :telemetry.attach(
        id,
        [:request_seal, :jose, :content_authentication],
        fn _, _, md, _ ->
          send(observer, {:same_worker, self(), md.outcome})
        end,
        nil
      )

    try do
      bad = %{item | token: RequestSeal.JOSEVectors.replace(item.token, 1, "AA")}
      assert {:ok, [{:ok, _}, failed, {:ok, _}]} = JWE.decrypt_many([item, bad, item], p)
      failure(failed, :decryption_failed, :crypto)

      events =
        for _ <- 1..3 do
          assert_receive {:same_worker, pid, outcome}
          {pid, outcome}
        end

      assert events |> Enum.map(&elem(&1, 0)) |> Enum.uniq() |> length() == 1
      assert Enum.sort(Enum.map(events, &elem(&1, 1))) == [:failed, :ok, :ok]

      # Exercise valid / width-failed / valid in that exact order in ONE real
      # worker. Its prepared fallback deliberately equals the actual CEK: the
      # middle AEAD authenticates, so only a fresh per-item flag can reject it.
      [protected, ek, iv, ct, tag] = Support.compact(item.token, 5)
      {:ok, [{:ok, cek}]} = Custody.unwrap(handle, [{Support.decode(ek), %{}, 256}])

      token = %{
        h: Header.parse(protected),
        alg: "A256KW",
        protected: protected,
        iv: Support.decode(iv),
        ct: Support.decode(ct),
        tag: Support.decode(tag),
        width_valid: true,
        fallback: cek
      }

      {worker, monitor} =
        spawn_monitor(fn -> RequestSeal.JOSE.JWE.Open.authentication_worker(observer) end)

      try do
        for {index, valid} <- [{0, true}, {1, false}, {2, true}] do
          send(worker, {:authenticate, index, %{token | width_valid: valid}, {:ok, cek}})
          assert_receive {:authenticated, ^worker, ^index, result}

          if valid,
            do: assert(match?({:ok, _}, result)),
            else: failure(result, :decryption_failed, :crypto)

          assert_receive {:same_worker, ^worker, outcome}
          assert outcome == if(valid, do: :ok, else: :failed)
        end
      after
        Process.exit(worker, :kill)
        assert_receive {:DOWN, ^monitor, _, ^worker, _}
      end
    after
      :telemetry.detach(id)
      :erlang.system_flag(:schedulers_online, previous)
    end
  end
end
