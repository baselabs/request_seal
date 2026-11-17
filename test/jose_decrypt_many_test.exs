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
      assert sink.owner == task.pid
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

    for _ <- 1..2 do
      assert_receive {:resolved, resolver, "A256KW"}
      send(resolver, :continue)
    end

    assert {:ok, [{:ok, _}, kw, dh_result, {:ok, _}]} = Task.await(task)
    failure(kw, :decryption_failed, :crypto)
    failure(dh_result, :decryption_failed, :crypto)
    for _ <- 1..2, do: assert_receive({:event, :content_authentication, %{}, %{outcome: :failed}})
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

  test "unwrap callback has no reason bearing library link or monitor", %{items: xs} do
    h = Controlled.start("A256KW", {:aes, @kek}, :all, self())
    on_exit(fn -> Custody.release(h) end)
    task = Task.async(fn -> JWE.decrypt_many(xs, policy(h)) end)
    assert_receive {:batch_holder, holder, runner, _, _, _}
    assert Process.info(runner, :links) == {:links, []}
    assert Process.info(runner, :monitored_by) == {:monitored_by, []}
    monitor = Process.monitor(runner)
    send(holder, :continue)
    assert {:ok, results} = Task.await(task)
    assert Enum.all?(results, &match?({:ok, _}, &1))
    assert_receive {:DOWN, ^monitor, _, ^runner, _}
  end

  test "batch public result remains withheld while custody is stalled", %{items: xs} do
    h = Controlled.start("A256KW", {:aes, @kek}, :stall, self())
    on_exit(fn -> Custody.release(h) end)
    task = Task.async(fn -> JWE.decrypt_many(xs, %{policy(h) | unwrap_timeout: 300}) end)
    assert_receive {:batch_holder, holder, _, _, _, _}
    send(holder, :continue)
    assert_receive {:batch_prefix, ^holder}
    assert Task.yield(task, 0) == nil
    assert {:ok, [{:ok, _}, _, _]} = Task.await(task)
  end

  test "batch caller exit stops callback despite its detached library link", %{items: xs} do
    h = Controlled.start("A256KW", {:aes, @kek}, :all, self())
    on_exit(fn -> Custody.release(h) end)
    task = Task.async(fn -> JWE.decrypt_many(xs, policy(h)) end)
    assert_receive {:batch_holder, _, runner, _, _, _}
    ref = Process.monitor(runner)
    Task.shutdown(task, :brutal_kill)
    assert_receive {:DOWN, ^ref, :process, ^runner, _}
  end

  test "telemetry runs in the caller after all library children end", %{items: xs, p: p} do
    observer = self()
    id = make_ref()

    :telemetry.attach(
      id,
      [:request_seal, :jose, :content_authentication],
      fn _, _, _, _ ->
        send(observer, {:handler_owner, self()})
      end,
      nil
    )

    try do
      task = Task.async(fn -> JWE.decrypt_many(xs, p) end)
      assert {:ok, results} = Task.await(task)
      assert Enum.all?(results, &match?({:ok, _}, &1))

      for _ <- xs do
        assert_receive {:handler_owner, pid}
        assert pid == task.pid
      end
    after
      :telemetry.detach(id)
    end
  end

  test "batch admission unfinished at R has input layer", %{items: [item | _], p: p} do
    assert {:ok, results} =
             JWE.decrypt_many(List.duplicate(item, 10_000), %{p | resolve_timeout: 1})

    assert Enum.any?(results, &(&1 == {:error, Error.new(:deadline_exceeded, :input)}))
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

  test "malformed range item does not stop its neighbours", %{p: p, items: [item | _]} do
    previous = :erlang.system_flag(:schedulers_online, 1)

    try do
      assert {:ok, [{:ok, _}, bad, {:ok, _}]} = JWE.decrypt_many([item, nil, item], p)
      failure(bad, :invalid_serialization)
    after
      :erlang.system_flag(:schedulers_online, previous)
    end
  end

  test "one real range resets the success flag even when fallback authenticates", %{
    items: [item | _],
    handle: handle
  } do
    [protected, ek, iv, ct, tag] = Support.compact(item.token, 5)
    {:ok, [{:ok, cek}]} = Custody.unwrap(handle, [{Support.decode(ek), %{}, 256}])

    token = %{
      h: Header.parse(protected),
      alg: "A256KW",
      enc: "A256GCM",
      protected: protected,
      iv: Support.decode(iv),
      ct: Support.decode(ct),
      tag: Support.decode(tag),
      width_valid: true
    }

    for valid <- [true, false, true] do
      {result, outcome} =
        RequestSeal.JOSE.JWE.Worker.authenticate(
          %{token | width_valid: valid},
          {:ok, cek},
          {:ok, cek},
          %{content: :binary}
        )

      if valid do
        assert {:ok, _} = result
        assert outcome == :ok
      else
        failure(result, :decryption_failed, :crypto)
        assert outcome == :failed
      end
    end
  end
end
