defmodule RequestSeal.CustodyLocalTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog
  require Logger
  alias RequestSeal.{Crypto, Custody, KeyIdentity, PublicKey}
  alias RequestSeal.Custody.Local

  @root Path.join(__DIR__, "fixtures/crypto")
  @vectors :json.decode(File.read!(Path.join(@root, "rfc9421.json")))
  @jwks :json.decode(File.read!(Path.join(__DIR__, "fixtures/custody/rfc7517.json")))
  @ed :json.decode(File.read!(Path.join(__DIR__, "fixtures/custody/rfc8037.json")))

  test "handles sign and verify all seven published RFC 9421 bases" do
    for v <- @vectors do
      assert {:ok, handle} = Local.new(v["algorithm"], material(v["key"]))
      assert handle.algorithm == v["algorithm"]
      assert handle.capabilities == [:sign, :verify]
      assert {:ok, signature} = Custody.sign(handle, v["base"])
      if v["key"] in ~w(rsa hmac ed25519), do: assert(signature == Base.decode64!(v["signature"]))
      assert :ok = Custody.verify(handle, v["base"], signature)
      assert_error(Custody.verify(handle, v["base"] <> "\n", signature), :invalid_signature)

      if v["key"] == "hmac" do
        assert_error(Custody.public_key(handle), :no_public_key)
      else
        assert {:ok, public} = Custody.public_key(handle)
        assert :ok = Crypto.verify(v["algorithm"], v["base"], signature, public)
      end
    end
  end

  test "P-384 and every explicit JWS extension retain algorithm binding" do
    p384 = :json.decode(File.read!(Path.join(@root, "rfc6979.json")))

    for {algorithm, key} <- [
          {"ecdsa-p384-sha384", {:ec, "P-384", Base.decode16!(p384["x"])}}
          | Enum.map(~w(RS256 PS256 PS384 PS512 HS256 ES256 ES384 EdDSA), fn name ->
              key =
                case name do
                  "HS256" -> material("hmac")
                  "ES256" -> material("p256")
                  "ES384" -> {:ec, "P-384", Base.decode16!(p384["x"])}
                  "EdDSA" -> material("ed25519")
                  _ -> material("rsa")
                end

              {{:jws, name}, key}
            end)
        ] do
      assert {:ok, handle} = Local.new(algorithm, key)
      assert {:ok, signature} = Custody.sign(handle, "sample")
      assert :ok = Custody.verify(handle, "sample", signature)
      assert_error(Custody.verify(handle, "test", signature), :invalid_signature)
    end

    assert_error(Local.new("none", material("rsa")), :unsupported_algorithm)
    assert_error(Local.new({:jws, "rs256"}, material("rsa")), :unsupported_algorithm)
  end

  test "four private PEM formats derive only the published public components" do
    for {id, alg} <- [
          {"rsa", "rsa-v1_5-sha256"},
          {"rsa_pss", "rsa-pss-sha512"},
          {"p256", "ecdsa-p256-sha256"},
          {"ed25519", "ed25519"}
        ] do
      assert {:ok, handle} =
               Local.import(alg, File.read!(Path.join(@root, id <> "_private.pem")), :pem)

      assert {:ok, public} = Custody.public_key(handle)

      assert {:ok, expected} =
               PublicKey.import(File.read!(Path.join(@root, id <> "_public.pem")), :pem)

      assert KeyIdentity.normalize(public.material) == KeyIdentity.normalize(expected.material)
      if id == "rsa_pss", do: assert(elem(public.material, 0) == :rsa_pss)
      assert {:ok, sig} = Custody.sign(handle, "sample")
      assert :ok = Crypto.verify(alg, "sample", sig, public)

      assert_error(
        Local.import(alg, File.read!(Path.join(@root, id <> "_public.pem")), :pem),
        :invalid_key
      )
    end

    assert_error(
      Local.import("rsa-v1_5-sha256", File.read!(Path.join(@root, "rsa_pss_private.pem")), :pem),
      :key_mismatch
    )
  end

  test "RFC 5958 v2 Ed25519 containers carrying a public key reject" do
    # RFC 8410 Section 10.3: independently published OneAsymmetricKey example.
    # https://www.rfc-editor.org/rfc/rfc8410.html#section-10.3
    pem = File.read!(Path.join(@root, "rfc8410_10_3_oneasymmetrickey.pem"))

    for algorithm <- ["ed25519", {:jws, "EdDSA"}] do
      assert_error(Local.import(algorithm, pem, :pem), :unsupported_format)
    end
  end

  test "RFC 5958 v2 Ed25519 containers without a public key reject" do
    pem = File.read!(Path.join(@root, "rfc8410_10_3_oneasymmetrickey.pem"))
    [{:PrivateKeyInfo, der, :not_encrypted}] = :public_key.pem_decode(pem)

    # Remove the final [1] public-key BIT STRING (35 bytes) from the RFC 8410
    # example, retain version INTEGER 1 and all other fields, and fix the length.
    <<0x30, 114, fields::binary-size(79), 0x81, 33, 0, _public::binary-size(32)>> = der
    assert <<2, 1, 1, _rest::binary>> = fields
    without_public = <<0x30, byte_size(fields), fields::binary>>
    pem = :public_key.pem_encode([{:PrivateKeyInfo, without_public, :not_encrypted}])

    for algorithm <- ["ed25519", {:jws, "EdDSA"}] do
      assert_error(Local.import(algorithm, pem, :pem), :unsupported_format)
    end
  end

  test "independent private JWKs enforce metadata and public/private agreement" do
    [ec, rsa] = @jwks["keys"]
    assert_error(Local.import("ecdsa-p256-sha256", ec, :jwk), :key_mismatch)
    # RFC 7517 marks this key for encryption. Removing use selects signing locally;
    # the key components themselves remain the independent published bytes.
    assert {:ok, ec_handle} = Local.import("ecdsa-p256-sha256", Map.delete(ec, "use"), :jwk)
    assert {:ok, rsa_handle} = Local.import({:jws, "RS256"}, rsa, :jwk)
    assert {:ok, rsa_public} = Custody.public_key(rsa_handle)
    assert rsa_public.algorithm == "RS256"
    assert {:ok, ed_handle} = Local.import("ed25519", @ed, :jwk)

    for handle <- [ec_handle, rsa_handle, ed_handle] do
      assert {:ok, signature} = Custody.sign(handle, "sample")
      assert :ok = Custody.verify(handle, "sample", signature)
    end

    assert {:ok, signature} =
             Custody.sign(ed_handle, "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc")

    assert Base.url_encode64(signature, padding: false) ==
             "hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"

    for jwk <- [rsa, @ed, Map.delete(ec, "use")] do
      alg =
        case jwk["kty"] do
          "RSA" -> "rsa-v1_5-sha256"
          "EC" -> "ecdsa-p256-sha256"
          "OKP" -> "ed25519"
        end

      assert_error(Local.import(alg, Map.delete(jwk, "d"), :jwk), :invalid_key)
      assert_error(Local.import(alg, Map.put(jwk, "alg", "HS256"), :jwk), :key_mismatch)
      assert_error(Local.import(alg, Map.put(jwk, "key_ops", ["verify"]), :jwk), :key_mismatch)
      assert_error(Local.import(alg, Map.put(jwk, "d", "AA"), :jwk), :invalid_key)
    end

    assert_error(
      Local.import(
        "ed25519",
        Map.put(@ed, "x", Base.url_encode64(<<0::256>>, padding: false)),
        :jwk
      ),
      :invalid_key
    )

    assert_error(Local.import("rsa-v1_5-sha256", Map.put(rsa, "qi", "AQ"), :jwk), :invalid_key)
  end

  test "symmetric identities are supplied never derived and unknown never matches" do
    {:hmac, secret} = material("hmac")

    assert {:ok, first} =
             Local.new("hmac-sha256", {:hmac, secret}, equivalence: "trusted-equivalence")

    assert {:ok, second} =
             Local.import(
               {:jws, "HS256"},
               %{"kty" => "oct", "k" => Base.url_encode64(secret, padding: false)},
               :jwk,
               equivalence: "trusted-equivalence"
             )

    assert {:ok, different} =
             Local.new("hmac-sha256", {:hmac, secret}, equivalence: "other-equivalence")

    assert {:ok, unknown} = Local.new("hmac-sha256", {:hmac, secret})
    assert {:ok, a} = Custody.identity(first)
    assert {:ok, b} = Custody.identity(second)
    assert {:ok, c} = Custody.identity(different)
    assert {:ok, u} = Custody.identity(unknown)
    assert KeyIdentity.same?(a, b)
    refute KeyIdentity.same?(a, c)
    refute KeyIdentity.same?(u, u)
    refute inspect(a) =~ "trusted-equivalence"
    assert a.kind == :symmetric
    assert u.kind == :unknown
    assert {:ok, rsa} = Local.new("rsa-v1_5-sha256", material("rsa"))
    assert {:ok, r} = Custody.identity(rsa)
    assert KeyIdentity.same?(r, %{r | value: put_elem(r.value, 0, :rsa_pss)})
  end

  test "malformed handles options keys and byte limits reject before custody work" do
    {:ok, handle} = Local.new("ed25519", material("ed25519"))

    for opts <- [
          [timeout: :infinity],
          [timeout: 0],
          [timeout: -1],
          [timeout: 300_001],
          [timeout: 1.0],
          [timeout: 20, timeout: 30],
          [unknown: 1],
          nil,
          %{},
          [1]
        ] do
      assert_error(Custody.sign(handle, "", opts), :invalid_options)
      assert_error(Custody.verify(handle, "", <<0>>, opts), :invalid_options)
    end

    for bad <- [
          nil,
          %{},
          %{handle | ref: "private-canary"},
          %{handle | custodian: :not_a_custodian},
          %{handle | capabilities: [:sign, :bad]},
          Map.put(handle, :extra, :value)
        ] do
      assert_error(Custody.sign(bad, ""), :invalid_handle)
    end

    assert_error(Custody.sign(%{handle | capabilities: [:verify]}, ""), :unsupported_operation)

    assert_error(
      Custody.verify(%{handle | capabilities: [:sign]}, "", <<0>>),
      :unsupported_operation
    )

    for bytes <- [nil, [], :binary.copy(<<0>>, 1_048_577)] do
      assert_error(Custody.sign(handle, bytes), :invalid_data)
    end

    assert_error(Custody.verify(handle, "", nil), :invalid_signature)
    assert_error(Custody.verify(handle, "", :binary.copy(<<0>>, 16_385)), :limit)
    assert {:ok, sig} = Custody.sign(handle, :binary.copy(<<0>>, 1_048_576))
    assert :ok = Custody.verify(handle, :binary.copy(<<0>>, 1_048_576), sig)

    for opts <- [
          [equivalence: ""],
          [equivalence: :bad],
          [equivalence: String.duplicate("a", 257)],
          [equivalence: "a", equivalence: "b"],
          [timeout: 1]
        ] do
      assert_error(Local.new("hmac-sha256", material("hmac"), opts), :invalid_options)
    end

    assert_error(Local.new("ed25519", material("ed25519"), equivalence: "a"), :invalid_options)
    assert_error(Local.new("ed25519", material("p256")), :key_mismatch)
    {:rsa, rsa} = material("rsa")

    for index <- 4..9 do
      assert_error(
        Local.new("rsa-v1_5-sha256", {:rsa, put_elem(rsa, index, elem(rsa, index) + 2)}),
        :invalid_key
      )
    end

    assert_error(Local.import("ed25519", "bad", :unknown), :unsupported_format)
  end

  test "encrypted containers are rejected and secret canaries never escape inspection errors or logs" do
    secret = "custody-private-canary-with-enough-entropy"
    {:ok, handle} = Local.new("hmac-sha256", {:hmac, secret})
    {:ok, identity} = Custody.identity(handle)

    for value <- [
          handle,
          identity,
          Custody.public_key(handle),
          Local.new("ed25519", {:hmac, secret})
        ] do
      refute inspect(value) =~ secret
      refute inspect(value, structs: false, limit: :infinity) =~ secret
    end

    assert inspect(handle) =~ "RequestSeal.KeyHandle"
    refute inspect(handle) =~ "ref:"
    assert inspect(handle, structs: false) =~ "#Function"

    assert capture_log(fn -> Logger.warning("custody-log-positive-probe") end) =~
             "custody-log-positive-probe"

    # Malformed caller reference triggers an actual Local callback exception.
    crashing = %{handle | ref: fn -> raise secret end}

    output =
      capture_log(fn ->
        assert_error(Custody.sign(crashing, ""), :custodian_failure)
        assert_error(Custody.public_key(crashing), :custodian_failure)
        assert_error(Custody.identity(crashing), :custodian_failure)
      end)

    refute output =~ secret
    {:error, error} = Custody.sign(crashing, "")
    refute Exception.format(:error, error, []) =~ secret

    assert inspect(Custody.public_key(handle), structs: false) ==
             inspect(
               {:error,
                struct(RequestSeal.Custody.Error, reason: :no_public_key, retryable: false)},
               structs: false
             )
  end

  @tag :holder
  test "local handle serialization excludes private material" do
    secret = "custody-serialization-canary-with-enough-entropy"
    assert :erlang.term_to_binary({:hmac, secret}) =~ secret
    assert {:ok, handle} = Local.new("hmac-sha256", {:hmac, secret})
    refute :erlang.term_to_binary(handle) =~ secret
    assert {:ok, signature} = Custody.sign(handle, "sample")
    assert :ok = Custody.verify(handle, "sample", signature)

    {:rsa, private} = material("rsa")
    <<131, rsa_canary::binary>> = :erlang.term_to_binary(elem(private, 4))
    assert :erlang.term_to_binary(private) =~ rsa_canary

    for alg <- ~w(RSA-OAEP RSA-OAEP-256) do
      assert {:ok, handle} = Local.new({:jwe, alg}, {:rsa, private})
      refute :erlang.term_to_binary(handle) =~ rsa_canary
      assert :ok = Local.release(handle)
    end
  end

  @tag :holder
  test "every function reachable from a local handle excludes private material" do
    secret = "custody-function-canary-" <> Base.encode16(:crypto.strong_rand_bytes(16))
    positive = fn -> secret end
    assert :erlang.term_to_binary(:erlang.fun_info(positive)) =~ secret
    assert {:ok, handle} = Local.new("hmac-sha256", {:hmac, secret})

    for fun <- reachable_functions(handle) do
      refute :erlang.term_to_binary(:erlang.fun_info(fun)) =~ secret
    end

    {:rsa, private} = material("rsa")
    <<131, rsa_canary::binary>> = :erlang.term_to_binary(elem(private, 4))
    positive = fn -> private end
    assert :erlang.term_to_binary(:erlang.fun_info(positive)) =~ rsa_canary

    for alg <- ~w(RSA-OAEP RSA-OAEP-256) do
      assert {:ok, handle} = Local.new({:jwe, alg}, {:rsa, private})

      for fun <- reachable_functions(handle) do
        refute :erlang.term_to_binary(:erlang.fun_info(fun)) =~ rsa_canary
      end

      assert :ok = Local.release(handle)
    end
  end

  @tag :holder
  test "sensitive holder hides its dictionary and queued messages" do
    secret = "custody-process-canary-with-enough-entropy"
    parent = self()

    positive =
      spawn(fn ->
        Process.put(:positive_probe, secret)
        send(parent, {:positive_ready, self()})

        receive do
          :stop -> :ok
        end
      end)

    try do
      assert_receive {:positive_ready, ^positive}
      send(positive, {:positive_message, secret})
      assert :erlang.term_to_binary(Process.info(positive, :dictionary)) =~ secret
      assert :erlang.term_to_binary(Process.info(positive, :messages)) =~ secret
    after
      send(positive, :stop)
    end

    assert {:ok, handle} = Local.new("hmac-sha256", {:hmac, secret})
    holder = holder(handle)
    assert :erlang.suspend_process(holder)

    try do
      # Probe while an operation is queued, not just an idle empty mailbox.
      caller = Task.async(fn -> Custody.sign(handle, "sample") end)
      send(holder, {:introspection_probe, secret})
      info = Process.info(holder, [:dictionary, :messages])
      assert info == [dictionary: [], messages: []]
      refute :erlang.term_to_binary(info) =~ secret
      :erlang.resume_process(holder)
      assert {:ok, signature} = Task.await(caller)
      assert :ok = Custody.verify(handle, "sample", signature)
    after
      if Process.info(holder, :status) == {:status, :suspended},
        do: :erlang.resume_process(holder)
    end
  end

  @tag :holder
  test "holder rejects sys state status and replacement introspection" do
    secret = "custody-sys-canary-with-enough-entropy"
    # An actual OTP process proves that sys introspection can expose state.
    {:ok, positive} = Agent.start(fn -> secret end)

    try do
      assert :erlang.term_to_binary(:sys.get_state(positive)) =~ secret
    after
      Agent.stop(positive)
    end

    assert {:ok, handle} = Local.new("hmac-sha256", {:hmac, secret})
    holder = holder(handle)
    parent = self()

    assert :sys.get_status(holder, 200) == {:error, :unsupported_operation}

    for operation <- [
          fn -> :sys.get_state(holder, 200) end,
          fn ->
            :sys.replace_state(
              holder,
              fn state -> send(parent, {:exported_state, state}) end,
              200
            )
          end
        ] do
      error = assert_raise ErlangError, operation
      assert error.original == :unsupported_operation
      refute :erlang.term_to_binary(error) =~ secret
    end

    refute_receive {:exported_state, _}, 50
    assert {:ok, _} = Custody.sign(handle, "sample")
  end

  @tag :holder
  test "holder exits when its creator dies even after handle transfer" do
    parent = self()

    creator =
      spawn(fn ->
        {:ok, handle} = Local.new("ed25519", material("ed25519"))
        send(parent, {:created_handle, handle})

        receive do
          :stop -> :ok
        end
      end)

    try do
      assert_receive {:created_handle, handle}, 1_000
      holder = holder(handle)
      monitor = Process.monitor(holder)
      assert {:ok, _} = Custody.sign(handle, "sample")
      send(creator, :stop)
      assert_receive {:DOWN, ^monitor, :process, ^holder, :normal}, 1_000
      assert_error(Custody.sign(handle, "sample"), :key_not_found)
    after
      Process.exit(creator, :kill)
    end
  end

  @tag :holder
  @tag :holder2_token
  test "holder tokens are 32-byte binaries and a PID alone cannot authorize operations" do
    assert {:ok, handle} = Local.new("ed25519", material("ed25519"))
    {pid, token} = handle.ref.()
    assert is_binary(token) and byte_size(token) == 32
    <<first, rest::binary>> = token
    wrong = <<Bitwise.bxor(first, 1), rest::binary>>

    for candidate <- [wrong, make_ref(), <<>>, binary_part(token, 0, 31), token <> <<0>>] do
      attacker =
        Task.async(fn ->
          reply = :erlang.alias()

          try do
            context = %RequestSeal.Custody.Context{
              owner: self(),
              deadline: System.monotonic_time(:millisecond) + 1_000
            }

            send(pid, {:request, candidate, self(), reply, context, {:sign, "ed25519", "sample"}})
            send(pid, {:release, candidate})
            # This response proves the holder consumed the preceding messages.
            assert :sys.get_status(pid, 1_000) == {:error, :unsupported_operation}
            refute_receive {^reply, _}, 20

            forged = %RequestSeal.KeyHandle{
              custodian: Local,
              algorithm: "ed25519",
              capabilities: [:sign, :verify],
              ref: fn -> {pid, candidate} end
            }

            reason =
              if is_binary(candidate) and byte_size(candidate) == 32,
                do: :deadline_exceeded,
                else: :invalid_handle

            result = Custody.sign(forged, "sample", timeout: 100)
            assert_error(result, reason)

            {forged, result}
          after
            :erlang.unalias(reply)
          end
        end)

      {forged, result} = Task.await(attacker, 2_000)

      for value <- [handle, forged, result], structs <- [true, false] do
        output = inspect(value, structs: structs, limit: :infinity)
        refute output =~ inspect(pid)
        refute output =~ inspect(token)
        refute output =~ inspect(candidate)
      end

      assert Process.alive?(pid)
      assert {:ok, signature} = Custody.sign(handle, "sample")
      assert :ok = Custody.verify(handle, "sample", signature)
    end

    assert :ok = Local.release(handle)
    IO.puts("TOKEN: 32-byte token; wrong binary, ref, and lengths rejected; real handle signs")
  end

  @tag :holder
  @tag :holder2_lifecycle
  test "a live creator releases every holder and returns the process count to baseline" do
    parent = self()
    key = material("hmac")
    count = 256

    creator =
      spawn(fn ->
        send(parent, {:creator_ready, self()})

        receive do
          :create -> :ok
        end

        handles =
          for _ <- 1..count do
            {:ok, handle} = Local.new("hmac-sha256", key)
            handle
          end

        send(parent, {:holders_created, Enum.map(handles, &holder/1)})

        receive do
          :release -> :ok
        end

        for handle <- handles, do: :ok = Local.release(handle)
        send(parent, :holders_released)

        receive do
          :stop -> :ok
        end
      end)

    try do
      assert_receive {:creator_ready, ^creator}, 1_000
      baseline = MapSet.new(Process.list())
      send(creator, :create)
      assert_receive {:holders_created, holders}, 5_000
      holder_set = MapSet.new(holders)
      assert MapSet.size(holder_set) == count
      assert Enum.all?(holders, &Process.alive?/1)
      active = MapSet.new(Process.list())
      assert MapSet.difference(active, baseline) == holder_set
      assert MapSet.size(active) == MapSet.size(baseline) + count
      monitors = Enum.map(holders, &Process.monitor/1)
      send(creator, :release)
      assert_receive :holders_released, 5_000

      for {pid, monitor} <- Enum.zip(holders, monitors),
          do: assert_receive({:DOWN, ^monitor, :process, ^pid, :normal}, 1_000)

      assert Process.alive?(creator)
      released = MapSet.new(Process.list())
      assert MapSet.disjoint?(released, holder_set)
      assert released == baseline

      IO.puts(
        "LIFECYCLE: processes #{MapSet.size(baseline)} -> #{MapSet.size(active)} -> " <>
          "#{MapSet.size(released)}; holders #{count} -> 0; creator alive"
      )
    after
      Process.exit(creator, :kill)
    end
  end

  @tag :holder
  test "release exits only its holder and signing after release is bounded" do
    assert {:ok, handle} = Local.new("ed25519", material("ed25519"))
    assert {:ok, other} = Local.new("ed25519", material("ed25519"))
    holder = holder(handle)
    monitor = Process.monitor(holder)
    assert :ok = Local.release(handle)
    assert_receive {:DOWN, ^monitor, :process, ^holder, :normal}, 1_000
    refute Process.alive?(holder)
    start = System.monotonic_time(:millisecond)
    assert_error(Custody.sign(handle, "sample", timeout: 300), :key_not_found)
    assert System.monotonic_time(:millisecond) - start < 1_000
    assert :ok = Local.release(handle)
    assert {:ok, _} = Custody.sign(other, "sample")

    assert_error(
      Local.release(%{handle | custodian: RequestSeal.Custody.SSHAgent}),
      :invalid_handle
    )
  end

  test "queued holder requests respect custody deadlines and caller cancellation" do
    assert {:ok, handle} = Local.new("ed25519", material("ed25519"))
    holder = holder(handle)
    parent = self()
    original = handle.ref

    observed = %{
      handle
      | ref: fn ->
          send(parent, {:queued_runner, self()})

          receive do
            :continue -> original.()
          end
        end
    }

    for mode <- [:deadline, :cancellation] do
      assert :erlang.suspend_process(holder)
      caller = Task.async(fn -> Custody.sign(observed, "sample", timeout: 300) end)

      try do
        assert_receive {:queued_runner, runner}, 1_000
        monitor = Process.monitor(runner)
        {:message_queue_len, queued} = Process.info(holder, :message_queue_len)
        send(runner, :continue)
        await_queued_request(holder, queued)

        if mode == :deadline do
          assert_error(Task.await(caller, 1_000), :deadline_exceeded)
        else
          Task.shutdown(caller, :brutal_kill)
        end

        assert_receive {:DOWN, ^monitor, :process, ^runner, reason}, 1_000
        assert reason in if(mode == :deadline, do: [:normal, :killed], else: [:killed])
        assert Process.alive?(holder)
      after
        Task.shutdown(caller, :brutal_kill)
        :erlang.resume_process(holder)
      end

      assert {:ok, signature} = Custody.sign(handle, "sample")
      assert :ok = Custody.verify(handle, "sample", signature)
      refute_receive {:DOWN, _, :process, _, _}, 20
    end
  end

  defp holder(handle) do
    assert {pid, token} = handle.ref.()
    assert is_pid(pid)
    assert is_binary(token) and byte_size(token) == 32
    pid
  end

  defp reachable_functions(fun) when is_function(fun) do
    {:env, env} = :erlang.fun_info(fun, :env)
    [fun | reachable_functions(env)]
  end

  defp reachable_functions(map) when is_map(map),
    do: map |> Map.to_list() |> reachable_functions()

  defp reachable_functions(tuple) when is_tuple(tuple),
    do: tuple |> Tuple.to_list() |> reachable_functions()

  defp reachable_functions(list) when is_list(list),
    do: Enum.flat_map(list, &reachable_functions/1)

  defp reachable_functions(_), do: []

  test "owner monitoring precedes the linked runner and caller death leaves no custody processes" do
    assert {:ok, handle} = Local.new("ed25519", material("ed25519"))
    test_pid = self()
    original = handle.ref

    delayed = %{
      handle
      | ref: fn ->
          Process.flag(:trap_exit, true)
          send(test_pid, {:blocked_runner, self()})

          receive do
            :continue -> original.()
          end
        end
    }

    before = MapSet.new(Process.list())
    caller = spawn(fn -> Custody.sign(delayed, "sample", timeout: 5_000) end)
    caller_ref = Process.monitor(caller)

    try do
      assert_receive {:blocked_runner, runner}, 1_000
      runner_ref = Process.monitor(runner)
      {:monitored_by, observers} = Process.info(caller, :monitored_by)
      # Exclude this test's own monitor when identifying the cancellation process.
      cancellation_monitors = observers -- [self()]
      assert length(cancellation_monitors) == 1
      [middle] = cancellation_monitors
      assert {:links, [^middle]} = Process.info(runner, :links)

      for pid <- [middle, runner] do
        assert :erlang.suspend_process(pid)

        try do
          send(pid, {:sensitivity_probe, make_ref()})
          assert Process.info(pid, :messages) == {:messages, []}
        after
          :erlang.resume_process(pid)
        end
      end

      assert {:trap_exit, true} = Process.info(middle, :trap_exit)
      assert {:monitors, monitors} = Process.info(middle, :monitors)
      assert {:process, caller} in monitors
      assert {:links, links} = Process.info(caller, :links)
      refute middle in links
      refute runner in links

      custody_processes = MapSet.new([caller, middle, runner])
      assert MapSet.disjoint?(before, custody_processes)
      active = MapSet.new(Process.list())
      assert MapSet.difference(active, before) == custody_processes
      assert MapSet.size(MapSet.intersection(active, custody_processes)) == 3
      middle_ref = Process.monitor(middle)
      Process.exit(caller, :kill)
      assert_receive {:DOWN, ^caller_ref, :process, ^caller, :killed}, 1_000
      assert_receive {:DOWN, ^runner_ref, :process, ^runner, :killed}, 1_000
      assert_receive {:DOWN, ^middle_ref, :process, ^middle, _}, 1_000
      after_death = MapSet.new(Process.list())
      assert MapSet.size(MapSet.intersection(after_death, custody_processes)) == 0
      assert MapSet.size(MapSet.difference(after_death, before)) == 0

      IO.puts(
        "OWNER DEATH: processes #{MapSet.size(before)} -> #{MapSet.size(active)} -> " <>
          "#{MapSet.size(after_death)}; custody 3 -> 0"
      )
    after
      Process.exit(caller, :kill)
    end
  end

  test "real encrypted PEMs PKCS8 containers and malformed imports retain their boundaries" do
    dir =
      Path.join(
        System.tmp_dir!(),
        "c-pem-" <> Integer.to_string(System.unique_integer([:positive]))
      )

    File.mkdir!(dir)
    File.chmod!(dir, 0o700)

    try do
      for {id, algorithm} <- [{"rsa", "rsa-v1_5-sha256"}, {"p256", "ecdsa-p256-sha256"}] do
        original = Path.join(@root, id <> "_private.pem")
        encrypted = Path.join(dir, id <> "-encrypted.pem")
        converted = Path.join(dir, id <> "-pkcs8.pem")

        assert {_, 0} =
                 System.cmd(
                   "openssl",
                   [
                     "pkcs8",
                     "-topk8",
                     "-in",
                     original,
                     "-out",
                     encrypted,
                     "-passout",
                     "pass:custody-container-canary"
                   ],
                   stderr_to_stdout: true
                 )

        assert_no_call(:public_key, :pem_decode, 1, fn ->
          assert_error(Local.import(algorithm, File.read!(encrypted), :pem), :unsupported_format)
        end)

        assert {_, 0} =
                 System.cmd(
                   "openssl",
                   ["pkcs8", "-topk8", "-nocrypt", "-in", original, "-out", converted],
                   stderr_to_stdout: true
                 )

        assert {:ok, handle} = Local.import(algorithm, File.read!(converted), :pem)
        assert {:ok, sig} = Custody.sign(handle, "sample")
        assert :ok = Custody.verify(handle, "sample", sig)
      end
    after
      File.rm_rf!(dir)
    end

    pem = File.read!(Path.join(@root, "ed25519_private.pem"))

    for bad <- [pem <> pem, nil, :binary.copy(<<0>>, 16_385), "invalid"] do
      assert_error(Local.import("ed25519", bad, :pem), :invalid_key)
    end

    for bad <- [
          Map.put(@ed, "x", @ed["x"] <> "="),
          Map.put(@ed, "alg", nil),
          Map.put(@ed, "use", nil),
          Map.put(@ed, "key_ops", nil),
          Map.put(@ed, "key_ops", ["sign", "sign"]),
          Map.merge(@ed, Map.new(1..33, &{Integer.to_string(&1), "public"})),
          Map.put(@ed, "oth", []),
          Map.put(@ed, "d", String.duplicate("a", 21_847))
        ] do
      assert_error(Local.import("ed25519", bad, :jwk), :invalid_key)
    end

    assert {:ok, signing} = Local.import("ed25519", Map.put(@ed, "key_ops", ["sign"]), :jwk)
    assert signing.capabilities == [:sign]
    assert {:ok, signing_public} = Custody.public_key(signing)
    assert signing_public.operations == ["sign"]
    assert {:ok, _} = Custody.sign(signing, "sample")

    assert_error(
      Custody.verify(%{signing | capabilities: [:sign, :verify]}, "sample", <<0>>),
      :unsupported_operation
    )

    assert_error(Local.new("ed25519", %PublicKey{}), :invalid_key)
  end

  test "bound algorithms and worker monitor messages do not escape completed local operations" do
    {:ok, handle} = Local.new("ed25519", material("ed25519"))
    assert_error(Custody.sign(%{handle | algorithm: {:jws, "EdDSA"}}, "sample"), :key_mismatch)

    assert_error(
      Custody.verify(%{handle | algorithm: {:jws, "EdDSA"}}, "sample", <<0>>),
      :key_mismatch
    )

    for _ <- 1..100, do: assert({:ok, _} = Custody.sign(handle, "sample"))
    Process.sleep(20)
    refute_receive {:DOWN, _, :process, _, _}, 50
  end

  test "custody deadlines terminate an actual local callback blocked before OTP signing" do
    {:ok, handle} = Local.new("ed25519", material("ed25519"))
    owner = self()
    original = handle.ref
    # Schedule the real Local callback at its reference read. The continuation
    # uses the original published key and actual OTP cryptography, never a reply double.
    delayed = %{
      handle
      | ref: fn ->
          send(owner, {:local_worker, self()})

          receive do
            :continue -> original.()
          end
        end
    }

    caller = Task.async(fn -> Custody.sign(delayed, "sample", timeout: 60) end)
    assert_receive {:local_worker, worker}, 1_000
    monitor = Process.monitor(worker)
    assert_error(Task.await(caller, 1_000), :deadline_exceeded)
    assert_receive {:DOWN, ^monitor, :process, ^worker, :killed}, 1_000
    assert {:ok, _} = Custody.sign(handle, "sample")
  end

  test "oversized data rejects before reading an actual secret-bearing reference" do
    {:ok, handle} = Local.new("ed25519", material("ed25519"))
    owner = self()
    original = handle.ref

    observed = %{
      handle
      | ref: fn ->
          send(owner, :private_reference_read)
          original.()
        end
    }

    assert_error(Custody.sign(observed, :binary.copy(<<0>>, 1_048_577)), :invalid_data)
    refute_receive :private_reference_read, 50
  end

  test "completed operations drain replayed copies of their actual worker result" do
    {:ok, handle} = Local.new("ed25519", material("ed25519"))
    owner = self()
    original = handle.ref

    delayed = %{
      handle
      | ref: fn ->
          send(owner, {:local_worker, self()})

          receive do
            :continue -> original.()
          end
        end
    }

    caller =
      Task.async(fn ->
        result = Custody.sign(delayed, "sample")

        receive do
          :collect -> {result, Process.info(self(), :messages)}
        end
      end)

    assert_receive {:local_worker, worker}, 1_000
    assert :erlang.suspend_process(caller.pid)

    try do
      send(worker, :continue)
      packet = await_worker_result(caller.pid)
      # Replay the real worker's nonce-tagged result, not an invented response.
      send(caller.pid, packet)
    after
      :erlang.resume_process(caller.pid)
    end

    send(caller.pid, :collect)
    assert {{:ok, signature}, {:messages, []}} = Task.await(caller, 1_000)
    assert :ok = Custody.verify(handle, "sample", signature)
  end

  test "PSS-only private imports reject before invoking the private primitive" do
    pem = File.read!(Path.join(@root, "rsa_pss_private.pem"))

    assert_no_call(Crypto, :sign, 3, fn ->
      assert_error(Local.import("rsa-v1_5-sha256", pem, :pem), :key_mismatch)
    end)
  end

  defp await_worker_result(pid, remaining \\ 100)
  defp await_worker_result(_, 0), do: flunk("actual worker did not produce a result")

  defp await_worker_result(pid, remaining) do
    {:messages, messages} = Process.info(pid, :messages)

    case Enum.find(messages, fn
           {ref, {:ok, bytes}} -> is_reference(ref) and is_binary(bytes)
           _ -> false
         end) do
      nil ->
        Process.sleep(10)
        await_worker_result(pid, remaining - 1)

      packet ->
        packet
    end
  end

  defp await_queued_request(holder, queued, attempts \\ 100)
  defp await_queued_request(_, _, 0), do: flunk("holder did not receive the real signing request")

  defp await_queued_request(holder, queued, attempts) do
    if Process.info(holder, :message_queue_len) == {:message_queue_len, queued} do
      Process.sleep(1)
      await_queued_request(holder, queued, attempts - 1)
    else
      assert Process.info(holder, :message_queue_len) == {:message_queue_len, queued + 1}
    end
  end

  defp assert_no_call(module, function, arity, operation) do
    task =
      Task.async(fn ->
        receive do
          :run -> operation.()
        end
      end)

    {:module, ^module} = Code.ensure_loaded(module)
    1 = :erlang.trace_pattern({module, function, arity}, true, [])
    :erlang.trace(task.pid, true, [:call, :arity])

    try do
      send(task.pid, :run)
      Task.await(task, 1_000)
      Process.sleep(20)
      refute_receive {:trace, _, :call, {^module, ^function, ^arity}}, 50

      args =
        case {module, function} do
          {Crypto, :sign} -> ["ed25519", "", material("ed25519")]
          {:public_key, :pem_decode} -> [File.read!(Path.join(@root, "ed25519_public.pem"))]
        end

      positive =
        Task.async(fn ->
          receive do
            :probe -> apply(module, function, args)
          end
        end)

      :erlang.trace(positive.pid, true, [:call, :arity])
      send(positive.pid, :probe)
      Task.await(positive, 1_000)
      assert_receive {:trace, _, :call, {^module, ^function, ^arity}}, 1_000
    after
      :erlang.trace_pattern({module, function, arity}, false, [])
    end
  end

  test "custody fixture hashes account for all extracted public artifacts" do
    root = Path.join(__DIR__, "fixtures/custody")
    lines = File.read!(Path.join(root, "SHA256SUMS")) |> String.split("\n", trim: true)
    assert length(lines) == 2

    for line <- lines do
      [hash, name] = String.split(line, "  ")

      assert Base.encode16(:crypto.hash(:sha256, File.read!(Path.join(root, name))), case: :lower) ==
               hash
    end

    assert Enum.sort(Enum.map(lines, &(String.split(&1, "  ") |> List.last()))) ==
             Enum.sort(File.ls!(root) -- ["SHA256SUMS"])
  end

  defp material("hmac"),
    do: {:hmac, Base.decode64!(String.trim(File.read!(Path.join(@root, "hmac.txt"))))}

  defp material(id) do
    [entry] = :public_key.pem_decode(File.read!(Path.join(@root, id <> "_private.pem")))

    case :public_key.pem_entry_decode(entry) do
      {:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = key -> {:rsa, key}
      {{:RSAPrivateKey, _, _, _, _, _, _, _, _, _, _} = key, _} -> {:rsa, key}
      {:ECPrivateKey, _, seed, {:namedCurve, {1, 3, 101, 112}}, _, _} -> {:ed25519, seed}
      {:ECPrivateKey, _, scalar, _, _, _} -> {:ec, "P-256", scalar}
    end
  end

  defp assert_error(result, reason) do
    assert {:error, error} = result
    assert error.__struct__ == RequestSeal.Custody.Error
    assert error.reason == reason
    assert error.retryable == reason in [:deadline_exceeded, :custodian_unavailable]
  end
end
