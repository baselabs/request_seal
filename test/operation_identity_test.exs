defmodule RequestSeal.OperationIdentityTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Custody.Local, Idempotency, Journal, Message, Policy, Replay}

  @now 1_760_000_000
  @components ~s[("@method" "@target-uri" "content-digest" "idempotency-key")]

  setup do
    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, signer} = Local.new("ed25519", {:ed25519, seed})
    {:ok, key} = RequestSeal.Custody.public_key(signer)
    on_exit(fn -> Local.release(signer) end)
    %{signer: signer, key: key}
  end

  test "a new signed attempt recovers the response and a changed body conflicts", ctx do
    journal = start_supervised!({Journal, max_entries: 2})
    store = start_supervised!({Idempotency.ETS, max_entries: 2, clock: fn -> @now end})
    replay = start_supervised!({Replay.ETS, max_entries: 8})
    opts = [namespace: "orders", principal: "account", now: @now, retention: 120]

    assert :recorded = Journal.record(journal, "orders", message("first"))
    assert :already_recorded = Journal.record(journal, "orders", message("first"))
    assert :conflict = Journal.record(journal, "orders", message("different"))

    assert {:ok, first} =
             Journal.reissue(journal, "orders", "create-1", spec("primary"), ctx.signer,
               clock: fn -> @now end
             )

    assert {:ok, retry} =
             Journal.reissue(journal, "orders", "create-1", spec("alias"), ctx.signer,
               clock: fn -> @now end
             )

    refute first.fields == retry.fields

    policy = policy(ctx.key, replay, :nonce)
    assert {:ok, record} = Idempotency.prepare(first, policy, "sig", opts)
    assert {:error, %{reason: :replayed}} = Idempotency.prepare(first, policy, "sig", opts)

    assert {:reserved, reservation} =
             Idempotency.reserve({Idempotency.ETS, store}, record, timeout: 1000)

    assert :in_progress = Idempotency.reserve({Idempotency.ETS, store}, record, timeout: 1000)

    response = %{
      status: 201,
      headers: [{"content-type", "text/plain"}, {"set-cookie", "secret"}],
      body: "created"
    }

    assert :stored =
             Idempotency.store({Idempotency.ETS, store}, reservation, response,
               timeout: 1000,
               allow_headers: ["content-type", "set-cookie"]
             )

    assert {:ok, same} = Idempotency.prepare(retry, policy, "sig", opts)
    assert same.fingerprint == record.fingerprint

    assert {:stored, %{body: "created", status: 201, headers: [{"content-type", "text/plain"}]}} =
             Idempotency.reserve({Idempotency.ETS, store}, same, timeout: 1000)

    assert {:ok, changed} =
             RequestSeal.sign(message("different"), spec("primary"), ctx.signer,
               clock: fn -> @now end
             )

    assert {:ok, conflict} = Idempotency.prepare(changed, policy, "sig", opts)
    assert :conflict = Idempotency.reserve({Idempotency.ETS, store}, conflict, timeout: 1000)

    assert {:reserved, _} =
             Idempotency.reserve({Idempotency.ETS, store}, %{same | principal: "another"},
               timeout: 1000
             )
  end

  test "operation commitment survives key rotation and fresh transport parameters", ctx do
    replay = start_supervised!({Replay.ETS, max_entries: 8})

    policy =
      policy(
        ctx.key,
        replay,
        {:operation,
         [~s["@method"], ~s["@target-uri"], ~s["content-digest"], ~s["idempotency-key"]]}
      )

    assert {:ok, first} =
             RequestSeal.sign(message("same"), spec("primary"), ctx.signer, clock: fn -> @now end)

    assert {:ok, _} = RequestSeal.verify(first, policy, label: "sig")

    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, rotated} = Local.new("ed25519", {:ed25519, seed})
    on_exit(fn -> Local.release(rotated) end)
    {:ok, key} = RequestSeal.Custody.public_key(rotated)
    second_policy = policy(key, replay, policy.replay.identifier)

    assert {:ok, second} =
             RequestSeal.sign(message("same"), spec("rotated"), rotated, clock: fn -> @now end)

    assert {:error, %{reason: :replayed}} =
             RequestSeal.verify(second, second_policy, label: "sig")
  end

  test "a replaced lease cannot complete and forbidden response shapes are refused" do
    {store, clock} = timed_store()
    record = record(@now, @now + 5, @now + 120)

    assert {:reserved, first} = Idempotency.reserve(store, record, timeout: 1000)
    :ok = :atomics.put(clock, 1, @now + 5)
    renewed = %{record | now: @now + 5, lease_until: @now + 10}
    assert {:reserved, second} = Idempotency.reserve(store, renewed, timeout: 1000)
    opts = [timeout: 1000, allow_headers: []]

    assert {:error, %{reason: :invalid_response}} =
             Idempotency.store(store, second, %{status: 204, headers: [], body: "bad"}, opts)

    response = %{status: 202, headers: [], body: "accepted"}
    assert :not_reserved = Idempotency.store(store, first, response, opts)
    assert :stored = Idempotency.store(store, second, response, opts)
    assert :not_reserved = Idempotency.store(store, second, response, opts)
    :ok = :atomics.put(clock, 1, @now + 119)
    assert {:ok, 0} = Idempotency.sweep(store, @now + 119, timeout: 1000)
    :ok = :atomics.put(clock, 1, @now + 120)
    assert {:ok, 1} = Idempotency.sweep(store, @now + 120, timeout: 1000)
  end

  test "the journal rejects credential fields and caller nonce overrides", ctx do
    signed_intent = message("first")
    {:ok, entry} = Journal.entry("orders", signed_intent)

    assert {:error, :invalid_options} =
             Journal.reissue(entry, spec("primary"), ctx.signer, nonce: <<0::256>>)

    assert {:error, :invalid_intent} =
             Journal.reissue(%{entry | body: "different"}, spec("primary"), ctx.signer, [])

    adds_length = %{
      spec("primary")
      | components:
          ~s[("@method" "@target-uri" "content-digest" "idempotency-key" "content-length")]
    }

    assert {:error, :invalid_intent} = Journal.reissue(entry, adds_length, ctx.signer, [])

    {:ok, field} =
      RequestSeal.FieldOccurrence.new(%{
        name: "Authorization",
        value: "Bearer example",
        section: :headers
      })

    assert {:error, :invalid_intent} =
             Journal.entry("orders", %{signed_intent | fields: signed_intent.fields ++ [field]})
  end

  test "late admission, renewal, completion, and sweep share the store clock" do
    {store, clock} = timed_store()
    record = record(@now, @now + 5, @now + 10)
    opts = [timeout: 1000]
    write_opts = [timeout: 1000, allow_headers: []]
    response = %{status: 200, headers: [], body: "accepted"}

    reserve = fn -> Idempotency.reserve(store, record, opts) end

    assert [in_progress: 1, reserved: 1] =
             [reserve, reserve]
             |> concurrently()
             |> Enum.frequencies_by(fn
               {:reserved, _} -> :reserved
               :in_progress -> :in_progress
             end)
             |> Enum.sort()

    assert {:ok, 0} = Idempotency.sweep(store, @now, opts)
    :ok = :atomics.put(clock, 1, @now + 5)

    assert {:error, %Idempotency.Error{reason: :record_expired}} =
             Idempotency.reserve(store, %{record | key: "late-new-key"}, opts)

    # Produce a token for the other key with a live lease before renewal.
    original = record(@now + 5, @now + 6, @now + 10)
    assert {:reserved, previous} = Idempotency.reserve(store, %{original | key: "race"}, opts)
    :ok = :atomics.put(clock, 1, @now + 6)
    renewed = %{original | key: "race", now: @now + 6, lease_until: @now + 9}

    assert [{:reserved, current}, :not_reserved, {:ok, 0}] =
             concurrently([
               fn -> Idempotency.reserve(store, renewed, opts) end,
               fn -> Idempotency.store(store, previous, response, write_opts) end,
               fn -> Idempotency.sweep(store, @now + 6, opts) end
             ])

    :ok = :atomics.put(clock, 1, @now + 10)
    fresh = %{renewed | now: @now + 10, lease_until: @now + 13, retain_until: @now + 20}

    assert [{:reserved, next}, :not_reserved, {:ok, swept}] =
             concurrently([
               fn -> Idempotency.reserve(store, fresh, opts) end,
               fn -> Idempotency.store(store, current, response, write_opts) end,
               fn -> Idempotency.sweep(store, @now + 10, opts) end
             ])

    assert swept in [1, 2]
    assert :stored = Idempotency.store(store, next, response, write_opts)
    assert {:stored, ^response} = Idempotency.reserve(store, fresh, opts)
  end

  defmodule InvalidAdapter do
    def reserve(:error, _, _) do
      {:error, %RequestSeal.Idempotency.Error{reason: {:wire, "canary"}}}
    end

    def reserve(:throw, _, _), do: throw({:replay_error, :store_timeout})
  end

  test "undeclared adapter returns cannot set the caller error or telemetry reason" do
    event = [:request_seal, :idempotency, :reserve]
    handler = {__MODULE__, make_ref()}

    forward = fn event, _, data, owner ->
      if self() == owner, do: send(owner, {event, data})
    end

    :ok = :telemetry.attach(handler, event, forward, self())
    on_exit(fn -> :telemetry.detach(handler) end)

    record = record(@now, @now + 5, @now + 10)

    for form <- [:error, :throw] do
      assert {:error, %Idempotency.Error{reason: :store_failed}} =
               Idempotency.reserve({InvalidAdapter, form}, record, timeout: 1000)

      assert_received {^event, %{outcome: :error, reason: :store_failed}}
      refute_received {^event, _}
    end
  end

  test "the journal refuses a captured scheme its request builder cannot reissue" do
    original = message("first")
    captured = %{original | scheme: "ftp"}
    assert :ok = Message.validate(captured)
    assert {:error, :invalid_intent} = Journal.entry("orders", captured)
  end

  test "a blocked clock times out and the owner accepts the next operation" do
    owner = self()
    reads = :atomics.new(1, [])

    clock = fn ->
      if :atomics.add_get(reads, 1, 1) == 1 do
        send(owner, {:clock_read, self()})

        receive do
          :resume -> @now
        end
      else
        @now
      end
    end

    pid = start_supervised!({Idempotency.ETS, max_entries: 2, clock: clock})
    store = Idempotency.ETS.store(pid)
    record = record(@now, @now + 5, @now + 10)
    task = Task.async(fn -> Idempotency.reserve(store, record, timeout: 1000) end)

    assert_receive {:clock_read, worker}, 1000
    assert {:error, %{reason: :store_timeout}} = Task.await(task, 3000)
    assert {:reserved, _} = Idempotency.reserve(store, record, timeout: 1000)
    refute Process.alive?(worker)
    assert Process.alive?(pid)
    assert :atomics.get(reads, 1) == 2
  end

  defmodule ResponseStore do
    alias RequestSeal.Idempotency.Record

    def reserve(pid, record, _) do
      Agent.get_and_update(pid, fn rows ->
        key = Record.key(record)

        case Map.fetch(rows, key) do
          {:ok, {:stored, _} = result} ->
            {result, rows}

          {:ok, {:pending, _}} ->
            {:in_progress, rows}

          :error ->
            token = :crypto.strong_rand_bytes(16)
            {{:reserved, token}, Map.put(rows, key, {:pending, token})}
        end
      end)
    end

    def store(pid, reservation, response, _) do
      Agent.get_and_update(pid, fn rows ->
        key = Record.key(reservation.record)
        token = reservation.token

        case Map.fetch(rows, key) do
          {:ok, {:pending, ^token}} -> {:stored, Map.put(rows, key, {:stored, response})}
          _ -> {:not_reserved, rows}
        end
      end)
    end
  end

  test "response authentication fields are excluded at storage and rejected on legacy readback" do
    pid = start_supervised!({Agent, fn -> %{} end})
    store = {ResponseStore, pid}
    record = record(@now, @now + 5, @now + 10)
    assert {:reserved, reservation} = Idempotency.reserve(store, record, timeout: 1000)

    transient = [
      {"authentication-info", "nextnonce=example"},
      {"proxy-authentication-info", "nextnonce=example"}
    ]

    clean = %{status: 200, headers: [{"content-type", "text/plain"}], body: "accepted"}
    dirty = %{clean | headers: clean.headers ++ transient}
    allow = Enum.map(dirty.headers, &elem(&1, 0))

    assert :stored =
             Idempotency.store(store, reservation, dirty, timeout: 1000, allow_headers: allow)

    assert {:stored, ^clean} = Idempotency.reserve(store, record, timeout: 1000)
    key = Idempotency.Record.key(record)
    assert Agent.get(pid, &Map.fetch!(&1, key)) == {:stored, clean}

    for field <- transient do
      legacy = %{clean | headers: [field | clean.headers]}
      :ok = Agent.update(pid, &Map.put(&1, key, {:stored, legacy}))

      assert {:error, %{reason: :store_failed}} =
               Idempotency.reserve(store, record, timeout: 1000)
    end
  end

  test "a partial journal snapshot is rejected before signing", ctx do
    assert {:ok, entry} = Journal.entry("orders", message("first"))
    owner = self()

    clock = fn ->
      send(owner, :signing)
      @now
    end

    for field <- [:namespace, :key, :method, :target, :fields, :body, :digest] do
      partial = Map.delete(entry, field)
      forged = Map.put(partial, :unknown, nil)

      for snapshot <- [partial, forged] do
        assert {:error, :invalid_intent} =
                 Journal.reissue(snapshot, spec("primary"), ctx.signer, clock: clock)
      end
    end

    refute_received :signing
    assert {:ok, _} = Journal.reissue(entry, spec("primary"), ctx.signer, clock: clock)
    assert_received :signing
  end

  test "misrouted and malformed calls leave both stores and their records intact" do
    {{Idempotency.ETS, store_pid} = store, _} = timed_store()
    journal = start_supervised!({Journal, max_entries: 2})
    request = message("first")
    record = record(@now, @now + 5, @now + 10)
    assert {:ok, entry} = Journal.entry("orders", request)
    assert :recorded = Journal.record(journal, "orders", request)
    assert {:reserved, reservation} = Idempotency.reserve(store, record, timeout: 1000)

    assert {:error, :journal_unavailable} = Journal.load(store_pid, "orders", "create-1")

    assert {:error, %{reason: :store_failed}} =
             Idempotency.reserve(Idempotency.ETS.store(journal), record, timeout: 1000)

    context = %RequestSeal.Custody.Context{
      owner: self(),
      deadline: System.monotonic_time(:millisecond) + 1000
    }

    assert {:error, :failure} = GenServer.call(store_pid, {{:reserve, :invalid}, context})
    assert {:error, :failure} = GenServer.call(store_pid, {{:reserve, record}, :invalid})

    malformed_record = record |> Map.delete(:now) |> Map.put(:unknown, @now)
    assert {:error, :failure} = GenServer.call(store_pid, {{:reserve, malformed_record}, context})
    assert {:error, :invalid_intent} = GenServer.call(journal, {:record, "orders", :invalid})
    assert {:error, :invalid_options} = GenServer.call(journal, {:forget, {"orders", nil}})
    assert Process.alive?(store_pid)
    assert Process.alive?(journal)
    assert :in_progress = Idempotency.reserve(store, record, timeout: 1000)
    assert {:ok, ^entry} = Journal.load(journal, "orders", "create-1")

    response = %{status: 200, headers: [], body: "accepted"}

    assert :stored =
             Idempotency.store(store, reservation, response, timeout: 1000, allow_headers: [])
  end

  test "journal admission reserves the complete signed field budget", ctx do
    original = message("first")
    # One maximal input value and one maximal 1,024-byte signature member.
    reserve = 65_536 + 256 + 3 + 1368 + byte_size("Signature-InputSignature")
    at_limit = pad_fields(original, 1_048_576 - reserve)
    above_limit = pad_fields(original, 1_048_576 - reserve + 1)
    full = pad_fields(original, 1_048_576)

    assert :ok = Message.validate(full)
    assert {:ok, entry} = Journal.entry("orders", at_limit)
    assert {:error, :invalid_intent} = Journal.entry("orders", above_limit)
    assert {:error, :invalid_intent} = Journal.entry("orders", full)

    assert {:ok, signed} =
             Journal.reissue(entry, spec("primary"), ctx.signer, clock: fn -> @now end)

    assert :ok = Message.validate(signed)
    assert Enum.take(signed.fields, length(at_limit.fields)) == at_limit.fields
  end

  defp pad_fields(message, size) do
    existing = Enum.sum(Enum.map(message.fields, &(byte_size(&1.name) + byte_size(&1.value))))
    {count, remainder} = {div(size - existing, 65_537), rem(size - existing, 65_537)}

    sizes = List.duplicate(65_537, count) ++ List.wrap(if remainder > 0, do: remainder)

    fields =
      Enum.map(sizes, fn size ->
        {:ok, field} =
          RequestSeal.FieldOccurrence.new(%{
            name: "x",
            value: :binary.copy("a", size - 1),
            section: :headers
          })

        field
      end)

    %{message | fields: message.fields ++ fields}
  end

  defp timed_store do
    clock = :atomics.new(1, [])
    :ok = :atomics.put(clock, 1, @now)
    read_clock = fn -> :atomics.get(clock, 1) end
    pid = start_supervised!({Idempotency.ETS, max_entries: 2, clock: read_clock})
    {Idempotency.ETS.store(pid), clock}
  end

  defp record(now, lease_until, retain_until) do
    %Idempotency.Record{
      namespace: "orders",
      principal: "account",
      key: "request",
      fingerprint: <<0::256>>,
      now: now,
      lease_until: lease_until,
      retain_until: retain_until
    }
  end

  defp concurrently(calls) do
    owner = self()
    tag = make_ref()

    tasks =
      for call <- calls do
        Task.async(fn ->
          send(owner, {tag, self()})

          receive do
            ^tag -> call.()
          end
        end)
      end

    for task <- tasks do
      pid = task.pid
      assert_receive {^tag, ^pid}
    end

    Enum.each(tasks, &send(&1.pid, tag))
    Task.await_many(tasks, 3000)
  end

  defp message(body) do
    {:ok, request} =
      Message.request(
        "POST",
        "https://api.example.test/orders",
        [{"idempotency-key", ~s["create-1"]}],
        body,
        digest: ["sha-256"]
      )

    request
  end

  defp spec(keyid),
    do: %{
      label: "sig",
      algorithm: "ed25519",
      components: @components,
      expires_in: 60,
      keyid: keyid
    }

  defp policy(key, replay, identifier) do
    {:ok, policy} =
      Policy.new(%{
        algorithms: ["ed25519"],
        components: @components,
        require_issued_for: :orders,
        key_resolver: fn _ ->
          {:ok,
           %{
             algorithm: "ed25519",
             key: key,
             issued_for: :orders,
             replay_scope: {:credential, :orders, "credential-1"}
           }}
        end,
        freshness: %{clock: fn -> @now end, max_age: 120, skew: 0, require_expires: true},
        content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
        replay: %{
          identifier: identifier,
          namespace: "orders",
          scope: :credential,
          store: Replay.ETS.store(replay),
          timeout: 1000,
          retain_until: @now + 120
        }
      })

    policy
  end
end
