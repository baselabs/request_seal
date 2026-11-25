defmodule RequestSeal.QuorumTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Custody, Message, Policy, Quorum, Replay}
  alias RequestSeal.Custody.Local

  @now 1_760_000_000
  @components ~s[("@method" "@target-uri")]
  @operation {:operation, [~s["@method"], ~s["@target-uri"]]}

  setup do
    keys =
      for name <- ["primary", "optional", "third", "fourth"], into: %{} do
        {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = Local.new("ed25519", {:ed25519, seed})
        {:ok, public} = Custody.public_key(handle)
        on_exit(fn -> Local.release(handle) end)
        {name, {handle, public}}
      end

    {:ok, message} = Message.request("GET", "https://example.test/operation", [], nil)
    pid = start_supervised!({Replay.ETS, max_entries: 4})
    %{keys: keys, message: message, store: Replay.ETS.store(pid), pid: pid}
  end

  test "relabeling or deleting any optional signature does not open a new claim", ctx do
    required = sign(ctx.message, ctx.keys, "primary", "main", "session")
    both = sign(required, ctx.keys, "optional", "extra", "other")
    relabeled = sign(ctx.message, ctx.keys, "primary", "renamed", "new")

    quorum =
      quorum(ctx, @operation, [
        slot(ctx, :main, "primary", true),
        slot(ctx, :optional, "optional", false)
      ])

    assert {:ok, %{count: 2, authorization: :not_evaluated, replay: %Replay.Receipt{}}} =
             RequestSeal.verify_quorum(both, quorum, [])

    assert {:error, %{reason: :replayed}} = RequestSeal.verify_quorum(required, quorum, [])
    assert {:error, %{reason: :replayed}} = RequestSeal.verify_quorum(relabeled, quorum, [])
    assert {:ok, 1} = Replay.ETS.sweep(ctx.pid, @now + 120)
  end

  test "an unassigned qualifying nonce disagreement never claims", ctx do
    first = sign(ctx.message, ctx.keys, "primary", "main", "first")
    both = sign(first, ctx.keys, "primary", "extra", "second")
    matching = sign(first, ctx.keys, "primary", "extra", "first")
    quorum = quorum(ctx, {:nonce, :shared}, [slot(ctx, :main, "primary", true)])

    assert {:error, %{reason: :replay_identity_mismatch, layer: :replay}} =
             RequestSeal.verify_quorum(both, quorum, [])

    assert {:ok, %{count: 1}} = RequestSeal.verify_quorum(matching, quorum, [])
    assert {:error, %{reason: :replayed}} = RequestSeal.verify_quorum(first, quorum, [])
  end

  test "aliases cannot count twice and a rejected threshold leaves the replay store empty", ctx do
    first = sign(ctx.message, ctx.keys, "primary", "one", "session")
    aliases = sign(first, ctx.keys, "primary", "two", "session")
    valid = sign(first, ctx.keys, "optional", "two", "session")

    slots = [
      slot(ctx, :one, nil, true),
      slot(ctx, :two, nil, true)
    ]

    quorum = quorum(ctx, @operation, slots, {:threshold, 2})

    assert {:error, %{reason: :quorum_not_met, layer: :quorum}} =
             RequestSeal.verify_quorum(aliases, quorum, [])

    assert {:ok, %{count: 2}} = RequestSeal.verify_quorum(valid, quorum, [])
  end

  test "bindings pass before a claim and enforce the selected authenticated parameter", ctx do
    first = sign(ctx.message, ctx.keys, "primary", "one", "first")
    mismatch = sign(first, ctx.keys, "optional", "two", "second")
    match = sign(first, ctx.keys, "optional", "two", "first")
    slots = [slot(ctx, :one, "primary", true), slot(ctx, :two, "optional", true)]
    quorum = quorum(ctx, @operation, slots)
    quorum = %{quorum | bindings: [{:same_parameter, "nonce", [:one, :two]}]}

    assert {:error, %{reason: :binding_unsatisfied}} =
             RequestSeal.verify_quorum(mismatch, quorum, [])

    assert {:ok, _} = RequestSeal.verify_quorum(match, quorum, [])
  end

  test "policy requires one composite claim, mandatory coverage, and a live deadline", ctx do
    slot = slot(ctx, :main, "primary", true)
    valid = quorum(ctx, @operation, [slot])

    assert {:error, %{reason: :invalid_quorum}} =
             Quorum.new(Map.from_struct(%{valid | replay: :not_required}))

    invalid = put_in(valid.replay.identifier, {:operation, [~s["@authority"]]})
    assert {:error, %{reason: :invalid_quorum}} = Quorum.new(Map.from_struct(invalid))

    signed = sign(ctx.message, ctx.keys, "primary", "main", "session")
    deadline = System.monotonic_time(:millisecond)

    assert {:error, %{reason: :deadline}} =
             RequestSeal.verify_quorum(signed, valid, deadline: deadline)

    assert {:ok, _} = RequestSeal.verify_quorum(signed, valid, [])
  end

  test "fixed retention refuses a signature with a longer window before claiming", ctx do
    signed = sign(ctx.message, ctx.keys, "primary", "main", "session")
    policy = quorum(ctx, @operation, [slot(ctx, :main, "primary", true)])
    too_short = put_in(policy.replay.retain_until, @now + 59)

    assert {:error, %{reason: :retention_exceeded}} =
             RequestSeal.verify_quorum(signed, too_short, [])

    assert {:ok, _} = RequestSeal.verify_quorum(signed, policy, [])
  end

  test "principal scope comes from all configured slots and role counts obey principal sharing",
       ctx do
    request = sign(ctx.message, ctx.keys, "primary", "one", "attempt")
    both = sign(request, ctx.keys, "optional", "two", "attempt")

    slots = [
      slot(ctx, :first, "primary", true) |> Map.merge(%{principal: "same", role: :writer}),
      slot(ctx, :second, "optional", true) |> Map.merge(%{principal: "same", role: :reviewer})
    ]

    policy = quorum(ctx, {:nonce, :shared}, slots)
    policy = %{policy | unit: {:role, shared_principal: false}}
    policy = put_in(policy.replay.scope, :principals)

    assert {:error, %{reason: :quorum_not_met}} = RequestSeal.verify_quorum(both, policy, [])

    shared = %{policy | unit: {:role, shared_principal: true}}
    assert {:ok, %{count: 2}} = RequestSeal.verify_quorum(both, shared, [])
    assert {:error, %{reason: :replayed}} = RequestSeal.verify_quorum(both, shared, [])
  end

  test "signature negotiation checks the covered challenge before claiming", ctx do
    label = "main"
    signed = sign(ctx.message, ctx.keys, "primary", label, "session")
    policy = quorum(ctx, @operation, [slot(ctx, :main, "primary", true)])

    {:ok, requests} =
      RequestSeal.AcceptSignature.parse("main=" <> @components <> ~s(;nonce="bad"),
        target: :request
      )

    assert {:error, %{reason: :negotiation_unfulfilled, layer: :negotiation}} =
             RequestSeal.verify_quorum(signed, policy, accept_signature: requests)

    {:ok, requests} =
      RequestSeal.AcceptSignature.parse("main=" <> @components <> ~s(;nonce="session"),
        target: :request
      )

    assert {:ok, %{negotiation: :fulfilled}} =
             RequestSeal.verify_quorum(signed, policy, accept_signature: requests)
  end

  test "unexpected and invalid labels follow their explicit policies", ctx do
    slot = Map.put(slot(ctx, :main, "primary", true), :label, "one")
    policy = quorum(ctx, @operation, [slot])
    policy = %{policy | unexpected: :reject, invalid: :reject}
    unexpected = sign(ctx.message, ctx.keys, "optional", "two", "session")
    invalid = sign(ctx.message, ctx.keys, "optional", "one", "session")

    assert {:error, %{reason: :unexpected_signature}} =
             RequestSeal.verify_quorum(unexpected, policy, [])

    assert {:error, %{reason: :nonqualifying_signature}} =
             RequestSeal.verify_quorum(invalid, policy, [])

    valid = sign(ctx.message, ctx.keys, "primary", "one", "session")
    assert {:ok, _} = RequestSeal.verify_quorum(valid, policy, [])
  end

  test "bounded assignment refuses an impossible dense policy without claiming", ctx do
    ids = [:one, :two, :three, :four, :five, :six, :seven, :eight, :nine, :ten]
    signer_ids = Enum.map(Enum.take(ids, 9), &Atom.to_string/1)

    {keys, signed} =
      Enum.reduce(signer_ids, {%{}, ctx.message}, fn id, {keys, signed} ->
        {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, signer} = Local.new("ed25519", {:ed25519, seed})
        {:ok, key} = Custody.public_key(signer)
        on_exit(fn -> Local.release(signer) end)
        keys = Map.put(keys, id, {signer, key})
        {keys, sign(signed, keys, id, id, "session")}
      end)

    ctx = %{ctx | keys: keys}
    slots = Enum.map(ids, &slot(ctx, &1, nil, true))
    policy = quorum(ctx, @operation, slots, {:threshold, 10})

    assert {:error, %{reason: :limit, layer: :input}} =
             RequestSeal.verify_quorum(signed, policy, [])

    accepting = %{policy | slots: Enum.take(slots, 1), mode: :all}
    assert {:ok, %{count: 1}} = RequestSeal.verify_quorum(signed, accepting, [])
  end

  test "unknown HMAC equivalence cannot fill a required key slot", ctx do
    {:ok, signer} = Local.new("hmac-sha256", {:hmac, :crypto.strong_rand_bytes(32)})
    on_exit(fn -> Local.release(signer) end)

    {:ok, signed} =
      RequestSeal.sign(
        ctx.message,
        %{
          label: "hmac",
          components: @components,
          algorithm: "hmac-sha256",
          expires_in: 60
        },
        signer, clock: fn -> @now end)

    slot = slot(ctx, :main, "primary", true)

    policy = %{
      slot.policy
      | algorithms: ["hmac-sha256"],
        key_resolver: fn _ -> {:ok, %{algorithm: "hmac-sha256", key: signer}} end
    }

    quorum = quorum(ctx, @operation, [%{slot | policy: policy}])

    assert {:error, %{reason: :ambiguous_key_identity, layer: :quorum}} =
             RequestSeal.verify_quorum(signed, quorum, [])
  end

  test "structured operation fields require the same schema in every slot", ctx do
    identifier = ~s["flags";sf]
    components = "(" <> identifier <> ")"

    make_slot = fn id, kind ->
      slot = slot(ctx, id, nil, false)
      schema = RequestSeal.SignatureFields.schema(kind, [:token, :boolean])

      policy = %{slot.policy | components: components, field_schemas: %{"flags" => schema}}
      %{slot | policy: policy}
    end

    policy = quorum(ctx, {:operation, [identifier]}, [make_slot.(:first, :list)], :any)
    compatible = %{policy | slots: [make_slot.(:first, :list), make_slot.(:second, :list)]}
    assert {:ok, _} = Quorum.new(Map.from_struct(compatible))

    incompatible_slots = [make_slot.(:first, :list), make_slot.(:second, :dictionary)]
    incompatible = %{compatible | slots: incompatible_slots}
    assert {:error, %{reason: :invalid_quorum}} = Quorum.new(Map.from_struct(incompatible))
  end

  test "concurrent disjoint signatures with different dictionary order share an operation", ctx do
    one = sign(ctx.message, ctx.keys, "primary", "one", "attempt-a")
    two = sign(one, ctx.keys, "optional", "two", "attempt-b")
    three = sign(ctx.message, ctx.keys, "third", "three", "attempt-c")
    four = sign(three, ctx.keys, "fourth", "four", "attempt-d")
    slots = [slot(ctx, :first, nil, false), slot(ctx, :second, nil, false)]
    policy = quorum(ctx, @operation, slots, {:threshold, 2})

    results =
      [two, four]
      |> Task.async_stream(&RequestSeal.verify_quorum(&1, policy, []), max_concurrency: 2)
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.count(results, &match?({:ok, %{count: 2}}, &1)) == 1
    assert Enum.count(results, &match?({:error, %{reason: :replayed}}, &1)) == 1

    {:ok, distinct} = Message.request("GET", "https://example.test/another", [], nil)
    one = sign(distinct, ctx.keys, "primary", "one", "attempt-a")
    two = sign(one, ctx.keys, "optional", "two", "attempt-b")
    assert {:ok, %{count: 2}} = RequestSeal.verify_quorum(two, policy, [])
  end

  test "principal and role thresholds cannot count an unknown alias beside the known key", ctx do
    material = {:hmac, :crypto.strong_rand_bytes(32)}
    {:ok, known} = Local.new("hmac-sha256", material, equivalence: "configured")
    {:ok, unknown} = Local.new("hmac-sha256", material)
    on_exit(fn -> Enum.each([known, unknown], &Local.release/1) end)

    handles = [known: known, unknown: unknown]

    {message, slots} =
      Enum.reduce(handles, {ctx.message, []}, fn {id, handle}, {message, slots} ->
        label = Atom.to_string(id)
        spec = %{label: label, components: @components, algorithm: "hmac-sha256", expires_in: 60}
        {:ok, signed} = RequestSeal.sign(message, spec, handle, clock: fn -> @now end)
        slot = slot(ctx, id, nil, false)
        key_resolver = fn _ -> {:ok, %{algorithm: "hmac-sha256", key: handle}} end
        policy = %{slot.policy | algorithms: ["hmac-sha256"], key_resolver: key_resolver}
        slot = Map.merge(slot, %{policy: policy, label: label, principal: label, role: id})
        {signed, [slot | slots]}
      end)

    policy = quorum(ctx, @operation, slots, {:threshold, 2})

    for unit <- [:principal, {:role, shared_principal: true}, {:role, shared_principal: false}] do
      assert {:error, %{reason: :quorum_not_met}} =
               RequestSeal.verify_quorum(message, %{policy | unit: unit}, [])
    end

    assert {:ok, %{count: 1}} =
             RequestSeal.verify_quorum(message, %{policy | mode: :any}, [])
  end

  defmodule FailedIdentity do
    alias RequestSeal.Custody.Local
    defdelegate sign(ref, algorithm, bytes, context), to: Local
    defdelegate public_key(ref), to: Local
    defdelegate verify(ref, algorithm, bytes, signature, context), to: Local
    def identity(_), do: {:error, :custodian_failure}
  end

  test "custody identity failures invalidate the candidate", ctx do
    {signer, _} = ctx.keys["primary"]
    signed = sign(ctx.message, ctx.keys, "primary", "main", "attempt")
    failed = %{signer | custodian: FailedIdentity}
    slot = slot(ctx, :main, "primary", true)
    resolver = fn _ -> {:ok, %{algorithm: "ed25519", key: failed}} end
    slot = %{slot | policy: %{slot.policy | key_resolver: resolver}}
    policy = quorum(ctx, @operation, [slot])
    policy = %{policy | invalid: :reject}

    assert {:error, %{reason: :nonqualifying_signature}} =
             RequestSeal.verify_quorum(signed, policy, [])

    assert {:ok, 0} = Replay.ETS.sweep(ctx.pid, @now + 120)
  end

  test "aggregate admission refuses too many eligible signature checks before resolution", ctx do
    message =
      Enum.reduce(1..9, ctx.message, fn i, message ->
        sign(message, ctx.keys, "primary", "sig-#{i}", "attempt")
      end)

    owner = self()

    slots =
      Enum.map(1..15, fn i ->
        slot = slot(ctx, :main, nil, false)

        resolver = fn _ ->
          send(owner, :resolved)
          :error
        end

        policy = %{slot.policy | key_resolver: resolver}
        %{slot | id: String.to_atom("quorum-budget-#{i}"), policy: policy}
      end)

    policy = quorum(ctx, @operation, slots, :any)
    assert {:error, %{reason: :limit}} = RequestSeal.verify_quorum(message, policy, [])
    refute_received :resolved
  end

  test "a blocked resolver is joined at the caller deadline", ctx do
    owner = self()
    signed = sign(ctx.message, ctx.keys, "primary", "main", "attempt")
    slot = slot(ctx, :main, "primary", true)

    resolver = fn _ ->
      send(owner, {:resolver, self()})

      receive do
        :finish -> :error
      end
    end

    slot = %{slot | policy: %{slot.policy | key_resolver: resolver}}
    policy = quorum(ctx, @operation, [slot])

    result =
      Task.async(fn ->
        deadline = System.monotonic_time(:millisecond) + 1000
        RequestSeal.verify_quorum(signed, policy, deadline: deadline)
      end)

    assert_receive {:resolver, pid}, 1000
    assert {:error, %{reason: :deadline}} = Task.await(result, 3000)
    refute Process.alive?(pid)
    assert {:ok, 0} = Replay.ETS.sweep(ctx.pid, @now + 120)
  end

  test "equivalent digest checks are reused and every signer still must cover the digest", ctx do
    covered = ~s[("@method" "@target-uri" "content-digest")]

    {:ok, request} =
      Message.request("POST", "https://example.test/operation", [], "data", digest: ["sha-256"])

    add = fn message, keyid, components ->
      {signer, _} = Map.fetch!(ctx.keys, keyid)
      label = if keyid == "primary", do: "one", else: "two"

      spec = %{
        label: label,
        keyid: keyid,
        algorithm: "ed25519",
        components: components,
        expires_in: 60
      }

      {:ok, signed} = RequestSeal.sign(message, spec, signer, clock: fn -> @now end)
      signed
    end

    first = add.(request, "primary", covered)
    valid = add.(first, "optional", covered)
    missing_digest = add.(first, "optional", @components)
    content = %{kind: :content, section: :headers, algorithms: ["sha-256"]}

    slots =
      Enum.map([{:main, "primary"}, {:other, "optional"}], fn {id, keyid} ->
        slot = slot(ctx, id, keyid, true)
        %{slot | policy: %{slot.policy | content: content}}
      end)

    policy = quorum(ctx, @operation, slots)
    assert {:error, %{reason: :quorum_not_met}} =
             RequestSeal.verify_quorum(missing_digest, policy, [])

    owner = self()

    task =
      Task.async(fn ->
        receive do
          :verify ->
            result = RequestSeal.verify_quorum(valid, policy, [])
            send(owner, {:verdict, self(), result})

            receive do
              :join -> :ok
            end
        end
      end)

    session = :trace.session_create(:quorum_digest, self(), [])
    worker = task.pid
    mfa = {RequestSeal.Digest, :check_validated, 3}

    try do
      assert :trace.function(session, mfa, true, [:local]) == 1
      assert :trace.process(session, worker, true, [:call, :arity]) == 1
      send(worker, :verify)
      assert_receive {:verdict, ^worker, {:ok, %{count: 2}}}, 3000
      delivered = :trace.delivered(session, worker)
      assert_receive {:trace_delivered, ^worker, ^delivered}
      assert_received {:trace, ^worker, :call, ^mfa}
      refute_received {:trace, ^worker, :call, ^mfa}
    after
      :trace.session_destroy(session)
      Task.shutdown(task, :brutal_kill)
    end
  end

  defp sign(message, keys, keyid, label, nonce) do
    {handle, _} = Map.fetch!(keys, keyid)

    {:ok, signed} =
      RequestSeal.sign(
        message,
        %{
          label: label,
          algorithm: "ed25519",
          signature_input:
            @components <>
              ~s(;created=#{@now};expires=#{@now + 60};nonce="#{nonce}";keyid="#{keyid}")
        },
        handle
      )

    signed
  end

  defp slot(ctx, id, keyid, required) do
    {:ok, policy} =
      Policy.new(%{
        algorithms: ["ed25519"],
        components: @components,
        key_resolver: fn facts ->
          with true <- keyid == nil or facts.keyid == keyid,
               {:ok, {_, key}} <- Map.fetch(ctx.keys, facts.keyid) do
            {:ok, %{algorithm: "ed25519", key: key}}
          else
            _ -> :error
          end
        end,
        freshness: %{clock: fn -> @now end, require_expires: true, max_age: 120, skew: 0},
        content: :not_required,
        replay: :not_required
      })

    %{id: id, policy: policy, required: required}
  end

  defp quorum(ctx, identifier, slots, mode \\ :all) do
    {:ok, quorum} =
      Quorum.new(%{
        mode: mode,
        unit: :key,
        slots: slots,
        unexpected: :ignore,
        invalid: :ignore,
        replay: %{
          identifier: identifier,
          scope: :namespace,
          namespace: "operation",
          store: ctx.store,
          timeout: 1000,
          retain_until: @now + 120
        }
      })

    quorum
  end
end
