defmodule RequestSeal.AshTest do
  use ExUnit.Case, async: false
  import ExUnit.CaptureLog

  alias RequestSeal.{
    Body,
    Crypto,
    Error,
    FieldOccurrence,
    Message,
    Policy,
    PublicKey,
    TransportFacts
  }

  alias RequestSeal.Ash.Scope
  alias RequestSeal.Test.Ash.Record
  @fixtures Path.join(__DIR__, "fixtures")
  @vectors :json.decode(File.read!(Path.join(@fixtures, "verification/rfc9421.json")))
  @bases :json.decode(File.read!(Path.join(@fixtures, "signature_base/rfc9421.json")))

  setup do
    stop_records()
    on_exit(fn -> stop_records() end)
    :ok
  end

  test "authenticated identity remains forbidden to destroy through options and scope" do
    # This opaque attributed value is owned by discovery and custody, not this adapter.
    principal = %{role: :reader, tenant: "a"}
    verification = %{verified() | principal: principal}
    owner = self()

    binding = %{
      actor: fn received ->
        send(owner, {:principal, received})
        {:ok, received}
      end,
      unattributed: :reject,
      tenant: fn received -> {:ok, received.tenant} end
    }

    assert {:ok, scope} = RequestSeal.Ash.scope(verification, binding)
    assert_received {:principal, ^principal}
    assert scope.principal == :attributed
    assert scope.authorize? == true

    for opts <- [Scope.to_opts(scope), [scope: scope]] do
      row = seed("a")
      assert {:ok, records} = Ash.read(Record, opts)
      assert Enum.map(records, & &1.id) |> Enum.member?(row.id)
      assert {:error, %Ash.Error.Forbidden{}} = Ash.destroy(row, opts)
      # A caller's explicit bypass is a positive control on the real action.
      assert :ok = Ash.destroy(row, Keyword.put(opts, :authorize?, false))
    end

    assert Scope.to_opts(scope) == [
             actor: principal,
             tenant: "a",
             context: scope.context,
             authorize?: true
           ]

    assert Ash.Scope.ToOpts.get_actor(scope) == {:ok, principal}
    assert Ash.Scope.ToOpts.get_tenant(scope) == {:ok, "a"}
    assert Ash.Scope.ToOpts.get_context(scope) == {:ok, scope.context}
    assert Ash.Scope.ToOpts.get_authorize?(scope) == {:ok, true}
    assert Ash.Scope.ToOpts.get_tracer(scope) == :error
  end

  test "unattributed signatures never call identity callbacks and remain anonymous or reject" do
    owner = self()

    callback = fn value ->
      send(owner, {:called, value})
      {:ok, value}
    end

    verification = verified()
    assert verification.principal == :unattributed
    binding = %{actor: callback, tenant: callback, unattributed: :anonymous}
    assert {:ok, scope} = RequestSeal.Ash.scope(verification, binding)
    assert scope.actor == nil
    assert scope.tenant == nil
    assert scope.principal == :unattributed
    refute_received {:called, _}
    assert {:ok, scope} = RequestSeal.Ash.scope(verification, %{binding | tenant: {:value, "a"}})
    seed("a")
    assert {:error, %Ash.Error.Forbidden{}} = Ash.read(Record, Scope.to_opts(scope))
    assert {:error, %Ash.Error.Forbidden{}} = Ash.read(Record, scope: scope)
    error(RequestSeal.Ash.scope(verification, %{binding | unattributed: :reject}), :unattributed)
    refute_received {:called, _}
  end

  test "tenant selection is explicit and queries enforce tenant isolation" do
    # Seed the other tenant FIRST; an empty result cannot come from an empty table.
    other = seed("b")
    verification = %{verified() | principal: %{role: :reader, tenant: "a"}}
    binding = caller_binding()
    assert {:ok, scope} = RequestSeal.Ash.scope(verification, binding)
    assert {:ok, []} = Ash.read(Record, scope: scope)
    assert {:ok, []} = Ash.read(Record, Scope.to_opts(scope))

    assert {:ok, other_scope} =
             RequestSeal.Ash.scope(verification, %{binding | tenant: {:value, "b"}})

    assert {:ok, [record]} = Ash.read(Record, scope: other_scope)
    assert record.id == other.id
    assert {:ok, [record]} = Ash.read(Record, Scope.to_opts(other_scope))
    assert record.id == other.id
    assert {:ok, absent} = RequestSeal.Ash.scope(verification, %{binding | tenant: :none})

    for opts <- [Scope.to_opts(absent), [scope: absent]] do
      assert {:error, %Ash.Error.Invalid{errors: errors}} = Ash.read(Record, opts)
      assert Enum.any?(errors, &match?(%Ash.Error.Invalid.TenantRequired{}, &1))
    end

    error(
      RequestSeal.Ash.scope(verification, %{binding | tenant: fn _ -> :error end}),
      :tenant_unbound
    )
  end

  test "ETS destroy of a loaded foreign-tenant record uses its primary key" do
    other = seed("b")
    verification = %{verified() | principal: %{role: :admin, tenant: "a"}}
    assert {:ok, scope} = RequestSeal.Ash.scope(verification, caller_binding())

    assert {:ok, []} = Ash.read(Record, scope: scope, authorize?: false)
    assert {:ok, [loaded]} = Ash.read(Record, tenant: "b", authorize?: false)
    assert loaded.id == other.id
    assert :ok = Ash.destroy(loaded, scope: scope)
    assert {:ok, []} = Ash.read(Record, tenant: "b", authorize?: false)
  end

  test "a tenant policy denies destroy of a loaded foreign-tenant record" do
    other = seed("b")
    verification = %{verified() | principal: %{role: :admin, tenant: "a"}}
    assert {:ok, scope} = RequestSeal.Ash.scope(verification, caller_binding())

    # Ash.destroy seeds an explicit tenant from loaded-record metadata before
    # resolving scope. Keep the caller's intended tenant explicit on this path.
    for opts <- [Scope.to_opts(scope), [scope: scope, tenant: scope.tenant]] do
      assert {:error, %Ash.Error.Forbidden{}} =
               Ash.destroy(other, Keyword.put(opts, :action, :tenant_destroy))

      assert {:ok, [survivor]} = Ash.read(Record, tenant: "b", authorize?: false)
      assert survivor.id == other.id
    end

    assert {:ok, own_scope} =
             RequestSeal.Ash.scope(verification, %{caller_binding() | tenant: {:value, "b"}})

    assert :ok =
             Ash.destroy(other,
               scope: own_scope,
               tenant: own_scope.tenant,
               action: :tenant_destroy
             )

    assert {:ok, []} = Ash.read(Record, tenant: "b", authorize?: false)
  end

  test "an attributed actor canary stays out of RequestSeal diagnostics and context" do
    canary = "ACTOR-CANARY"
    principal = %{role: :reader, tenant: "a", secret: canary}
    verification = %{verified() | principal: principal}
    assert {:ok, scope} = RequestSeal.Ash.scope(verification, caller_binding())
    # Actor/tenant options deliberately retain caller values; they are not diagnostics.
    assert Scope.to_opts(scope)[:actor].secret == canary
    refute inspect(scope) =~ canary
    refute inspect(scope.context, limit: :infinity) =~ canary
    refute inspect(Scope.to_opts(scope)[:context], limit: :infinity) =~ canary

    for callback <- [
          fn _ -> raise canary end,
          fn _ -> throw(canary) end,
          fn _ -> exit(canary) end,
          fn _ -> {:error, canary} end
        ],
        field <- [:actor, :tenant] do
      assert {:error, %Error{detail: nil} = error} =
               RequestSeal.Ash.scope(verification, Map.put(caller_binding(), field, callback))

      assert error.reason == if(field == :actor, do: :actor_unbound, else: :tenant_unbound)
      refute inspect(error, limit: :infinity) =~ canary
      refute inspect(Map.from_struct(error), limit: :infinity) =~ canary
    end
  end

  test "Ash Forbidden inspection and enabled policy breakdowns expose caller actors" do
    previous = Application.fetch_env(:ash, :policies)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:ash, :policies, value)
        :error -> Application.delete_env(:ash, :policies)
      end
    end)

    canary = "ACTOR-CANARY"
    verification = %{verified() | principal: %{role: :reader, tenant: "a", secret: canary}}
    assert {:ok, scope} = RequestSeal.Ash.scope(verification, caller_binding())
    row = seed("a")

    Application.put_env(:ash, :policies, show_policy_breakdowns?: false)
    assert {:error, %Ash.Error.Forbidden{} = forbidden} = Ash.destroy(row, scope: scope)
    assert inspect(forbidden, limit: :infinity) =~ canary
    refute Exception.message(forbidden) =~ canary

    Application.put_env(:ash, :policies,
      show_policy_breakdowns?: true,
      log_policy_breakdowns: :error
    )

    log =
      capture_log(fn ->
        assert {:error, %Ash.Error.Forbidden{} = forbidden} = Ash.destroy(row, scope: scope)
        assert Exception.message(forbidden) =~ canary
      end)

    assert log =~ canary
    assert log =~ "Actor:"
  end

  for principal <- [nil, false] do
    @invalid_principal principal
    test "absent principal #{inspect(principal)} rejects before actor or tenant callbacks" do
      verification = verified()
      owner = self()

      callback = fn principal ->
        send(owner, {:odd_principal, principal})
        {:ok, %{id: principal}}
      end

      binding = %{actor: callback, tenant: callback, unattributed: :anonymous}

      error(
        RequestSeal.Ash.scope(%{verification | principal: @invalid_principal}, binding),
        :invalid_verification
      )

      refute_received {:odd_principal, _}
    end
  end

  test "other opaque principal values remain caller-attributed as the mapping contract specifies" do
    verification = verified()
    binding = %{actor: fn p -> {:ok, %{id: p}} end, tenant: :none, unattributed: :anonymous}

    for principal <- [:anonymous, "unattributed", :foo, [], {:unattributed}, %{id: "caller"}] do
      assert {:ok, scope} =
               RequestSeal.Ash.scope(%{verification | principal: principal}, binding)

      assert scope.principal == :attributed
      assert scope.actor == %{id: principal}
    end

    assert {:ok, scope} = RequestSeal.Ash.scope(verification, binding)
    assert scope.principal == :unattributed
    assert scope.actor == nil
  end

  test "caller-owned policies compose over checked digest facts" do
    verification = %{verified("B.2.3", true) | principal: %{role: :reader, tenant: "a"}}
    assert {:ok, scope} = RequestSeal.Ash.scope(verification, caller_binding())
    assert scope.context.request_seal.content == :checked

    for opts <- [Scope.to_opts(scope), [scope: scope]] do
      assert {:ok, _} = Record |> Ash.Changeset.for_create(:create, %{}, opts) |> Ash.create()
    end

    assert {:ok, unchecked} =
             RequestSeal.Ash.scope(%{verification | content: :not_required}, caller_binding())

    for opts <- [Scope.to_opts(unchecked), [scope: unchecked]] do
      assert {:error, %Ash.Error.Forbidden{}} =
               Record |> Ash.Changeset.for_create(:create, %{}, opts) |> Ash.create()
    end
  end

  test "invalid verification fails before callbacks" do
    v = verified()
    owner = self()

    b = %{
      caller_binding()
      | actor: fn p ->
          send(owner, :bound)
          {:ok, p}
        end
    }

    for invalid <- [
          nil,
          %{},
          Map.from_struct(v),
          %{v | signature: nil},
          %{v | signature: %{crypto: :invalid}},
          %{v | signature: %{v.signature | crypto: :invalid}},
          %{v | authorization: :authorized}
        ] do
      error(RequestSeal.Ash.scope(invalid, b), :invalid_verification)
    end

    refute_received :bound
  end

  test "scope context rejects malformed or unbounded verified facts" do
    v = verified()

    for changes <- [
          %{label: String.duplicate("a", 257)},
          %{profile: %{name: :rfc9421, keyid: "test-key-rsa-pss"}},
          %{profile: %{name: "test-key-rsa-pss"}},
          %{profile: %{name: {:test_pkg, :synthetic}}},
          %{signature: %{v.signature | covered: ["x" | :invalid]}},
          %{signature: %{v.signature | covered: [nil]}},
          %{signature: %{v.signature | covered: [<<1::1>>]}},
          %{signature: %{v.signature | covered: [""]}},
          %{signature: %{v.signature | covered: List.duplicate(~s["date"], 257)}},
          %{signature: %{v.signature | covered: [String.duplicate("x", 65_537)]}},
          %{content: :invalid},
          %{content: %{}},
          %{content: %{kind: :invalid, checked: ["sha-512"], bytes: 18, unsupported: 0}},
          %{freshness: :invalid},
          %{freshness: %{}},
          %{freshness: %{now: :invalid, created: nil, expires: nil, max_age: nil, skew: 0}},
          %{replay: %{store: RequestSeal.Replay.ETS, retain_until: 1_618_884_534}},
          %{replay: :claimed}
        ] do
      error(RequestSeal.Ash.scope(struct!(v, changes), caller_binding()), :invalid_verification)
    end
  end

  test "published B.2.1 verification with a real ETS receipt projects only claimed status" do
    pid = start_supervised!({RequestSeal.Replay.ETS, max_entries: 1})

    replay = %{
      identifier: :nonce,
      namespace: "ash-scope",
      commitment: fn facts -> {:ok, facts.identifier} end,
      store: RequestSeal.Replay.ETS.store(pid),
      timeout: 2000
    }

    v = verified("B.2.1", false, true, replay)
    assert %RequestSeal.Replay.Receipt{store: RequestSeal.Replay.ETS} = v.replay

    assert {:ok, scope} =
             RequestSeal.Ash.scope(v, %{caller_binding() | unattributed: :anonymous})

    assert scope.authorize? == true

    assert scope.context == %{
             request_seal: %{
               label: v.label,
               profile: v.profile,
               principal: :unattributed,
               covered: v.signature.covered,
               content: :not_required,
               freshness: :evaluated,
               replay: :claimed
             }
           }
  end

  test "binding requires every choice and rejects unknown keys and bare tenants" do
    v = %{verified() | principal: %{role: :reader, tenant: "a"}}
    b = caller_binding()

    invalid = [
      nil,
      [],
      Map.put(b, :authorize?, false),
      %{b | actor: nil},
      %{b | actor: fn -> :error end},
      %{b | tenant: "a"},
      %{b | tenant: {:other, "a"}},
      %{b | unattributed: :allow}
    ]

    for candidate <- invalid ++ Enum.map(Map.keys(b), &Map.delete(b, &1)) do
      error(RequestSeal.Ash.scope(v, candidate), :invalid_binding)
    end
  end

  test "actor callbacks reject nil malformed values errors and all fault classes" do
    v = %{verified() | principal: %{role: :reader, tenant: "a"}}

    callbacks = [
      fn _ -> {:ok, nil} end,
      fn _ -> :error end,
      fn _ -> {:ok, :actor, :extra} end,
      fn _ -> :actor end,
      fn _ -> raise "test-key-rsa-pss" end,
      fn _ -> throw("test-shared-secret") end,
      fn _ -> exit("test-key-rsa-pss") end
    ]

    for callback <- callbacks do
      error(RequestSeal.Ash.scope(v, %{caller_binding() | actor: callback}), :actor_unbound)
    end
  end

  test "tenant callbacks reject malformed values errors and all fault classes" do
    v = %{verified() | principal: %{role: :reader, tenant: "a"}}

    callbacks = [
      fn _ -> :error end,
      fn _ -> {:ok, "a", :extra} end,
      fn _ -> "a" end,
      fn _ -> raise "test-key-rsa-pss" end,
      fn _ -> throw("test-shared-secret") end,
      fn _ -> exit("test-key-rsa-pss") end
    ]

    for callback <- callbacks do
      error(RequestSeal.Ash.scope(v, %{caller_binding() | tenant: callback}), :tenant_unbound)
    end

    assert {:ok, %{tenant: nil}} =
             RequestSeal.Ash.scope(v, %{caller_binding() | tenant: fn _ -> {:ok, nil} end})
  end

  test "context projects bounded facts and excludes key identifiers and parameter bytes" do
    for section <- ["B.2.3", "B.2.5"] do
      v = verified(section)

      assert {:ok, scope} =
               RequestSeal.Ash.scope(v, %{
                 caller_binding()
                 | unattributed: :anonymous,
                   tenant: {:value, "a"}
               })

      assert scope.context == %{
               request_seal: %{
                 label: v.label,
                 profile: v.profile,
                 principal: :unattributed,
                 covered: v.signature.covered,
                 content: :not_required,
                 freshness: :not_evaluated,
                 replay: :not_required
               }
             }

      assert {:error, %Ash.Error.Forbidden{} = forbidden} = Ash.read(Record, scope: scope)

      for canary <- ["test-key-rsa-pss", "test-shared-secret"] do
        # Known-positive controls: these canaries really occur in the input vectors.
        assert Enum.any?(@vectors, &String.contains?(&1["signature_input"], canary))
        refute inspect(scope) =~ canary
        refute inspect(Scope.to_opts(scope)[:context]) =~ canary
        refute Exception.message(forbidden) =~ canary
      end
    end

    v = verified("B.2.3", true, true)
    {:ok, scope} = RequestSeal.Ash.scope(v, %{caller_binding() | unattributed: :anonymous})
    assert scope.context.request_seal.freshness == :evaluated
  end

  test "framework references are confined to the guarded protocol implementation" do
    files = Path.wildcard(Path.join(__DIR__, "../lib/**/*.ex"))
    # Positive control: the instrument sees the guarded protocol we actually invoke.
    hits =
      Enum.filter(files, fn file ->
        {:ok, ast} = Code.string_to_quoted(File.read!(file))

        {_, references} =
          Macro.prewalk(ast, [], fn
            {:__aliases__, _, [:Ash | _]} = node, refs -> {node, [node | refs]}
            node, refs -> {node, refs}
          end)

        references != []
      end)

    assert Enum.any?(hits, &String.ends_with?(&1, "/ash/scope.ex"))
    assert Enum.all?(hits, &String.contains?(&1, "/lib/request_seal/ash/"))

    {xref, status} =
      System.cmd("mix", ["xref", "graph", "--format", "plain"],
        stderr_to_stdout: true,
        env: [{"MIX_ENV", "test"}]
      )

    assert status == 0, xref
    assert xref =~ "lib/request_seal/ash/scope.ex"
  end

  defp caller_binding,
    do: %{actor: fn p -> {:ok, p} end, unattributed: :reject, tenant: fn p -> {:ok, p.tenant} end}

  defp stop_records do
    manager = Module.concat(Ash.DataLayer.Ets.Info.table(Record), Ash.DataLayer.Ets.TableManager)

    case Process.whereis(manager) do
      nil ->
        :ok

      pid ->
        monitor = Process.monitor(pid)
        Ash.DataLayer.Ets.stop(Record)
        # stop/1 sends an asynchronous exit; wait before the next test reuses the table.
        assert_receive {:DOWN, ^monitor, :process, ^pid, _}, 5_000
    end
  end

  defp seed(tenant),
    do:
      Record
      |> Ash.Changeset.for_create(:create, %{}, tenant: tenant, authorize?: false)
      |> Ash.create!()

  defp error(result, reason) do
    assert {:error,
            %Error{layer: :binding, reason: ^reason, detail: nil, retryable: false} = error} =
             result

    assert error.correlation =~ ~r/\A[0-9a-f]{16}\z/
    for canary <- ["test-key-rsa-pss", "test-shared-secret"], do: refute(inspect(error) =~ canary)
  end

  defp verified(section \\ "B.2.3", checked? \\ false, fresh? \\ false, replay \\ :not_required) do
    vector = Enum.find(@vectors, &(&1["section"] == section))
    public = Enum.find(@bases, &(&1["section"] == section))["message"]
    {:ok, body} = Body.new(%{state: :retained, bytes: ~s[{"hello": "world"}]})
    {:ok, transport} = TransportFacts.new(%{})
    fields = Enum.map(public["fields"], fn [name, value] -> field(name, value) end)

    {:ok, message} =
      Message.new(%{
        kind: :request,
        method: public["method"],
        raw_target: public["raw_target"],
        target_form: :origin,
        scheme: public["scheme"],
        authority: public["authority"],
        fields:
          fields ++
            [
              field("Signature-Input", vector["signature_input"]),
              field("Signature", vector["signature"])
            ],
        body: body,
        transport: transport,
        trailers: :unavailable
      })

    key = public_key(vector["key"])

    {:ok, policy} =
      Policy.new(%{
        algorithms: [vector["algorithm"]],
        components: "()",
        extra_components: :allow,
        key_resolver: fn _ -> {:ok, %{algorithm: vector["algorithm"], key: key}} end,
        content:
          if(checked?,
            do: %{kind: :content, algorithms: ["sha-512"], section: :headers},
            else: :not_required
          ),
        freshness:
          if(fresh?,
            do: %{clock: fn -> 1_618_884_474 end, max_age: 60, skew: 0, require_expires: false},
            else: :not_evaluated
          ),
        replay: replay
      })

    {:ok, verification} = RequestSeal.verify(message, policy, label: vector["label"])
    verification
  end

  defp field(name, value) do
    {:ok, field} =
      FieldOccurrence.new(%{name: name, value: value, section: :headers, provenance: :caller})

    field
  end

  defp public_key("hmac") do
    secret =
      File.read!(Path.join(@fixtures, "crypto/hmac.txt")) |> String.trim() |> Base.decode64!()

    fn algorithm, bytes, signature ->
      Crypto.verify(algorithm, bytes, signature, {:hmac, secret})
    end
  end

  defp public_key(name) do
    {:ok, key} =
      PublicKey.import(File.read!(Path.join(@fixtures, "crypto/" <> name <> "_public.pem")), :pem)

    key
  end
end
