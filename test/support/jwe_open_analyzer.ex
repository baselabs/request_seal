defmodule RequestSeal.Test.JWEOpenAnalyzer do
  @moduledoc false
  alias RequestSeal.JOSE.JWE.{
    Bounds,
    Codec,
    Coordinator,
    Guard,
    Open,
    Preflight,
    Resolver,
    Unwrap,
    Worker
  }

  @library [Guard, Coordinator, Preflight, Worker, Bounds, Codec]
  @roles %{
    Guard => :guard,
    Coordinator => :library,
    Preflight => :library,
    Worker => :library,
    Resolver => :caller_code,
    Unwrap => :caller_code
  }

  # Exact OTP operations, with the reason each may run without invoking caller code.
  @allowed %{
    {:atomics, :new, 2} => "create the caller stop and accepted-cardinality cells",
    {:atomics, :get, 2} => "read stop flag or accepted cardinality",
    {:atomics, :put, 3} => "publish accepted cardinality once, or stop preflight input",
    {:ets, :new, 2} => "create registry, ended set or end notice",
    {:ets, :give_away, 3} => "transfer notice or registry ownership",
    {:ets, :info, 2} => "constant owner read before dequeue or callback",
    {:ets, :insert, 2} => "record child, end marker or reply outcome",
    {:ets, :lookup, 2} => "read one slot or outcome",
    {:ets, :lookup_element, 4} =>
      "read a slot pid without copying its row; missing slots have a default",
    {:ets, :select, 3} => "literal registry match spec excludes joined resolvers in 64-row pages",
    {:ets, :select, 1} => "continue the same bounded registry sweep without caller code",
    {:ets, :foldl, 3} => "one registry sweep with a literal library function",
    {:ets, :delete, 1} => "free a received child notice",
    {:erlang, :process_flag, 2} => "sensitivity, trap exits and off-heap queues",
    {:erlang, :unlink, 1} => "remove reason-bearing link before caller code",
    {:erlang, :monitor, 2} => "observe only library processes",
    {:erlang, :exit, 1} => "closed atom exit",
    {:erlang, :exit, 2} => "kill a registered child or coordinator",
    {:erlang, :spawn_opt, 4} => "closed role dispatch with constant arguments",
    {:erlang, :spawn_link, 3} => "start coordinator with registry heir at guard",
    {:erlang, :send_after, 4} => "absolute rounded-up millisecond wakeup",
    {:erlang, :monotonic_time, 1} => "read absolute microsecond deadline",
    {:erlang, :send, 2} => "library-built protocol envelope",
    {:erlang, :self, 0} => "local identity",
    {:erlang, :make_ref, 0} => "opaque call or route tag",
    {:erlang, :alias, 0} => "revocable delivery route",
    {:erlang, :unalias, 1} => "revoke routed deliveries",
    {:erlang, :system_info, 1} => "bound range count by online schedulers",
    {:erlang, :fun_info, 2} => "bounded walk includes closure environment",
    {:erlang, :iolist_to_binary, 1} => "bounded JSON serialization",
    {:erlang, :error, 1} => "library exception contained at role entry",
    {:erlang, :error, 2} => "library exception contained at role entry",
    {:erlang, :throw, 1} => "closed preflight or codec refusal",
    {:erts_debug, :flat_size, 1} =>
      "exact size only after the budget-limited walk, or scalar integer size",
    {:maps, :get, 2} => "bounded local state lookup",
    {:maps, :get, 3} => "bounded local state lookup with default",
    {:maps, :put, 3} => "cap-bounded local state update",
    {:maps, :find, 2} => "bounded local state lookup",
    {:maps, :take, 2} => "settle one group",
    {:maps, :remove, 2} => "drop one settled position",
    {:maps, :keys, 1} => "bounded policy or JSON keys",
    {:maps, :to_list, 1} => "cap-bounded state pass or bounded JSON object",
    {:maps, :from_list, 1} => "rebuild cap-bounded state once after expiry",
    {:maps, :iterator, 1} => "word-limited map walk without copying entries",
    {:maps, :next, 1} => "one bounded map-walk unit",
    {:maps, :merge, 2} => "bounded public agreement parameters",
    {:lists, :member, 2} => "bounded policy or JSON selection",
    {:lists, :keymember, 3} => "bounded duplicate JSON member check",
    {:lists, :sort, 1} => "bounded exact policy keys",
    {:lists, :reverse, 1} => "bounded rows or JSON accumulator",
    {:lists, :all, 2} => "literal library JSON predicate",
    {:lists, :any, 2} => "literal library JSON predicate",
    {:binary, :longest_common_prefix, 1} =>
      "skip repetition of one validated whitespace word in a capped binary",
    {:binary, :match, 3} => "at most five scoped separator searches in one capped token",
    {:binary, :part, 3} => "binary slice without caller code",
    {:binary, :last, 1} => "canonical base64 tail bits",
    {:binary, :decode_unsigned, 1} => "bounded public EC coordinate",
    {:base64, :decode, 2} => "bounded canonical base64url",
    {:json, :encode, 1} => "validated plain JSON tree",
    {:json, :decode, 3} => "literal bounded decoder accumulators",
    {:crypto, :strong_rand_bytes, 1} => "fresh per-item fallback CEK",
    {:crypto, :crypto_one_time_aead, 7} => "authenticate in sensitive range worker",
    {:crypto, :compute_key, 4} => "validate bounded public EC point"
  }

  def roles, do: @roles
  def allowlist, do: @allowed

  def check do
    forms = Map.new([Open, Resolver, Unwrap | @library], &{&1, forms(&1)})

    sites =
      for {m, fs} <- forms,
          {:function, _, f, a, body} <- fs,
          call <- calls(body),
          spawn?(call),
          do: {m, f, a, call}

    roots = Enum.map(sites, fn {_, _, _, call} -> spawn_target!(call) end)

    expected = [
      {Guard, :run, 9},
      {Coordinator, :run, 10},
      {Preflight, :run, 5},
      {Worker, :run, 9},
      {Resolver, :run, 8},
      {Unwrap, :run, 8}
    ]

    if Enum.sort(roots) != Enum.sort(expected), do: raise("spawn roots differ: #{inspect(roots)}")
    Enum.each(@library, fn m -> inspect_module(m, forms[m], forms) end)

    exits =
      for {module, fs} <- forms,
          module in [Guard, Coordinator],
          {:function, _, function, arity, body} <- fs,
          {:call, _, {:remote, _, {:atom, _, :erlang}, {:atom, _, :exit}}, [_, _]} <- calls(body),
          do: {module, function, arity}

    expected_exits = [
      {Guard, :kill, 3},
      {Guard, :sweep, 3},
      {Coordinator, :receive_one, 1},
      {Coordinator, :resolved, 3},
      {Coordinator, :expire_positions, 2},
      {Coordinator, :finish_group, 4},
      {Coordinator, :kill_groups, 1},
      {Coordinator, :dead_positions, 4},
      {Coordinator, :drain_preflight, 2},
      {Coordinator, :kill_registered, 1}
    ]

    unless Enum.sort(exits) == Enum.sort(expected_exits),
      do: raise("JWE kill site inventory differs: #{inspect(exits)}")

    wiring!(forms)
    inventory!()
    %{roots: roots, roles: @roles, allowlist: @allowed, sites: sites}
  end

  def forms(module) do
    case :beam_lib.chunks(:code.which(module), [:abstract_code]) do
      {:ok, {^module, [abstract_code: {:raw_abstract_v1, forms}]}} ->
        if Enum.any?(forms, &match?({:attribute, _, :on_load, _}, &1)),
          do: raise("on_load is forbidden: #{module}")

        forms

      _ ->
        raise "missing abstract code: #{module}"
    end
  end

  def analyze_forms(module, fs), do: inspect_module(module, fs, %{module => fs})

  defp inspect_module(module, fs, modules) do
    if Enum.any?(fs, &match?({:attribute, _, :on_load, _}, &1)),
      do: raise("on_load is forbidden")

    Enum.each(fs, fn
      {:function, _, _, _, body} ->
        validate_forms!(body)

        Enum.each(calls(body), fn
          {:call, _, {:remote, _, {:atom, _, m}, {:atom, _, f}}, args} ->
            arity = length(args)

            cond do
              m in @library ->
                unless Enum.any?(modules[m], &match?({:function, _, ^f, ^arity, _}, &1)),
                  do: raise("undefined library call #{inspect({m, f, arity})}")

              Map.has_key?(@allowed, {m, f, arity}) ->
                :ok

              m == :erlang and {f, arity} in basic_bifs() ->
                :ok

              true ->
                raise "caller code reachable: #{inspect({module, m, f, arity})}"
            end

          {:call, _, {:atom, _, f}, args} ->
            arity = length(args)

            unless {f, arity} in basic_bifs() or
                     Enum.any?(fs, &match?({:function, _, ^f, ^arity, _}, &1)),
                   do: raise("undefined local call")

          call ->
            raise "dynamic caller code: #{inspect(call)}"
        end)

      _ ->
        :ok
    end)
  end

  defp basic_bifs do
    [
      is_atom: 1,
      is_binary: 1,
      is_bitstring: 1,
      is_boolean: 1,
      is_float: 1,
      is_function: 1,
      is_function: 2,
      is_integer: 1,
      is_list: 1,
      is_map: 1,
      is_map_key: 2,
      is_number: 1,
      is_pid: 1,
      is_reference: 1,
      is_tuple: 1,
      map_size: 1,
      tuple_size: 1,
      byte_size: 1,
      bit_size: 1,
      map_get: 2,
      element: 2,
      length: 1,
      hd: 1,
      tl: 1,
      min: 2,
      max: 2,
      self: 0,
      get_module_info: 1,
      get_module_info: 2
    ]
  end

  # Refuse unknown abstract forms rather than silently skipping their children.
  def validate_forms!(xs) when is_list(xs), do: Enum.each(xs, &validate_forms!/1)

  def validate_forms!({tag, _, _}) when tag in [:atom, :integer, :float, :char, :string, :var],
    do: :ok

  def validate_forms!({nil, _}), do: :ok

  def validate_forms!({:clause, _, patterns, guards, body}),
    do: validate_forms!([patterns, guards, body])

  def validate_forms!({:call, _, {:remote, _, {:atom, _, m}, {:atom, _, f}}, [fun | rest]})
      when {m, f} in [{:lists, :all}, {:lists, :any}, {:ets, :foldl}] do
    literal_fun!(fun)
    validate_forms!(rest)
  end

  def validate_forms!(
        {:call, _, {:remote, _, {:atom, _, :json}, {:atom, _, :decode}},
         [bytes, acc, {:map, _, fields}]}
      ) do
    validate_forms!([bytes, acc])

    Enum.each(fields, fn
      {:map_field_assoc, _, {:atom, _, key}, fun} when key in [:object_push, :array_push] ->
        literal_fun!(fun)

      field ->
        validate_forms!(field)
    end)
  end

  def validate_forms!({:call, _, {:remote, _, {:atom, _, _}, {:atom, _, _}}, args}),
    do: validate_arguments!(args)

  def validate_forms!({:call, _, {:atom, _, _}, args}), do: validate_arguments!(args)
  def validate_forms!({:call, _, _, _}), do: raise("dynamic callee")
  def validate_forms!({:fun, _, _}), do: raise("unapproved fun value")

  def validate_forms!({:bin_element, _, value, size, types}) do
    validate_forms!(value)
    if size != :default, do: validate_forms!(size)

    unless types == :default or
             Enum.all?(types, &(is_atom(&1) or match?({:unit, n} when is_integer(n), &1))),
           do: raise("unknown binary type")
  end

  def validate_forms!({:op, _, op, value}) when op in [:+, :-, :bnot, :not],
    do: validate_forms!(value)

  def validate_forms!({:op, _, op, a, b})
      when op in [
             :+,
             :-,
             :*,
             :/,
             :div,
             :rem,
             :==,
             :"/=",
             :"=:=",
             :"=/=",
             :<,
             :>,
             :"=<",
             :>=,
             :and,
             :or,
             :xor,
             :andalso,
             :orelse,
             :++,
             :--,
             :!,
             :band,
             :bor,
             :bxor,
             :bsl,
             :bsr
           ],
      do: validate_forms!([a, b])

  def validate_forms!(node) when is_tuple(node) do
    tag = elem(node, 0)

    if tag in [
         :cons,
         :tuple,
         :map,
         :map_field_assoc,
         :map_field_exact,
         :match,
         :block,
         :case,
         :if,
         :receive,
         :try,
         :bin,
         :lc,
         :bc,
         :mc,
         :generate,
         :b_generate,
         :m_generate
       ] do
      node |> Tuple.to_list() |> Enum.drop(2) |> validate_forms!()
    else
      raise "unknown or forbidden abstract form: #{inspect(tag)}"
    end
  end

  def validate_forms!(_), do: raise("unknown abstract term")
  defp literal_fun!({:fun, _, {:clauses, clauses}}), do: validate_forms!(clauses)
  defp literal_fun!(_), do: raise("callback must be a literal library fun")
  defp validate_arguments!(args), do: validate_forms!(args)

  def calls(term) when is_list(term), do: Enum.flat_map(term, &calls/1)
  def calls({:call, _, _, _} = term), do: [term | Enum.flat_map(Tuple.to_list(term), &calls/1)]
  def calls(term) when is_tuple(term), do: Enum.flat_map(Tuple.to_list(term), &calls/1)
  def calls(_), do: []

  defp spawn?({:call, _, {:remote, _, {:atom, _, :erlang}, {:atom, _, f}}, _}),
    do: f in [:spawn_opt, :spawn_link, :spawn, :spawn_monitor]

  defp spawn?(_), do: false

  defp spawn_target!({:call, _, _, [{:atom, _, m}, {:atom, _, f}, args | _]}),
    do: {m, f, list_length!(args)}

  defp spawn_target!(call), do: raise("nonliteral spawn target: #{inspect(call)}")
  defp list_length!({nil, _}), do: 0
  defp list_length!({:cons, _, _, tail}), do: 1 + list_length!(tail)
  defp list_length!(_), do: raise("nonliteral spawn argument list")

  # All non-JWE process creation and exit/2 sites are independently enumerated.
  # This prevents a new process helper from escaping the six-role inventory.
  defp inventory! do
    directory = :code.which(Open) |> List.to_string() |> Path.dirname()
    files = Path.wildcard(Path.join(directory, "Elixir.RequestSeal*.beam"))

    outside =
      for file <- files,
          module = file |> Path.basename(".beam") |> String.to_atom(),
          not String.starts_with?(Atom.to_string(module), "Elixir.RequestSeal.Test."),
          module not in [Open, Resolver, Unwrap | @library],
          {:function, _, function, arity, body} <- forms(module),
          call <- calls(body),
          process_site?(call),
          do: {module, function, arity, site_name(call)}

    expected = [
      {RequestSeal.Custody, :run_worker, 2, :spawn_monitor},
      {RequestSeal.Custody, :watch_owner, 4, :spawn_link},
      {RequestSeal.Custody, :stop_runner, 1, :exit},
      {RequestSeal.Replay, :run, 2, :spawn_monitor},
      {RequestSeal.Replay, :watch_owner, 3, :spawn_link},
      {RequestSeal.Replay, :stop_runner, 1, :exit},
      {RequestSeal.Custody.Sink, :collect, 2, :spawn_monitor},
      {RequestSeal.Custody.Local, :start_holder, 4, :spawn_monitor},
      {RequestSeal.Custody.Local, :start_holder, 4, :exit},
      {RequestSeal.Discovery.Support, :run, 2, :spawn_monitor},
      {RequestSeal.Discovery.Support, :watch, 3, :spawn_link},
      {RequestSeal.Discovery.Support, :stop, 1, :exit},
      {RequestSeal.Discovery.Cache, :pending, 6, :spawn_opt},
      {RequestSeal.Discovery.Cache, :stop_flight, 1, :exit},
      {RequestSeal.SystemCommand, :agent, 2, :spawn_monitor}
    ]

    unless Enum.sort(outside) == Enum.sort(expected),
      do: raise("process site inventory differs: #{inspect(outside)}")
  end

  defp process_site?(call), do: spawn?(call) or site_name(call) == :exit

  defp site_name({:call, _, {:remote, _, {:atom, _, m}, {:atom, _, f}}, args})
       when m in [:erlang, Process] and f in [:spawn, :spawn_opt, :spawn_monitor, :spawn_link] and
              is_list(args),
       do: f

  defp site_name({:call, _, {:remote, _, {:atom, _, m}, {:atom, _, :exit}}, [_, _]})
       when m in [:erlang, Process], do: :exit

  defp site_name(_), do: nil

  defp wiring!(forms) do
    resolver =
      for {:function, _, :start_child, _, body} <- forms[Coordinator],
          call <- calls(body),
          spawn?(call),
          spawn_target!(call) == {Resolver, :run, 8},
          do: call

    if length(resolver) != 1, do: raise("coordinator must spawn the production resolver entry")
    worker_source = File.read!("lib/request_seal/jose/jwe/worker.ex")

    unless worker_source =~ "{:ok, algorithm, %KeyHandle{} = handle, digest}" and
             worker_source =~ "when is_atom(refusal)",
           do: raise("range answer must match only bounded shape")

    deletes =
      for {m, fs} <- forms,
          {:function, _, f, _, body} <- fs,
          {:call, _, {:remote, _, {:atom, _, :ets}, {:atom, _, :delete}}, [_]} <- calls(body),
          do: {m, f}

    expected_deletes = [{Guard, :receive_one}, {Guard, :join}, {Open, :drain}]

    unless Enum.sort(deletes) == Enum.sort(expected_deletes),
      do: raise("notice deletion inventory differs: #{inspect(deletes)}")
  end
end
