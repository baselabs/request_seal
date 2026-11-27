defmodule RequestSeal.Quorum.Evaluation do
  @moduledoc false

  alias RequestSeal.{
    AcceptSignature,
    Authentication,
    Error,
    KeyIdentity,
    Message,
    Quorum,
    Replay,
    SignatureFields
  }

  alias RequestSeal.Custody.Context
  alias RequestSeal.Quorum.Verification

  @work_budget 16_384

  def verify(message, quorum, opts) do
    protect(fn ->
      {deadline, requests} = options(opts)
      checkpoint(deadline)

      {assignments, count, negotiation, key} =
        unwrap(evaluate(message, quorum, requests, deadline))

      checkpoint(deadline)
      replay = claim(key, quorum.replay, deadline)

      {:ok,
       %Verification{
         assignments: assignments,
         count: count,
         negotiation: negotiation,
         replay: replay
       }}
    end)
  end

  defp evaluate(message, quorum, requests, deadline) do
    callback = fn ->
      protect(fn ->
        checkpoint(deadline)
        ensure(Quorum.valid?(quorum), :invalid_quorum, :input)
        ensure(Message.validate(message) == :ok, :invalid_message, :input)
        validate_requests(requests, message.kind)

        {entries, signatures} =
          unwrap(Authentication.dictionaries(message, quorum.max_signatures))

        check_signature_limits(quorum.slots, length(entries))
        eligible = admission(entries, quorum.slots)
        candidates = qualify(eligible, signatures, message, quorum, deadline)
        {count, selected} = assign(candidates, quorum, deadline)
        negotiation = negotiate(requests, candidates, entries, deadline)
        key = replay_key(candidates, quorum.replay)

        assignments =
          Map.new(selected, fn {id, candidate} -> {id, candidate.verification} end)

        {:ok, {assignments, count, negotiation, key}}
      end)
    end

    if deadline do
      context = %Context{owner: self(), deadline: deadline}

      case Replay.run(context, callback) do
        {:error, %Replay.Error{reason: :store_timeout}} -> fail(:deadline, :quorum)
        {:error, %Replay.Error{reason: :invalid_options}} -> fail(:invalid_options, :input)
        {:error, %Replay.Error{}} -> {:error, Error.new(:internal, :internal, :exit)}
        result -> result
      end
    else
      callback.()
    end
  end

  defp protect(fun) do
    fun.()
  rescue
    exception -> {:error, Error.new(:internal, :internal, exception.__struct__)}
  catch
    {:quorum, %Error{} = error} -> {:error, error}
    :exit, _ -> {:error, Error.new(:internal, :internal, :exit)}
    _, _ -> {:error, Error.new(:internal, :internal, :throw)}
  end

  defp options(opts) when is_list(opts) and length(opts) <= 2 do
    ensure(Keyword.keyword?(opts), :invalid_options, :input)
    keys = Keyword.keys(opts)
    deadline = opts[:deadline]

    ensure(
      Enum.all?(keys, &(&1 in [:deadline, :accept_signature])) and
        Enum.uniq(keys) == keys and (is_nil(deadline) or is_integer(deadline)),
      :invalid_options,
      :input
    )

    {deadline, Keyword.get(opts, :accept_signature, [])}
  end

  defp options(_), do: fail(:invalid_options, :input)

  defp validate_requests(requests, kind) do
    case AcceptSignature.validate_requests(requests, kind) do
      :ok -> :ok
      {:error, error} -> throw({:quorum, error})
    end
  end

  defp check_signature_limits(slots, count) do
    ensure(Enum.all?(slots, &(count <= &1.policy.max_signatures)), :limit, :input)
  end

  defp admission(entries, slots) do
    slots = Enum.sort_by(slots, & &1.id)

    {eligible, _count} =
      entries
      |> Enum.sort_by(&elem(&1, 0))
      |> Enum.map_reduce(0, fn {label, input}, count ->
        tag = SignatureFields.parameters(input)["tag"]

        eligible = Enum.filter(slots, &Quorum.selector_matches?(&1, label, tag))

        count = count + length(eligible)
        ensure(count <= Quorum.verification_budget(), :limit, :input)
        {{label, input, eligible}, count}
      end)

    eligible
  end

  defp qualify(eligible, signatures, message, quorum, deadline) do
    [first | _] = quorum.slots
    now = unwrap(Authentication.freshness_time(first.policy.freshness))

    context = %{
      quorum_now: now,
      quorum_replay: {scope(quorum), identifier(quorum.replay.identifier)}
    }

    {groups, _} =
      Enum.map_reduce(eligible, %{}, fn {label, input, slots}, digest_cache ->
        checkpoint(deadline)

        {records, cache} =
          Enum.reduce(slots, {[], digest_cache}, fn slot, {records, cache} ->
            checkpoint(deadline)

            {result, cache} =
              Authentication.verify_label(
                message,
                slot.policy,
                label,
                input,
                signatures[label],
                context,
                cache
              )

            checkpoint(deadline)

            case result do
              {:ok, {verification, identity, replay}} ->
                candidate = %{
                  slot: slot,
                  label: label,
                  verification: verification,
                  key: identity_vertex(identity),
                  replay: replay,
                  covered: MapSet.new(verification.signature.covered)
                }

                {[candidate | records], cache}

              {:error, _} ->
                {records, cache}
            end
          end)

        ensure(slots != [] or quorum.unexpected == :ignore, :unexpected_signature, :quorum)

        ensure(
          slots == [] or records != [] or quorum.invalid == :ignore,
          :nonqualifying_signature,
          :quorum
        )

        {Enum.reverse(records), Map.take(cache, [:content])}
      end)

    List.flatten(groups)
  end

  defp identity_vertex(%KeyIdentity{kind: :public, value: material}), do: {:public, material}
  defp identity_vertex(%KeyIdentity{kind: :symmetric, value: value}), do: {:symmetric, value}
  defp identity_vertex(_), do: :unknown

  defp assignments_by_slot(records, quorum, state) do
    {known, unknown} = Enum.split_with(records, &(&1.key != :unknown))
    unknown_slots = MapSet.new(unknown, & &1.slot.id)

    # Only authenticated key identities establish independence. A label
    # observed under two known identities connects them into one class.
    {parents, state} =
      Enum.reduce(known, {%{}, state}, fn record, {parents, state} ->
        {left, state} = root({:label, record.label}, parents, state)
        {right, state} = root(record.key, parents, state)

        if left == right,
          do: {parents, state},
          else: {Map.put(parents, max(left, right), min(left, right)), state}
      end)

    {edges, state} =
      Enum.map_reduce(known, state, fn record, state ->
        {class, state} = root({:label, record.label}, parents, state)
        {Map.put(record, :class, class), state}
      end)

    edges = Enum.group_by(edges, & &1.slot.id)

    Enum.map_reduce(Enum.sort_by(quorum.slots, &{not &1.required, &1.id}), state, fn slot,
                                                                                     state ->
      available = Map.get(edges, slot.id, [])

      ensure(
        not slot.required or available != [] or not MapSet.member?(unknown_slots, slot.id),
        :ambiguous_key_identity,
        :quorum
      )

      {{slot, available}, spend(state)}
    end)
  end

  defp root(vertex, parents, state) do
    state = spend(state)

    case Map.fetch(parents, vertex) do
      {:ok, next} -> root(next, parents, state)
      :error -> {vertex, state}
    end
  end

  defp assign(candidates, quorum, deadline) do
    upper = unit_bound(quorum.slots, quorum.unit)
    state = %{work: 0, best: nil, bound: false, required: false, deadline: deadline}
    {slots, state} = assignments_by_slot(candidates, quorum, state)
    state = search(slots, %{}, MapSet.new(), upper, quorum, state)

    case state do
      %{best: {{count, _}, selected}} -> {count, selected}
      %{required: true, bound: false} -> fail(:binding_unsatisfied, :quorum)
      _ -> fail(:quorum_not_met, :quorum)
    end
  catch
    {:work_budget, {{count, _}, selected}} -> {count, selected}
    {:work_budget, nil} -> fail(:limit, :input)
  end

  @spec search(list(), map(), MapSet.t(), non_neg_integer(), map(), map()) :: map()
  defp search([], selected, _used, _upper, quorum, state) when map_size(selected) > 0 do
    state = %{spend(state) | required: true}
    {bound?, state} = bindings?(selected, quorum.bindings, state)

    if bound? do
      state = %{state | bound: true}
      chosen = Map.values(selected)
      {count, state} = count(chosen, quorum.unit, state)
      score = {count, map_size(selected)}

      {met?, state} = mode_met?(count, chosen, quorum, state)

      if met? and better?(state.best, score),
        do: %{state | best: {score, selected}},
        else: state
    else
      state
    end
  end

  defp search([], _selected, _used, _upper, _quorum, state), do: spend(state)

  defp search([{slot, edges} | rest] = slots, selected, used, upper, quorum, state) do
    state = spend(state)
    max_size = map_size(selected) + length(slots)

    if better?(state.best, {min(max_size, upper), max_size}) do
      state =
        Enum.reduce_while(edges, state, fn candidate, state ->
          if better?(state.best, {min(max_size, upper), max_size}) do
            state = spend(state)

            state =
              if MapSet.member?(used, candidate.class) do
                state
              else
                search(
                  rest,
                  Map.put(selected, slot.id, candidate),
                  MapSet.put(used, candidate.class),
                  upper,
                  quorum,
                  state
                )
              end

            {:cont, state}
          else
            {:halt, state}
          end
        end)

      if slot.required,
        do: state,
        else: search(rest, selected, used, upper, quorum, state)
    else
      state
    end
  end

  defp better?(nil, _), do: true
  defp better?({best, _}, candidate), do: candidate > best

  defp mode_met?(count, _, %{mode: {:threshold, n}}, state), do: {count >= n, state}

  defp mode_met?(
         _,
         records,
         %{mode: :all, unit: {:role, [shared_principal: false]} = unit},
         state
       ) do
    required = Enum.filter(records, & &1.slot.required)
    {count, state} = count(required, unit, state)
    {count == unit_bound(Enum.map(required, & &1.slot), {:role, [shared_principal: true]}), state}
  end

  defp mode_met?(count, _, _, state), do: {count > 0, state}

  defp unit_bound(slots, :key), do: length(slots)
  defp unit_bound(slots, :principal), do: distinct(slots, :principal)
  defp unit_bound(slots, {:role, _}), do: distinct(slots, :role)

  defp distinct(slots, key), do: slots |> MapSet.new(&Map.fetch!(&1, key)) |> MapSet.size()

  @doc false
  def count_units(slots, unit), do: elem(count_slots(slots, unit, nil), 0)

  defp count(records, unit, state), do: count_slots(Enum.map(records, & &1.slot), unit, state)

  defp count_slots(slots, {:role, [shared_principal: false]}, state) do
    edges = Enum.group_by(slots, & &1.role, & &1.principal)

    {matching, state} =
      edges
      |> Map.keys()
      |> Enum.sort()
      |> Enum.reduce({%{}, state}, fn role, {matching, state} ->
        case augment(role, edges, matching, MapSet.new(), state) do
          {:matched, matching, state} -> {matching, state}
          {:unmatched, _, state} -> {matching, state}
        end
      end)

    {map_size(matching), state}
  end

  defp count_slots(slots, unit, state), do: {unit_bound(slots, unit), state}

  @spec augment(term(), map(), map(), MapSet.t(), map()) ::
          {:matched, map(), map()} | {:unmatched, MapSet.t(), map()}
  defp augment(role, edges, matching, seen, state) do
    state = spend(state)

    Enum.reduce_while(Map.fetch!(edges, role), {:unmatched, seen, state}, fn principal,
                                                                             {:unmatched, seen,
                                                                              state} ->
      state = spend(state)

      cond do
        MapSet.member?(seen, principal) ->
          {:cont, {:unmatched, seen, state}}

        not Map.has_key?(matching, principal) ->
          {:halt, {:matched, Map.put(matching, principal, role), state}}

        true ->
          seen = MapSet.put(seen, principal)

          case augment(Map.fetch!(matching, principal), edges, matching, seen, state) do
            {:matched, updated, state} ->
              {:halt, {:matched, Map.put(updated, principal, role), state}}

            {:unmatched, seen, state} ->
              {:cont, {:unmatched, seen, state}}
          end
      end
    end)
  end

  defp bindings?(selected, bindings, state) do
    Enum.reduce_while(bindings, {true, state}, fn binding, {true, state} ->
      state = spend(state)
      if binding?(selected, binding), do: {:cont, {true, state}}, else: {:halt, {false, state}}
    end)
  end

  defp binding?(selected, {:nested, [outer: outer, inner: inner]}) do
    with {:ok, outer} <- Map.fetch(selected, outer),
         {:ok, inner} <- Map.fetch(selected, inner) do
      Enum.all?(["signature-input", "signature"], fn field ->
        MapSet.member?(outer.covered, ~s["#{field}";key="#{inner.label}"])
      end)
    else
      _ -> false
    end
  end

  defp binding?(selected, {:same_parameter, name, slots}) do
    case Enum.uniq(Enum.map(slots, &get_parameter(selected, &1, name))) do
      [value] when value != nil -> true
      _ -> false
    end
  end

  defp get_parameter(selected, id, name) do
    case Map.fetch(selected, id) do
      {:ok, candidate} -> candidate.verification.signature.parameters[name]
      :error -> nil
    end
  end

  defp negotiate([], _candidates, _entries, _deadline), do: :not_requested

  defp negotiate(requests, candidates, entries, deadline) do
    qualified =
      candidates
      |> Enum.reject(&(&1.key == :unknown))
      |> Map.new(&{&1.label, &1.verification.signature.parameters})

    inputs = Map.new(entries)

    Enum.each(requests, fn request ->
      checkpoint(deadline)
      label = request.label

      ensure(
        Map.has_key?(qualified, label) and
          MapSet.new(SignatureFields.identities(inputs[label].value)) ==
            MapSet.new(SignatureFields.identities(request.components.value)) and
          Enum.all?(request.parameters, fn
            {name, true} -> is_integer(qualified[label][name])
            {name, value} -> qualified[label][name] == value
          end),
        :negotiation_unfulfilled,
        :negotiation
      )
    end)

    :fulfilled
  end

  defp replay_key(candidates, replay) do
    ensure(
      Enum.all?(
        candidates,
        &(Authentication.retain_until(&1.verification.freshness) <= replay.retain_until)
      ),
      :retention_exceeded,
      :replay
    )

    case Enum.uniq_by(candidates, & &1.replay) do
      [%{replay: {:ok, digest}}] -> digest
      _ -> fail(:replay_identity_mismatch, :replay)
    end
  end

  defp claim(key, replay, deadline) do
    commitment = fn _ -> {:ok, key} end

    policy = %{
      namespace: replay.namespace,
      store: replay.store,
      timeout: replay.timeout,
      commitment: commitment
    }

    unwrap(Replay.commit(policy, %{}, replay.retain_until, deadline))
  end

  defp scope(%{replay: %{scope: :namespace}}), do: :namespace

  defp scope(quorum),
    do: {:principals, quorum.slots |> Enum.map(& &1.principal) |> Enum.uniq() |> Enum.sort()}

  defp identifier({:nonce, :shared}), do: :nonce
  defp identifier(identifier), do: identifier

  defp spend(nil), do: nil

  defp spend(state) do
    checkpoint(state.deadline)
    if state.work >= @work_budget, do: throw({:work_budget, state.best})
    %{state | work: state.work + 1}
  end

  defp checkpoint(nil), do: :ok

  defp checkpoint(deadline),
    do: ensure(System.monotonic_time(:millisecond) < deadline, :deadline, :quorum)

  defp unwrap({:ok, value}), do: value
  defp unwrap({:error, %Error{} = error}), do: throw({:quorum, error})
  defp ensure(true, _, _), do: :ok
  defp ensure(_, reason, layer), do: fail(reason, layer)
  defp fail(reason, layer), do: throw({:quorum, Error.new(reason, layer)})
end
