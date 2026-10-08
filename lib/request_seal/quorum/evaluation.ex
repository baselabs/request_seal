defmodule RequestSeal.Quorum.Evaluation do
  @moduledoc false
  alias RequestSeal.{
    AcceptSignature,
    Authentication,
    Error,
    KeyIdentity,
    Message,
    Quorum,
    SignatureFields
  }

  alias RequestSeal.Quorum.Verification

  def verify(message, quorum, opts) do
    protect(fn ->
      ensure(
        Quorum.bounded_list?(opts, 0, 1) and Keyword.keyword?(opts) and
          Enum.all?(Keyword.keys(opts), &(&1 == :accept_signature)),
        :invalid_options,
        :input
      )

      ensure(Quorum.valid?(quorum), :invalid_quorum, :input)

      ensure(
        Enum.all?(quorum.slots, &(&1.policy.replay == :not_required)),
        :invalid_policy,
        :input
      )

      ensure(Message.validate(message) == :ok, :invalid_message, :input)
      requests = Keyword.get(opts, :accept_signature, [])

      case AcceptSignature.validate_requests(requests, message.kind) do
        :ok -> :ok
        {:error, error} -> throw({:quorum_error, error})
      end

      {entries, signatures} = unwrap(Authentication.dictionaries(message, quorum.max_signatures))
      # Normalize optional slot fields for validated direct structs as well.
      {:ok, quorum} = Quorum.new(Map.from_struct(quorum))

      {qualified, facts, outcomes} =
        Enum.reduce(Enum.sort_by(entries, &elem(&1, 0)), {[], [], []}, fn {label, input},
                                                                          {qualified, facts,
                                                                           outcomes} ->
          params = SignatureFields.parameters(input)

          slots =
            Enum.filter(quorum.slots, fn s ->
              (s.label == nil or s.label == label) and (s.tag == nil or s.tag == params["tag"])
            end)

          {records, failures} =
            verify_candidates(message, slots, label, input, signatures[label], %{}, [], [])

          outcome =
            cond do
              slots == [] -> {:unexpected, nil}
              records == [] -> {:invalid, List.last(failures).reason}
              true -> {:qualified, nil}
            end

          facts =
            if slots == [],
              do:
                facts ++
                  [%{label: label, slot: nil, reason: :unexpected_signature, layer: :quorum}],
              else: facts ++ failures

          {qualified ++ records, facts, outcomes ++ [outcome]}
        end)

      Enum.each(outcomes, fn
        {:unexpected, _} ->
          ensure(quorum.unexpected == :ignore, :unexpected_signature, :quorum)

        {:invalid, reason} ->
          if quorum.invalid == :reject, do: fail(:nonqualifying_signature, :quorum, reason)

        _ ->
          :ok
      end)

      {qualified, pool} = assign(qualified, quorum, requests)
      count = count(qualified, quorum.unit)
      required = for s <- quorum.slots, s.required, do: s.id
      satisfied = for s <- quorum.slots, Enum.any?(qualified, &(&1.slot.id == s.id)), do: s.id

      met =
        count > 0 and Enum.all?(required, &(&1 in satisfied)) and
          case quorum.mode do
            :all -> roles_met?(qualified, quorum)
            :any -> true
            {:threshold, n} -> count >= n
          end

      ensure(met, :quorum_not_met, :quorum)
      bindings = bindings(qualified, quorum.bindings)
      negotiation = negotiation(pool, requests)
      order = quorum.slots |> Enum.with_index() |> Map.new(fn {s, i} -> {s.id, i} end)
      qualified = Enum.sort_by(qualified, &{order[&1.slot.id], &1.verification.label})

      {:ok,
       %Verification{
         profile: %{name: :rfc9421},
         mode: quorum.mode,
         unit: quorum.unit,
         required: required,
         satisfied: satisfied,
         count: count,
         qualifying:
           Enum.map(qualified, fn r ->
             %{
               label: r.verification.label,
               slot: r.slot.id,
               principal: r.slot.principal,
               role: r.slot.role
             }
           end),
         signatures: Map.new(qualified, &{&1.verification.label, &1.verification}),
         nonqualifying: facts,
         bindings: bindings,
         negotiation: negotiation
       }}
    end)
  end

  defp verify_candidates(_, [], _, _, _, _, records, failures), do: {records, failures}

  defp verify_candidates(message, [slot | rest], label, input, sig, cache, records, failures) do
    {result, cache} =
      Authentication.verify_label(message, slot.policy, label, input, sig, %{}, cache)

    case result do
      {:ok, verification, identity} ->
        record = %{
          label: label,
          slot: slot,
          verification: verification,
          identity: identity,
          input: input
        }

        verify_candidates(message, rest, label, input, sig, cache, records ++ [record], failures)

      {:error, error} ->
        fact = %{label: label, slot: slot.id, reason: error.reason, layer: error.layer}
        verify_candidates(message, rest, label, input, sig, cache, records, failures ++ [fact])
    end
  end

  @node_budget 131_072

  defp assign(records, quorum, requests) do
    records = merge_identity_classes(records)
    records = drop_unknown_for_key_unit(records, quorum)
    labels = Enum.map(requests, & &1.label)
    slots = Enum.sort_by(quorum.slots, & &1.id)

    records =
      Enum.sort_by(
        records,
        &{&1.slot.id, &1.verification.label not in labels, &1.verification.label}
      )

    edges = Enum.group_by(records, & &1.slot.id, &{&1.class, &1})
    bound = binding_slots(quorum.bindings)
    required = Enum.filter(slots, & &1.required)
    mandatory = Enum.filter(slots, &(&1.required or MapSet.member?(bound, &1.id)))
    required_match = cover_required_by_matching(required, edges, :quorum_not_met)
    cover_required_by_matching(mandatory, edges, :binding_unsatisfied)

    chosen =
      if quorum.bindings == [] and quorum.unit != {:role, [shared_principal: false]} do
        maximize_units_by_matching(slots, edges, required_match, quorum.unit)
      else
        search_assignment(slots, edges, bound, quorum)
      end

    ensure(
      length(Enum.uniq_by(chosen, & &1.verification.label)) == length(chosen),
      :quorum_not_met,
      :quorum
    )

    ensure(length(Enum.uniq_by(chosen, & &1.class)) == length(chosen), :quorum_not_met, :quorum)

    ensure(
      Enum.all?(required, fn s -> Enum.any?(chosen, &(&1.slot.id == s.id)) end),
      :quorum_not_met,
      :quorum
    )

    ensure(bindings_hold?(chosen, quorum.bindings), :binding_unsatisfied, :quorum)
    {chosen, records}
  end

  # Labels and observed equivalence values are vertices, not independent
  # capacities. One label can bridge previously separate trusted identities.
  defp merge_identity_classes(records) do
    identities = records |> Enum.map(& &1.identity) |> Enum.uniq()

    nodes =
      Map.new(identities, fn identity ->
        node =
          if KeyIdentity.same?(identity, identity),
            do: {:identity, identity.kind, KeyIdentity.normalize(identity.value)},
            else: :pool

        {identity, node}
      end)

    {parents, known} =
      Enum.reduce(records, {%{}, MapSet.new()}, fn r, {parents, known} ->
        label = {:label, r.verification.label}
        value = nodes[r.identity]
        parents = union(parents, label, value)
        known = if value == :pool, do: known, else: MapSet.put(known, r.verification.label)
        {parents, known}
      end)

    Enum.map(records, fn r ->
      Map.merge(r, %{
        class: root(parents, {:label, r.verification.label}),
        known: MapSet.member?(known, r.verification.label)
      })
    end)
  end

  defp root(parents, node) do
    case Map.get(parents, node, node) do
      ^node -> node
      parent -> root(parents, parent)
    end
  end

  defp union(parents, label, value) do
    a = root(parents, label)
    b = root(parents, value)
    # Deterministic roots; link each observed vertex to its current root.
    parents = Map.put(parents, label, a) |> Map.put(value, b)
    if a == b, do: parents, else: Map.put(parents, max(a, b), min(a, b))
  end

  defp drop_unknown_for_key_unit(records, %{unit: :key, slots: slots}) do
    {known, unknown} = Enum.split_with(records, & &1.known)

    Enum.each(slots, fn slot ->
      ensure(
        not slot.required or Enum.any?(known, &(&1.slot.id == slot.id)) or
          not Enum.any?(unknown, &(&1.slot.id == slot.id)),
        :ambiguous_key_identity,
        :quorum
      )
    end)

    known
  end

  defp drop_unknown_for_key_unit(records, _), do: records

  defp binding_slots(bindings) do
    bindings
    |> Enum.flat_map(fn
      {:nested, [outer: o, inner: i]} -> [o, i]
      {:same_parameter, _, ids} -> ids
    end)
    |> MapSet.new()
  end

  defp cover_required_by_matching(slots, edges, reason) do
    Enum.reduce(slots, %{}, fn slot, matched ->
      case assign_slot(slot.id, edges, matched, MapSet.new()) do
        {:ok, updated} -> updated
        {:error, _} -> fail(reason, :quorum)
      end
    end)
  end

  defp maximize_units_by_matching(slots, edges, matched, :key),
    do: fill_optional(slots, edges, matched)

  defp maximize_units_by_matching(slots, edges, matched, unit) do
    group = fn slot -> if unit == :principal, do: slot.principal, else: slot.role end
    covered = matched |> Map.values() |> Enum.map(&group.(&1.slot)) |> MapSet.new()
    groups = slots |> Enum.reject(& &1.required) |> Enum.group_by(group)
    # Mandatory slots retain their own vertices. Each other unit has a group
    # vertex whose edges retain the canonical slot and actual candidate record.
    group_edges =
      Map.new(groups, fn {g, members} ->
        {{:group, g},
         Enum.flat_map(members, fn slot ->
           Enum.map(Map.get(edges, slot.id, []), fn {class, r} ->
             {class, Map.put(r, :vertex, {:group, g})}
           end)
         end)}
      end)

    matched = Map.new(matched, fn {c, r} -> {c, Map.put(r, :vertex, r.slot.id)} end)

    all_edges =
      Map.merge(
        Map.new(edges, fn {id, rs} ->
          {id, Enum.map(rs, fn {c, r} -> {c, Map.put(r, :vertex, id)} end)}
        end),
        group_edges
      )

    matched =
      groups
      |> Map.keys()
      |> Enum.sort()
      |> Enum.reject(&MapSet.member?(covered, &1))
      |> Enum.reduce(matched, fn g, acc ->
        case assign_slot({:group, g}, all_edges, acc, MapSet.new()) do
          {:ok, updated} -> updated
          {:error, _} -> acc
        end
      end)

    matched = Map.new(matched, fn {c, r} -> {c, Map.delete(r, :vertex)} end)
    fill_optional(slots, edges, matched)
  end

  defp fill_optional(slots, edges, matched) do
    Enum.reduce(slots, matched, fn slot, acc ->
      if Enum.any?(Map.values(acc), &(&1.slot.id == slot.id)) do
        acc
      else
        case assign_slot(slot.id, edges, acc, MapSet.new()) do
          {:ok, updated} -> updated
          {:error, _} -> acc
        end
      end
    end)
    |> Map.values()
  end

  defp assign_slot(slot, edges, matched, seen) do
    Enum.reduce_while(Map.get(edges, slot, []), {:error, seen}, fn {key, record},
                                                                   {:error, seen} ->
      if MapSet.member?(seen, key) do
        {:cont, {:error, seen}}
      else
        seen = MapSet.put(seen, key)

        result =
          case Map.fetch(matched, key) do
            :error ->
              {:ok, matched}

            {:ok, occupied} ->
              assign_slot(Map.get(occupied, :vertex, occupied.slot.id), edges, matched, seen)
          end

        case result do
          {:ok, updated} -> {:halt, {:ok, Map.put(updated, key, record)}}
          {:error, visited} -> {:cont, {:error, visited}}
        end
      end
    end)
  end

  defp search_assignment(slots, edges, bound, quorum) do
    classes =
      edges
      |> Map.values()
      |> List.flatten()
      |> Enum.map(&elem(&1, 0))
      |> MapSet.new()
      |> MapSet.size()

    ctx = %{edges: edges, bound: bound, quorum: quorum, classes: classes}
    {best, _, exhausted} = search(slots, %{}, %{}, ctx, {nil, 0, false})
    if exhausted and (best == nil or not mode_met?(best, quorum)), do: fail(:limit, :input)
    ensure(best != nil, :binding_unsatisfied, :quorum)
    best
  end

  defp search(_, _, _, _, {best, nodes, true}), do: {best, nodes, true}

  defp search(slots, matched, fixed, ctx, {best, nodes, false}) do
    if nodes >= @node_budget do
      {best, nodes, true}
    else
      state = {best, nodes + 1, false}
      records = Map.values(matched)

      cond do
        slots == [] ->
          if bindings_hold?(records, ctx.quorum.bindings) and
               better?(records, best, ctx.quorum.unit),
             do: {records, nodes + 1, false},
             else: state

        pruned?(slots, records, best, ctx) ->
          state

        true ->
          [slot | rest] = slots

          if MapSet.member?(ctx.bound, slot.id) do
            Enum.reduce_while(Map.get(ctx.edges, slot.id, []), state, fn {class, record}, acc ->
              chosen = Map.put(fixed, slot.id, record)

              acc =
                if partial_bindings_hold?(Map.values(chosen), ctx.quorum.bindings) do
                  edges = fixed_edges(ctx.edges, chosen)

                  case assign_slot(slot.id, edges, matched, MapSet.new()) do
                    {:ok, updated} -> search(rest, updated, chosen, ctx, acc)
                    {:error, _} -> acc
                  end
                else
                  acc
                end

              # A fixed class cannot be reused; retain the record, not merely
              # its identity, throughout later augmenting paths.
              _ = class
              if elem(acc, 2), do: {:halt, acc}, else: {:cont, acc}
            end)
          else
            state =
              case assign_slot(slot.id, fixed_edges(ctx.edges, fixed), matched, MapSet.new()) do
                {:ok, updated} -> search(rest, updated, fixed, ctx, state)
                {:error, _} -> state
              end

            if slot.required, do: state, else: search(rest, matched, fixed, ctx, state)
          end
      end
    end
  end

  defp fixed_edges(edges, fixed),
    do: Enum.reduce(fixed, edges, fn {id, r}, acc -> Map.put(acc, id, [{r.class, r}]) end)

  defp better?(_, nil, _), do: true

  defp better?(records, best, unit),
    do: {count(records, unit), length(records)} > {count(best, unit), length(best)}

  defp pruned?(_, _, nil, _), do: false

  defp pruned?(slots, records, best, ctx) do
    current = count(records, ctx.quorum.unit)
    remaining = count(records ++ Enum.map(slots, &%{slot: &1}), ctx.quorum.unit) - current
    upper = current + min(remaining, ctx.classes - length(records))
    # Preserve the secondary objective when another slot can fit at equal count.
    {upper, length(records) + length(slots)} <= {count(best, ctx.quorum.unit), length(best)}
  end

  defp mode_met?(records, quorum) do
    count = count(records, quorum.unit)

    count > 0 and
      Enum.all?(quorum.slots, fn s ->
        not s.required or Enum.any?(records, &(&1.slot.id == s.id))
      end) and
      case quorum.mode do
        :all -> roles_met?(records, quorum)
        :any -> true
        {:threshold, n} -> count >= n
      end
  end

  defp count(records, :key), do: length(records)

  defp count(records, :principal),
    do: records |> Enum.map(& &1.slot.principal) |> Enum.uniq() |> length()

  defp count(records, {:role, [shared_principal: true]}),
    do: records |> Enum.map(& &1.slot.role) |> Enum.uniq() |> length()

  defp count(records, {:role, [shared_principal: false]}) do
    # Maximum matching prevents wire order from consuming the only principal
    # eligible for another role when a rotated/alternative signer is available.
    edges = Enum.group_by(records, & &1.slot.role, & &1.slot.principal)

    edges
    |> Map.keys()
    |> Enum.sort()
    |> Enum.reduce(%{}, fn role, matched ->
      case augment(role, edges, matched, MapSet.new()) do
        {:ok, updated} -> updated
        {:error, _seen} -> matched
      end
    end)
    |> map_size()
  end

  defp augment(role, edges, matched, seen) do
    Enum.reduce_while(Enum.uniq(edges[role]), {:error, seen}, fn principal, {:error, seen} ->
      if MapSet.member?(seen, principal) do
        {:cont, {:error, seen}}
      else
        seen = MapSet.put(seen, principal)

        result =
          case Map.fetch(matched, principal) do
            :error -> {:ok, matched}
            {:ok, occupied} -> augment(occupied, edges, matched, seen)
          end

        case result do
          {:ok, updated} -> {:halt, {:ok, Map.put(updated, principal, role)}}
          {:error, visited} -> {:cont, {:error, visited}}
        end
      end
    end)
  end

  defp roles_met?(records, %{unit: {:role, [shared_principal: false]}, slots: slots} = q) do
    required = Enum.filter(slots, & &1.required)
    records = Enum.filter(records, fn r -> Enum.any?(required, &(&1.id == r.slot.id)) end)
    count(records, q.unit) == required |> Enum.map(& &1.role) |> Enum.uniq() |> length()
  end

  defp roles_met?(_, _), do: true

  defp bindings(_, []), do: :not_required

  defp bindings(records, bindings) do
    ensure(bindings_hold?(records, bindings), :binding_unsatisfied, :quorum)
    Enum.map(bindings, &{&1, :satisfied})
  end

  defp bindings_hold?(records, bindings),
    do: Enum.all?(bindings, &binding_holds?(records, &1, false))

  defp partial_bindings_hold?(records, bindings),
    do: Enum.all?(bindings, &binding_holds?(records, &1, true))

  defp binding_holds?(records, {:nested, [outer: outer, inner: inner]}, partial) do
    o = Enum.find(records, &(&1.slot.id == outer))
    i = Enum.find(records, &(&1.slot.id == inner))

    if o == nil or i == nil do
      partial
    else
      Enum.all?(["signature-input", "signature"], fn name ->
        {name, [{"key", {:string, i.verification.label}}]} in SignatureFields.identities(
          o.input.value
        )
      end)
    end
  end

  defp binding_holds?(records, {:same_parameter, name, slots}, partial) do
    selected = Enum.filter(records, &(&1.slot.id in slots))
    values = Enum.map(selected, & &1.verification.signature.parameters[name])

    (partial or length(selected) == length(slots)) and
      Enum.all?(values, &(&1 != nil)) and length(Enum.uniq(values)) <= 1
  end

  defp negotiation(_, []), do: :not_requested

  defp negotiation(records, requests) do
    Enum.each(requests, fn request ->
      ensure(
        Enum.any?(records, fn r ->
          r.verification.label == request.label and
            MapSet.new(SignatureFields.identities(r.input.value)) ==
              MapSet.new(SignatureFields.identities(request.components.value)) and
            Enum.all?(request.parameters, fn
              {name, true} when name in ["created", "expires"] ->
                is_integer(r.verification.signature.parameters[name])

              {name, value} ->
                r.verification.signature.parameters[name] == value
            end)
        end),
        :negotiation_unfulfilled,
        :negotiation
      )
    end)

    :fulfilled
  end

  defp unwrap({:ok, value}), do: value
  defp unwrap({:error, error}), do: throw({:quorum_error, error})
  defp ensure(true, _, _), do: :ok
  defp ensure(_, reason, layer), do: fail(reason, layer)

  defp fail(reason, layer, detail \\ nil),
    do: throw({:quorum_error, Error.new(reason, layer, detail)})

  defp protect(fun) do
    fun.()
  catch
    {:quorum_error, error} -> {:error, error}
  end
end
