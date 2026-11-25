defmodule RequestSeal.Quorum do
  @moduledoc """
  An explicit RFC 9421 policy for multiple independent signatures.

  Each slot has its own generic verification policy, a required flag, and
  optional label and authenticated tag selectors. Slots declare trusted
  principals and roles when the counting unit needs them. One key identity
  class can fill at most one slot. The quorum owns one composite replay claim.
  """
  alias RequestSeal.{Error, Policy, SignatureFields}
  alias RequestSeal.Replay.{Claim, Commitment}
  alias RequestSeal.StructuredFields.{Schema, Value}

  @derive {Inspect, only: [:mode, :unit, :max_signatures]}
  @enforce_keys [:mode, :unit, :slots, :unexpected, :invalid, :replay]
  defstruct @enforce_keys ++ [bindings: [], max_signatures: 16]

  @type t :: %__MODULE__{
          mode: :all | :any | {:threshold, 1..16},
          unit: :key | :principal | {:role, [{:shared_principal, boolean()}]},
          slots: [map()],
          unexpected: :ignore | :reject,
          invalid: :ignore | :reject,
          replay: map(),
          bindings: [term()],
          max_signatures: 1..64
        }

  @doc """
  Build a quorum without invoking callbacks. Required keys are `:mode`, `:unit`,
  `:slots`, `:unexpected`, `:invalid` and `:replay`.

  Every mode requires all required slots and at least one qualifying signature.
  `:all` also requires at least one configured required slot, and
  `{:threshold, n}` requires at least `n` distinct counted units.
  Units are `:key`, `:principal`, and `{:role, shared_principal: boolean}`.
  `:unexpected` and `:invalid` choose `:ignore` or `:reject` for an
  unselected label or a label which fails all selector-eligible policies.

  Each of 1–16 slots requires a unique atom `:id`, a generic `:policy`
  with finite freshness and `replay: :not_required`, and a Boolean
  `:required`. Optional `:label` and `:tag` limit matching signatures.
  `:principal` is a trusted binary for principal and role units, and
  `:role` is a trusted atom for role units.

  `:replay` supplies a bounded namespace, store, timeout and fixed exclusive
  retention end, as in the library-built replay policy. Choose
  `identifier: {:nonce, :shared}` or `identifier: {:operation, ordered_ids}`
  and `scope: :namespace` or `scope: :principals`. The latter requires a
  trusted principal in every slot. Operation identifiers must be mandatory
  under every slot policy. All slots must use the same valid schema for each
  structured operation field.

  `:bindings` defaults to `[]`. It accepts at most 64 distinct
  `{:nested, outer: slot_id, inner: slot_id}` or
  `{:same_parameter, name, slot_ids}` constraints. Names are `"nonce"`,
  `"tag"` or `"created"`. Both kinds require every referenced slot.
  `:max_signatures` defaults to 16 and may be 1–64.
  """
  @spec new(map()) :: {:ok, t()} | {:error, Error.t()}
  def new(attrs) when is_map(attrs) and not is_struct(attrs) do
    if Enum.all?(@enforce_keys, &Map.has_key?(attrs, &1)) and
         Enum.all?(Map.keys(attrs), &(&1 in (@enforce_keys ++ [:bindings, :max_signatures]))) do
      quorum = struct(__MODULE__, attrs)
      if valid?(quorum), do: {:ok, quorum}, else: invalid()
    else
      invalid()
    end
  end

  def new(_), do: invalid()

  @doc false
  def valid?(%__MODULE__{} = quorum) do
    map_size(quorum) == 9 and quorum.max_signatures in 1..64 and
      bounded_list?(quorum.slots, 1, 16) and unit?(quorum.unit) and
      Enum.all?(quorum.slots, &slot?(&1, quorum.unit)) and
      unique?(Enum.map(quorum.slots, & &1.id)) and
      mode?(quorum.mode, quorum.slots, quorum.max_signatures) and
      quorum.unexpected in [:ignore, :reject] and quorum.invalid in [:ignore, :reject] and
      bounded_list?(quorum.bindings, 0, 64) and unique?(quorum.bindings) and
      Enum.all?(quorum.bindings, &binding?(&1, Enum.map(quorum.slots, fn slot -> slot.id end))) and
      replay?(quorum.replay, quorum.slots)
  end

  def valid?(_), do: false

  defp replay?(replay, slots) do
    Commitment.settings?(replay) and
      (replay.scope == :namespace or
         (replay.scope == :principals and Enum.all?(slots, &Claim.bounded?(&1[:principal])))) and
      replay_identifier?(replay.identifier, slots)
  end

  defp replay_identifier?({:nonce, :shared}, _slots), do: true

  defp replay_identifier?({:operation, ids} = identifier, slots) do
    with true <- Enum.all?(slots, &Commitment.operation?(identifier, &1.policy.components)),
         {:ok, components} <- Commitment.operation_components(ids) do
      Enum.all?(components, &common_schema?(&1, slots))
    else
      _ -> false
    end
  end

  defp replay_identifier?(_, _), do: false

  defp common_schema?(%Value{value: {:string, name}, parameters: parameters}, slots) do
    member? = List.keymember?(parameters, "key", 0)

    if member? or List.keymember?(parameters, "sf", 0) do
      case Enum.uniq(Enum.map(slots, &Map.get(&1.policy.field_schemas, name))) do
        [%Schema{type: type}] -> not member? or type == :dictionary
        _ -> false
      end
    else
      true
    end
  end

  defp slot?(%{id: id, policy: policy, required: required} = slot, unit) do
    Enum.all?(Map.keys(slot), &(&1 in [:id, :policy, :required, :label, :tag, :principal, :role])) and
      name?(id) and is_boolean(required) and Policy.valid?(policy) and
      policy.replay == :not_required and finite?(policy.freshness) and
      (policy.content == :not_required or policy.content.kind == :content) and
      (slot[:label] == nil or SignatureFields.label?(slot.label)) and
      (slot[:tag] == nil or Claim.bounded?(slot.tag)) and
      (slot[:principal] == nil or Claim.bounded?(slot.principal)) and
      (slot[:role] == nil or name?(slot.role)) and
      (unit == :key or Claim.bounded?(slot[:principal])) and
      (not match?({:role, _}, unit) or name?(slot[:role]))
  end

  defp slot?(_, _), do: false

  defp finite?(%{require_expires: expires, max_age: age}), do: expires or age != nil
  defp finite?(_), do: false

  defp unit?(unit) when unit in [:key, :principal], do: true
  defp unit?({:role, [shared_principal: shared]}), do: is_boolean(shared)
  defp unit?(_), do: false

  defp mode?(:all, slots, _), do: Enum.any?(slots, & &1.required)
  defp mode?(:any, _, _), do: true
  defp mode?({:threshold, n}, slots, max), do: is_integer(n) and n in 1..min(length(slots), max)
  defp mode?(_, _, _), do: false

  defp binding?({:nested, [outer: outer, inner: inner]}, ids),
    do: outer != inner and outer in ids and inner in ids

  defp binding?({:same_parameter, name, slots}, ids),
    do:
      name in ["nonce", "tag", "created"] and bounded_list?(slots, 1, 16) and unique?(slots) and
        Enum.all?(slots, &(&1 in ids))

  defp binding?(_, _), do: false

  defp name?(value), do: is_atom(value) and value not in [nil, true, false]
  defp unique?(list), do: length(list) == MapSet.size(MapSet.new(list))
  defp bounded_list?(list, min, max), do: list_count(list, 0, min, max)
  defp list_count([], count, min, _), do: count >= min

  defp list_count([_ | rest], count, min, max) when count < max,
    do: list_count(rest, count + 1, min, max)

  defp list_count(_, _, _, _), do: false

  defp invalid, do: {:error, Error.new(:invalid_quorum, :input)}
end
