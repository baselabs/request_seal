defmodule RequestSeal.Quorum do
  @moduledoc """
  Explicit composite RFC 9421 verification policy.

  `new/1` builds the policy that `RequestSeal.verify_quorum/3` evaluates:
  a mode, a counting unit, 1 to 16 signer slots (each with its own
  `RequestSeal.Policy`), and the handling of unexpected and invalid labels.
  Labels never count. Every mode requires all configured required slots and
  at least one qualifying signature. `:all` requires at least one required
  slot; `:any` requires one eligible signer; thresholds count distinct
  qualifying units. Every signature must meet its own slot's complete policy.
  Each slot receives at most one signature; each label and each identity
  class occupies at most one slot across every counting unit. Observations of
  one label merge all its known identities and any unknown observation into
  one class. Unknown observations share a pool. A label is known if any
  eligible verification supplies a known identity. Required slots must be
  filled in every mode; an unfilled bound slot fails its binding. No coverage
  union is performed.

  `verify_quorum/3` requires `replay: :not_required` in every slot policy.
  A required replay policy returns `:invalid_policy`, layer `:input`, before
  any callback or store claim, including in optional or unmatched slots.
  Composite replay requires one claim after the complete quorum, bindings,
  and negotiation pass; per-label claims can consume nonqualifying candidates.
  Required replay is rejected until that composite replay design exists.

  Slot content checks use the message's retained body only. Quorum
  verification accepts no `:representation` or `:digest_state` option;
  streamed or unavailable content cannot qualify when a digest is required.

  Assignment maximizes counting units, then filled slots, in canonical slot-id
  and candidate-label order, preferring challenge labels. Declaration and wire
  order cannot change the chosen set; output lists retain configured slot order.
  Within the configured input limits and with existing covered bytes preserved,
  adding an unrelated optional signature preserves a feasible quorum except:

  * `unexpected: :reject` rejects a new label with no selector-eligible slot.
  * `invalid: :reject` rejects a new eligible label that fails every slot policy.
  * A newly verified label spanning identity classes merges them and can reduce
    the count or reject the quorum. This includes a label observed as unknown
    under one slot and known under another: it bridges the shared unknown pool
    into the known class, reducing capacity for unknown-only labels as well.

  An unfillable required slot returns `:quorum_not_met` before binding checks,
  even when a binding also fails. Once required slots can be filled, an unfillable
  bound slot or inconsistent binding returns `:binding_unsatisfied`. After a valid
  assignment is found, an unmet mode or threshold returns `:quorum_not_met`.

  Principal and role counting bindings establish no attribution. Key
  identities stay internal. Unknown key equivalence cannot count in key-unit
  quorums; optional unknown identities are ignored, while a required slot with
  only unknown candidates rejects with `:ambiguous_key_identity`.
  Principal/role policies conservatively assign the shared unknown pool to at
  most one slot.

  Bindings search the complete eligible candidate pool, including alternatives
  with the same key. Nested bindings require both inner dictionary members;
  same-parameter bindings require equal, non-nil values. Negotiation searches
  the verified, selector-eligible pool after key-unit filtering. A challenge
  label can fulfill negotiation without counting as a unit; it appears in
  `qualifying` and `signatures` only when assigned. A tampered challenge fails.

  Verification performs at most 64 × 16 label-slot attempts. Without bindings,
  key, principal, and shared-principal role units use polynomial matching.
  Other assignments use exact search with a 131,072-node budget. On exhaustion,
  a best-so-far assignment is returned only if it satisfies the mode, required
  slots, and bindings; otherwise the result is `:limit`, layer `:input`.
  Selector-free bound slots populated by trusted signers can exhaust that budget;
  the bound prevents unbounded search and never produces partial success.
  """
  alias RequestSeal.{Error, Policy, SignatureFields}
  @derive {Inspect, only: [:mode, :unit, :max_signatures]}
  defstruct [:mode, :unit, :slots, :unexpected, :invalid, bindings: [], max_signatures: 16]

  @type t :: %__MODULE__{
          mode: :all | :any | {:threshold, 1..64},
          unit: :key | :principal | {:role, keyword()},
          slots: [map()],
          unexpected: :reject | :ignore,
          invalid: :reject | :ignore,
          bindings: [term()],
          max_signatures: 1..64
        }
  @required [:mode, :unit, :slots, :unexpected, :invalid]
  @optional [:bindings, :max_signatures]
  @doc """
  Construct a bounded composite policy without invoking a callback.

  ## Parameters

    * `attrs` - map with all five required keys and any of the two optional
      keys. Unknown keys reject.
      * `:mode` - `:all`, `:any`, or `{:threshold, n}` with `n` from 1 to
        `:max_signatures`. `:all` requires at least one required slot.
      * `:unit` - `:key`, `:principal`, or `{:role, shared_principal: boolean}`.
      * `:slots` - list of 1 to 16 slot maps, described below.
      * `:unexpected` - `:reject` or `:ignore`, for a label with no
        selector-eligible slot.
      * `:invalid` - `:reject` or `:ignore`, for an eligible label that fails
        every slot policy.
      * `:bindings` - optional, default `[]`, at most 64 unique entries:
        `{:nested, outer: id, inner: id}` requires the outer to cover both the
        inner's actual `"signature-input";key="<inner-label>"` and
        `"signature";key="<inner-label>"` dictionary members;
        `{:same_parameter, name, ids}` (`name` is `"nonce"`, `"tag"`, or
        `"created"`; 1 to 16 unique slot ids) requires identical, present
        values across the selected slots. Bindings must reference configured
        slots and cannot bind a nested signature to itself.
      * `:max_signatures` - optional, default 16 (1 to 64); thresholds cannot
        exceed this bound.

  Each slot requires a unique atom `:id` (not `nil`, `true`, or `false`), a
  valid `RequestSeal.Policy` as `:policy`, and Boolean `:required`. Optional
  `:label` (a valid signature label) and `:tag` (1 to 256 bytes) selectors
  default to nil (any); `:principal` (1 to 256 bytes) and `:role` (an atom)
  default to nil. Principal counting requires a principal in every slot. Role
  counting additionally requires a role in every slot. With
  `shared_principal: false`, one principal counts toward only one role.
  Slot policy `:content` must be `:not_required` or a Content-Digest policy
  (`kind: :content`); representation digest policies reject, including in
  optional or unmatched slots.

  ## Returns

    * `{:ok, %RequestSeal.Quorum{}}` - slots normalized with nil `:label`,
      `:tag`, `:principal`, and `:role` defaults. Inspection shows only
      `mode`, `unit`, and `max_signatures`.
    * `{:error, %RequestSeal.Error{}}` - always reason `:invalid_quorum`,
      layer `:input`, for unknown units, malformed choices, duplicate or
      invalid bindings, or a non-map argument. Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {public, _secret} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, key} = RequestSeal.PublicKey.import({:ed25519, public}, :raw)
      iex> {:ok, policy} =
      ...>   RequestSeal.Policy.new(%{
      ...>     algorithms: ["ed25519"],
      ...>     components: ~s[("@method" "@path")],
      ...>     key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: key}} end,
      ...>     freshness: %{clock: fn -> System.system_time(:second) end, max_age: 300, skew: 5, require_expires: false},
      ...>     content: :not_required,
      ...>     replay: :not_required
      ...>   })
      iex> slots = [
      ...>   %{id: :author, policy: policy, required: true, label: "author", principal: "writer@example.org", role: :author},
      ...>   %{id: :editor, policy: policy, required: true, label: "editor", principal: "editor@example.org", role: :editor}
      ...> ]
      iex> {:ok, quorum} =
      ...>   RequestSeal.Quorum.new(%{
      ...>     mode: :all,
      ...>     unit: {:role, shared_principal: false},
      ...>     slots: slots,
      ...>     unexpected: :ignore,
      ...>     invalid: :reject,
      ...>     bindings: [{:nested, outer: :editor, inner: :author}]
      ...>   })
      iex> {quorum.mode, quorum.max_signatures, Enum.map(quorum.slots, & &1.tag)}
      {:all, 16, [nil, nil]}
      iex> {:error, error} =
      ...>   RequestSeal.Quorum.new(%{
      ...>     mode: :all,
      ...>     unit: :key,
      ...>     slots: [%{id: :author, policy: policy, required: false}],
      ...>     unexpected: :ignore,
      ...>     invalid: :ignore
      ...>   })
      iex> {error.reason, error.layer}
      {:invalid_quorum, :input}
  """
  @spec new(map()) :: {:ok, t()} | {:error, Error.t()}
  def new(attrs) when is_map(attrs) do
    if Enum.all?(@required, &Map.has_key?(attrs, &1)) and
         Enum.all?(Map.keys(attrs), &(&1 in (@required ++ @optional))) do
      q = struct(__MODULE__, attrs)
      if valid?(q), do: {:ok, %{q | slots: Enum.map(q.slots, &normalize_slot/1)}}, else: invalid()
    else
      invalid()
    end
  end

  def new(_), do: invalid()
  @doc false
  def valid?(%__MODULE__{} = q) do
    Enum.sort(Map.keys(q)) == Enum.sort(Map.keys(%__MODULE__{})) and
      is_integer(q.max_signatures) and q.max_signatures in 1..64 and
      mode?(q.mode, q.max_signatures) and unit?(q.unit) and
      q.unexpected in [:reject, :ignore] and q.invalid in [:reject, :ignore] and
      bounded_list?(q.slots, 1, 16) and Enum.all?(q.slots, &slot?(&1, q.unit)) and
      length(Enum.uniq_by(q.slots, & &1.id)) == length(q.slots) and
      (q.mode != :all or Enum.any?(q.slots, & &1.required)) and
      bounded_list?(q.bindings, 0, 64) and
      length(Enum.uniq(q.bindings)) == length(q.bindings) and
      Enum.all?(q.bindings, &binding?(&1, Enum.map(q.slots, fn s -> s.id end)))
  end

  def valid?(_), do: false
  defp mode?(mode, _) when mode in [:all, :any], do: true
  defp mode?({:threshold, n}, max), do: is_integer(n) and n in 1..max
  defp mode?(_, _), do: false
  defp unit?(u) when u in [:key, :principal], do: true
  defp unit?({:role, [shared_principal: b]}), do: is_boolean(b)
  defp unit?(_), do: false
  defp normalize_slot(s), do: Map.merge(%{label: nil, tag: nil, principal: nil, role: nil}, s)

  defp slot?(%{id: id, policy: p, required: required} = raw, unit) do
    s = normalize_slot(raw)

    is_atom(id) and id not in [nil, true, false] and Policy.valid?(p) and
      content?(p.content) and is_boolean(required) and
      Enum.all?(Map.keys(s), &(&1 in [:id, :policy, :required, :label, :tag, :principal, :role])) and
      (s.label == nil or SignatureFields.label?(s.label)) and
      (s.tag == nil or text?(s.tag)) and (s.principal == nil or text?(s.principal)) and
      (s.role == nil or (is_atom(s.role) and s.role not in [true, false])) and
      (unit == :key or text?(s.principal)) and
      (not match?({:role, _}, unit) or (is_atom(s.role) and s.role != nil))
  end

  defp slot?(_, _), do: false
  defp content?(:not_required), do: true
  defp content?(%{kind: :content}), do: true
  defp content?(_), do: false
  defp text?(s), do: is_binary(s) and byte_size(s) in 1..256

  defp binding?({:nested, [outer: outer, inner: inner]}, ids),
    do: outer in ids and inner in ids and outer != inner

  defp binding?({:same_parameter, name, slots}, ids),
    do:
      name in ~w(nonce tag created) and bounded_list?(slots, 1, 16) and
        length(Enum.uniq(slots)) == length(slots) and Enum.all?(slots, &(&1 in ids))

  defp binding?(_, _), do: false
  @doc false
  def bounded_list?(xs, min, max), do: list_count(xs, 0, min, max)
  defp list_count([], n, min, _), do: n >= min
  defp list_count([_ | tail], n, min, max) when n < max, do: list_count(tail, n + 1, min, max)
  defp list_count(_, _, _, _), do: false
  defp invalid, do: {:error, Error.new(:invalid_quorum, :input)}
end
