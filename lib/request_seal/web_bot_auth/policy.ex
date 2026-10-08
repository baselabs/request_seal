defmodule RequestSeal.WebBotAuth.Policy do
  @moduledoc """
  Explicit policy for `draft-ietf-webbotauth-httpsig-protocol-00`.

  `new/1` requires `:algorithms`, `:agents`, `:cache` (PID or nil),
  `:freshness` (clock, skew, max_age), `:content`, and `:replay`.
  Freshness always requires expiration. Content and replay use the generic
  `RequestSeal.Policy` contracts; HMAC algorithms are forbidden.

  The arity-one `:agents` trust function receives `identifier`, `location`, and
  `type` (`:directory`, `:jwks_uri`, or `:cimd`) and returns `{:ok, source_or_key_set}`
  or `:error`. It selects caller-configured trust, never an arbitrary fetch URL.
  A Source requires a caller-started cache. A KeySet must be fresh and associated
  with the same URL and type. Attribution requires this trusted association.

  Optional choices: `:components` (extra required identifiers, default `"()"`),
  `:max_lifetime` (1..604,800 seconds, default 86,400), `:unresolved` (`:reject`
  or `{:held_keys, key_resolver}`), `:test_keys` (`:reject` or `:allow`),
  `:untagged` (`:ignore` or `:reject`), `:max_signatures` (1..64, default 16),
  and `:field_schemas`. Held-key verification attributes only the thumbprint,
  never an unresolved agent URL. The `:held_keys` option waives the draft's
  field-presence rule only when the field is absent.
  A present `Signature-Agent` field, including an empty dictionary, must have
  a member for the selected signature label or verification rejects with `:missing_member`.
  Test keys default to rejection under Section 6.8.

  Within the caller's chosen replay namespace, commitments should hash each
  signature's nonce, keyid, and agent identifier only (`identifier`, `keyid`, and
  `agent.identifier` in the supplied facts; held keys have no agent identifier).
  Replay facts retain the agent's stable `kind`, `identifier`, `type`, `origin`,
  and `thumbprint` fields. They exclude provenance and cache-refresh fields such as
  `fetched_at` and `revision`, so hashing the supplied facts is stable across directory
  refreshes. Full provenance remains available in the verification result.
  Replay scope remains caller-owned,
  as described in [RFC 9421 Section 7.2.2](https://www.rfc-editor.org/rfc/rfc9421.html#section-7.2.2).
  Inspection omits callback environments and source configuration.
  """
  alias RequestSeal.{Error, Policy, SignatureFields}
  @derive {Inspect, only: [:algorithms, :max_lifetime, :test_keys, :untagged, :max_signatures]}
  defstruct [
    :algorithms,
    :agents,
    :cache,
    :freshness,
    :content,
    :replay,
    components: "()",
    max_lifetime: 86_400,
    unresolved: :reject,
    test_keys: :reject,
    untagged: :ignore,
    max_signatures: 16,
    field_schemas: %{}
  ]

  @type agents :: (map() ->
                     {:ok, RequestSeal.Discovery.Source.t() | RequestSeal.Discovery.KeySet.t()}
                     | :error)
  @type t :: %__MODULE__{
          algorithms: list(),
          agents: agents(),
          cache: pid() | nil,
          freshness: map(),
          content: term(),
          replay: term(),
          components: binary(),
          max_lifetime: pos_integer(),
          unresolved: term(),
          test_keys: :reject | :allow,
          untagged: :ignore | :reject,
          max_signatures: pos_integer(),
          field_schemas: map()
        }
  @required [:algorithms, :agents, :cache, :freshness, :content, :replay]
  @type signer :: RequestSeal.Policy.signer()
  @doc "Construct an explicit policy without invoking trust, clock, or storage."
  @spec new(map()) :: {:ok, t()} | {:error, Error.t()}
  def new(attrs) when is_map(attrs) and not is_struct(attrs) do
    allowed = Map.keys(Map.from_struct(%__MODULE__{}))

    if Enum.all?(@required, &Map.has_key?(attrs, &1)) and
         Enum.all?(Map.keys(attrs), &(&1 in allowed)) do
      p = struct(__MODULE__, attrs)
      if valid?(p), do: {:ok, p}, else: invalid()
    else
      invalid()
    end
  end

  def new(_), do: invalid()
  @doc false
  def valid?(%__MODULE__{} = p) do
    Enum.sort(Map.keys(p)) == Enum.sort(Map.keys(%__MODULE__{})) and
      is_function(p.agents, 1) and (p.cache == nil or is_pid(p.cache)) and
      is_integer(p.max_lifetime) and p.max_lifetime in 1..604_800 and
      p.test_keys in [:reject, :allow] and p.untagged in [:ignore, :reject] and
      (p.unresolved == :reject or match?({:held_keys, fun} when is_function(fun, 1), p.unresolved)) and
      freshness?(p.freshness) and generic_valid?(p)
  end

  def valid?(_), do: false

  defp freshness?(%{clock: _, skew: _, max_age: _} = f),
    do: Enum.all?(Map.keys(f), &(&1 in [:clock, :skew, :max_age, :require_expires]))

  defp freshness?(_), do: false

  defp generic_valid?(p) do
    case Policy.new(%{
           algorithms: p.algorithms,
           components: p.components,
           key_resolver: fn _ -> :error end,
           freshness: Map.put(p.freshness, :require_expires, true),
           content: p.content,
           replay: p.replay,
           max_signatures: p.max_signatures,
           field_schemas: p.field_schemas
         }) do
      {:ok, _} ->
        Enum.all?(p.algorithms, &(&1 not in ["hmac-sha256", {:jws, "HS256"}])) and
          case SignatureFields.inner(p.components) do
            {:ok, value} -> value.parameters == []
            _ -> false
          end

      _ ->
        false
    end
  end

  defp invalid, do: {:error, Error.new(:invalid_policy, :input)}
end
