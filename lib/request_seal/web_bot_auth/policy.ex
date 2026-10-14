defmodule RequestSeal.WebBotAuth.Policy do
  @moduledoc """
  Explicit policy for `draft-ietf-webbotauth-httpsig-protocol-00`.

  `new/1` validates every choice without invoking trust, clock, or storage.
  Content and replay use the generic `RequestSeal.Policy` contracts; HMAC
  algorithms are forbidden. The `:agents` trust function selects
  caller-configured trust, never an arbitrary fetch URL. Attribution requires
  this trusted association. Held-key verification attributes only the
  thumbprint, never an unresolved agent URL. Test keys default to rejection
  under Section 6.8.

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
  @doc """
  Construct an explicit policy without invoking trust, clock, or storage.

  ## Parameters

    * `attrs` - a plain map (not a struct) with the required keys below and any
      of the optional keys. Unknown keys reject.

  Required keys:

    * `:algorithms` - nonempty unique list of `RequestSeal.Crypto` HTTP tokens or
      `{:jws, name}` selections, as in `RequestSeal.Policy`; `"hmac-sha256"` and
      `{:jws, "HS256"}` reject.
    * `:agents` - arity-one trust function receiving
      `%{identifier: id, location: url, type: type}`, where `type` is
      `:directory`, `:jwks_uri`, or `:cimd`, `location` is the received member
      URL, and `identifier` is the directory URL
      (`origin/.well-known/http-message-signatures-directory`) or the normalized
      location. It returns `{:ok, %RequestSeal.Discovery.Source{}}`,
      `{:ok, %RequestSeal.Discovery.KeySet{}}`, or `:error`. A Source requires a
      caller-started `:cache`. A KeySet must be fresh and associated with the
      same URL and type. Sources must allow no redirects.
    * `:cache` - a `RequestSeal.Discovery.Cache` PID, or nil.
    * `:freshness` - map with `:clock` (arity zero, integer Unix seconds),
      `:skew` (integer 0 to 86,400 seconds), and `:max_age` (nil or integer 1 to
      253,402,300,799 seconds). An optional `:require_expires` key is accepted,
      but expiration is always required.
    * `:content` - `:not_required` or a `RequestSeal.Policy` content map.
    * `:replay` - `:not_required` or a `RequestSeal.Policy` replay map.

  ## Options

    * `:components` - serialized Inner List of extra required component
      identifiers, without Inner List parameters. Default `"()"`.
    * `:max_lifetime` - integer seconds, 1 to 604,800. Default 86,400.
    * `:unresolved` - `:reject` (default) or `{:held_keys, key_resolver}`. The
      arity-one resolver receives `%{label: label, keyid: keyid, tag: tag}` and
      returns `{:ok, %{algorithm: algorithm, key: %RequestSeal.PublicKey{}}}` or
      `:error`; the algorithm must be in `:algorithms` and the key's thumbprint
      must equal `keyid`. It applies when no trusted association resolves,
      except for revoked keys, source mismatches, and non-origin directory
      locations. It waives the draft's `Signature-Agent` presence rule only when
      the field is absent.
    * `:test_keys` - `:reject` (default) or `:allow`.
    * `:untagged` - `:ignore` (default; listed in `ignored`) or `:reject`.
    * `:max_signatures` - integer 1 to 64. Default 16.
    * `:field_schemas` - Structured Fields schemas, as in `RequestSeal.Policy`.
      Default `%{}`.

  ## Returns

    * `{:ok, %RequestSeal.WebBotAuth.Policy{}}`.
    * `{:error, %RequestSeal.Error{}}` - always reason `:invalid_policy`, layer
      `:input`. Meanings: `RequestSeal.Error`.

  ## Examples

      iex> attrs = %{algorithms: ["ed25519"], agents: fn _ -> :error end, cache: nil, freshness: %{clock: fn -> 1_760_000_000 end, skew: 5, max_age: 60}, content: :not_required, replay: :not_required}
      iex> {:ok, policy} = RequestSeal.WebBotAuth.Policy.new(attrs)
      iex> {policy.max_lifetime, policy.unresolved, policy.test_keys, policy.untagged}
      {86400, :reject, :reject, :ignore}
      iex> {:error, error} = RequestSeal.WebBotAuth.Policy.new(%{attrs | algorithms: ["hmac-sha256"]})
      iex> error.reason
      :invalid_policy
      iex> {:error, error} = RequestSeal.WebBotAuth.Policy.new(Map.put(attrs, :max_lifetime, 604_801))
      iex> error.reason
      :invalid_policy
  """
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
