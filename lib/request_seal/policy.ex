defmodule RequestSeal.Policy do
  @moduledoc """
  Explicit generic RFC 9421 acceptance policy; no implicit profile or required choices.

  `new/1` takes six required choices (algorithms, required components, key
  resolver, freshness, content, replay) plus optional bounds, validates them
  without invoking any callback, and returns an opaque policy for
  `RequestSeal.verify/3`, `RequestSeal.Quorum` slots, and `RequestSeal.Profile`.
  Verification revalidates directly built structs.

  RFC 9421 Section 2.2.3 lowercases the authority host and omits default ports
  (HTTP 80 and HTTPS 443). Coverage of `@authority` alone can accept the same
  signature across `http://example.com`, `http://example.com:80`,
  `https://example.com`, and `https://example.com:443` when all other covered
  values match. Require `@scheme` (or `@target-uri`) whenever scheme matters.
  Plug supports `@scheme`; its unavailable exact target evidence prevents
  coverage of `@target-uri`.

  The resolver's algorithm is authoritative; sender `alg` never selects it.
  Key identity values remain internal; no trusted principal association is
  inferred.
  """
  alias RequestSeal.{Error, SignatureFields}
  alias RequestSeal.StructuredFields.Schema
  @derive {Inspect, only: [:algorithms, :extra_components, :max_signatures]}
  defstruct [
    :algorithms,
    :components,
    :key_resolver,
    :freshness,
    :content,
    :replay,
    field_schemas: %{},
    extra_components: :allow,
    max_signatures: 16
  ]

  @type verify_fun :: (RequestSeal.Crypto.algorithm(), binary(), binary() ->
                         :ok | {:error, term()})
  @type signer :: (RequestSeal.Crypto.algorithm(), binary() -> {:ok, binary()} | {:error, term()})
  @type t :: %__MODULE__{
          algorithms: [RequestSeal.Crypto.algorithm()],
          components: binary(),
          key_resolver: (map() ->
                           {:ok,
                            %{
                              optional(:identity) => RequestSeal.KeyIdentity.t(),
                              algorithm: RequestSeal.Crypto.algorithm(),
                              key: RequestSeal.PublicKey.t() | verify_fun()
                            }}
                           | :error),
          freshness: :not_evaluated | map(),
          content: :not_required | map(),
          replay: :not_required | map(),
          field_schemas: map(),
          extra_components: :allow | :reject,
          max_signatures: 1..64
        }
  @required [:algorithms, :components, :key_resolver, :freshness, :content, :replay]
  @optional [:field_schemas, :extra_components, :max_signatures]
  @doc """
  Construct a fully explicit policy or return a bounded invalid-policy error.

  ## Parameters

    * `attrs` - map with all six required keys and any of the three optional
      keys. Unknown keys reject.
      * `:algorithms` - nonempty unique list of at most 64 exact
        `RequestSeal.Crypto` HTTP tokens or supported `{:jws, name}`
        selections. JWS requires sender `alg` to be absent.
      * `:components` - serialized Structured Fields Inner List of at most 256
        required component identifiers, with exact parameter identity and no
        metadata parameters. `"()"` explicitly permits no required coverage.
        Duplicate identifiers reject.
      * `:key_resolver` - arity-one function. At verification it receives a
        map of `keyid` (binary or nil), `label` (binary), and `tag` (binary or
        nil), and returns `{:ok, %{algorithm: algorithm, key: key}}` or
        `:error`. `key` is a `RequestSeal.PublicKey` or an arity-three
        verification function `(algorithm, base, signature)` returning `:ok`
        or `{:error, term}`. HMAC (`"hmac-sha256"`, `{:jws, "HS256"}`) secret
        custody must stay inside such a function. Optional `:identity`
        carries a trusted `RequestSeal.KeyIdentity`. Public keys derive their
        canonical public identity and must agree with a supplied identity.
        Verification functions without one have unknown key equivalence.
      * `:freshness` - `:not_evaluated` or a map containing exactly `:clock`
        (arity zero, integer Unix seconds), `:max_age` (1 to
        253,402,300,799, or nil), `:skew` (0 to 86,400), and
        `:require_expires` (Boolean). Max-age requires created; expiration is
        exclusive, max-age inclusive. All checks must pass for some integer
        clock within `[now - skew, now + skew]`. At verification, clocks must
        return integers from 0 through 253,402,300,799. RFC integer bounds
        apply to signature timestamps.
      * `:content` - `:not_required` or a map of exactly `:kind` (`:content`
        or `:representation`), nonempty unique `:algorithms` (`"sha-256"`,
        `"sha-512"`), and `:section` (`:headers` or `:trailers`). Verification
        requires full coverage of precisely that digest field, recomputes it,
        and requires every supported present algorithm to be selected.
        Unknown algorithms cannot establish integrity.
      * `:replay` - `:not_required` or a map with exactly `:identifier`
        (`:nonce`), `:namespace` (caller tenant/trust context, 1..256 bytes),
        `:commitment` (arity-one function returning `{:ok, key}` with 1..256
        bytes or `:error`), `:store` (`RequestSeal.Replay.Store`), and
        `:timeout` (1..300,000 ms). Required replay requires bounded
        freshness: `require_expires: true` or max-age.
        After validation the function receives exactly `identifier`, `algorithm`,
        `keyid`, `tag`, `created`, `expires`, and `profile: %{name: :rfc9421}`
        or a package-namespaced extension stamp; never a signature label. Its result
        is claimed once under the caller namespace. A derived retention end above
        253,402,300,799 rejects with `:retention_exceeded` at `:replay` before
        commitment or storage, even if the authenticated wire timestamp is valid.
        RequestSeal supplies no application commitment recipe. Nonce is an authenticated
        RFC 9421 signature parameter, limited to 1,024 bytes; absent/empty nonce rejects.
        Retention ends at the first rejected second: minimum of `expires + skew`
        and `created + max_age + skew + 1`, over present bounds.
      * `:field_schemas` - optional, default `%{}`. At most 1,024 lowercase
        field names mapped to validated `RequestSeal.StructuredFields.Schema`
        values.
      * `:extra_components` - optional, default `:allow`; `:reject` requires
        exact coverage.
      * `:max_signatures` - optional, default 16 (1 to 64). Counts dictionary
        encounters, including repeats, before duplicate-label rejection.

  ## Returns

    * `{:ok, %RequestSeal.Policy{}}` - inspection shows only `algorithms`,
      `extra_components`, and `max_signatures`.
    * `{:error, %RequestSeal.Error{}}` - always reason `:invalid_policy`,
      layer `:input`, `retryable: false`, for a missing, unknown, or invalid
      key, or a non-map argument. Meanings: `RequestSeal.Error`.

  ## Examples

      iex> {public, _secret} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, key} = RequestSeal.PublicKey.import({:ed25519, public}, :raw)
      iex> attrs = %{
      ...>   algorithms: ["ed25519"],
      ...>   components: ~s[("@method" "@scheme" "@authority" "@path" "content-digest")],
      ...>   key_resolver: fn
      ...>     %{keyid: "telemetry-agent"} -> {:ok, %{algorithm: "ed25519", key: key}}
      ...>     _ -> :error
      ...>   end,
      ...>   freshness: %{clock: fn -> System.system_time(:second) end, max_age: 300, skew: 5, require_expires: false},
      ...>   content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
      ...>   replay: :not_required
      ...> }
      iex> {:ok, policy} = RequestSeal.Policy.new(attrs)
      iex> {policy.extra_components, policy.max_signatures}
      {:allow, 16}
      iex> {:error, error} = RequestSeal.Policy.new(Map.delete(attrs, :replay))
      iex> {error.reason, error.layer}
      {:invalid_policy, :input}
      iex> {:error, error} = RequestSeal.Policy.new(%{attrs | freshness: %{attrs.freshness | skew: 86_401}})
      iex> error.reason
      :invalid_policy
  """
  @spec new(map()) :: {:ok, t()} | {:error, Error.t()}
  def new(attrs) when is_map(attrs) do
    if Enum.all?(@required, &Map.has_key?(attrs, &1)) and
         Enum.all?(Map.keys(attrs), &(&1 in (@required ++ @optional))) do
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
      list?(p.algorithms, &SignatureFields.algorithm?/1) and
      is_binary(p.components) and valid_components?(p.components) and
      is_function(p.key_resolver, 1) and freshness?(p.freshness) and content?(p.content) and
      RequestSeal.Replay.policy?(p.replay, p.freshness) and schemas?(p.field_schemas) and
      p.extra_components in [:allow, :reject] and is_integer(p.max_signatures) and
      p.max_signatures in 1..64
  end

  def valid?(_), do: false

  defp valid_components?(bytes) do
    case SignatureFields.inner(bytes) do
      {:ok, value} -> value.parameters == []
      _ -> false
    end
  end

  defp list?(xs, pred),
    do:
      proper_list?(xs) and length(xs) in 1..64 and length(xs) == length(Enum.uniq(xs)) and
        Enum.all?(xs, pred)

  defp proper_list?([]), do: true
  defp proper_list?([_ | tail]), do: proper_list?(tail)
  defp proper_list?(_), do: false

  defp freshness?(:not_evaluated), do: true

  defp freshness?(%{clock: clock, max_age: age, skew: skew, require_expires: req} = f),
    do:
      map_size(f) == 4 and is_function(clock, 0) and
        (age == nil or (is_integer(age) and age in 1..253_402_300_799)) and is_integer(skew) and
        skew in 0..86_400 and is_boolean(req)

  defp freshness?(_), do: false
  defp content?(:not_required), do: true

  defp content?(%{kind: kind, algorithms: algorithms, section: section} = c),
    do:
      map_size(c) == 3 and kind in [:content, :representation] and
        section in [:headers, :trailers] and list?(algorithms, &(&1 in ["sha-256", "sha-512"]))

  defp content?(_), do: false
  @doc false
  def schemas?(schemas),
    do:
      is_map(schemas) and map_size(schemas) <= 1024 and
        Enum.all?(schemas, fn {name, schema} ->
          SignatureFields.field_name?(name) and Schema.validate(schema) == :ok
        end)

  defp invalid, do: {:error, Error.new(:invalid_policy, :input)}
end
