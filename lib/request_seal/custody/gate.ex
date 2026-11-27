defmodule RequestSeal.Custody.Gate do
  @moduledoc """
  Single-use admission for signing an exact HTTP signature base.

  Set `:admission` when constructing a Local HTTP key. The same sensitive
  holder must admit the request before invoking cryptography. Applications
  provide a decision function, a clock, and the atomic single-use boundary.
  Admission digests and decisions are absent from telemetry and inspection.
  """

  alias RequestSeal.{Custody, KeyHandle, Message, Policy, Replay, SignatureBase, SignatureFields}
  alias RequestSeal.Custody.{Context, Error, Support}
  alias RequestSeal.Replay.{Claim, Store}
  import Support, only: [ensure: 2, fail: 1]

  @max_clock 253_402_300_799
  @required [:port, :once, :required_components, :max_lifetime, :clock, :skew, :tag]
  @optional [:algorithm, :keyid, :record]

  defmodule Request do
    @moduledoc "Bounded facts about the canonical bytes awaiting admission."
    @derive {Inspect, only: [:algorithm, :created, :expires]}
    defstruct [
      :algorithm,
      :base_sha256,
      :commitment,
      :components,
      :created,
      :expires,
      :nonce,
      :keyid,
      :tag
    ]

    @type t :: %__MODULE__{
            algorithm: binary(),
            base_sha256: <<_::256>>,
            commitment: <<_::256>>,
            components: [{binary(), binary()}],
            created: non_neg_integer(),
            expires: non_neg_integer(),
            nonce: binary(),
            keyid: binary() | nil,
            tag: binary()
          }
  end

  defmodule Admission do
    @moduledoc "The decision identifier, approved component commitment, and exclusive expiry."
    @derive {Inspect, only: [:not_after]}
    defstruct [:decision, :commitment, :not_after, :nonce]

    @type t :: %__MODULE__{
            decision: binary(),
            commitment: <<_::256>>,
            not_after: non_neg_integer(),
            nonce: binary() | nil
          }
  end

  defmodule Admitted do
    @moduledoc "Consumed admission for one exact base through its exclusive expiry."
    @derive {Inspect, only: [:not_after]}
    defstruct [:decision, :base_sha256, :not_after]

    @type t :: %__MODULE__{
            decision: binary(),
            base_sha256: <<_::256>>,
            not_after: non_neg_integer()
          }
  end

  defmodule Signed do
    @moduledoc "Result presented to the optional recorder before returning the signature."
    @derive {Inspect, only: []}
    defstruct [:decision, :base_sha256, :signature_sha256]

    @type t :: %__MODULE__{
            decision: binary(),
            base_sha256: <<_::256>>,
            signature_sha256: <<_::256>>
          }
  end

  @type config :: %{
          required(:port) => (Request.t(), Context.t() -> {:allow, Admission.t()} | :deny),
          required(:once) => {:store, Store.t(), binary()} | :port_owned,
          required(:required_components) => [binary()],
          required(:max_lifetime) => 1..86_400,
          required(:clock) => (-> non_neg_integer()),
          required(:skew) => 0..300,
          required(:tag) => binary(),
          optional(:keyid) => binary(),
          optional(:algorithm) => binary(),
          optional(:record) => (Signed.t(), Context.t() -> :ok | :error)
        }

  @doc """
  Constructs a Local HTTP signing key with mandatory admission. The underlying
  holder has the gate configuration from inception. Options accept `:issued_for`.
  Release the key through `RequestSeal.Custody.release/1`.
  """
  @spec new(binary(), tuple(), config(), keyword()) :: {:ok, KeyHandle.t()} | {:error, Error.t()}
  def new(algorithm, material, config, opts \\ []) do
    Support.safe(fn ->
      Support.options(opts, [:issued_for])
      validate!(config, algorithm)
      Custody.Local.new(algorithm, material, [{:admission, config} | opts])
    end)
  end

  @doc """
  Computes the SHA-256 commitment to ordered covered identifiers and values in
  an RFC 9421 message. Supply a serialized parameterless Inner List of components
  and optional `:field_schemas`. The framing starts with the ASCII domain
  `request-seal signing-commitment` followed by a zero byte. Each identifier
  and value is preceded by its byte length as an unsigned 32-bit big-endian integer.
  """
  @spec commitment(Message.t(), binary(), keyword()) :: {:ok, <<_::256>>} | {:error, Error.t()}
  def commitment(message, components, opts \\ []) do
    Support.safe(fn ->
      Support.options(opts, [:field_schemas])
      schemas = Keyword.get(opts, :field_schemas, %{})
      ensure(Policy.schemas?(schemas), :invalid_options)

      with {:ok, %{parameters: []} = input} <- SignatureFields.inner(components),
           {:ok, parts} <- SignatureBase.components(message, input, field_schemas: schemas) do
        {:ok, hash_components(parts.components)}
      else
        _ -> {:error, Error.new(:invalid_data)}
      end
    end)
  end

  @doc """
  Admits and spends one decision without invoking a key. The configuration
  must specify `:algorithm`. An external signer uses the returned SHA-256
  and exclusive expiry to bind its subsequent operation to the exact bytes.
  With `:port_owned` the port must atomically spend the decision before
  returning. With `{:store, store, namespace}` the gate spends it.
  """
  @spec check(binary(), config(), Context.t()) :: {:ok, Admitted.t()} | {:error, Error.t()}
  def check(bytes, config, context) do
    Support.safe(
      fn ->
        ensure(is_map(config) and Map.has_key?(config, :algorithm), :invalid_options)
        validate!(config, config.algorithm)
        ensure(valid_context?(context), :invalid_options)
        {:ok, admit(bytes, config, context, config.algorithm)}
      end,
      :custodian_failure
    )
  end

  @doc false
  def validate!(config, algorithm) do
    ensure(
      is_binary(algorithm) and algorithm in RequestSeal.Crypto.algorithms(),
      :unsupported_algorithm
    )

    ensure(
      is_map(config) and not is_struct(config) and Enum.all?(@required, &Map.has_key?(config, &1)) and
        Enum.all?(Map.keys(config), &(&1 in (@required ++ @optional))),
      :invalid_options
    )

    ensure(
      is_function(config.port, 2) and is_function(config.clock, 0) and
        is_integer(config.skew) and config.skew in 0..300 and
        is_integer(config.max_lifetime) and config.max_lifetime in 1..86_400 and
        printable?(config.tag) and
        (not Map.has_key?(config, :keyid) or printable?(config.keyid)) and
        (not Map.has_key?(config, :record) or is_function(config.record, 2)) and
        Map.get(config, :algorithm, algorithm) == algorithm,
      :invalid_options
    )

    ids = config.required_components

    ensure(
      is_list(ids) and length(ids) in 1..256 and Enum.uniq(ids) == ids and
        Enum.all?(ids, &bounded?(&1, 1_024)),
      :invalid_options
    )

    serialized = "(" <> Enum.join(ids, " ") <> ")"

    with {:ok, %{parameters: [], value: items}} <- SignatureFields.inner(serialized),
         {:ok, ^ids} <- SignatureFields.identifiers(items) do
      :ok
    else
      _ -> fail(:invalid_options)
    end

    case config.once do
      :port_owned ->
        :ok

      {:store, store, namespace} ->
        ensure(Store.valid?(store) and Claim.bounded?(namespace), :invalid_options)

      _ ->
        fail(:invalid_options)
    end
  end

  @doc false
  def finish(config, admitted, signature, context) do
    live!(context)
    record(config, admitted, signature, context)
    ensure(admitted.not_after > clock(config, context), :gate_window)
    live!(context)
  end

  @doc false
  def admit(bytes, config, context, algorithm) do
    live!(context)

    parts =
      case SignatureBase.parse(bytes) do
        {:ok, parts} -> parts
        _ -> fail(:gate_malformed_base)
      end

    params = SignatureFields.parameters(parts.inner_list)
    covered = Enum.map(parts.components, &elem(&1, 0))

    %{"created" => created, "expires" => expires, "nonce" => nonce} =
      require_coverage(params, covered, config, algorithm)

    now = clock(config, context)

    ensure(
      created in 0..@max_clock and expires in 0..@max_clock and
        abs(now - created) <= config.skew and expires > now and
        (expires - created) in 1..config.max_lifetime,
      :gate_window
    )

    request = %Request{
      algorithm: algorithm,
      base_sha256: :crypto.hash(:sha256, bytes),
      commitment: hash_components(parts.components),
      components: parts.components,
      created: created,
      expires: expires,
      nonce: nonce,
      keyid: params["keyid"],
      tag: params["tag"]
    }

    admission =
      case callback(context, fn -> config.port.(request, context) end, :gate_unavailable) do
        {:allow, %Admission{} = admission} ->
          ensure(valid_admission?(admission), :gate_unavailable)
          admission

        :deny ->
          fail(:gate_denied)

        _ ->
          fail(:gate_unavailable)
      end

    ensure(
      :crypto.hash_equals(request.commitment, admission.commitment) and
        admission.nonce in [nil, nonce],
      :gate_mismatch
    )

    ensure(expires <= admission.not_after and expires > clock(config, context), :gate_window)
    spend(config.once, admission, config.skew, context)
    ensure(expires > clock(config, context), :gate_window)

    %Admitted{
      decision: admission.decision,
      base_sha256: request.base_sha256,
      not_after: expires
    }
  end

  defp require_coverage(params, covered, config, algorithm) do
    ensure(
      Enum.all?(config.required_components, &(&1 in covered)) and
        is_integer(params["created"]) and is_integer(params["expires"]) and
        bounded?(params["nonce"], 1_024) and
        params["tag"] == config.tag and
        (not Map.has_key?(config, :keyid) or params["keyid"] == config.keyid) and
        params["alg"] in [nil, algorithm],
      :gate_coverage
    )

    params
  end

  defp spend(:port_owned, _, _, _), do: :ok

  defp spend({:store, store, namespace}, admission, skew, context) do
    retain_until = admission.not_after + skew + 1
    ensure(retain_until <= @max_clock, :gate_window)
    live!(context)

    claim = %Claim{
      namespace: namespace,
      key: :crypto.hash(:sha256, ["request-seal signing-gate", <<0>>, admission.decision]),
      retain_until: retain_until
    }

    case Replay.claim_in_context(store, claim, context) do
      :claimed -> :ok
      :already_claimed -> fail(:gate_spent)
      _ -> fail(:gate_store_failed)
    end
  end

  defp record(%{record: fun}, admitted, signature, context) do
    event = %Signed{
      decision: admitted.decision,
      base_sha256: admitted.base_sha256,
      signature_sha256: :crypto.hash(:sha256, signature)
    }

    ensure(
      callback(context, fn -> fun.(event, context) end, :gate_unrecorded) == :ok,
      :gate_unrecorded
    )
  end

  defp record(_, _, _, _), do: :ok

  defp callback(context, fun, reason) do
    case Custody.run(context, fn -> {:ok, fun.()} end) do
      {:ok, result} -> result
      {:error, %Error{reason: :deadline_exceeded}} -> fail(:deadline_exceeded)
      _ -> fail(reason)
    end
  end

  defp clock(config, context) do
    now = callback(context, config.clock, :gate_window)
    ensure(is_integer(now) and now in 0..@max_clock, :gate_window)
    now
  end

  @doc false
  def live!(context) do
    ensure(Context.remaining(context) > 0, :deadline_exceeded)

    ensure(
      Process.alive?(context.owner) and
        (context.key_owner == nil or Process.alive?(context.key_owner)),
      :custodian_failure
    )
  end

  defp valid_context?(%Context{deadline: deadline, owner: owner}),
    do: is_integer(deadline) and is_pid(owner)

  defp valid_context?(_), do: false

  defp valid_admission?(%Admission{} = admission) do
    map_size(admission) == 5 and bounded?(admission.decision, 256) and
      match?(<<_::256>>, admission.commitment) and is_integer(admission.not_after) and
      admission.not_after in 0..@max_clock and
      (admission.nonce == nil or bounded?(admission.nonce, 1_024))
  end

  defp printable?(value),
    do: bounded?(value, 1_024) and Enum.all?(:binary.bin_to_list(value), &(&1 in 32..126))

  defp bounded?(value, max), do: is_binary(value) and byte_size(value) in 1..max

  defp hash_components(components) do
    fields =
      Enum.map(components, fn {identifier, value} ->
        [<<byte_size(identifier)::32>>, identifier, <<byte_size(value)::32>>, value]
      end)

    :crypto.hash(:sha256, ["request-seal signing-commitment", <<0>>, fields])
  end
end
