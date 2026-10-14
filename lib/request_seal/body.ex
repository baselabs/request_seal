defmodule RequestSeal.Body do
  @moduledoc """
  Caller-owned body availability, without implicit reads or replayability.

  A body is `:retained` (exact bytes held in memory), `:streaming` (an opaque
  caller-owned PID or reference), `:unavailable`, or `:consumed`. Empty retained
  bytes are different from unavailable bytes. Stream handles are opaque;
  construction and validation never invoke, enumerate, close, or claim to have
  consumed them.

  Values are snapshots supplied by the caller, not a stream controller. A later
  snapshot must report consumption; copying a value does not make a stream
  replayable. A stream can remain unread after transport completes, so known
  trailers can coexist with `:streaming`. This module neither hashes content
  nor validates message framing.
  Inspection hides body bytes and handles.
  """
  alias RequestSeal.Message.Validation
  @derive {Inspect, only: []}
  defstruct [:state, :bytes, :source, ownership: :caller, max_bytes: 1_048_576]

  @type t :: %__MODULE__{
          state: :retained | :streaming | :unavailable | :consumed,
          bytes: binary() | nil,
          source: pid() | reference() | nil,
          ownership: :caller,
          max_bytes: non_neg_integer()
        }

  @doc """
  Construct an availability snapshot from an attribute map.

  ## Parameters

    * `attrs` - a plain map (not a struct) using only these keys; unknown keys reject:
      * `:state` (required) - `:retained`, `:streaming`, `:unavailable`, or `:consumed`.
      * `:bytes` - binary, required for `:retained` and otherwise absent or `nil`.
      * `:source` - a caller-owned PID or reference, required for `:streaming` and
        otherwise absent or `nil`.
      * `:ownership` - only `:caller` (the default).
      * `:max_bytes` - nonnegative integer bounding retained bytes, default
        1,048,576. Any nonnegative integer is allowed as the caller's retention
        policy.

  ## Returns

    * `{:ok, %RequestSeal.Body{}}`.
    * `{:error, %RequestSeal.Message.Error{reason: :invalid_body}}` - the only
      reason: a missing or unknown key, a state without its required value, a
      value not allowed for the state, or retained bytes over `:max_bytes`.
      Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: <<0, 255>>, max_bytes: 2})
      iex> {body.state, body.bytes, body.ownership}
      {:retained, <<0, 255>>, :caller}
      iex> RequestSeal.Body.new(%{state: :streaming})
      {:error, %RequestSeal.Message.Error{reason: :invalid_body}}

  A stream handle is kept but never read:

      iex> source = make_ref()
      iex> {:ok, body} = RequestSeal.Body.new(%{state: :streaming, source: source})
      iex> body.source == source
      true
      iex> RequestSeal.Body.new(%{state: :retained, bytes: "crawl page 3", max_bytes: 4})
      {:error, %RequestSeal.Message.Error{reason: :invalid_body}}
  """
  @spec new(map()) :: {:ok, t()} | {:error, RequestSeal.Message.Error.t()}
  def new(attrs), do: Validation.construct(attrs, __MODULE__, [:state], :invalid_body)

  @doc """
  Validate a snapshot without touching the caller's body source.

  Applies the rules of `new/1` to an existing struct, including one built or
  modified directly.

  ## Parameters

    * `body` - any term; only a `RequestSeal.Body` struct can pass.

  ## Returns

    * `:ok`.
    * `{:error, %RequestSeal.Message.Error{reason: :invalid_body}}` - the only
      reason. Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, body} = RequestSeal.Body.new(%{state: :consumed})
      iex> RequestSeal.Body.validate(body)
      :ok
      iex> RequestSeal.Body.validate(%{body | bytes: "already read"})
      {:error, %RequestSeal.Message.Error{reason: :invalid_body}}
  """
  @spec validate(term()) :: :ok | {:error, RequestSeal.Message.Error.t()}
  def validate(%__MODULE__{} = body) do
    if Validation.exact_struct?(body, __MODULE__) and body.ownership == :caller and
         is_integer(body.max_bytes) and body.max_bytes >= 0 and valid_state?(body),
       do: :ok,
       else: Validation.error(:invalid_body)
  end

  def validate(_), do: Validation.error(:invalid_body)

  defp valid_state?(%{state: :retained, bytes: bytes, source: nil, max_bytes: max}),
    do: is_binary(bytes) and byte_size(bytes) <= max

  defp valid_state?(%{state: :streaming, bytes: nil, source: source}),
    do: is_pid(source) or is_reference(source)

  defp valid_state?(%{state: state, bytes: nil, source: nil})
       when state in [:unavailable, :consumed], do: true

  defp valid_state?(_), do: false
end
