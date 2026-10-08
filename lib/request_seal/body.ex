defmodule RequestSeal.Body do
  @moduledoc """
  Caller-owned body availability, without implicit reads or replayability.

  `new/1` requires `:state`: `:retained` requires binary `:bytes`; `:streaming`
  requires a caller-owned `:source` PID or reference; `:unavailable` and `:consumed`
  carry neither. Empty retained bytes are different from unavailable bytes.
  `:ownership` can only be `:caller`. `:max_bytes` bounds retained bytes (default
  1,048,576; any nonnegative integer is allowed as the caller's retention policy).
  Unknown keys reject. Stream handles are opaque; construction/validation never
  invoke, enumerate, close, or claim to have consumed them.

  Values are snapshots supplied by the caller, not a stream controller. A later
  snapshot must report consumption; copying a value does not make a stream
  replayable. A stream can remain unread after transport completes, so known
  trailers can coexist with `:streaming`. This module neither hashes content
  nor validates message framing.
  Inspection hides body bytes and handles.

      iex> {:ok, body} = RequestSeal.Body.new(%{state: :retained, bytes: <<0, 255>>, max_bytes: 2})
      iex> {body.state, body.bytes, body.ownership}
      {:retained, <<0, 255>>, :caller}
      iex> RequestSeal.Body.new(%{state: :streaming})
      {:error, %RequestSeal.Message.Error{reason: :invalid_body}}
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

  @doc "Construct an availability snapshot or return `:invalid_body`."
  @spec new(map()) :: {:ok, t()} | {:error, RequestSeal.Message.Error.t()}
  def new(attrs), do: Validation.construct(attrs, __MODULE__, [:state], :invalid_body)

  @doc "Validate a snapshot without touching the caller's body source."
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
