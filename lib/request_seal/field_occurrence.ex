defmodule RequestSeal.FieldOccurrence do
  @moduledoc """
  One ordered HTTP field occurrence, before normalization (RFC 9421 Section 2.1).

  Name case and every supplied value byte, including surrounding whitespace and
  obs-text, remain unchanged. Capture must happen before an adapter discards
  that evidence: CR, LF, and obsolete line folding cannot be represented.

  The optional provenance describes the caller's source, never authenticated
  transport evidence. Inspection is redacted; access fields explicitly when raw
  bytes are needed.
  """
  alias RequestSeal.Message.Validation
  @derive {Inspect, only: []}
  defstruct [:name, :value, :section, provenance: :caller]

  @type t :: %__MODULE__{
          name: binary(),
          value: binary(),
          section: :headers | :trailers,
          provenance: :caller | :http1 | :http2 | :http3
        }

  @doc """
  Construct a raw occurrence from an attribute map.

  ## Parameters

    * `attrs` - a plain map (not a struct) using only these keys; unknown keys reject:
      * `:name` (required) - an HTTP token of 1..256 bytes; case is kept.
      * `:value` (required) - a binary of at most 65,536 bytes containing only
        HTAB, space, visible ASCII, and obs-text (0x80..0xFF). CR, LF, DEL, and
        other controls reject, so obsolete folding rejects too.
      * `:section` (required) - `:headers` or `:trailers`.
      * `:provenance` - `:caller` (default), `:http1`, `:http2`, or `:http3`.

  ## Returns

    * `{:ok, %RequestSeal.FieldOccurrence{}}`.
    * `{:error, %RequestSeal.Message.Error{reason: :invalid_field}}` - the only
      reason. Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, field} = RequestSeal.FieldOccurrence.new(%{name: "Accept", value: " text/plain", section: :headers})
      iex> {field.name, field.value, field.section}
      {"Accept", " text/plain", :headers}
      iex> RequestSeal.FieldOccurrence.new(%{name: "bad name", value: "", section: :headers})
      {:error, %RequestSeal.Message.Error{reason: :invalid_field}}
      iex> RequestSeal.FieldOccurrence.new(%{name: "X-Build", value: <<"118", 13, 10, "X-Other: 1">>, section: :headers})
      {:error, %RequestSeal.Message.Error{reason: :invalid_field}}
  """
  @spec new(map()) :: {:ok, t()} | {:error, RequestSeal.Message.Error.t()}
  def new(attrs),
    do: Validation.construct(attrs, __MODULE__, [:name, :value, :section], :invalid_field)

  @doc """
  Check shape, source section, token syntax, raw value bytes, and bounds.

  Applies the rules of `new/1` to an existing struct, including one built or
  modified directly.

  ## Parameters

    * `field` - any term; only a `RequestSeal.FieldOccurrence` struct can pass.

  ## Returns

    * `:ok`.
    * `{:error, %RequestSeal.Message.Error{reason: :invalid_field}}` - the only
      reason. Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, field} = RequestSeal.FieldOccurrence.new(%{name: "grpc-status", value: "0", section: :trailers, provenance: :http2})
      iex> RequestSeal.FieldOccurrence.validate(field)
      :ok
      iex> RequestSeal.FieldOccurrence.validate(%{field | section: :body})
      {:error, %RequestSeal.Message.Error{reason: :invalid_field}}
  """
  @spec validate(term()) :: :ok | {:error, RequestSeal.Message.Error.t()}
  def validate(%__MODULE__{} = field) do
    if Validation.exact_struct?(field, __MODULE__) and Validation.token?(field.name, 256) and
         Validation.field_value?(field.value) and field.section in [:headers, :trailers] and
         field.provenance in [:caller, :http1, :http2, :http3],
       do: :ok,
       else: Validation.error(:invalid_field)
  end

  def validate(_), do: Validation.error(:invalid_field)
end
