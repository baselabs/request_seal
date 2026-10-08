defmodule RequestSeal.FieldOccurrence do
  @moduledoc """
  One ordered HTTP field occurrence, before normalization (RFC 9421 Section 2.1).

  `new/1` requires a map with `:name`, `:value`, and `:section` (`:headers` or
  `:trailers`). Name case and every supplied value byte, including surrounding
  whitespace and obs-text, remain unchanged. CR, LF, other controls, and obsolete
  folding reject; capture must happen before an adapter discards that evidence.
  Names are HTTP tokens of at most 256 bytes; values are at most 65,536 bytes.

  Optional `:provenance` is `:caller` (default), `:http1`, `:http2`, or `:http3`.
  It describes the caller's source, never authenticated transport evidence.
  Unknown keys reject. `validate/1` rechecks even manually modified structs.
  Inspection is redacted; access fields explicitly when raw bytes are needed.

      iex> {:ok, field} = RequestSeal.FieldOccurrence.new(%{name: "Accept", value: " text/plain", section: :headers})
      iex> {field.name, field.value, field.section}
      {"Accept", " text/plain", :headers}
      iex> RequestSeal.FieldOccurrence.new(%{name: "bad name", value: "", section: :headers})
      {:error, %RequestSeal.Message.Error{reason: :invalid_field}}
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

  @doc "Construct a raw occurrence or return `:invalid_field`."
  @spec new(map()) :: {:ok, t()} | {:error, RequestSeal.Message.Error.t()}
  def new(attrs),
    do: Validation.construct(attrs, __MODULE__, [:name, :value, :section], :invalid_field)

  @doc "Check shape, source section, token syntax, raw value bytes, and bounds."
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
