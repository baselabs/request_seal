defmodule RequestSeal.StructuredFields.Value do
  @moduledoc """
  Ordered Structured Fields data (RFC 9651 Section 3).

  `:type` is `:item`, `:inner_list`, `:list`, or `:dictionary`. An item's `:value`
  is a tagged bare item: `{:integer, n}`, `{:decimal, {coefficient, scale}}`,
  `{:string, ascii}`, `{:token, ascii}`, `{:bytes, binary}`, `{:boolean, boolean}`,
  `{:date, unix_seconds}`, or `{:display_string, utf8}`. Decimals are exact base-10
  values, coefficient / 10^scale; floats are not accepted. Serialization rounds
  to three places with ties to even. Scale is bounded to 18 and coefficient
  magnitude to 10^30 - 1 before arithmetic.

  Lists and inner lists contain ordered Values. Dictionaries contain ordered
  `{key, Value}` pairs. Parameters are ordered `{key, bare_item}` pairs on items
  and inner lists only. Parsing duplicates keeps the first key position and the
  last value, as the RFC requires. Hand-constructed duplicates reject during
  serialization. Inner lists cannot nest. Inspection omits values; access them
  explicitly. This structure establishes no authentication or authorization.
  """
  @derive {Inspect, only: [:type]}
  defstruct [:type, :value, parameters: []]

  @type bare ::
          {:integer, integer()}
          | {:decimal, {integer(), 0..18}}
          | {:string | :token | :bytes | :display_string, binary()}
          | {:boolean, boolean()}
          | {:date, integer()}
  @type t :: %__MODULE__{
          type: :item | :inner_list | :list | :dictionary,
          value: bare() | [t()] | [{binary(), t()}],
          parameters: [{binary(), bare()}]
        }
end
