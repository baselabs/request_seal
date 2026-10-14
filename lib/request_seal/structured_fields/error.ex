defmodule RequestSeal.StructuredFields.Error do
  @moduledoc """
  Bounded Structured Fields errors, containing no input bytes.

  `:syntax` means malformed wire input; `:invalid_value` means an invalid value
  supplied for serialization. `:revision_type` rejects a type unavailable in the
  explicitly selected RFC revision; `:schema_type` rejects a field's disallowed
  item, inner-list, or parameter type. `:limit` means a documented bound was
  exceeded. `:invalid_schema` and `:invalid_limits` reject invalid configuration.
  `:invalid_message`, `:invalid_field`, `:missing_field`, and
  `:unavailable_section` identify field capture failures. No partial parse is
  returned on failure. `:duplicate_key` means a dictionary key required to be
  unique (the `:unique_keys` option of `RequestSeal.StructuredFields.parse_field/5`,
  also used by the library's own field policies) repeats before deduplication.
  `:duplicate_parameter` rejects repeated parameter names when uniqueness is
  required (the `:unique_parameters` option of the same function, also used by
  the signature parsing policy).
  """
  @enforce_keys [:reason]
  defstruct [:reason]
  @type t :: %__MODULE__{reason: atom()}
end
