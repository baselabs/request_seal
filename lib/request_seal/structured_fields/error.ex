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
  returned on failure. The internal field-policy hook uses `:duplicate_key` when
  a key required to be unique repeats before dictionary deduplication.
  `:duplicate_parameter` rejects repeated parameter names when the signature
  parsing policy requires uniqueness.
  """
  @enforce_keys [:reason]
  defstruct [:reason]
  @type t :: %__MODULE__{reason: atom()}
end
