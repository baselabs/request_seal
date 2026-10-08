defmodule RequestSeal.Digest.Error do
  @moduledoc """
  Bounded digest failures without body, field, or algorithm input bytes.

  `:mismatch` means a computed checksum differs. `:unsupported_algorithm` means
  no SHA-256/SHA-512 checksum can be checked, or computation requested another
  algorithm. `:uncomputed_algorithm` means a stream did not hash a supported
  algorithm present in the field. `:conflicting_digest` rejects a supported algorithm
  repeated across combined field occurrences, including identical checksums.
  `:invalid_digest_length` rejects a known
  algorithm's wrong checksum size. `:invalid_preference` rejects a weight outside
  0..10. `:body_unavailable` distinguishes missing/consumed/streaming bytes from
  retained empty content; `:representation_required` requires explicit complete
  representation bytes. `:invalid_field` rejects a selector other than the two
  RFC 9530 preference field names. `:invalid_body`, `:invalid_message`, `:invalid_kind`,
  `:invalid_chunk`, `:invalid_state`, and `:invalid_options` reject invalid caller
  values. A `:max_bytes` above 16 MiB on `compute/3` or `check/3` returns `:invalid_options`.
  `:limit` rejects excess content bytes. Structured Fields errors retain
  their own bounded reason vocabulary. No failure returns partial integrity facts.
  """
  @enforce_keys [:reason]
  defstruct [:reason]
  @type t :: %__MODULE__{reason: atom()}
end
