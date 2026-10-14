defmodule RequestSeal.Digest.Error do
  @moduledoc """
  Bounded digest failures without body, field, or algorithm input bytes.

    * `:mismatch` - a computed checksum differs from the field.
    * `:unsupported_algorithm` - no SHA-256/SHA-512 checksum can be checked, or a
      computation's algorithm list is not a nonempty unique list of `"sha-256"`
      and `"sha-512"`.
    * `:uncomputed_algorithm` - a stream did not hash a supported algorithm present
      in the field.
    * `:conflicting_digest` - a supported algorithm repeats across combined field
      occurrences, including identical checksums.
    * `:invalid_digest_length` - a known algorithm's checksum has the wrong size.
    * `:invalid_preference` - a preference weight is outside 0..10.
    * `:body_unavailable` - the body is streaming, unavailable, or consumed; this
      distinguishes missing bytes from retained empty content.
    * `:representation_required` - a representation check lacks explicit complete
      representation bytes.
    * `:invalid_field` - a preference selector other than the two RFC 9530
      preference field names.
    * `:invalid_body`, `:invalid_message`, `:invalid_kind`, `:invalid_chunk`,
      `:invalid_state`, and `:invalid_options` - invalid caller values. A
      `:max_bytes` above 16 MiB on `RequestSeal.Digest.compute/3` or
      `RequestSeal.Digest.check/3` returns `:invalid_options`.
    * `:limit` - content bytes exceed the `:max_bytes` bound.

  Structured Fields errors retain their own bounded reason vocabulary
  (`RequestSeal.StructuredFields.Error`); for example, an invalid Message given to
  `RequestSeal.Digest.check_stream/3` or `RequestSeal.Digest.preferences/3`
  returns that module's `:invalid_message`. No failure returns partial integrity
  facts.
  """
  @enforce_keys [:reason]
  defstruct [:reason]
  @type t :: %__MODULE__{reason: atom()}
end
