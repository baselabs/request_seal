defmodule RequestSeal.SignatureBase.Error do
  @moduledoc """
  Bounded signature-base errors, without supplied bytes or partial output.

  Reasons:

  * Input: `:invalid_message`, `:invalid_options`, `:invalid_signature_parameters`,
    `:limit` (documented resource ceilings).
  * Components: `:invalid_component`, `:unknown_component`, `:duplicate_component`,
    `:invalid_component_parameters`, `:incompatible_parameters`.
  * Context: `:wrong_message_kind`, `:missing_request_context`, `:unavailable_origin`,
    `:unavailable_trailers`, `:missing_field`.
  * Fields: `:non_ascii`, `:unknown_field_schema`, `:invalid_field_schema`,
    `:invalid_structured_field`, `:missing_dictionary_key`.
  * Query: `:noncanonical_query_name`, `:invalid_query_encoding`,
    `:missing_query_parameter`, `:ambiguous_query_parameter`.

  Correct input or supply missing capture/schema evidence before retrying. None
  indicates cryptographic validity, authentication, or authorization. Errors
  contain only the enumerated reason; there is no exception or telemetry path.
  """
  @enforce_keys [:reason]
  defstruct [:reason]

  @type reason ::
          :invalid_message
          | :invalid_options
          | :invalid_signature_parameters
          | :limit
          | :invalid_component
          | :unknown_component
          | :duplicate_component
          | :invalid_component_parameters
          | :incompatible_parameters
          | :wrong_message_kind
          | :missing_request_context
          | :unavailable_origin
          | :unavailable_trailers
          | :missing_field
          | :non_ascii
          | :unknown_field_schema
          | :invalid_field_schema
          | :invalid_structured_field
          | :missing_dictionary_key
          | :noncanonical_query_name
          | :invalid_query_encoding
          | :missing_query_parameter
          | :ambiguous_query_parameter
  @type t :: %__MODULE__{reason: reason()}
end
