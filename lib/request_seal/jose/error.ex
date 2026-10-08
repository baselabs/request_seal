defmodule RequestSeal.JOSE.Error do
  @moduledoc """
  Closed, redacted JOSE errors. Only `:deadline_exceeded` is retryable.

  Input errors: `:invalid_options`, `:invalid_policy`, `:limit`,
  `:invalid_serialization`, `:invalid_base64`, `:invalid_header`,
  `:duplicate_member`, `:unsupported_header`, `:unsupported_serialization`,
  `:compression_unsupported`, `:detached_payload`, `:invalid_iv`, `:invalid_tag`.
  Selection errors: `:algorithm_not_permitted`, `:algorithm_mismatch`,
  `:unsupported_critical_header`, `:unknown_key`, `:key_resolver_failed`.
  Operation errors: `:invalid_signature`, `:signer_failed`, `:decryption_failed`,
  `:entropy_failure`, `:deadline_exceeded`, `:nesting_depth`, `:content_type_mismatch`.
  Unwrap and authentication failures share `:decryption_failed`; no bytes, key
  identifiers, callback reason, or exception text is retained. Correlation is nil.
  Layers identify `:input`, `:key`, `:crypto`, or `:nesting`.
  """
  @reasons ~w(invalid_options invalid_policy limit invalid_serialization invalid_base64
    invalid_header duplicate_member unsupported_header unsupported_serialization
    compression_unsupported detached_payload algorithm_not_permitted algorithm_mismatch
    unsupported_critical_header unknown_key key_resolver_failed invalid_signature signer_failed
    invalid_iv invalid_tag decryption_failed entropy_failure deadline_exceeded nesting_depth
    content_type_mismatch)a
  defstruct [:reason, :layer, :correlation, retryable: false]
  @type reason :: unquote(Enum.reduce(@reasons, &{:|, [], [&1, &2]}))
  @type t :: %__MODULE__{reason: reason(), layer: atom(), retryable: boolean(), correlation: nil}
  @doc false
  def new(reason, layer) when reason in @reasons,
    do: %__MODULE__{reason: reason, layer: layer, retryable: reason == :deadline_exceeded}
end
