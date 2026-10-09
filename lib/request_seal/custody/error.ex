defmodule RequestSeal.Custody.Error do
  @moduledoc """
  Bounded custody failures. No exception, reference, key, socket path, peer text,
  or input bytes are retained. Only `:deadline_exceeded` and
  `:custodian_unavailable` are retryable; callers decide whether replay is safe.

  Reasons:

  * `:invalid_handle`, `:invalid_options`: malformed capability or options.
  * `:unsupported_algorithm`, `:unsupported_operation`, `:unsupported_format`:
    explicitly unimplemented selection; no fallback.
  * `:invalid_key`, `:key_mismatch`: invalid material or incompatible binding.
  * `:invalid_data`, `:invalid_signature`, `:limit`: invalid or excessive bytes.
  * `:decryption_failed`: RSA-OAEP key unwrapping failed; no private diagnostics.
  * `:no_public_key`: symmetric custody has no public export.
  * `:key_not_found`: the selected key was released, removed, or is unavailable.
  * `:deadline_exceeded`: the absolute operation deadline expired.
  * `:custodian_unavailable`: connection absent, refused, or closed.
  * `:custodian_rejected`: provider refusal or returned signature fails verification.
  * `:custodian_protocol`: malformed or excessive agent protocol response.
  * `:custodian_failure`: callback crash, unexpected response, or unmapped failure.
  """
  defstruct [:reason, :retryable]
  @reasons ~w(invalid_handle invalid_options unsupported_algorithm unsupported_operation
              invalid_key key_mismatch invalid_data invalid_signature unsupported_format
              no_public_key key_not_found deadline_exceeded custodian_unavailable
              custodian_rejected custodian_protocol custodian_failure decryption_failed limit)a
  @type reason :: unquote(Enum.reduce(@reasons, &{:|, [], [&1, &2]}))
  @type t :: %__MODULE__{reason: reason(), retryable: boolean()}
  @doc false
  def new(reason) do
    reason = if reason in @reasons, do: reason, else: :custodian_failure
    %__MODULE__{reason: reason, retryable: reason in [:deadline_exceeded, :custodian_unavailable]}
  end
end
