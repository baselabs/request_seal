defmodule RequestSeal.Custody.Error do
  @moduledoc """
  Bounded custody failures. No exception, reference, key, socket path, peer text,
  or input bytes are retained. Only `:deadline_exceeded` and
  `:custodian_unavailable` are retryable; callers decide whether replay is safe.

  Reasons:

  * `:invalid_handle`, `:invalid_options`: malformed capability, options, or
    SSH agent socket path.
  * `:unsupported_algorithm`, `:unsupported_operation`, `:unsupported_format`:
    explicitly unimplemented selection; no fallback.
  * `:invalid_key`, `:key_mismatch`: invalid material or incompatible binding.
  * `:issued_for_mismatch`: the requested purpose differs from the handle.
  * `:gate_malformed_base`, `:gate_coverage`, `:gate_window`: malformed
    canonical base, missing configured metadata or coverage, or invalid time.
  * `:gate_denied`, `:gate_unavailable`, `:gate_mismatch`: port refusal, invalid
    port answer, or different component commitment or nonce.
  * `:gate_spent`, `:gate_store_failed`, `:gate_unrecorded`: a consumed decision,
    uncertain or failed storage, or failure to record before signature release.
  * `:key_denied`, `:key_fingerprint_unknown`: denied or unavailable public identity.
  * `:invalid_data`, `:invalid_signature`, `:limit`: invalid or excessive bytes.
  * `:invalid_signing_output`: signing returned malformed or excessive output bytes.
  * `:decryption_failed`: key unwrapping failed; no private diagnostics.
  * `:no_public_key`: symmetric custody has no public export.
  * `:key_not_found`: the selected key was released, removed, or is unavailable.
  * `:unavailable`: an uncommitted child or invalid atomic commit state.
  * `:deadline_exceeded`: the absolute operation deadline expired.
  * `:custodian_unavailable`: connection absent, refused, or closed.
  * `:custodian_rejected`: provider refusal or returned signature fails verification.
  * `:custodian_protocol`: malformed or excessive agent protocol response.
  * `:custodian_failure`: callback crash, unexpected response, or unmapped failure.
  """
  defstruct [:reason, :retryable]
  @reasons ~w(invalid_handle invalid_options unsupported_algorithm unsupported_operation
              invalid_key key_mismatch key_denied key_fingerprint_unknown invalid_data invalid_signature unsupported_format invalid_signing_output
              no_public_key key_not_found unavailable deadline_exceeded custodian_unavailable
              custodian_rejected custodian_protocol custodian_failure decryption_failed limit
              issued_for_mismatch gate_malformed_base gate_coverage gate_window gate_denied
              gate_unavailable gate_mismatch gate_spent gate_store_failed gate_unrecorded)a
  @type reason :: unquote(Enum.reduce(@reasons, &{:|, [], [&1, &2]}))
  @type t :: %__MODULE__{reason: reason(), retryable: boolean()}
  @doc false
  def new(reason) do
    reason = if reason in @reasons, do: reason, else: :custodian_failure
    %__MODULE__{reason: reason, retryable: reason in [:deadline_exceeded, :custodian_unavailable]}
  end
end
