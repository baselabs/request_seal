defmodule RequestSeal.Discovery.Error do
  @moduledoc """
  Bounded discovery failures, containing only `reason` and `retryable`.

  Configuration failures: `:invalid_source`, `:invalid_options`.
  Transport failures: `:transport_unavailable` (caller must start SSL),
  `:resolution_failed`, `:address_denied`, `:connect_failed`, `:tls_failed`,
  `:deadline_exceeded`, `:redirect_denied`, `:redirect_limit`.
  Response failures: `:unexpected_status`, `:unexpected_media_type`, `:limit`,
  `:invalid_response`, `:invalid_key_set`, `:client_id_mismatch`,
  `:ambiguous_key_source`, `:directory_unsigned`, `:directory_signature_invalid`.
  Resolution/cache failures: `:unknown_key`, `:revoked_key`,
  `:source_unavailable`, `:cache_overloaded`.

  Connect failure, deadline expiry, source unavailability, cache overload and
  `:unexpected_status` from 5xx responses are retryable; 4xx responses are not.
  Retryability never authorizes replay of an application operation.
  No host, URL, key ID, exception, bytes, or peer text is retained.
  """
  defstruct [:reason, :retryable]
  @reasons ~w(invalid_source invalid_options transport_unavailable resolution_failed
    address_denied connect_failed tls_failed deadline_exceeded redirect_denied
    redirect_limit unexpected_status unexpected_media_type limit invalid_response
    invalid_key_set client_id_mismatch ambiguous_key_source directory_unsigned
    directory_signature_invalid unknown_key revoked_key source_unavailable cache_overloaded)a
  @type reason :: unquote(Enum.reduce(@reasons, &{:|, [], [&1, &2]}))
  @type t :: %__MODULE__{reason: reason(), retryable: boolean()}
  @doc false
  def new(reason) do
    reason = if reason in @reasons, do: reason, else: :invalid_response

    %__MODULE__{
      reason: reason,
      retryable:
        reason in [:connect_failed, :deadline_exceeded, :source_unavailable, :cache_overloaded]
    }
  end
end
