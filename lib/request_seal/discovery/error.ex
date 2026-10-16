defmodule RequestSeal.Discovery.Error do
  @moduledoc """
  Bounded discovery failures, containing only `reason` and `retryable`.

  Connect failure, deadline expiry, DNS resolution trouble, source unavailability, cache overload and
  `:unexpected_status` from 5xx responses are retryable; 4xx responses and a
  configured host that does not exist are not.
  Retryability never authorizes replay of an application operation.
  No host, URL, key ID, exception, bytes, or peer text is retained.

  Configuration failures:

    * `:invalid_source` - the source or its attributes are not a valid
      `RequestSeal.Discovery.Source`.
    * `:invalid_options` - unknown, duplicate or out-of-range options, an invalid
      clock, or an invalid `negative_ttl`.
    * `:domain_not_found` - DNS answered authoritatively that the configured
      host does not exist (NXDOMAIN on every queried family): a configuration
      error, not resolver trouble.

  Transport failures:

    * `:transport_unavailable` - the caller has not started the `:ssl` application.
    * `:resolution_failed` - DNS returned no usable address, or more than 64;
      possibly transient resolver trouble, so retryable.
    * `:address_denied` - a resolved or connected address is private or
      special-purpose and not in `permitted_addresses`.
    * `:connect_failed` - no address accepted a connection, or the request could
      not be sent.
    * `:tls_failed` - TLS negotiation or certificate validation failed, or the
      trust roots could not be loaded.
    * `:deadline_exceeded` - the operation deadline expired.
    * `:redirect_denied` - a redirect the source does not allow: redirects are
      disabled, the `Location` is missing, invalid or longer than 2,048 bytes, the
      target leaves the origin under `:same_origin`, or a CIMD `jwks_uri` names
      another origin.
    * `:redirect_limit` - more redirects than `max_redirects`.

  Response failures:

    * `:unexpected_status` - a final status other than 200.
    * `:unexpected_media_type` - a missing or disallowed `Content-Type`.
    * `:limit` - a size or count bound was exceeded, such as body bytes, decoded
      bytes, header size, key count, JSON depth or members, or removals per source.
    * `:invalid_response` - malformed HTTP framing, content coding, cache fields or
      JSON, or an unexpected internal failure.
    * `:invalid_key_set` - the key set or a key entry is malformed or carries
      private material, an ID or `kid` breaks the source's key ID mode, eligible
      entries repeat an ID, or a CIMD document names no key source.
    * `:client_id_mismatch` - a CIMD document's `client_id` differs from the
      source location.
    * `:ambiguous_key_source` - a CIMD document has both `jwks` and `jwks_uri`.
    * `:directory_unsigned` - a directory without a signature while
      `require_signed_directory` is true.
    * `:directory_signature_invalid` - a selected directory signature is missing,
      malformed, expired or does not verify.

  Resolution/cache failures:

    * `:unknown_key` - the key ID is malformed for the source's mode, or no fresh,
      compatible key has that ID.
    * `:revoked_key` - the thumbprint is revoked by the source or removed from the cache.
    * `:source_unavailable` - the source is within negative freshness, its fetch
      was canceled or failed unexpectedly, or the cache is not running.
    * `:cache_overloaded` - the cache's source, in-flight or waiter bound is reached.
  """
  defstruct [:reason, :retryable]

  @reasons ~w(invalid_source invalid_options domain_not_found transport_unavailable resolution_failed
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
        reason in [
          :connect_failed,
          :deadline_exceeded,
          :resolution_failed,
          :source_unavailable,
          :cache_overloaded
        ]
    }
  end
end
