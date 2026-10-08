defmodule RequestSeal.Error do
  @moduledoc """
  Bounded failures from `RequestSeal.verify/3`, `RequestSeal.sign/4`, `RequestSeal.Policy.new/1`, `RequestSeal.Ash.scope/2`, `RequestSeal.Profile`, quorum verification, and signature negotiation.

  Every error has `retryable: false`, a library-generated random 16-character
  lowercase hex `correlation`, and `detail: nil` except the Web Bot Auth reasons listed below and `:signature_base_failed`,
  whose detail is one of these bounded signature-base reason atoms (or
  `:nonqualifying_signature`, whose detail is the rejected signature reason):

  * `:limit` — signature-base or Structured Fields resource ceiling.
  * `:wrong_message_kind`, `:missing_request_context`, `:unavailable_origin`,
    `:unavailable_trailers`, `:missing_field` — required context or field unavailable.
  * `:non_ascii`, `:unknown_field_schema`, `:invalid_field_schema`,
    `:invalid_structured_field`, `:missing_dictionary_key` — field derivation rejects.
  * `:noncanonical_query_name`, `:invalid_query_encoding`, `:missing_query_parameter`,
    `:ambiguous_query_parameter` — query derivation rejects.

  No caller bytes, key identifiers, exception text, or partial verification value
  are kept.

  Closed reasons by layer:

  * `:input`: `:invalid_message` (message validation), `:invalid_policy` (missing
    choices or invalid policy), `:invalid_options` (invalid, duplicate, unknown,
    or missing options/specification), `:algorithm_mismatch` (signing `alg` differs
    from the explicit algorithm or accompanies JWS), `:limit` (wire/member/component
    bounds, including a decoded `Signature` member or nonce exceeding 1,024 bytes).
  * `:input` additionally includes `:invalid_quorum` (malformed composite policy)
    and `:invalid_profile` (invalid extension profile namespace, keys, values or size,
    or a generic verification `:profile` or `:principal` option).
  * `:fields`: `:duplicate_parameter` (repeated parameter names on signature or request members/components), `:duplicate_label` (repeated labels within or across occurrences), `:missing_signature_input`, `:missing_signature` (absent field),
    `:invalid_signature_input` (invalid dictionary, components or parameter types),
    `:invalid_signature_field` (invalid byte-sequence dictionary), `:unknown_label`
    (selected label absent from both), `:label_mismatch` (unpaired dictionary
    labels), `:label_in_use` (signing would reuse an existing label).
  * Web Bot Auth `:fields`: `:invalid_signature_agent` (detail `:legacy_string`,
    `:invalid_dictionary`, `:duplicate_member`, or `:invalid_member`),
    `:no_web_bot_auth_signature` (no selected tag).
  * Web Bot Auth `:policy`: `:invalid_keyid` (not a canonical SHA-256 thumbprint),
    `:nested_coverage_incomplete` (inner input or components absent),
    `:test_key_rejected` (published test key forbidden), `:unexpected_signature`
    (untagged label with rejection selected).
  * Web Bot Auth `:freshness`: `:lifetime_exceeded` (nonpositive or excessive window).
  * Web Bot Auth `:key`: `:agent_unresolved` with detail `:missing_member`,
    `:unsupported_type`, `:not_an_origin`, `:untrusted_agent`, `:source_mismatch`,
    `:unknown_key`, `:revoked_key`, `:source_unavailable`, or `:timeout`.
    These details never carry an agent URL, key ID, or nonce.
  * `:policy`: `:algorithm_not_permitted` (sender `alg` or authoritative algorithm
    outside allowlist), `:algorithm_mismatch` (verification HTTP alg differs from
    the authoritative algorithm or accompanies JWS),
    `:missing_required_component` (exact identifier absent), `:unexpected_component`
    (extra identifier with rejection selected).
  * `:profile`: extension packages document their own bounded reason atoms and
    details for source-specific acceptance rules.
  * `:key`: `:unknown_key` (resolver returned `:error`), `:key_resolver_failed`
    (callback fault or malformed algorithm/key result).
  * `:crypto`: `:invalid_signature` (cryptography rejects), `:signature_base_failed`
    (base construction rejects), `:verifier_failed` (verification callback fault,
    malformed result or invalid key), `:signer_failed` (signer fault, error,
    malformed result, empty signature or more than 1,024 bytes).
  * `:content`: `:digest_not_covered` (exact complete selected digest not signed),
    `:digest_unsupported` (no usable selected digest or invalid digest field),
    `:digest_mismatch` (checksum disagrees), `:body_unavailable` (required body or
    representation unavailable).
  * `:quorum`: `:quorum_not_met` (required slots or distinct-unit count unmet),
    `:unexpected_signature` (unmatched label with rejection selected),
    `:nonqualifying_signature` (matched label failed every eligible slot;
    `detail` is its last bounded reason), `:ambiguous_key_identity` (trusted
    key equivalence unknown), `:binding_unsatisfied` (nested or parameter binding).
  * `:negotiation`: `:invalid_accept_signature` (malformed request or unsupported
    parameter), `:inapplicable_component` (wrong target context),
    `:negotiation_unfulfilled` (eligible verified label, component set, or parameter differs),
    `:negotiation_unfulfillable` (unavailable component, incompatible chooser,
    unfulfillable parameter, callback fault, or signing failure).
  * `:freshness`: `:invalid_clock` (fault or noninteger/out-of-range clock),
    `:missing_created` (max-age requires created), `:missing_expires` (required
    expiration absent), `:created_in_future`, `:expired`, `:too_old` (time checks).
  * `:binding`: `:invalid_verification` (not a successful Verification with valid
    crypto, unevaluated authorization, and bounded current-profile facts),
    `:invalid_binding` (missing, unknown, or invalid explicit mapping choices),
    `:unattributed` (caller rejects anonymous identity), `:actor_unbound` (actor
    callback faults, returns :error, malformed data, or a nil actor),
    `:tenant_unbound` (tenant callback faults, returns :error, or malformed data).
  * `:replay`: `:missing_replay_identifier` (absent or empty authenticated nonce),
    `:commitment_failed` (callback fault, error, malformed or oversized key),
    `:replayed`, `:store_unavailable`, `:store_timeout`, `:store_failed` (capacity,
    adapter fault, or contract violation). Store timeouts are indeterminate.
  """
  defstruct [:reason, :layer, :correlation, retryable: false, detail: nil]

  @type t :: %__MODULE__{
          reason: atom(),
          layer:
            :input
            | :fields
            | :profile
            | :policy
            | :key
            | :crypto
            | :content
            | :freshness
            | :binding
            | :replay
            | :quorum
            | :negotiation,
          retryable: false,
          detail: atom() | nil,
          correlation: binary()
        }
  @doc false
  def new(reason, layer, detail \\ nil) do
    %__MODULE__{
      reason: reason,
      layer: layer,
      detail: detail,
      correlation: Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    }
  end
end
