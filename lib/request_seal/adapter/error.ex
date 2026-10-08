defmodule RequestSeal.Adapter.Error do
  @moduledoc """
  Bounded HTTP adapter failures, always nonretryable. `message/1` includes only
  the reason and random correlation token; inspection excludes source details.

  Closed reasons: `:invalid_options` (missing/unknown/duplicate choices),
  `:invalid_request` (unfaithful framework value), `:not_final_step` (signing
  no longer last), `:cross_origin_redirect` (origin policy),
  `:unsupported_delivery` (delivery cannot withhold bytes),
  `:unsupported_component` (transport cannot faithfully supply a component),
  `:body_unavailable` (required bytes not retained), `:digest_conflict` (caller
  digest disagrees), `:limit` (retention/resource bound), `:signing_failed`
  (custody or signing rejection), and `:response_rejected` (verification failed).
  Plug also reports `:not_captured`, `:already_verified`, `:parser_order`,
  `:untrusted_proxy`, and `:request_rejected` (with a bounded core source error).
  Plug uses `:unsupported_component` when required or covered exact-target
  evidence is unavailable, including target-dependent related-request signing.
  `source` is a bounded core, custody, or message error, never a framework exception.
  `attempt` counts final signing attempts, starting at one; attach errors use zero.
  """
  @derive {Inspect, only: [:reason, :adapter, :stage, :attempt, :retryable, :correlation]}
  defexception [:reason, :adapter, :stage, :attempt, :source, :correlation, retryable: false]

  @type reason ::
          :invalid_options
          | :invalid_request
          | :not_final_step
          | :cross_origin_redirect
          | :unsupported_delivery
          | :unsupported_component
          | :body_unavailable
          | :digest_conflict
          | :limit
          | :signing_failed
          | :response_rejected
          | :not_captured
          | :already_verified
          | :parser_order
          | :untrusted_proxy
          | :request_rejected
  @type t :: %__MODULE__{
          reason: reason(),
          adapter: :req | :finch | :plug,
          stage: :attach | :capture | :sign | :verify,
          attempt: non_neg_integer(),
          source:
            RequestSeal.Error.t()
            | RequestSeal.Custody.Error.t()
            | RequestSeal.Message.Error.t()
            | nil,
          retryable: false,
          correlation: binary()
        }
  @doc false
  def new(reason, adapter, stage, attempt, source \\ nil) do
    %__MODULE__{
      reason: reason,
      adapter: adapter,
      stage: stage,
      attempt: attempt,
      source: source,
      correlation: Base.encode16(:crypto.strong_rand_bytes(8), case: :lower)
    }
  end

  @impl true
  def message(error), do: "#{error.reason} (#{error.correlation})"
end
