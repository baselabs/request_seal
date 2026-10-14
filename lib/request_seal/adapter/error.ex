defmodule RequestSeal.Adapter.Error do
  @moduledoc """
  Bounded HTTP adapter failures, always nonretryable. `message/1` includes only
  the reason and random correlation token; inspection excludes source details.

  Closed reasons: `:invalid_options` (missing/unknown/duplicate/invalid choices),
  `:invalid_request` (unfaithful or unusable framework value), `:not_final_step` (signing
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

  An unexpected exception, throw, or exit inside an adapter stage returns that
  stage's fallback reason without source details: `:invalid_options` at
  `:attach`, `:invalid_request` at `:capture`, `:signing_failed` at `:sign`, and
  `:response_rejected` at `:verify`. Plug `init/1` errors are raised with the
  plug's own stage (`:capture`, `:verify`, or `:sign`).

  `attempt` counts final signing attempts. Req starts at one and reports a
  response error under the attempt that produced it; Finch always uses one.
  Plug uses zero for capture, request verification, and option errors, and one
  for response signing. Req attach errors use zero.
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

  @doc """
  Returns the reason and the random correlation token, never source details.

  ## Parameters

    * `error` - a `RequestSeal.Adapter.Error`.

  ## Returns

    * binary - `"<reason> (<correlation>)"`, where the correlation is 16
      lowercase hexadecimal characters drawn at construction.

  ## Examples

      iex> {:error, error} = RequestSeal.Finch.request_message(:not_a_finch_request)
      iex> Exception.message(error) =~ ~r/^invalid_request [(][0-9a-f]{16}[)]$/
      true
  """
  @impl true
  def message(error), do: "#{error.reason} (#{error.correlation})"
end
