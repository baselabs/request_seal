defmodule RequestSeal.Telemetry do
  @moduledoc """
  The versioned telemetry contract (v1) for verification, replay, and custody.

  Events are emitted through
  [`:telemetry`](https://hexdocs.pm/telemetry/) with bounded, low-cardinality
  metadata only: closed reason and layer atoms from `RequestSeal.Error`,
  outcomes, and durations. No signature label, key ID, header name or value,
  URL, principal, nonce, body or base bytes, exception text, or any other
  attacker-controlled or high-cardinality value ever appears in event names,
  measurements, or metadata. Handlers own storage and aggregation.

  Every event carries one measurement, `:duration`, an integer in
  `System.monotonic_time/0` native units covering the emitting call.

  | Event | Emitted by | Metadata |
  | --- | --- | --- |
  | `[:request_seal, :verify, :stop]` | `RequestSeal.verify/3` | `:outcome` (`:ok` or `:error`), `:reason` (atom or nil), `:layer` (atom or nil), `:detail` (atom or nil) |
  | `[:request_seal, :verify_quorum, :stop]` | `RequestSeal.verify_quorum/3` | as above |
  | `[:request_seal, :web_bot_auth, :verify, :stop]` | `RequestSeal.WebBotAuth.verify/3` | as above |
  | `[:request_seal, :replay, :claim]` | the required-replay commit shared by every profile | `:outcome` (`:claimed`, `:already_claimed`, or `:error`), `:reason` (atom or nil) |
  | `[:request_seal, :custody, :sign, :stop]` | the shared custody signing path of both `RequestSeal.sign/4` forms | `:outcome` (`:ok` or `:error`), `:reason` (a bounded `RequestSeal.Custody.Error` reason atom or nil) |

  A rejected verification reports its bounded `reason` and `layer` exactly as
  returned to the caller; `:limit` and the retryable `:deadline` make resource
  exhaustion observable. An `:internal` reason marks an unexpected internal
  fault — not named by the input — with the exception class in `detail`.

  The event list, names, measurement keys, and metadata keys are a versioned
  public contract: additive events and keys may arrive in minor releases;
  renames and removals require a major version. This module carries no
  functions; attach handlers with `:telemetry.attach/4`.

  ## Examples

      iex> :telemetry.attach_many("ops-verify", [
      ...>   [:request_seal, :verify, :stop]
      ...> ], fn _m, _me, md, _c ->
      ...>   send(self(), {:verified, md.outcome})
      ...> end, nil)
      ...> :telemetry.detach("ops-verify")
      :ok
  """

  @events [
    [:request_seal, :verify, :stop],
    [:request_seal, :verify_quorum, :stop],
    [:request_seal, :web_bot_auth, :verify, :stop],
    [:request_seal, :replay, :claim],
    [:request_seal, :custody, :sign, :stop]
  ]

  @doc """
  The v1 event names, as documented above.
  """
  @spec events() :: [list(atom())]
  def events, do: @events

  @doc false
  def emit(event, duration, metadata) do
    :telemetry.execute(event, %{duration: duration}, metadata)
  end

  @doc false
  def meta({:ok, _}), do: %{outcome: :ok, reason: nil, layer: nil, detail: nil}

  def meta({:error, %RequestSeal.Error{} = error}) do
    %{outcome: :error, reason: error.reason, layer: error.layer, detail: error.detail}
  end
end
