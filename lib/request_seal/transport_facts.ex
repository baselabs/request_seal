defmodule RequestSeal.TransportFacts do
  @moduledoc """
  Enumerated caller declarations about HTTP transport.

  `new/1` accepts `:http_version` (`:unknown`, `:http1_0`, `:http1_1`, `:http2`,
  `:http3`) and `:tls` (`:unknown`, `:plain`, `:tls`). Both default to `:unknown`.
  `:evidence` is always `:declared`; attempts to supply observed or verified
  evidence reject. No arbitrary metadata, addresses, or forwarded fields are
  accepted. A declaration cannot prove a connection's security prerequisites.

      iex> {:ok, facts} = RequestSeal.TransportFacts.new(%{http_version: :http2, tls: :tls})
      iex> facts.evidence
      :declared
      iex> RequestSeal.TransportFacts.new(%{evidence: :observed})
      {:error, %RequestSeal.Message.Error{reason: :invalid_transport}}
  """
  alias RequestSeal.Message.Validation
  defstruct http_version: :unknown, tls: :unknown, evidence: :declared

  @type t :: %__MODULE__{
          http_version: :unknown | :http1_0 | :http1_1 | :http2 | :http3,
          tls: :unknown | :plain | :tls,
          evidence: :declared
        }

  @doc "Construct enumerated declarations or return `:invalid_transport`."
  @spec new(map()) :: {:ok, t()} | {:error, RequestSeal.Message.Error.t()}
  def new(attrs), do: Validation.construct(attrs, __MODULE__, [], :invalid_transport)

  @doc "Recheck the declaration boundary, including manually modified structs."
  @spec validate(term()) :: :ok | {:error, RequestSeal.Message.Error.t()}
  def validate(%__MODULE__{} = facts) do
    if Validation.exact_struct?(facts, __MODULE__) and facts.evidence == :declared and
         facts.http_version in [:unknown, :http1_0, :http1_1, :http2, :http3] and
         facts.tls in [:unknown, :plain, :tls],
       do: :ok,
       else: Validation.error(:invalid_transport)
  end

  def validate(_), do: Validation.error(:invalid_transport)
end
