defmodule RequestSeal.TransportFacts do
  @moduledoc """
  Enumerated caller declarations about HTTP transport.

  Evidence is always `:declared`: values describe what the caller says, not what
  was observed or verified. No arbitrary metadata, addresses, or forwarded fields
  are accepted. A declaration cannot prove a connection's security prerequisites.
  """
  alias RequestSeal.Message.Validation
  defstruct http_version: :unknown, tls: :unknown, evidence: :declared

  @type t :: %__MODULE__{
          http_version: :unknown | :http1_0 | :http1_1 | :http2 | :http3,
          tls: :unknown | :plain | :tls,
          evidence: :declared
        }

  @doc """
  Construct enumerated declarations from an attribute map.

  ## Parameters

    * `attrs` - a plain map (not a struct) using only these keys; unknown keys reject:
      * `:http_version` - `:unknown` (default), `:http1_0`, `:http1_1`, `:http2`, or `:http3`.
      * `:tls` - `:unknown` (default), `:plain`, or `:tls`.
      * `:evidence` - only `:declared` (the default); attempts to supply observed
        or verified evidence reject.

  ## Returns

    * `{:ok, %RequestSeal.TransportFacts{}}`.
    * `{:error, %RequestSeal.Message.Error{reason: :invalid_transport}}` - the
      only reason. Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, facts} = RequestSeal.TransportFacts.new(%{http_version: :http2, tls: :tls})
      iex> facts.evidence
      :declared
      iex> RequestSeal.TransportFacts.new(%{evidence: :observed})
      {:error, %RequestSeal.Message.Error{reason: :invalid_transport}}
      iex> RequestSeal.TransportFacts.new(%{client_address: "192.0.2.10"})
      {:error, %RequestSeal.Message.Error{reason: :invalid_transport}}
  """
  @spec new(map()) :: {:ok, t()} | {:error, RequestSeal.Message.Error.t()}
  def new(attrs), do: Validation.construct(attrs, __MODULE__, [], :invalid_transport)

  @doc """
  Recheck the declaration boundary, including manually modified structs.

  ## Parameters

    * `facts` - any term; only a `RequestSeal.TransportFacts` struct can pass.

  ## Returns

    * `:ok`.
    * `{:error, %RequestSeal.Message.Error{reason: :invalid_transport}}` - the
      only reason. Meanings: `RequestSeal.Message.Error`.

  ## Examples

      iex> {:ok, facts} = RequestSeal.TransportFacts.new(%{})
      iex> RequestSeal.TransportFacts.validate(facts)
      :ok
      iex> RequestSeal.TransportFacts.validate(%{facts | evidence: :verified})
      {:error, %RequestSeal.Message.Error{reason: :invalid_transport}}
  """
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
