defmodule RequestSeal.DenySet do
  @moduledoc """
  An explicit caller-managed deny set indexed by RFC 7638 SHA-256 thumbprints.
  Configure it on a signature verification policy or at custody import. A
  configured set, even if empty, requires a verifiable public-key identity.
  """

  alias RequestSeal.{Custody, Error, KeyHandle, PublicKey}

  @max_entries 65_536
  @derive {Inspect, only: []}
  defstruct entries: %{}
  @opaque t :: %__MODULE__{entries: %{optional(<<_::256>>) => true}}

  @doc """
  Build a set from up to 65,536 canonical unpadded Base64url SHA-256 thumbprints.
  Duplicate entries denote the same key. Invalid entries or lists return
  `{:error, %RequestSeal.Error{reason: :invalid_options}}`.

      iex> {:ok, _set} = RequestSeal.DenySet.new(["kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"])
  """
  @spec new([binary()]) :: {:ok, t()} | {:error, Error.t()}
  def new(entries) do
    case collect(entries, %{}, 0) do
      {:ok, entries} -> {:ok, %__MODULE__{entries: entries}}
      :error -> {:error, Error.new(:invalid_options, :input)}
    end
  end

  @doc """
  Check a validated public key against the set. Returns `:ok`, or
  `{:error, reason}` for `:key_denied`, `:key_fingerprint_unknown`, or
  `:invalid_options`. Passing nil disables the check.
  """
  @spec check(t() | nil, PublicKey.t()) ::
          :ok | {:error, :key_denied | :key_fingerprint_unknown | :invalid_options}
  def check(nil, _key), do: :ok

  def check(set, key) do
    with true <- valid?(set),
         {:ok, thumbprint} <- PublicKey.thumbprint(key),
         {:ok, bytes} <- decode(thumbprint) do
      if Map.has_key?(set.entries, bytes), do: {:error, :key_denied}, else: :ok
    else
      false -> {:error, :invalid_options}
      _ -> {:error, :key_fingerprint_unknown}
    end
  end

  @doc """
  Return the published Web Bot Auth test-key thumbprints for callers that also
  want to exclude those keys outside Web Bot Auth.
  """
  @spec published_test_keys() :: [binary()]
  def published_test_keys, do: RequestSeal.WebBotAuth.published_test_key_thumbprints()

  @doc false
  def valid?(nil), do: true

  def valid?(%__MODULE__{entries: entries} = set) do
    map_size(set) == 2 and is_map(entries) and not is_struct(entries) and
      map_size(entries) <= @max_entries and
      Enum.all?(Map.to_list(entries), fn
        {<<_::256>>, true} -> true
        _ -> false
      end)
  end

  def valid?(_), do: false

  @doc false
  def thumbprint?(value), do: match?({:ok, _}, decode(value))

  @doc false
  def check_proof(nil, _), do: :ok

  def check_proof(set, signers) when is_list(signers) and length(signers) in 1..64 do
    Enum.reduce_while(signers, :ok, fn signer, :ok ->
      case decode(signer) do
        {:ok, bytes} ->
          if Map.has_key?(set.entries, bytes),
            do: {:halt, {:error, :key_denied}},
            else: {:cont, :ok}

        :error ->
          {:halt, {:error, :key_fingerprint_unknown}}
      end
    end)
  end

  def check_proof(_, _), do: {:error, :key_fingerprint_unknown}

  @doc false
  def public_for_verification(nil, _key, false), do: {:ok, nil}

  def public_for_verification(set, %KeyHandle{} = handle, capture?) do
    with {:ok, public} <- Custody.public_key(handle) do
      public_for_verification(set, public, capture?)
    else
      _ -> {:error, :key_fingerprint_unknown}
    end
  end

  def public_for_verification(set, %PublicKey{} = key, _) do
    with :ok <- check(set, key), do: {:ok, key}
  end

  @doc false
  def valid_admission_options?(opts) do
    expected = Keyword.fetch(opts, :expected_thumbprint)

    valid?(opts[:deny]) and
      case expected do
        :error -> true
        {:ok, value} -> thumbprint?(value)
      end
  end

  defp collect([], acc, _count), do: {:ok, acc}

  defp collect([entry | rest], acc, count) when count < @max_entries do
    with {:ok, bytes} <- decode(entry), do: collect(rest, Map.put(acc, bytes, true), count + 1)
  end

  defp collect(_, _, _), do: :error

  defp decode(value) when is_binary(value) and byte_size(value) == 43 do
    with {:ok, <<_::256>> = bytes} <- Base.url_decode64(value, padding: false),
         true <- Base.url_encode64(bytes, padding: false) == value do
      {:ok, bytes}
    else
      _ -> :error
    end
  end

  defp decode(_), do: :error
end
