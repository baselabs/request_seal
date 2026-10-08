defmodule RequestSeal.Discovery.KeySet do
  @moduledoc """
  Bounded source-bound public keys, freshness and directory proof status.
  `revision` is SHA-256 over the fetched JSON bytes, not an origin-assigned sequence.
  `lookup/3` accepts IDs under the source's explicit `key_id` mode and an algorithm
  allowlist. Default IDs are computed RFC thumbprints; directory-assigned IDs
  never replace cryptographic identity or thumbprint revocation. It rejects stale, revoked, incompatible or malformed entries. Key
  restrictions remain enforced by `PublicKey`. Snapshot lookup uses system time;
  the cache's `:clock` supports caller-controlled time for resolution/fetching.
  """
  alias RequestSeal.{PublicKey, SignatureFields}
  alias RequestSeal.Crypto.Algorithm
  alias RequestSeal.Discovery.{Source, Resolution}
  @derive {Inspect, only: [:fetched_at, :expires_at, :proof]}
  defstruct [:source, :origin, :keys, :fetched_at, :expires_at, :revision, :proof]

  @type t :: %__MODULE__{
          source: Source.t(),
          origin: binary(),
          keys: %{binary() => Resolution.t()},
          fetched_at: integer(),
          expires_at: integer(),
          revision: binary(),
          proof: :signed | :unsigned | :not_applicable
        }
  @doc "Find a fresh, nonrevoked source-selected ID under the algorithm allowlist."
  @spec lookup(t(), binary(), [RequestSeal.Crypto.algorithm()]) :: {:ok, Resolution.t()} | :error
  def lookup(set, keyid, algorithms),
    do: lookup_at(set, keyid, algorithms, System.system_time(:second))

  @doc false
  def lookup_at(%__MODULE__{} = set, keyid, algorithms, now) do
    Source.validate!(set.source)

    with true <- Source.key_id?(set.source, keyid),
         true <-
           is_list(algorithms) and length(algorithms) in 1..64 and
             Enum.all?(algorithms, &SignatureFields.algorithm?/1),
         true <- is_integer(now) and is_integer(set.expires_at) and now < set.expires_at,
         {:ok, %Resolution{} = entry} <- Map.fetch(set.keys, keyid),
         true <- identity?(set.source, entry, keyid) and now < entry.expires_at,
         false <- entry.thumbprint in set.source.revoked,
         {:ok, thumbprint} <- PublicKey.thumbprint(entry.key),
         true <- thumbprint == entry.thumbprint,
         algorithm when algorithm != nil <- Enum.find(algorithms, &compatible?(entry, &1)) do
      {:ok, %{entry | algorithm: algorithm, revision: set.revision}}
    else
      _ -> :error
    end
  rescue
    _ -> :error
  catch
    _, _ -> :error
  end

  def lookup_at(_, _, _, _), do: :error

  defp identity?(%Source{key_id: :thumbprint}, entry, keyid),
    do: entry.thumbprint == keyid and entry.key_id in [nil, keyid]

  defp identity?(%Source{key_id: :directory}, entry, keyid), do: entry.key_id == keyid

  defp compatible?(entry, algorithm) do
    PublicKey.bind!(entry.key, Algorithm.resolve(algorithm))
    entry.asserted_algorithm in [nil, algorithm]
  catch
    _, _ -> false
  end
end
