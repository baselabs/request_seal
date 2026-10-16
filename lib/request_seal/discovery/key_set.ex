defmodule RequestSeal.Discovery.KeySet do
  @moduledoc """
  Bounded source-bound public keys, freshness and directory proof status.

  `revision` is SHA-256 over the fetched JSON bytes, not an origin-assigned sequence.
  Default IDs are computed RFC thumbprints; directory-assigned IDs never replace
  cryptographic identity or thumbprint revocation. Key restrictions remain
  enforced by `RequestSeal.PublicKey`. The cache's `:clock` supports
  caller-controlled time for resolution and fetching. `etag` is the source's
  ETag validator, if it sent one; the cache revalidates conditionally with it.
  """
  alias RequestSeal.{PublicKey, SignatureFields}
  alias RequestSeal.Crypto.Algorithm
  alias RequestSeal.Discovery.{Source, Resolution}
  @derive {Inspect, only: [:fetched_at, :expires_at, :proof]}
  defstruct [:source, :origin, :keys, :fetched_at, :expires_at, :revision, :proof, :etag]

  @type t :: %__MODULE__{
          source: Source.t(),
          origin: binary(),
          keys: %{binary() => Resolution.t()},
          fetched_at: integer(),
          expires_at: integer(),
          revision: binary(),
          proof: :signed | :unsigned | :not_applicable,
          etag: binary() | nil
        }
  @doc """
  Find a fresh, nonrevoked key by its source-selected ID under an algorithm allowlist.

  Lookup uses system time. It revalidates the set's source, recomputes the key's
  thumbprint, and rejects stale, revoked, incompatible or malformed entries.

  ## Parameters

    * `set` - a `RequestSeal.Discovery.KeySet`, normally from
      `RequestSeal.Discovery.fetch/2`.
    * `keyid` - an ID under the source's `key_id` mode: an RFC 7638 thumbprint
      (43 base64url characters) by default, or a directory-assigned ID of 1–256
      printable ASCII bytes with `key_id: :directory`.
    * `algorithms` - 1 to 64 algorithm identifiers accepted by a policy (the names
      in `RequestSeal.Crypto.algorithms/0` or `{:jws, name}` tuples). The first
      entry the key can use, and that matches any algorithm the source asserted,
      is selected.

  ## Returns

    * `{:ok, %RequestSeal.Discovery.Resolution{}}` - the entry with `algorithm`
      set to the selected algorithm and `revision` set to the set's revision.
    * `:error` - the ID is malformed for the mode or absent; the set or entry has
      expired; the thumbprint is revoked by the source; no allowed algorithm fits
      the key; the source or allowlist is invalid; or `set` is not a key set.

  ## Examples

  A key set normally comes from `RequestSeal.Discovery.fetch/2`; this example
  builds one from a locally generated Ed25519 key so it runs offline.

      iex> {public, _private} = :crypto.generate_key(:eddsa, :ed25519)
      iex> {:ok, key} =
      ...>   RequestSeal.PublicKey.import(
      ...>     %{"kty" => "OKP", "crv" => "Ed25519", "x" => Base.url_encode64(public, padding: false)},
      ...>     :jwk
      ...>   )
      iex> {:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
      iex> {:ok, source} =
      ...>   RequestSeal.Discovery.Source.new(%{type: :jwks_uri, location: "https://keys.example/jwks.json"})
      iex> entry = %RequestSeal.Discovery.Resolution{
      ...>   key: key,
      ...>   key_id: thumbprint,
      ...>   thumbprint: thumbprint,
      ...>   algorithm: "ed25519",
      ...>   origin: "https://keys.example",
      ...>   source_type: :jwks_uri,
      ...>   location: source.location,
      ...>   fetched_at: 0,
      ...>   expires_at: 253_402_300_799,
      ...>   proof: :not_applicable
      ...> }
      iex> set = %RequestSeal.Discovery.KeySet{
      ...>   source: source,
      ...>   origin: "https://keys.example",
      ...>   keys: %{thumbprint => entry},
      ...>   fetched_at: 0,
      ...>   expires_at: 253_402_300_799,
      ...>   revision: "example-revision",
      ...>   proof: :not_applicable
      ...> }
      iex> {:ok, resolution} =
      ...>   RequestSeal.Discovery.KeySet.lookup(set, thumbprint, ["ecdsa-p256-sha256", "ed25519"])
      iex> {resolution.algorithm, resolution.revision, resolution.thumbprint == thumbprint}
      {"ed25519", "example-revision", true}
      iex> RequestSeal.Discovery.KeySet.lookup(set, thumbprint, ["ecdsa-p256-sha256"])
      :error
      iex> RequestSeal.Discovery.KeySet.lookup(set, "unknown", ["ed25519"])
      :error
  """
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

    # Either allowlist spelling matches the source's normalized assertion; the
    # JOSE name comparison is total, including algorithms without an HTTP
    # identifier (PS256, PS384).
    entry.asserted_algorithm == nil or
      Algorithm.jose_id(entry.asserted_algorithm) == Algorithm.jose_id(algorithm)
  catch
    _, _ -> false
  end
end
