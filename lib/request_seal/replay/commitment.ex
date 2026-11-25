defmodule RequestSeal.Replay.Commitment do
  @moduledoc """
  Deterministic replay commitments over authenticated values and trusted scope.

  The 32-byte result identifies one nonce or operation inside a replay namespace.
  Use credential or principal scope to keep the same boundary across key rotation.
  A caller-supplied symmetric identity identifies key material within the
  caller's trust domain. The wire key ID and signature label establish neither
  kind of identity. This module derives bytes. Verification and atomic admission
  are separate operations.
  """

  alias RequestSeal.{Custody, KeyHandle, KeyIdentity, PublicKey, SignatureFields}
  alias RequestSeal.Replay.{Claim, Store}

  @type scope ::
          {:principal, binary()}
          | {:credential, atom(), binary()}
          | {:key, KeyIdentity.t()}
  @type identity :: {:nonce, binary()} | {:operation, [{binary(), binary()}]}

  @doc """
  Derive a commitment for the generic RFC 9421 profile.

  Scopes are framed separately from the identity. Operation pairs use exact
  serialized signature-base identifiers and values, ordered by the policy.
  Each identifier must be canonical and unique. Identifiers and values are
  framed separately.
  Returns `{:error, :ambiguous_replay_scope}` for unusable scopes and
  `{:error, :missing_replay_identifier}` for absent or malformed identity.
  """
  @spec key(scope(), identity()) ::
          {:ok, <<_::256>>} | {:error, :ambiguous_replay_scope | :missing_replay_identifier}
  def key(scope, identity), do: derive("rfc9421", scope_bytes(scope), identity)

  @doc false
  def quorum_key(scope, identity),
    do: derive("rfc9421/quorum", quorum_scope_bytes(scope), identity)

  defp derive(profile, scope, identity) do
    with {:ok, scoped} <- scope,
         {:ok, identified} <- identity_bytes(identity) do
      {:ok, digest("request-seal replay v1", [profile, scoped, identified])}
    end
  end

  @doc false
  def digest(domain, parts), do: :crypto.hash(:sha256, [domain, frame(parts)])

  @doc false
  def frame(parts), do: Enum.map(parts, &[<<byte_size(&1)::unsigned-big-32>>, &1])

  @doc false
  def policy?(replay, components, freshness) do
    settings?(replay) and replay.scope in [:credential, :principal, :key] and
      (replay.identifier == :nonce or operation?(replay.identifier, components)) and
      is_map(freshness) and (freshness.require_expires or freshness.max_age != nil)
  end

  @doc false
  def settings?(
        %{
          identifier: _,
          scope: _,
          namespace: namespace,
          store: store,
          timeout: timeout,
          retain_until: retain_until
        } = replay
      ) do
    map_size(replay) == 6 and Claim.bounded?(namespace) and Store.valid?(store) and
      is_integer(timeout) and timeout in 1..300_000 and
      is_integer(retain_until) and retain_until in 1..253_402_300_799
  end

  def settings?(_), do: false

  @doc false
  def operation?({:operation, ids}, components) when is_list(ids) do
    with true <- length(ids) in 1..64 and length(ids) == length(Enum.uniq(ids)),
         {:ok, input} <- SignatureFields.inner(components),
         {:ok, covered} <- SignatureFields.identifiers(input.value) do
      Enum.all?(ids, &(&1 in covered and stable_component?(&1)))
    else
      _ -> false
    end
  rescue
    ArgumentError -> false
  end

  def operation?(_, _), do: false

  @doc false
  def select({:operation, ids}, _params, components),
    do: {:operation, Enum.map(ids, &List.keyfind(components, &1, 0))}

  def select(:nonce, params, _components), do: {:nonce, params["nonce"]}

  @doc false
  def key_identity(%PublicKey{material: material}),
    do: {:ok, %KeyIdentity{kind: :public, value: KeyIdentity.normalize(material)}}

  def key_identity(%KeyHandle{} = key), do: Custody.identity(key)

  defp stable_component?(id) do
    not Enum.any?([~s["signature"], ~s["signature-input"]], fn name ->
      id == name or String.starts_with?(id, name <> ";")
    end)
  end

  defp scope_bytes({:principal, principal})
       when is_binary(principal) and byte_size(principal) in 1..256,
       do: {:ok, ["principal", frame([principal])] |> IO.iodata_to_binary()}

  defp scope_bytes({:credential, purpose, credential})
       when is_atom(purpose) and purpose not in [true, false] and
              is_binary(credential) and byte_size(credential) in 1..256 do
    binding = if purpose == nil, do: <<0>>, else: <<1>> <> Atom.to_string(purpose)
    {:ok, IO.iodata_to_binary(["credential", frame([binding, credential])])}
  end

  defp scope_bytes({:key, %KeyIdentity{kind: :public, value: material} = identity})
       when map_size(identity) == 3 do
    with {:ok, key} <- PublicKey.import(material, :raw),
         {:ok, thumbprint} <- PublicKey.thumbprint(key) do
      {:ok, IO.iodata_to_binary(["key", frame(["public", thumbprint])])}
    else
      _ -> {:error, :ambiguous_replay_scope}
    end
  end

  defp scope_bytes({:key, %KeyIdentity{kind: :symmetric, value: value} = identity})
       when map_size(identity) == 3 and is_binary(value) and byte_size(value) in 1..256,
       do: {:ok, IO.iodata_to_binary(["key", frame(["symmetric", value])])}

  defp scope_bytes(_), do: {:error, :ambiguous_replay_scope}

  defp quorum_scope_bytes(:namespace), do: {:ok, "namespace"}

  defp quorum_scope_bytes({:principals, values}) when is_list(values) do
    with true <- length(values) in 1..16 and Enum.all?(values, &Claim.bounded?/1),
         principals = values |> Enum.uniq() |> Enum.sort() do
      {:ok, IO.iodata_to_binary(["principals", frame(principals)])}
    else
      _ -> {:error, :ambiguous_replay_scope}
    end
  rescue
    ArgumentError -> {:error, :ambiguous_replay_scope}
  end

  defp quorum_scope_bytes(_), do: {:error, :ambiguous_replay_scope}

  defp identity_bytes({:nonce, nonce}) when is_binary(nonce) and byte_size(nonce) in 1..1024,
    do: {:ok, IO.iodata_to_binary(["nonce", frame([nonce])])}

  defp identity_bytes({:operation, pairs}) when is_list(pairs) do
    with true <- length(pairs) in 1..64,
         {:ok, parts} <- operation_parts(pairs, [], 0),
         ids = Enum.map(pairs, &elem(&1, 0)),
         {:ok, _} <- operation_components(ids) do
      {:ok, IO.iodata_to_binary(["operation", frame(parts)])}
    else
      _ -> {:error, :missing_replay_identifier}
    end
  rescue
    ArgumentError -> {:error, :missing_replay_identifier}
  end

  defp identity_bytes(_), do: {:error, :missing_replay_identifier}

  @doc false
  def operation_components(ids) do
    wire = IO.iodata_to_binary(["(", Enum.intersperse(ids, " "), ")"])

    with {:ok, input} <- SignatureFields.inner(wire),
         true <- input.parameters == [],
         {:ok, ^ids} <- SignatureFields.identifiers(input.value),
         true <- Enum.all?(ids, &stable_component?/1) do
      {:ok, input.value}
    else
      _ -> :error
    end
  end

  defp operation_parts([], acc, _), do: {:ok, Enum.reverse(acc)}

  defp operation_parts([{id, value} | rest], acc, bytes)
       when is_binary(id) and byte_size(id) in 3..65_536 and is_binary(value) and
              bytes + byte_size(id) + byte_size(value) <= 1_048_576 do
    operation_parts(rest, [value, id | acc], bytes + byte_size(id) + byte_size(value))
  end

  defp operation_parts(_, _, _), do: :error
end
