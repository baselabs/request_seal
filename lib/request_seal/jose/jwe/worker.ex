defmodule RequestSeal.JOSE.JWE.Worker do
  @moduledoc false
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Result}
  alias RequestSeal.KeyHandle

  def run(tag, parent, address, w, lo, hi, r, d, _mode) do
    :erlang.process_flag(:sensitive, true)
    try do
      {p, rows} = intake(tag, nil, [])
      positions = admit(:lists.reverse(rows), tag, parent, address, p, r, d, %{})
      loop(%{tag: tag, parent: parent, address: address, w: w, lo: lo, hi: hi,
        r: r, d: d, p: p, positions: positions, groups: %{}, routes: %{}})
    catch
      _, _ -> exit(:internal_failure)
    end
    exit(:normal)
  end

  defp intake(tag, p, rows) do
    receive do
      {^tag, :policy, policy} -> intake(tag, policy, rows)
      {^tag, :row, i, row} -> intake(tag, p, [{i, row} | rows])
      {^tag, :rows_done} -> {p, rows}
    end
  end

  defp admit([], _, _, _, _, _, _, positions), do: positions
  defp admit([{i, row} | rest], tag, parent, address, p, r, d, positions) do
    positions =
      if Bounds.before?(Bounds.now(), r) do
        result = case row do
          {:failed, error} -> {:error, error}
          {expected, split} -> Codec.admit(split, expected, p)
        end
        case result do
          {:ok, token} ->
            kind = if token.width_valid, do: :ready, else: :width_failed
            send(parent, {tag, :admitted, i, kind})
            position = %{token: token, fallback: nil, handle: nil, route: nil, group: nil}
            if kind == :width_failed do
              prepared = fallback(token)
              report(tag, parent, address, i, authenticate(token, prepared, :error, p), d)
              positions
            else
              :maps.put(i, position, positions)
            end
          {:error, error} ->
            send(parent, {tag, :admitted, i, {:error, error.reason, error.layer}})
            positions
        end
      else
        positions
      end
    admit(rest, tag, parent, address, p, r, d, positions)
  end

  defp loop(s) do
    s = expire(:maps.to_list(s.groups), s)
    tag = s.tag
    wait = nearest(:maps.to_list(s.groups), s.d)
    if Bounds.now() < s.d do
      receive do
        {^tag, :resolver, i, pid} ->
          case :maps.find(i, s.positions) do
            {:ok, position} ->
              t = position.token
              send(pid, {tag, :request, %{algorithm: t.alg, encryption: t.enc, header: t.h}, s.p.key_resolver})
            :error -> :ok
          end
          loop(s)
        # The producer validates and bounds the handle. No raw callback answer enters here.
        {^tag, :answer, i, {:ok, algorithm, %KeyHandle{} = handle, digest}}
        when is_binary(algorithm) and is_binary(digest) and byte_size(digest) == 32 ->
          loop(answer(s, i, {:ok, handle, digest}))
        {^tag, :answer, i, refusal} when is_atom(refusal) -> loop(answer(s, i, refusal))
        {^tag, :member, i, g, pid, u, count} -> loop(member(s, i, g, pid, u, count))
        {^tag, :group_summary, g, kind} -> loop(close(s, g, kind))
        {route_tag, i, outcome} when is_reference(route_tag) ->
          loop(delivery(s, route_tag, i, outcome))
        _ -> loop(s)
      after
        Bounds.remaining(wait) -> loop(s)
      end
    end
  end

  defp answer(s, i, answer) do
    case :maps.find(i, s.positions) do
      {:ok, position} ->
        if Bounds.before?(Bounds.now(), s.r) and position.fallback == nil do
          prepared = fallback(position.token)
          case {prepared, answer} do
            {{:ok, _}, {:ok, handle, digest}} ->
              {route, routes} = case :maps.find(digest, s.routes) do
                {:ok, route} -> {route, s.routes}
                :error ->
                  route = {:erlang.alias(), make_ref()}
                  {route, :maps.put(digest, route, s.routes)}
              end
              send(s.parent, {s.tag, :resolved, i, {:ok, digest}})
              %{s | positions: :maps.put(i, %{position | handle: handle, fallback: prepared, route: route}, s.positions), routes: routes}
            {{:error, error}, _} ->
              send(s.parent, {s.tag, :resolved, i, {:error, error.reason, error.layer}})
              %{s | positions: :maps.remove(i, s.positions)}
            {_, refusal} when refusal in [:unknown_key, :algorithm_mismatch, :key_resolver_failed] ->
              send(s.parent, {s.tag, :resolved, i, {:error, refusal, :key}})
              %{s | positions: :maps.remove(i, s.positions)}
            _ ->
              send(s.parent, {s.tag, :resolved, i, :refused})
              report(s.tag, s.parent, s.address, i, authenticate(position.token, prepared, :error, s.p), s.d)
              %{s | positions: :maps.remove(i, s.positions)}
          end
        else
          s
        end
      :error -> s
    end
  end

  defp member(s, i, g, pid, u, count) do
    case :maps.find(i, s.positions) do
      {:ok, position} ->
        group = :maps.get(g, s.groups, %{pid: pid, u: u, count: count, members: [], sent: false, route: position.route})
        group = %{group | members: [i | group.members]}
        position = %{position | group: g}
        s = %{s | positions: :maps.put(i, position, s.positions)}
        if length(group.members) == count and not group.sent do
          contributions = contributions(group.members, s.positions, [])
          handle = if same_handles?(group.members, s.positions, position.handle), do: position.handle, else: nil
          if pid != nil and Bounds.now() < u,
            do: send(pid, {s.tag, :contribution, g, s.w, handle, contributions, self()})
          %{s | groups: :maps.put(g, %{group | sent: true}, s.groups)}
        else
          %{s | groups: :maps.put(g, group, s.groups)}
        end
      :error -> s
    end
  end

  defp same_handles?([], _, _), do: true
  defp same_handles?([i | rest], positions, handle),
    do: :erlang.map_get(:handle, :maps.get(i, positions)) === handle and same_handles?(rest, positions, handle)

  defp contributions([], _, acc), do: acc
  defp contributions([i | rest], positions, acc) do
    p = :maps.get(i, positions)
    t = p.token
    item = {i, t.ek, t.params, Codec.width(t.enc) * 8}
    contributions(rest, positions, [{i, item, p.route} | acc])
  end

  defp delivery(s, route_tag, i, outcome) do
    case :maps.find(i, s.positions) do
      {:ok, %{route: {_, ^route_tag}, group: g} = position} when g != nil ->
        group = :maps.get(g, s.groups)
        if Bounds.now() < group.u do
          finish_position(s, i, position, outcome)
        else
          close(s, g, :timeout)
        end
      _ -> s
    end
  end

  defp close(s, g, kind) do
    case :maps.take(g, s.groups) do
      {group, groups} ->
        kind = if Bounds.now() >= group.u, do: :timeout, else: kind
        revoke(group.route)
        finish_members(group.members, %{s | groups: groups}, kind)
      :error -> s
    end
  end

  defp revoke({address, tag}) do
    :erlang.unalias(address)
    drain(tag)
  end

  defp drain(tag) do
    receive do
      {^tag, _, _} -> drain(tag)
    after
      0 -> :ok
    end
  end

  defp finish_members([], s, _), do: s
  defp finish_members([i | rest], s, kind) do
    s = case :maps.find(i, s.positions) do
      {:ok, position} -> finish_position(s, i, position, kind)
      :error -> s
    end
    finish_members(rest, s, kind)
  end

  defp finish_position(s, i, position, outcome) do
    report(s.tag, s.parent, s.address, i, authenticate(position.token, position.fallback, outcome, s.p), s.d)
    %{s | positions: :maps.remove(i, s.positions)}
  end

  defp expire([], s), do: s
  defp expire([{g, group} | rest], s) do
    s = if Bounds.now() >= group.u, do: close(s, g, :timeout), else: s
    expire(rest, s)
  end
  defp nearest([], d), do: d
  defp nearest([{_, group} | rest], d), do: nearest(rest, min(d, group.u))

  def fallback(token) do
    width = Codec.width(token.enc)
    try do
      {:ok, :crypto.strong_rand_bytes(width)}
    catch
      _, _ -> Codec.error(:entropy_failure, :crypto)
    end
  end

  def authenticate(_, {:error, _} = error, _, _), do: {error, nil}
  def authenticate(token, {:ok, prepared}, delivery, p) do
    {plaintext, success} = aead(token, prepared, delivery)
    if is_binary(plaintext) and success do
      object = if p.content == :object, do: Codec.object(plaintext, p.max_plaintext), else: {:ok, nil}
      case object do
        {:ok, object} ->
          {{:ok, %Result{algorithm: token.alg, encryption: token.enc, header: token.h,
             protected: token.protected, plaintext: plaintext, object: object}}, :ok}
        error -> {error, :ok}
      end
    else
      {Codec.error(:decryption_failed, :crypto), :failed}
    end
  end

  defp aead(token, prepared, delivery) do
    {key, success} = case delivery do
      {:ok, key} when is_binary(key) and byte_size(key) == byte_size(prepared) and token.width_valid -> {key, true}
      _ -> {prepared, false}
    end
    cipher = Codec.cipher(token.enc)
    iv = token.iv
    ct = token.ct
    protected = token.protected
    tag = token.tag
    try do
      {:crypto.crypto_one_time_aead(cipher, key, iv, ct, protected, tag, false), success}
    catch
      _, _ -> {nil, false}
    end
  end

  defp report(tag, parent, address, i, {result, auth}, d) do
    if Bounds.now() < d do
      case result do
        {:ok, payload} ->
          send(address, {tag, :payload, i, payload})
          send(parent, {tag, :result, i, :ok, :crypto, auth})
        {:error, error} -> send(parent, {tag, :result, i, error.reason, error.layer, auth})
      end
    end
  end
end
