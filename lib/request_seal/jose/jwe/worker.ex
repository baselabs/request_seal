defmodule RequestSeal.JOSE.JWE.Worker do
  @moduledoc false
  import :erlang, only: [map_get: 2]
  alias RequestSeal.JOSE.JWE.{Bounds, Codec, Result}
  alias RequestSeal.KeyHandle

  def run(tag, parent, address, w, lo, hi, r, d, _mode) do
    :erlang.process_flag(:sensitive, true)

    try do
      {p, rows} = intake(tag, nil, [])
      positions = admit(:lists.reverse(rows), tag, parent, address, p, r, d, %{})

      loop(%{
        tag: tag,
        parent: parent,
        address: address,
        w: w,
        lo: lo,
        hi: hi,
        r: r,
        d: d,
        p: p,
        positions: positions,
        groups: %{},
        u: nil,
        routes: %{}
      })
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
        result =
          case row do
            {:failed, error} -> {:error, error}
            {expected, split} -> Codec.admit(split, expected, p)
          end

        case result do
          {:ok, token} ->
            kind = if map_get(:width_valid, token), do: :ready, else: :width_failed
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
            failure = {:error, map_get(:reason, error), map_get(:layer, error)}
            send(parent, {tag, :admitted, i, failure})
            positions
        end
      else
        positions
      end

    admit(rest, tag, parent, address, p, r, d, positions)
  end

  defp loop(s) do
    s = expire(s)
    tag = map_get(:tag, s)
    wait = if map_get(:u, s) == nil, do: map_get(:d, s), else: min(map_get(:d, s), map_get(:u, s))

    # A settled range has no remaining delivery or authentication work. Return
    # before the coordinator drains notices and replies: its exit/link phase
    # must not be the event that finally releases every empty worker.
    if map_size(map_get(:positions, s)) > 0 and Bounds.now() < map_get(:d, s) do
      receive do
        {^tag, :resolver, i, pid} ->
          case :maps.find(i, map_get(:positions, s)) do
            {:ok, position} ->
              t = map_get(:token, position)

              request = %{
                algorithm: map_get(:alg, t),
                encryption: map_get(:enc, t),
                header: map_get(:h, t)
              }

              send(pid, {tag, :request, request, map_get(:key_resolver, map_get(:p, s))})

            :error ->
              :ok
          end

          loop(s)

        # The producer validates and bounds the handle. No raw callback answer enters here.
        {^tag, :answer, i, {:ok, algorithm, %KeyHandle{} = handle, digest}}
        when is_binary(algorithm) and is_binary(digest) and byte_size(digest) == 32 ->
          loop(answer(s, i, {:ok, handle, digest}))

        {^tag, :answer, i, refusal} when is_atom(refusal) ->
          loop(answer(s, i, refusal))

        {^tag, :member, i, g, pid, u, count} ->
          loop(member(s, i, g, pid, u, count))

        {^tag, :unwrap_expired, u} ->
          loop(%{s | u: u})

        {^tag, :group_summary, g, kind} ->
          loop(close(s, g, kind))

        {route_tag, i, outcome} when is_reference(route_tag) ->
          loop(delivery(s, route_tag, i, outcome))

        _ ->
          loop(s)
      after
        Bounds.remaining(wait) -> loop(s)
      end
    end
  end

  defp answer(s, i, answer) do
    case :maps.find(i, map_get(:positions, s)) do
      {:ok, position} ->
        if Bounds.before?(Bounds.now(), map_get(:r, s)) and map_get(:fallback, position) == nil do
          prepared = fallback(map_get(:token, position))

          case {prepared, answer} do
            {{:ok, _}, {:ok, handle, digest}} ->
              {route, routes} =
                case :maps.find(digest, map_get(:routes, s)) do
                  {:ok, route} ->
                    {route, map_get(:routes, s)}

                  :error ->
                    route = {:erlang.alias(), make_ref()}
                    {route, :maps.put(digest, route, map_get(:routes, s))}
                end

              send(map_get(:parent, s), {map_get(:tag, s), :resolved, i, {:ok, digest}})

              %{
                s
                | positions:
                    :maps.put(
                      i,
                      %{position | handle: handle, fallback: prepared, route: route},
                      map_get(:positions, s)
                    ),
                  routes: routes
              }

            {{:error, error}, _} ->
              failure = {:error, map_get(:reason, error), map_get(:layer, error)}
              send(map_get(:parent, s), {map_get(:tag, s), :resolved, i, failure})
              %{s | positions: :maps.remove(i, map_get(:positions, s))}

            {_, refusal}
            when refusal in [:unknown_key, :algorithm_mismatch, :key_resolver_failed] ->
              send(map_get(:parent, s), {map_get(:tag, s), :resolved, i, {:error, refusal, :key}})
              %{s | positions: :maps.remove(i, map_get(:positions, s))}

            _ ->
              send(map_get(:parent, s), {map_get(:tag, s), :resolved, i, :refused})

              report(
                map_get(:tag, s),
                map_get(:parent, s),
                map_get(:address, s),
                i,
                authenticate(map_get(:token, position), prepared, :error, map_get(:p, s)),
                map_get(:d, s)
              )

              %{s | positions: :maps.remove(i, map_get(:positions, s))}
          end
        else
          s
        end

      :error ->
        s
    end
  end

  defp member(s, i, g, pid, u, count) do
    case :maps.find(i, map_get(:positions, s)) do
      {:ok, position} ->
        group =
          :maps.get(g, map_get(:groups, s), %{
            pid: pid,
            u: u,
            count: count,
            received: 0,
            members: [],
            sent: false,
            route: map_get(:route, position)
          })

        group = %{
          group
          | members: [i | map_get(:members, group)],
            received: map_get(:received, group) + 1
        }

        position = %{position | group: g}

        s = %{
          s
          | positions: :maps.put(i, position, map_get(:positions, s)),
            u: u
        }

        if map_get(:received, group) == count and not map_get(:sent, group) do
          members = map_get(:members, group)
          positions = map_get(:positions, s)
          contributions = contributions(members, positions, [])

          handle =
            if same_handles?(members, positions, map_get(:handle, position)),
              do: map_get(:handle, position),
              else: nil

          if pid != nil and Bounds.now() < u do
            send(
              pid,
              {map_get(:tag, s), :contribution, g, map_get(:w, s), handle, contributions, self()}
            )
          end

          %{s | groups: :maps.put(g, %{group | sent: true}, map_get(:groups, s))}
        else
          %{s | groups: :maps.put(g, group, map_get(:groups, s))}
        end

      :error ->
        s
    end
  end

  defp same_handles?([], _, _), do: true

  defp same_handles?([i | rest], positions, handle),
    do:
      map_get(:handle, :maps.get(i, positions)) === handle and
        same_handles?(rest, positions, handle)

  defp contributions([], _, acc), do: acc

  defp contributions([i | rest], positions, acc) do
    p = :maps.get(i, positions)
    t = map_get(:token, p)
    item = {i, map_get(:ek, t), map_get(:params, t), Codec.width(map_get(:enc, t)) * 8}
    contributions(rest, positions, [{i, item, map_get(:route, p)} | acc])
  end

  defp delivery(s, route_tag, i, outcome) do
    case :maps.find(i, map_get(:positions, s)) do
      {:ok, %{route: {_, ^route_tag}, group: g} = position} when g != nil ->
        group = :maps.get(g, map_get(:groups, s))

        if Bounds.now() < map_get(:u, group) do
          finish_position(s, i, position, outcome)
        else
          close(s, g, :timeout)
        end

      _ ->
        s
    end
  end

  defp close(s, g, kind) do
    case :maps.take(g, map_get(:groups, s)) do
      {group, groups} ->
        kind = if Bounds.now() >= map_get(:u, group), do: :timeout, else: kind
        revoke(map_get(:route, group))
        finish_members(map_get(:members, group), %{s | groups: groups}, kind)

      :error ->
        s
    end
  end

  # The main receive discards queued outcomes for removed positions. A receive
  # per revoked route would rescan the remaining mailbox once for every group.
  defp revoke({address, _tag}), do: :erlang.unalias(address)

  defp finish_members([], s, _), do: s

  defp finish_members([i | rest], s, kind) do
    s =
      case :maps.find(i, map_get(:positions, s)) do
        {:ok, position} -> finish_position(s, i, position, kind)
        :error -> s
      end

    finish_members(rest, s, kind)
  end

  defp finish_position(s, i, position, outcome) do
    report(
      map_get(:tag, s),
      map_get(:parent, s),
      map_get(:address, s),
      i,
      authenticate(
        map_get(:token, position),
        map_get(:fallback, position),
        outcome,
        map_get(:p, s)
      ),
      map_get(:d, s)
    )

    %{s | positions: :maps.remove(i, map_get(:positions, s))}
  end

  # Every group in a call shares the coordinator's one U. Check it in constant
  # time between messages, then visit each remaining group once at expiry.
  defp expire(%{u: nil} = s), do: s

  defp expire(s) do
    if Bounds.now() >= map_get(:u, s) do
      expire_routes(:maps.to_list(map_get(:routes, s)))
      rows = :maps.to_list(map_get(:positions, s))
      # Authentication needs the rows and policy, not the revoked group/route
      # maps or the original position HAMT. Do not keep them live across AEAD.
      s = %{s | groups: %{}, positions: %{}, routes: %{}, u: nil}
      positions = expire_positions(rows, s, [])
      %{s | positions: :maps.from_list(positions)}
    else
      s
    end
  end

  defp expire_routes([]), do: :ok

  defp expire_routes([{_, route} | rest]) do
    revoke(route)
    expire_routes(rest)
  end

  # All groups have the same U. A prepared position may still have its member
  # message queued. Settle it now as well, so those late messages cannot cause
  # another full expiry pass or grant a new delivery window.
  defp expire_positions([], _, positions), do: positions

  defp expire_positions([{i, position} | rest], s, positions) do
    positions =
      if map_get(:fallback, position) == nil do
        [{i, position} | positions]
      else
        report(
          map_get(:tag, s),
          map_get(:parent, s),
          map_get(:address, s),
          i,
          authenticate(
            map_get(:token, position),
            map_get(:fallback, position),
            :timeout,
            map_get(:p, s)
          ),
          map_get(:d, s)
        )

        positions
      end

    expire_positions(rest, s, positions)
  end

  def fallback(token) do
    width = Codec.width(map_get(:enc, token))

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
      object =
        if map_get(:content, p) == :object,
          do: Codec.object(plaintext, map_get(:max_plaintext, p)),
          else: {:ok, nil}

      case object do
        {:ok, object} ->
          {{:ok,
            %Result{
              algorithm: map_get(:alg, token),
              encryption: map_get(:enc, token),
              header: map_get(:h, token),
              protected: map_get(:protected, token),
              plaintext: plaintext,
              object: object
            }}, :ok}

        error ->
          {error, :ok}
      end
    else
      {Codec.error(:decryption_failed, :crypto), :failed}
    end
  end

  defp aead(token, prepared, delivery) do
    {key, success} =
      case delivery do
        {:ok, key}
        when is_binary(key) and byte_size(key) == byte_size(prepared) and
               map_get(:width_valid, token) ->
          {key, true}

        _ ->
          {prepared, false}
      end

    cipher = Codec.cipher(map_get(:enc, token))
    iv = map_get(:iv, token)
    ct = map_get(:ct, token)
    protected = map_get(:protected, token)
    tag = map_get(:tag, token)

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

        {:error, error} ->
          send(parent, {tag, :result, i, map_get(:reason, error), map_get(:layer, error), auth})
      end
    end
  end
end
