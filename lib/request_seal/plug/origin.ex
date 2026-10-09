if Code.ensure_loaded?(Plug.Conn) do
  defmodule RequestSeal.Plug.Origin do
    @moduledoc false
    import Bitwise
    alias RequestSeal.Adapter.Signing
    alias RequestSeal.Message.Validation

    def validate!(:connection), do: :ok

    def validate!({:declared, scheme, authority}) do
      Signing.ensure(
        Validation.scheme?(scheme) and Validation.authority?(authority),
        :invalid_options
      )
    end

    def validate!({:forwarded, %{trusted_peers: peers, field: field} = opts}) do
      Signing.ensure(
        map_size(opts) == 2 and field in [:forwarded, :x_forwarded] and is_list(peers) and
          length(peers) in 1..1024 and Enum.all?(peers, &cidr?/1),
        :invalid_options
      )
    end

    def validate!(_), do: Signing.fail(:invalid_options)

    def select!(conn, :connection) do
      normalized_host = String.downcase(conn.host, :ascii)

      host =
        if String.contains?(normalized_host, ":") and
             not String.starts_with?(normalized_host, "["),
           do: "[" <> normalized_host <> "]",
           else: normalized_host

      default_port? =
        (conn.scheme == :http and conn.port == 80) or
          (conn.scheme == :https and conn.port == 443)

      %{
        scheme: to_string(conn.scheme),
        authority: if(default_port?, do: host, else: host <> ":" <> Integer.to_string(conn.port)),
        source: :connection
      }
    end

    def select!(_, {:declared, scheme, authority}),
      do: %{scheme: scheme, authority: authority, source: :declared}

    def select!(conn, {:forwarded, %{trusted_peers: peers, field: field}}) do
      # Use the socket peer, not conn.remote_ip, which middleware may have rewritten.
      peer = Plug.Conn.get_peer_data(conn).address
      Signing.ensure(Enum.any?(peers, &contains?(&1, peer)), :untrusted_proxy)

      {scheme, authority} =
        case field do
          :forwarded -> forwarded!(conn)
          :x_forwarded -> x_forwarded!(conn)
        end

      Signing.ensure(
        Validation.scheme?(scheme) and Validation.authority?(authority),
        :invalid_request
      )

      %{scheme: scheme, authority: authority, source: :forwarded}
    end

    defp cidr?({ip, prefix}) do
      case address(ip) do
        {_, bits} -> is_integer(prefix) and prefix in 0..bits
        _ -> false
      end
    end

    defp cidr?(_), do: false

    defp address(ip) when is_tuple(ip) and tuple_size(ip) in [4, 8] do
      width = if tuple_size(ip) == 4, do: 8, else: 16

      if Enum.all?(Tuple.to_list(ip), &(is_integer(&1) and &1 >= 0 and &1 < 1 <<< width)) do
        {Enum.reduce(Tuple.to_list(ip), 0, fn part, n -> (n <<< width) + part end),
         tuple_size(ip) * width}
      end
    end

    defp address(_), do: nil

    @doc false
    def contains?({network, prefix}, ip) do
      case {address(network), address(ip)} do
        {{a, bits}, {b, bits}} ->
          a >>> (bits - prefix) == b >>> (bits - prefix)

        # A dual-stack socket represents an IPv4 peer in ::ffff:0:0/96.
        {{a, 32}, {b, 128}} when b >>> 32 == 0xFFFF ->
          a >>> (32 - prefix) == (b &&& 0xFFFFFFFF) >>> (32 - prefix)

        # Broad IPv6 ranges can contain mapped addresses without a mapped base.
        # Narrow mapped subnets retain their original IPv4 host-bit restrictions.
        {{a, 128}, {b, 32}} when prefix <= 96 or a >>> 32 == 0xFFFF ->
          a >>> (128 - prefix) == ((0xFFFF <<< 32) + b) >>> (128 - prefix)

        _ ->
          false
      end
    end

    defp values!(conn, name) do
      values = Plug.Conn.get_req_header(conn, name)

      Signing.ensure(
        values != [] and length(values) <= 1024 and
          Enum.reduce(values, 0, &(byte_size(&1) + &2)) <= 1_048_576,
        :invalid_request
      )

      Enum.join(values, ",")
    end

    defp forwarded!(conn) do
      elements = values!(conn, "forwarded") |> split!(?,)

      pairs =
        Enum.map(elements, fn e ->
          e
          |> split!(?;)
          |> Enum.reduce(%{}, fn p, acc ->
            case String.split(p, "=", parts: 2) do
              [name, value] ->
                name = String.downcase(String.trim(name))

                Signing.ensure(
                  Validation.token?(name, 256) and not Map.has_key?(acc, name),
                  :invalid_request
                )

                Map.put(acc, name, value!(String.trim(value)))

              _ ->
                Signing.fail(:invalid_request)
            end
          end)
        end)

      last = List.last(pairs)
      {Map.get(last, "proto"), Map.get(last, "host")}
    end

    defp x_forwarded!(conn) do
      schemes = values!(conn, "x-forwarded-proto") |> split!(?,)
      hosts = values!(conn, "x-forwarded-host") |> split!(?,)
      Signing.ensure(length(schemes) == length(hosts), :invalid_request)
      {List.last(schemes), List.last(hosts)}
    end

    defp value!("\"" <> rest) do
      Signing.ensure(String.ends_with?(rest, "\""), :invalid_request)
      inner = binary_part(rest, 0, byte_size(rest) - 1)
      decoded = unquote_value!(inner, []) |> Enum.reverse() |> IO.iodata_to_binary()
      Signing.ensure(decoded != "", :invalid_request)
      decoded
    end

    defp value!(token) do
      Signing.ensure(Validation.token?(token, 65_536), :invalid_request)
      token
    end

    defp unquote_value!("", acc), do: acc

    defp unquote_value!(<<"\\", char, rest::binary>>, acc) when char == 9 or char in 32..126,
      do: unquote_value!(rest, [<<char>> | acc])

    defp unquote_value!(<<char, rest::binary>>, acc)
         when char == 9 or char == 32 or char == 33 or char in 35..91 or char in 93..255,
         do: unquote_value!(rest, [<<char>> | acc])

    defp unquote_value!(_, _), do: Signing.fail(:invalid_request)

    # Linear scanner: separators inside quoted strings and quoted-pairs stay intact.
    defp split!(bytes, separator), do: split!(bytes, separator, false, false, [], [])

    defp split!("", _, false, false, parts, current) do
      Enum.reverse([part!(current) | parts])
    end

    defp split!("", _, _, _, _, _), do: Signing.fail(:invalid_request)

    defp split!(<<c, rest::binary>>, sep, quoted, escaped, parts, current) do
      cond do
        escaped -> split!(rest, sep, quoted, false, parts, [<<c>> | current])
        quoted and c == ?\\ -> split!(rest, sep, true, true, parts, [<<c>> | current])
        c == ?" -> split!(rest, sep, not quoted, false, parts, [<<c>> | current])
        c == sep and not quoted -> split!(rest, sep, false, false, [part!(current) | parts], [])
        true -> split!(rest, sep, quoted, false, parts, [<<c>> | current])
      end
    end

    defp part!(chars) do
      chars |> Enum.reverse() |> IO.iodata_to_binary() |> String.trim()
    end
  end
end
