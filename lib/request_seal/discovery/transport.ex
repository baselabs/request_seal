defmodule RequestSeal.Discovery.Transport do
  # SSL is optional: the consuming application declares and starts it.
  @compile {:no_warn_undefined, :ssl}
  @moduledoc false
  alias RequestSeal.Discovery.{Address, Source, Support}
  import Support, only: [ensure: 2]

  def connect(uri, source, deadline) do
    ensure(
      Enum.any?(Application.started_applications(), &(elem(&1, 0) == :ssl)),
      :transport_unavailable
    )

    host = uri |> Source.origin() |> URI.parse() |> Map.fetch!(:host) |> String.to_charlist()
    addresses = resolve(host, deadline)
    # Validate the complete DNS answer before trying any address. Connect only
    # by tuple: another DNS lookup cannot replace the vetted destination.
    ensure(
      Enum.all?(addresses, &Address.allowed?(&1, source.permitted_addresses)),
      :address_denied
    )

    roots =
      try do
        if source.cacerts == :os, do: :public_key.cacerts_get(), else: source.cacerts
      rescue
        _ -> ensure(false, :tls_failed)
      end

    opts = [
      active: false,
      mode: :binary,
      verify: :verify_peer,
      cacerts: roots,
      server_name_indication: host,
      customize_hostname_check: [match_fun: :public_key.pkix_verify_hostname_match_fun(:https)],
      versions: [:"tlsv1.3", :"tlsv1.2"],
      log_level: :none,
      depth: 10
    ]

    attempt(addresses, uri.port, opts, source, deadline, :connect_failed)
  end

  defp resolve(host, deadline) do
    answers =
      Enum.map([:inet6, :inet], fn family ->
        :inet.getaddrs(host, family, Support.remaining(deadline))
      end)

    ensure(not Enum.any?(answers, &match?({:error, :timeout}, &1)), :deadline_exceeded)

    addresses =
      Enum.flat_map(answers, fn
        {:ok, addresses} -> addresses
        _ -> []
      end)
      |> Enum.uniq()

    ensure(addresses != [] and length(addresses) <= 64, :resolution_failed)
    addresses
  end

  defp attempt([], _, _, _, _, reason), do: ensure(false, reason)

  defp attempt([ip | rest], port, opts, source, deadline, reason) do
    family = if tuple_size(ip) == 8, do: :inet6, else: :inet

    case :ssl.connect(ip, port, [family | opts], Support.remaining(deadline)) do
      {:ok, socket} ->
        try do
          {:ok, {peer, ^port}} = :ssl.peername(socket)

          ensure(
            peer == ip and Address.allowed?(peer, source.permitted_addresses),
            :address_denied
          )

          socket
        catch
          kind, error ->
            :ssl.close(socket)
            :erlang.raise(kind, error, __STACKTRACE__)
        end

      {:error, :timeout} ->
        ensure(false, :deadline_exceeded)

      {:error, failure} ->
        error =
          if failure in [:econnrefused, :enetunreach, :ehostunreach, :closed, :eaddrnotavail],
            do: reason,
            else: :tls_failed

        attempt(rest, port, opts, source, deadline, error)
    end
  end
end
