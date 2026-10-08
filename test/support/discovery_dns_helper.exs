# A real authoritative DNS publisher for a controlled test zone, isolated in its
# own BEAM so resolver configuration cannot affect another test or application.
Code.require_file("discovery_peer_helper.exs", __DIR__)
ExUnit.start()

defmodule RequestSeal.DiscoveryDNSTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Discovery
  alias RequestSeal.Discovery.{Source, Address}
  alias RequestSeal.DiscoveryPeer, as: Peer

  test "vetted tuple connects and both-family DNS changes fail closed" do
    owner = self()

    {:ok, records} =
      Agent.start_link(fn -> %{a: {127, 0, 0, 1}, aaaa: {0, 0, 0, 0, 0, 0, 0, 1}} end)

    {:ok, udp} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    {:ok, {_, port}} = :inet.sockname(udp)
    dns = spawn(fn -> serve(udp, records, owner) end)
    :ok = :gen_udp.controlling_process(udp, dns)

    on_exit(fn ->
      :gen_udp.close(udp)
      Process.exit(dns, :kill)
    end)

    :ok = :inet_db.set_resolv_conf(~c"")
    :ok = :inet_db.res_option(:nameservers, [{{127, 0, 0, 1}, port}])
    :ok = :inet_db.set_lookup([:dns])

    p =
      Peer.start(
        fn socket, _ ->
          Peer.reply(socket, Peer.directory(), [
            {"Content-Type", "application/http-message-signatures-directory+json"}
          ])
        end,
        ~c"directory.test"
      )

    on_exit(fn -> Peer.stop(p) end)

    {:ok, source} =
      Source.new(%{
        type: :directory,
        location: "https://directory.test:#{p.port}",
        cacerts: p.cacerts,
        permitted_addresses: [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}],
        require_signed_directory: false
      })

    assert {:ok, _} = Discovery.fetch(source, [])
    assert_receive {:dns_query, :aaaa}, 1_000
    assert_receive {:dns_query, :a}, 1_000
    assert_receive {:accepted, _}, 1_000
    refute_receive {:dns_query, _}, 50
    # The name now points to a private metadata address. A fresh lookup cannot
    # reuse the previous positive tuple; the entire answer is rejected.
    Agent.update(records, &%{&1 | a: {169, 254, 169, 254}})
    assert {:error, %{reason: :address_denied}} = Discovery.fetch(source, [])
    assert_receive {:dns_query, :aaaa}, 1_000
    assert_receive {:dns_query, :a}, 1_000
    refute_receive {:accepted, _}, 50
    # Positive recovery proves the instrument still reaches the real publisher.
    Agent.update(records, &%{&1 | a: {127, 0, 0, 1}})
    assert {:ok, _} = Discovery.fetch(source, [])
    assert_receive {:accepted, _}, 1_000
    refute Address.allowed?({169, 254, 169, 254}, source.permitted_addresses)

    IO.puts(
      "DNS rebinding: both families vetted; denied rebind rejected; tuple connect reached configured TLS publisher"
    )
  end

  defp serve(socket, records, owner) do
    case :gen_udp.recv(socket, 0, 5_000) do
      {:ok, {ip, port, bytes}} ->
        {:ok, msg} = :inet_dns.decode(bytes)
        [query] = :inet_dns.msg(msg, :qdlist)
        name = :inet_dns.dns_query(query, :domain)
        type = :inet_dns.dns_query(query, :type)
        send(owner, {:dns_query, type})
        data = Agent.get(records, &Map.get(&1, type))

        answers =
          if data,
            do: [:inet_dns.make_rr(domain: name, type: type, class: :in, ttl: 0, data: data)],
            else: []

        header = :inet_dns.make_header(:inet_dns.msg(msg, :header), qr: true, aa: true, rcode: 0)
        response = :inet_dns.make_msg(msg, header: header, anlist: answers) |> :inet_dns.encode()
        :ok = :gen_udp.send(socket, ip, port, response)
        serve(socket, records, owner)

      _ ->
        :ok
    end
  end
end
