defmodule RequestSeal.GuideCredentialProxyTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "every proxy fence executes with real custody and both outbound clients" do
    binding = []

    binding =
      E.eval(
        ~S'''
        directory = Path.join(System.tmp_dir!(), "requestseal-proxy-#{System.unique_integer([:positive])}")
        :ok = File.mkdir(directory)
        :ok = File.chmod(directory, 0o700)
        seed_file = Path.join(directory, "signing.seed")
        :ok = File.touch(seed_file)
        :ok = File.chmod(seed_file, 0o600)
        ''',
        binding,
        "docs/guides/credential-proxy.md",
        1
      )

    on_exit(fn -> File.rm_rf!(Keyword.fetch!(binding, :directory)) end)

    binding =
      E.eval(
        ~S'''
        {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
        :ok = File.write(seed_file, Base.url_encode64(seed, padding: false))
        children = [
          {RequestSeal.Custody.Local.Owner,
           name: CredentialProxyExample.Custody,
           keys: [outbound: {"ed25519", {:file, seed_file, :base64url}}]},
          {Finch, name: CredentialProxyExample.Finch}
        ]
        {:ok, supervisor} = Supervisor.start_link(children, strategy: :one_for_one)
        {:ok, handle} = RequestSeal.Custody.Local.Owner.fetch(CredentialProxyExample.Custody, :outbound)
        {:ok, key} = RequestSeal.Custody.public_key(handle)

        components = ~s[("@method" "@scheme" "@authority" "@path" "content-type" "content-digest")]
        signing = %{
          label: "sig", algorithm: "ed25519", components: components,
          expires_in: 60, keyid: "proxy-key", digest: ["sha-256"]
        }
        {:ok, policy} = RequestSeal.Policy.new(%{
          algorithms: ["ed25519"], components: components,
          key_resolver: fn
            %{keyid: "proxy-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
            _ -> :error
          end,
          freshness: %{
            clock: fn -> System.system_time(:second) end,
            max_age: 60, skew: 5, require_expires: true
          },
          content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
          replay: :not_required
        })
        ''',
        binding,
        "docs/guides/credential-proxy.md",
        2
      )

    on_exit(fn ->
      supervisor = Keyword.fetch!(binding, :supervisor)
      if Process.alive?(supervisor), do: Supervisor.stop(supervisor)
    end)

    assert RequestSeal.Custody.Local.Owner.ready?(CredentialProxyExample.Custody, :outbound)

    binding =
      E.eval(
        ~S'''
        defmodule CredentialProxyExample.Upstream do
          @behaviour Plug
          def init(options), do: options

          def call(%Plug.Conn{method: "POST", request_path: "/events", query_string: ""} = conn, options) do
            conn = RequestSeal.Plug.Capture.call(conn,
              RequestSeal.Plug.Capture.init(
                origin: :connection, max_body_bytes: 4096, read_timeout: 5_000))
            conn = RequestSeal.Plug.Verify.call(conn,
              RequestSeal.Plug.Verify.init(
                policy: options[:policy], label: "sig", on_reject: {:halt, 401}))

            if conn.halted do
              conn
            else
              {:ok, capture} = RequestSeal.Plug.capture(conn)
              Plug.Conn.send_resp(conn, 200, capture.message.body.bytes)
            end
          end

          def call(conn, _options), do: Plug.Conn.send_resp(conn, 404, "")
        end

        defmodule CredentialProxyExample.Proxy do
          @behaviour Plug
          def init(options), do: options

          def call(%Plug.Conn{method: "POST", path_info: ["forward", client], query_string: ""} = conn, options)
              when client in ["req", "finch"] do
            case Plug.Conn.read_body(conn, length: 4096, read_timeout: 5_000) do
              {:ok, body, conn} when byte_size(body) <= 4096 ->
                case RequestSeal.Custody.Local.Owner.fetch(options[:custody], :outbound) do
                  {:ok, handle} ->
                    case forward(client, body, handle, options) do
                      {:ok, %{status: status, body: bytes}} -> Plug.Conn.send_resp(conn, status, bytes)
                      {:error, _} -> Plug.Conn.send_resp(conn, 502, "upstream exchange failed")
                    end

                  {:error, _} ->
                    Plug.Conn.send_resp(conn, 503, "signing unavailable")
                end

              {:ok, _body, conn} -> Plug.Conn.send_resp(conn, 413, "")
              {:more, _body, conn} -> Plug.Conn.send_resp(conn, 413, "")
              {:error, _} -> Plug.Conn.send_resp(conn, 400, "")
            end
          end

          def call(conn, _options), do: Plug.Conn.send_resp(conn, 404, "")

          defp forward("req", body, handle, options) do
            request = Req.new(
              method: :post, url: options[:upstream], body: body,
              headers: [{"content-type", "application/octet-stream"}],
              finch: [name: CredentialProxyExample.Finch],
              retry: false, redirect: false, decode_body: false)

            with {:ok, request} <- RequestSeal.Req.attach(request,
                   sign: options[:signing], signer: handle, verify: :none) do
              Req.request(request)
            end
          end

          defp forward("finch", body, handle, options) do
            request = Finch.build(:post, options[:upstream],
              [{"content-type", "application/octet-stream"}], body)

            with {:ok, request} <- RequestSeal.Finch.sign(request, options[:signing], handle) do
              Finch.request(request, CredentialProxyExample.Finch)
            end
          end
        end
        ''',
        binding,
        "docs/guides/credential-proxy.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        {:ok, upstream_server} = Supervisor.start_child(supervisor,
          Supervisor.child_spec({Bandit,
            plug: {CredentialProxyExample.Upstream, policy: policy},
            ip: {127, 0, 0, 1}, port: 0, startup_log: false,
            http_options: [compress: false]}, id: :example_upstream))
        {:ok, {_, upstream_port}} = ThousandIsland.listener_info(upstream_server)
        upstream_url = "http://127.0.0.1:#{upstream_port}/events"

        {:ok, proxy_server} = Supervisor.start_child(supervisor,
          Supervisor.child_spec({Bandit,
            plug: {CredentialProxyExample.Proxy,
              custody: CredentialProxyExample.Custody, upstream: upstream_url, signing: signing},
            ip: {127, 0, 0, 1}, port: 0, startup_log: false,
            http_options: [compress: false]}, id: :example_proxy))
        {:ok, {_, proxy_port}} = ThousandIsland.listener_info(proxy_server)
        proxy_url = "http://127.0.0.1:#{proxy_port}"
        ''',
        binding,
        "docs/guides/credential-proxy.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        payload = <<0, 255, "exact proxy bytes\r\n", 0>>
        responses =
          for client <- ["req", "finch"] do
            request = Finch.build(:post, proxy_url <> "/forward/" <> client, [], payload)
            {:ok, response} = Finch.request(request, CredentialProxyExample.Finch)
            200 = response.status
            ^payload = response.body
            response
          end
        ''',
        binding,
        "docs/guides/credential-proxy.md",
        5
      )

    payload = Keyword.fetch!(binding, :payload)

    assert [%{status: 200, body: ^payload}, %{status: 200, body: ^payload}] =
             Keyword.fetch!(binding, :responses)

    upstream = Keyword.fetch!(binding, :upstream_url)

    unsigned =
      Finch.build(:post, upstream, [{"content-type", "application/octet-stream"}], payload)

    assert {:ok, %{status: 401}} = Finch.request(unsigned, CredentialProxyExample.Finch)

    assert {:ok, signed} =
             RequestSeal.Finch.sign(
               unsigned,
               Keyword.fetch!(binding, :signing),
               Keyword.fetch!(binding, :handle)
             )

    assert {:ok, %{status: 200, body: ^payload}} =
             Finch.request(signed, CredentialProxyExample.Finch)

    <<_first, rest::binary>> = payload

    assert {:ok, %{status: 401}} =
             Finch.request(%{signed | body: <<1, rest::binary>>}, CredentialProxyExample.Finch)

    for client <- ["req", "finch"] do
      url = Keyword.fetch!(binding, :proxy_url) <> "/forward/" <> client

      incoming =
        Finch.build(
          :post,
          url,
          [
            {"content-digest", "sha-256=:AA==:"},
            {"signature", "sig=:AQ==:"},
            {"x-upstream", "http://request-seal.invalid/"}
          ],
          payload
        )

      assert {:ok, %{status: 200, body: ^payload}} =
               Finch.request(incoming, CredentialProxyExample.Finch)

      overflow = Finch.build(:post, url, [], String.duplicate("x", 4097))
      assert {:ok, %{status: 413}} = Finch.request(overflow, CredentialProxyExample.Finch)
    end

    for path <- ["/other", "/forward/req?destination=other", "/forward/other"] do
      request = Finch.build(:post, Keyword.fetch!(binding, :proxy_url) <> path, [], payload)
      assert {:ok, %{status: 404}} = Finch.request(request, CredentialProxyExample.Finch)
    end

    binding =
      E.eval(
        ~S'''
        :ok = RequestSeal.Custody.release(handle)
        refusals =
          for client <- ["req", "finch"] do
            request = Finch.build(:post, proxy_url <> "/forward/" <> client, [], payload)
            {:ok, response} = Finch.request(request, CredentialProxyExample.Finch)
            503 = response.status
            "signing unavailable" = response.body
            response
          end
        ''',
        binding,
        "docs/guides/credential-proxy.md",
        6
      )

    assert [%{status: 503}, %{status: 503}] = Keyword.fetch!(binding, :refusals)
    refute RequestSeal.Custody.Local.Owner.ready?(CredentialProxyExample.Custody, :outbound)

    binding =
      E.eval(
        ~S'''
        :ok = Supervisor.stop(supervisor)
        :ok = File.rm(seed_file)
        :ok = File.rmdir(directory)
        ''',
        binding,
        "docs/guides/credential-proxy.md",
        7
      )

    refute File.exists?(Keyword.fetch!(binding, :directory))
    refute Process.alive?(Keyword.fetch!(binding, :supervisor))

    E.assert_fences("docs/guides/credential-proxy.md", 7)
    assert is_list(binding)
  end
end
