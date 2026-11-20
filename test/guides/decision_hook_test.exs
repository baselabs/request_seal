defmodule RequestSeal.GuideDecisionHookTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "every decision-hook fence executes with real signed requests and responses" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {_public, caller_seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, caller_handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, caller_seed})
        {:ok, caller_key} = RequestSeal.Custody.public_key(caller_handle)
        {_public, service_seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, service_handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, service_seed})
        {:ok, service_key} = RequestSeal.Custody.public_key(service_handle)

        request_components = ~s[("@method" "@scheme" "@authority" "@path" "content-type" "content-digest")]
        response_components = ~s[("@status" "content-type" "content-digest" "@method";req "@scheme";req "@authority";req "@path";req "content-digest";req "signature";req)]

        policy_for = fn key, trusted_id, components ->
          RequestSeal.Policy.new(%{
            algorithms: ["ed25519"],
            components: components,
            key_resolver: fn
              %{keyid: ^trusted_id} -> {:ok, %{algorithm: "ed25519", key: key}}
              _ -> :error
            end,
            freshness: %{
              clock: fn -> System.system_time(:second) end,
              max_age: 60,
              skew: 5,
              require_expires: true
            },
            content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
            replay: :not_required
          })
        end

        {:ok, request_policy} = policy_for.(caller_key, "caller-key", request_components)
        {:ok, response_policy} = policy_for.(service_key, "service-key", response_components)
        request_signing = %{
          label: "sig",
          algorithm: "ed25519",
          components: request_components,
          expires_in: 60,
          keyid: "caller-key",
          digest: ["sha-256"]
        }
        response_signing = %{
          label: "decision",
          algorithm: "ed25519",
          components: response_components,
          parameters: %{
            created: true,
            expires_in: 60,
            nonce: :random,
            alg: true,
            keyid: "service-key",
            tag: nil
          },
          digest: ["sha-256"],
          field_schemas: %{}
        }
        ''',
        binding,
        "docs/guides/decision-hook.md",
        1
      )

    on_exit(fn ->
      RequestSeal.Custody.release(Keyword.fetch!(binding, :caller_handle))
      RequestSeal.Custody.release(Keyword.fetch!(binding, :service_handle))
    end)

    binding =
      E.eval(
        ~S'''
        defmodule DecisionHookExample.Receiver do
          @behaviour Plug
          def init(options), do: options

          def call(%Plug.Conn{method: "POST", request_path: "/decision", query_string: ""} = conn, options) do
            conn = RequestSeal.Plug.Capture.call(conn,
              RequestSeal.Plug.Capture.init(
                origin: :connection, max_body_bytes: 4096, read_timeout: 5_000))
            conn = RequestSeal.Plug.Verify.call(conn,
              RequestSeal.Plug.Verify.init(
                policy: options[:request_policy], label: "sig", on_reject: {:halt, 401}))

            if conn.halted do
              conn
            else
              {:ok, capture} = RequestSeal.Plug.capture(conn)
              {status, decision} =
                case options[:decide].(capture.message.body.bytes) do
                  :allow -> {200, "allow"}
                  _ -> {403, "deny"}
                end

              conn = RequestSeal.Plug.SignResponse.call(conn,
                RequestSeal.Plug.SignResponse.init(
                  sign: options[:response_signing], signer: options[:service_handle],
                  signing_timeout: 5_000, clock: fn -> System.system_time(:second) end,
                  on_failure: {:respond, 503}))

              body = :json.encode(%{"decision" => decision}) |> IO.iodata_to_binary()
              conn
              |> Plug.Conn.put_resp_content_type("application/json")
              |> Plug.Conn.send_resp(status, body)
            end
          end

          def call(conn, _options), do: Plug.Conn.send_resp(conn, 404, "")
        end
        ''',
        binding,
        "docs/guides/decision-hook.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        {:ok, pool} = Finch.start_link(name: DecisionHookExample.Finch)
        {:ok, server} = Bandit.start_link(
          plug: {DecisionHookExample.Receiver,
            request_policy: request_policy,
            response_signing: response_signing,
            service_handle: service_handle,
            decide: fn body ->
              if :json.decode(body) == %{"operation" => "read"}, do: :allow, else: :deny
            end},
          ip: {127, 0, 0, 1}, port: 0, startup_log: false,
          http_options: [compress: false])
        {:ok, {_, port}} = ThousandIsland.listener_info(server)
        url = "http://127.0.0.1:#{port}/decision"
        ''',
        binding,
        "docs/guides/decision-hook.md",
        3
      )

    on_exit(fn ->
      for key <- [:server, :pool] do
        pid = Keyword.fetch!(binding, key)
        if Process.alive?(pid), do: Supervisor.stop(pid)
      end
    end)

    binding =
      E.eval(
        ~S'''
        decisions =
          for {operation, expected_status, expected_decision} <- [
                {"read", 200, "allow"}, {"write", 403, "deny"}
              ] do
            body = :json.encode(%{"operation" => operation}) |> IO.iodata_to_binary()
            {:ok, request} = RequestSeal.Req.attach(
              Req.new(url: url, method: :post, body: body,
                headers: [{"content-type", "application/json"}],
                finch: [name: DecisionHookExample.Finch],
                retry: false, redirect: false, decode_body: false),
              sign: request_signing, signer: caller_handle,
              verify: %{policy: response_policy, label: "decision", max_stream_bytes: 4096})
            {:ok, response} = Req.request(request)
            ^expected_status = response.status
            {:ok, verification} = RequestSeal.Req.verification(response)
            :valid = verification.signature.crypto
            %{"decision" => ^expected_decision} = :json.decode(response.body)
            {operation, response, verification}
          end
        ''',
        binding,
        "docs/guides/decision-hook.md",
        4
      )

    assert [{"read", %{status: 200}, allow}, {"write", %{status: 403}, deny}] =
             Keyword.fetch!(binding, :decisions)

    assert allow.signature.crypto == :valid
    assert deny.signature.crypto == :valid
    assert ~s("signature";req) in allow.signature.covered
    assert ~s("content-digest";req) in deny.signature.covered

    unsigned =
      Finch.build(
        :post,
        Keyword.fetch!(binding, :url),
        [{"content-type", "application/json"}],
        ~s({"operation":"read"})
      )

    assert {:ok, signed} =
             RequestSeal.Finch.sign(
               unsigned,
               Keyword.fetch!(binding, :request_signing),
               Keyword.fetch!(binding, :caller_handle)
             )

    for request <- [unsigned, %{signed | body: ~s({"operation":"edit"})}] do
      assert {:ok, %{status: 401}} = Finch.request(request, DecisionHookExample.Finch)
    end

    binding =
      E.eval(
        ~S'''
        request = Finch.build(:post, url, [{"content-type", "application/json"}], ~s({"operation":"read"}))
        {:ok, sent} = RequestSeal.Finch.sign(request, request_signing, caller_handle)
        {:ok, response} = Finch.request(sent, DecisionHookExample.Finch)
        {:ok, _verified} = RequestSeal.Finch.verify(response, sent, response_policy, label: "decision")

        {:ok, other_request} = RequestSeal.Finch.sign(request, request_signing, caller_handle)
        {:error, %RequestSeal.Adapter.Error{reason: :response_rejected}} =
          RequestSeal.Finch.verify(response, other_request, response_policy, label: "decision")
        {:error, %RequestSeal.Adapter.Error{reason: :response_rejected}} =
          RequestSeal.Finch.verify(%{response | body: ~s({"decision":"deny"})}, sent,
            response_policy, label: "decision")
        unsigned = %{response | headers: Enum.reject(response.headers, fn {name, _} ->
          String.downcase(name) in ["signature", "signature-input"]
        end)}
        {:error, %RequestSeal.Adapter.Error{reason: :response_rejected}} =
          RequestSeal.Finch.verify(unsigned, sent, response_policy, label: "decision")
        ''',
        binding,
        "docs/guides/decision-hook.md",
        5
      )

    response = Keyword.fetch!(binding, :response)
    sent = Keyword.fetch!(binding, :sent)
    policy = Keyword.fetch!(binding, :response_policy)

    assert {:error, %RequestSeal.Adapter.Error{reason: :response_rejected}} =
             RequestSeal.Finch.verify(%{response | status: 403}, sent, policy, label: "decision")

    binding =
      E.eval(
        ~S'''
        :ok = Supervisor.stop(server)
        :ok = Supervisor.stop(pool)
        :ok = RequestSeal.Custody.release(caller_handle)
        :ok = RequestSeal.Custody.release(service_handle)
        ''',
        binding,
        "docs/guides/decision-hook.md",
        6
      )

    E.assert_fences("docs/guides/decision-hook.md", 6)
    assert is_list(binding)
  end
end
