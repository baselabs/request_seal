defmodule RequestSeal.DocsEndpoint do
  @moduledoc false
  use Phoenix.Endpoint, otp_app: :request_seal
  plug(:pipeline)
  plug(:sign_response)
  plug(:controller)

  defp pipeline(conn, _) do
    options = Application.fetch_env!(:request_seal, :docs_endpoint)
    options.pipeline.call(conn, options.pipeline.init(policy: options.policy))
  end

  defp sign_response(conn, _) do
    options = Application.fetch_env!(:request_seal, :docs_endpoint)

    conn =
      if options[:response_signer] do
        options.response_signer.sign(conn, options.handle, options.response_signing)
      else
        RequestSeal.Plug.SignResponse.call(conn, options.response_options)
      end

    Plug.Conn.register_before_send(conn, fn conn ->
      send(options.owner, {:docs_request, RequestSeal.Plug.verification(conn), conn.body_params})
      conn
    end)
  end

  defp controller(conn, _) do
    options = Application.fetch_env!(:request_seal, :docs_endpoint)
    conn = Plug.Conn.fetch_query_params(conn)
    options.controller.call(conn, options.controller.init(:create))
  end
end

defmodule RequestSeal.DocsExamples do
  @moduledoc false
  import ExUnit.Assertions

  def eval(code, binding, document, index) do
    # These examples intentionally recompile resources loaded by test support.
    # Restore compiler settings before evaluating any other example.
    {result, binding} =
      if String.starts_with?(code, "defmodule AshApp.") do
        previous =
          Code.compiler_options(ignore_module_conflict: true, ignore_already_consolidated: true)

        try do
          Code.eval_string(code, binding)
        after
          Code.compiler_options(previous)
        end
      else
        Code.eval_string(code, binding)
      end

    key = {__MODULE__, document}
    executed = Process.get(key, [])
    assert index not in executed, "document fence executed more than once"
    Process.put(key, executed ++ [index])
    Keyword.put(binding, :example_result, result)
  end

  def assert_fences(document, count) do
    assert Process.get({__MODULE__, document}, []) == Enum.to_list(1..count)
  end

  def configure(app, key, value) do
    previous = Application.fetch_env(app, key)
    Application.put_env(app, key, value)

    ExUnit.Callbacks.on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(app, key, value)
        :error -> Application.delete_env(app, key)
      end
    end)
  end

  def endpoint(binding, pipeline, controller, response_signer \\ nil) do
    policy = Keyword.fetch!(binding, :policy)
    signing = RequestSeal.Signing.normalize_spec!(Keyword.fetch!(binding, :signing))
    handle = Keyword.fetch!(binding, :handle)
    configure(:my_app, :http_signature_policy, policy)

    spec = %{
      signing
      | label: "res",
        components: ~s[("@status" "@method";req "@path";req "content-digest")]
    }

    options =
      RequestSeal.Plug.SignResponse.init(
        sign: spec,
        signer: handle,
        signing_timeout: 5_000,
        clock: fn -> System.system_time(:second) end,
        on_failure: {:respond, 503}
      )

    configure(:request_seal, :docs_endpoint, %{
      pipeline: pipeline,
      policy: policy,
      controller: controller,
      response_options: options,
      owner: self(),
      response_signer: response_signer,
      response_signing: Keyword.get(binding, :response_signing, spec),
      signing: signing,
      handle: handle
    })

    configure(:request_seal, RequestSeal.DocsEndpoint,
      server: true,
      adapter: Bandit.PhoenixAdapter,
      http: [ip: {127, 0, 0, 1}, port: 0, http_options: [compress: false]],
      secret_key_base: String.duplicate("a", 64),
      debug_errors: false,
      pubsub_server: RequestSeal.DocsPubSub
    )

    ExUnit.Callbacks.start_supervised!({Phoenix.PubSub, name: RequestSeal.DocsPubSub})
    ExUnit.Callbacks.start_supervised!(RequestSeal.DocsEndpoint)
    {:ok, {_, port}} = Bandit.PhoenixAdapter.server_info(RequestSeal.DocsEndpoint, :http)
    url = "http://127.0.0.1:#{port}/webhooks"
    configure(:my_app, :webhook_url, url)
    Keyword.put(binding, :url, url)
  end

  def publisher(binding) do
    {:ok, _} = Application.ensure_all_started(:ssl)

    chain = %{
      root: [key: {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}}, digest: :sha256],
      intermediates: [],
      peer: [
        key: {:namedCurve, {1, 2, 840, 10045, 3, 1, 7}},
        digest: :sha256,
        extensions: [{:Extension, {2, 5, 29, 17}, false, [{:dNSName, ~c"localhost"}]}]
      ]
    }

    tls = :public_key.pkix_test_data(%{server_chain: chain, client_chain: chain})

    pid =
      ExUnit.Callbacks.start_supervised!(
        {Bandit,
         plug: {RequestSeal.DocsKeyPublisher, key: Keyword.fetch!(binding, :key)},
         scheme: :https,
         ip: {127, 0, 0, 1},
         port: 0,
         startup_log: false,
         thousand_island_options: [transport_options: tls.server_config]}
      )

    {:ok, {_, port}} = ThousandIsland.listener_info(pid)

    binding
    |> Keyword.put(:jwks_url, "https://localhost:#{port}/keys")
    |> Keyword.put(:trust_roots, tls.client_config[:cacerts])
    |> Keyword.put(:permitted_addresses, [{127, 0, 0, 1}, {0, 0, 0, 0, 0, 0, 0, 1}])
  end

  def assert_received_request do
    assert_receive {:docs_request, {:ok, result}, %{"event" => "created"}}, 5_000
    assert result.signature.crypto == :valid
    assert result.content.checked == ["sha-256"]
  end

  def assert_rejected_request(binding) do
    request =
      Finch.build(
        :post,
        Keyword.fetch!(binding, :url),
        [{"content-type", "application/json"}],
        ~s({"event":"created"})
      )

    {:ok, response} = Finch.request(request, MyApp.Finch)
    assert response.status == 401
    refute_receive {:docs_request, _, _}

    {:ok, request} =
      RequestSeal.Finch.sign(
        request,
        Keyword.fetch!(binding, :signing),
        Keyword.fetch!(binding, :handle)
      )

    request = %{request | body: ~s({"event":"changed"})}
    {:ok, response} = Finch.request(request, MyApp.Finch)
    assert response.status == 401
    refute_receive {:docs_request, _, _}
  end

  def assert_rejected_signature(binding) do
    signed = Keyword.fetch!(binding, :signed)
    policy = Keyword.fetch!(binding, :policy)

    assert {:error, %RequestSeal.Error{reason: :invalid_signature}} =
             RequestSeal.verify(%{signed | raw_target: "/changed"}, policy, label: "sig")

    assert {:error, %RequestSeal.Error{reason: :digest_mismatch}} =
             RequestSeal.verify(%{signed | body: %{signed.body | bytes: "changed"}}, policy,
               label: "sig"
             )
  end

  def seed_documents(resource) do
    :ok = Ash.DataLayer.Ets.stop(resource)
    ExUnit.Callbacks.on_exit(fn -> Ash.DataLayer.Ets.stop(resource) end)
    # Insert the other tenant first so a lost tenant filter changes the result.
    Ash.Seed.seed!(resource, %{}, tenant: "other")
    Ash.Seed.seed!(resource, %{}, tenant: "demo")
  end

  def assert_ash_read(binding, record) do
    assert [%{id: id, tenant_id: "demo"}] = Keyword.fetch!(binding, :documents)
    assert id == record.id
  end

  def assert_ash_denial(binding, resource \\ MyApp.Document) do
    scope = Keyword.fetch!(binding, :scope)
    assert scope.authorize?
    assert scope.actor == %{role: :reader}
    assert scope.tenant == "demo"

    assert {:error, %Ash.Error.Forbidden{}} =
             Ash.read(resource,
               scope: %{scope | actor: %{role: :visitor}},
               authorize?: true
             )

    assert {:error, %RequestSeal.Error{reason: :actor_unbound}} =
             RequestSeal.Ash.scope(Keyword.fetch!(binding, :verification), %{
               actor: fn _ -> :error end,
               tenant: :none,
               unattributed: :reject
             })
  end
end

defmodule MyApp.Document do
  use Ash.Resource,
    domain: MyApp.Documents,
    data_layer: Ash.DataLayer.Ets,
    authorizers: [Ash.Policy.Authorizer]

  ets do
    private?(false)
  end

  multitenancy do
    strategy(:attribute)
    attribute(:tenant_id)
  end

  attributes do
    uuid_primary_key(:id)
    attribute(:tenant_id, :string, allow_nil?: false)
  end

  actions do
    defaults([:read])
  end

  policies do
    policy action_type(:read) do
      authorize_if(actor_attribute_equals(:role, :reader))
    end
  end
end

defmodule MyApp.Documents do
  use Ash.Domain, validate_config_inclusion?: false

  resources do
    resource(MyApp.Document)
  end
end

defmodule RequestSeal.DocsPipeline do
  use Plug.Builder

  plug(RequestSeal.Plug.Capture,
    origin: :connection,
    max_body_bytes: 1_048_576,
    read_timeout: 5_000
  )

  plug(Plug.Parsers,
    parsers: [:json],
    pass: ["*/*"],
    json_decoder: Jason,
    body_reader: {RequestSeal.Plug.Capture, :read_body, []}
  )

  plug(:verify_signature)

  defp verify_signature(conn, _) do
    policy = Application.fetch_env!(:my_app, :http_signature_policy)

    RequestSeal.Plug.Verify.call(
      conn,
      RequestSeal.Plug.Verify.init(
        policy: policy,
        label: "sig",
        assign: :verified,
        on_reject: {:halt, 401}
      )
    )
  end
end

defmodule RequestSeal.DocsController do
  use Phoenix.Controller, formats: [:json]

  def create(conn, params) do
    {:ok, verified} = RequestSeal.Plug.verification(conn)
    json(conn, %{signature_label: verified.label, event: params["event"]})
  end
end

defmodule RequestSeal.DocsKeyPublisher do
  @moduledoc false
  import Plug.Conn
  def init(options), do: options

  def call(conn, options) do
    if conn.method == "GET" and conn.request_path == "/keys" do
      {:ok, jwk} = RequestSeal.PublicKey.export(options[:key], :jwk)
      body = :json.encode(%{"keys" => [jwk]}) |> IO.iodata_to_binary()

      conn
      |> put_resp_content_type("application/jwk-set+json")
      |> put_resp_header("cache-control", "max-age=300")
      |> send_resp(200, body)
    else
      send_resp(conn, 404, "")
    end
  end
end
