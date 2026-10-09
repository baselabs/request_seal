defmodule RequestSeal.GuidePhoenixAndPlugTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        {:ok, key} = RequestSeal.Custody.public_key(handle)
        ''',
        binding,
        "docs/guides/phoenix-and-plug.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, policy} =
          RequestSeal.Policy.new(%{
            algorithms: ["ed25519"],
            components: ~s[("@method" "@scheme" "@authority" "@path" "content-digest")],
            key_resolver: fn
              %{keyid: "demo-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
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
        ''',
        binding,
        "docs/guides/phoenix-and-plug.md",
        2
      )

    assert RequestSeal.Policy.valid?(Keyword.fetch!(binding, :policy))

    E.configure(:my_app, :http_signature_policy, Keyword.fetch!(binding, :policy))

    binding =
      E.eval(
        ~S'''
        Application.put_env(:my_app, :http_signature_policy, policy)
        ''',
        binding,
        "docs/guides/phoenix-and-plug.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        defmodule WebhookApp.WebhookPipeline do
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

          plug(RequestSeal.Plug.Verify,
            policy: {Application, :fetch_env!, [:my_app, :http_signature_policy]},
            label: "sig",
            assign: :verified,
            on_reject: {:halt, 401}
          )
        end
        ''',
        binding,
        "docs/guides/phoenix-and-plug.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        defmodule WebhookApp.WebhookController do
          use Phoenix.Controller, formats: [:json]

          def create(conn, params) do
            {:ok, verified} = RequestSeal.Plug.verification(conn)
            json(conn, %{signature_label: verified.label, event: params["event"]})
          end
        end
        ''',
        binding,
        "docs/guides/phoenix-and-plug.md",
        5
      )

    binding =
      E.eval(
        ~S'''
        response_signing = %{
          label: "res",
          algorithm: "ed25519",
          components: ~s[("@status" "@method";req "@path";req "content-digest")],
          parameters: %{
            created: true,
            expires_in: 60,
            nonce: :random,
            alg: true,
            keyid: "demo-key",
            tag: nil
          },
          digest: ["sha-256"],
          field_schemas: %{}
        }
        ''',
        binding,
        "docs/guides/phoenix-and-plug.md",
        6
      )

    binding =
      E.eval(
        ~S'''
        defmodule WebhookApp.ResponseSignature do
          def sign(conn, handle, signing) do
            options =
              RequestSeal.Plug.SignResponse.init(
                sign: signing,
                signer: handle,
                signing_timeout: 5_000,
                clock: fn -> System.system_time(:second) end,
                on_failure: {:respond, 503}
              )

            RequestSeal.Plug.SignResponse.call(conn, options)
          end
        end
        ''',
        binding,
        "docs/guides/phoenix-and-plug.md",
        7
      )

    signing = %{
      label: "sig",
      algorithm: "ed25519",
      components: ~s[("@method" "@scheme" "@authority" "@path" "content-digest")],
      parameters: %{
        created: true,
        expires_in: 60,
        nonce: :random,
        alg: true,
        keyid: "demo-key",
        tag: nil
      },
      digest: ["sha-256"],
      field_schemas: %{}
    }

    binding = Keyword.put(binding, :signing, signing)

    binding =
      E.endpoint(
        binding,
        WebhookApp.WebhookPipeline,
        WebhookApp.WebhookController,
        WebhookApp.ResponseSignature
      )

    {:ok, _pool} = Finch.start_link(name: MyApp.Finch)

    request =
      Req.new(
        url: Keyword.fetch!(binding, :url),
        method: :post,
        json: %{"event" => "created"},
        finch: [name: MyApp.Finch],
        retry: false
      )

    {:ok, request} =
      RequestSeal.Req.attach(request,
        sign: signing,
        signer: Keyword.fetch!(binding, :handle),
        verify: :none
      )

    {:ok, response} = Req.request(request)
    assert response.status == 200
    E.assert_received_request()

    {:ok, response_policy} =
      RequestSeal.Policy.new(%{
        Map.from_struct(Keyword.fetch!(binding, :policy))
        | components: ~s[("@status" "@method";req "@path";req "content-digest")]
      })

    {:ok, signed_request} =
      RequestSeal.Finch.sign(
        Finch.build(
          :post,
          Keyword.fetch!(binding, :url),
          [{"content-type", "application/json"}],
          ~s({"event":"created"})
        ),
        signing,
        Keyword.fetch!(binding, :handle)
      )

    {:ok, signed_response} = Finch.request(signed_request, MyApp.Finch)

    assert {:ok, verified_response} =
             RequestSeal.Finch.verify(signed_response, signed_request, response_policy,
               label: "res"
             )

    assert verified_response.signature.crypto == :valid
    E.assert_received_request()
    E.assert_rejected_request(binding)
    E.assert_fences("docs/guides/phoenix-and-plug.md", 7)
    assert is_list(binding)
  end
end
