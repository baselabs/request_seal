defmodule RequestSeal.GuideReqAndFinchTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "Finch and Req carry the trusted signing purpose through normalization" do
    {:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", issued_for: :build)

    spec = %{
      label: "sig",
      algorithm: "ed25519",
      components: ~s[("@method" "@path")],
      expires_in: 60,
      issued_for: :build
    }

    url = "https://example.test/builds"
    finch = Finch.build(:get, url)
    assert {:ok, signed} = RequestSeal.Finch.sign(finch, spec, handle)
    assert Enum.any?(signed.headers, fn {name, _} -> String.downcase(name) == "signature" end)

    assert {:error, %{reason: :invalid_options, source: %{reason: :issued_for_mismatch}}} =
             RequestSeal.Finch.sign(finch, %{spec | issued_for: :audit}, handle)

    assert {:ok, req} =
             RequestSeal.Req.attach(Req.new(url: url), sign: spec, signer: handle, verify: :none)

    assert %Req.Request{} = signed = RequestSeal.Req.sign_attempt(req)
    assert Req.Request.get_header(signed, "signature") != []

    assert {:ok, req} =
             RequestSeal.Req.attach(Req.new(url: url),
               sign: %{spec | issued_for: :audit},
               signer: handle,
               verify: :none
             )

    assert {%Req.Request{halted: true},
            %{reason: :invalid_options, source: %{reason: :issued_for_mismatch}}} =
             RequestSeal.Req.sign_attempt(req)
  end

  test "documented examples execute against real cryptography and integrations" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", [])
        {:ok, key} = RequestSeal.Custody.public_key(handle)
        components = ~s[("@method" "@scheme" "@authority" "@path" "content-digest")]

        {:ok, policy} =
          RequestSeal.Policy.new(%{
            algorithms: ["ed25519"],
            components: components,
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

        signing = %{
          label: "sig",
          algorithm: "ed25519",
          components: components,
          expires_in: 60,
          keyid: "demo-key",
          digest: ["sha-256"]
        }
        ''',
        binding,
        "docs/guides/req-and-finch.md",
        1
      )

    binding = E.endpoint(binding, RequestSeal.DocsPipeline, RequestSeal.DocsController)

    binding =
      E.eval(
        ~S'''
        url = Application.get_env(:my_app, :webhook_url, "http://127.0.0.1:4000/webhooks")
        {:ok, _pool} = Finch.start_link(name: MyApp.Finch)

        request =
          Req.new(
            url: url,
            method: :post,
            json: %{"event" => "created"},
            finch: [name: MyApp.Finch],
            retry: false
          )

        {:ok, request} = RequestSeal.Req.attach(request, sign: signing, signer: handle, verify: :none)
        {:ok, response} = Req.request(request)
        ''',
        binding,
        "docs/guides/req-and-finch.md",
        2
      )

    assert Keyword.fetch!(binding, :response).status == 200
    E.assert_received_request()

    binding =
      E.eval(
        ~S'''
        {:ok, response_policy} =
          RequestSeal.Policy.new(%{
            Map.from_struct(policy)
            | components: ~s[("@status" "@method";req "@path";req "content-digest")]
          })
        ''',
        binding,
        "docs/guides/req-and-finch.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        {:ok, request} =
          RequestSeal.Req.attach(
            Req.new(
              url: url,
              method: :post,
              json: %{"event" => "created"},
              finch: [name: MyApp.Finch],
              retry: false
            ),
            sign: signing,
            signer: handle,
            verify: %{policy: response_policy, label: "res", max_stream_bytes: 1_048_576}
          )

        {:ok, response} = Req.request(request)
        {:ok, verified_response} = RequestSeal.Req.verification(response)
        verified_response.signature.crypto
        # => :valid
        ''',
        binding,
        "docs/guides/req-and-finch.md",
        4
      )

    assert Keyword.fetch!(binding, :response).status == 200
    E.assert_received_request()
    assert Keyword.fetch!(binding, :verified_response).signature.crypto == :valid

    binding =
      E.eval(
        ~S'''
        request = Finch.build(:post, url, [{"content-type", "application/json"}], ~s({"event":"created"}))
        {:ok, request} = RequestSeal.Finch.sign(request, signing, handle)
        {:ok, response} = Finch.request(request, MyApp.Finch)

        {:ok, verified_response} =
          RequestSeal.Finch.verify(response, request, response_policy, label: "res")

        verified_response.signature.crypto
        # => :valid
        ''',
        binding,
        "docs/guides/req-and-finch.md",
        5
      )

    assert Keyword.fetch!(binding, :response).status == 200
    E.assert_received_request()
    assert Keyword.fetch!(binding, :verified_response).signature.crypto == :valid
    E.assert_rejected_request(binding)

    binding =
      E.eval(
        ~S'''
        :answered = RequestSeal.Finch.classify({:ok, response}, request)
        :unknown = RequestSeal.Req.classify({:error, %Req.TransportError{reason: :timeout}})
        ''',
        binding,
        "docs/guides/req-and-finch.md",
        6
      )

    E.assert_fences("docs/guides/req-and-finch.md", 6)
    assert is_list(binding)
  end
end
