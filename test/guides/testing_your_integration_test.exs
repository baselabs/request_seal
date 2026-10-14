defmodule RequestSeal.GuideTestingYourIntegrationTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {_public_bytes, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, handle} = RequestSeal.Custody.Local.new("ed25519", {:ed25519, seed})
        {:ok, key} = RequestSeal.Custody.public_key(handle)
        components = ~s[("@method" "@scheme" "@authority" "@path" "content-digest")]
        ''',
        binding,
        "docs/guides/testing-your-integration.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        created = 1_790_000_000
        nonce = :binary.copy(<<7>>, 32)

        {:ok, message} =
          RequestSeal.Message.request(
            "POST",
            "https://inventory.example.com/restock",
            [{"content-type", "application/json"}],
            ~s({"sku":"LAMP-9","quantity":12}),
            digest: ["sha-256"]
          )

        spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60, keyid: "test-key"}
        sign = fn -> RequestSeal.sign(message, spec, handle, clock: fn -> created end, nonce: nonce) end

        {:ok, first} = sign.()
        {:ok, second} = sign.()
        true = first.fields == second.fields

        [signature_input] = for f <- first.fields, f.name == "Signature-Input", do: f.value
        true = signature_input =~ ";created=1790000000;expires=1790000060;"
        ''',
        binding,
        "docs/guides/testing-your-integration.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        policy_at = fn now ->
          {:ok, policy} =
            RequestSeal.Policy.new(%{
              algorithms: ["ed25519"],
              components: components,
              key_resolver: fn
                %{keyid: "test-key"} -> {:ok, %{algorithm: "ed25519", key: key}}
                _ -> :error
              end,
              freshness: %{clock: fn -> now end, max_age: 60, skew: 0, require_expires: true},
              content: %{kind: :content, algorithms: ["sha-256"], section: :headers},
              replay: :not_required
            })

          policy
        end

        {:ok, verification} = RequestSeal.verify(first, policy_at.(created + 59), label: "sig")
        :valid = verification.signature.crypto
        ["sha-256"] = verification.content.checked
        :not_evaluated = verification.authorization

        {:error, %RequestSeal.Error{reason: :expired, layer: :freshness}} =
          RequestSeal.verify(first, policy_at.(created + 60), label: "sig")
        ''',
        binding,
        "docs/guides/testing-your-integration.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        deliver = fn request, body ->
          conn =
            Enum.reduce(request.fields, Plug.Test.conn(:post, "https://inventory.example.com/restock", body), fn field, conn ->
              Plug.Conn.put_req_header(conn, String.downcase(field.name), field.value)
            end)

          RequestSeal.Plug.Capture.call(conn, RequestSeal.Plug.Capture.init(origin: :connection, max_body_bytes: 65_536, read_timeout: 5_000))
          |> RequestSeal.Plug.Verify.call(
            RequestSeal.Plug.Verify.init(policy: policy_at.(created + 1), label: "sig", on_reject: {:halt, 401})
          )
        end

        accepted = deliver.(first, ~s({"sku":"LAMP-9","quantity":12}))
        false = accepted.halted
        {:ok, %RequestSeal.Verification{}} = RequestSeal.Plug.verification(accepted)

        rejected = deliver.(first, ~s({"sku":"LAMP-9","quantity":120}))
        {true, 401} = {rejected.halted, rejected.status}
        ''',
        binding,
        "docs/guides/testing-your-integration.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        {:ok, store} = RequestSeal.Replay.ETS.start_link(max_entries: 100)

        replay = %{
          identifier: :nonce,
          namespace: "inventory-tests",
          commitment: fn facts -> {:ok, facts.identifier} end,
          store: RequestSeal.Replay.ETS.store(store),
          timeout: 5_000
        }

        {:ok, once} = RequestSeal.Policy.new(%{Map.from_struct(policy_at.(created + 1)) | replay: replay})
        {:ok, _} = RequestSeal.verify(first, once, label: "sig")
        {:error, %RequestSeal.Error{reason: :replayed}} = RequestSeal.verify(first, once, label: "sig")

        GenServer.stop(store)
        :ok = RequestSeal.Custody.Local.release(handle)
        ''',
        binding,
        "docs/guides/testing-your-integration.md",
        5
      )

    assert :ok = RequestSeal.Message.validate(Keyword.fetch!(binding, :first))
    E.assert_fences("docs/guides/testing-your-integration.md", 5)
  end
end
