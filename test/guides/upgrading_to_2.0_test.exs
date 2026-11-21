defmodule RequestSeal.GuideUpgradingTo20Test do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute with real cryptography" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {:request_seal, "~> 2.0"}
        ''',
        binding,
        "docs/guides/upgrading-to-2.0.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, http_handle} = RequestSeal.Custody.Local.generate("ed25519", [])
        {:ok, http_key} = RequestSeal.Custody.public_key(http_handle)
        {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
        components = ~s[("@method" "@scheme" "@authority" "@path")]
        spec = %{label: "sig", algorithm: "ed25519", components: components, expires_in: 60}
        {:ok, signed} = RequestSeal.sign(message, spec, http_handle)

        {:ok, http_policy} = RequestSeal.Policy.new(%{
          algorithms: ["ed25519"], components: components,
          key_resolver: fn _ -> {:ok, %{algorithm: "ed25519", key: http_key}} end,
          freshness: :not_evaluated, content: :not_required, replay: :not_required
        })
        {:ok, _verification} = RequestSeal.verify(signed, http_policy, label: "sig")

        {:ok, requests} = RequestSeal.AcceptSignature.parse(~s[reply=("@method" "@path")], target: :request)
        chooser = fn _ -> {:ok, %{algorithm: "ed25519", created: nil, expires: nil}} end
        {:ok, _negotiated} = RequestSeal.AcceptSignature.fulfill(message, requests, chooser, [http_handle], [])
        :ok = RequestSeal.Custody.release(http_handle)
        ''',
        binding,
        "docs/guides/upgrading-to-2.0.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        {:ok, jws_handle} = RequestSeal.Custody.Local.generate({:jws, "EdDSA"}, [])
        {:ok, jws_key} = RequestSeal.Custody.public_key(jws_handle)
        {:ok, token} = RequestSeal.JOSE.JWS.sign([{"alg", "EdDSA"}, {"typ", "JOSE"}], "payload", jws_handle)

        jws_policy = %{
          algorithms: ["EdDSA"], timeout: 5_000,
          protected: %{expected: %{"typ" => "JOSE"}, permitted: [], embedded_key: :refuse},
          key_resolver: fn _ -> {:ok, %{algorithm: "EdDSA", key: jws_key}} end
        }
        {:ok, %{payload: "payload"}} = RequestSeal.JOSE.JWS.verify(token, jws_policy)
        {:error, %{reason: :protected_mismatch, layer: :input}} =
          RequestSeal.JOSE.JWS.verify(token, %{jws_policy | protected: %{jws_policy.protected | expected: %{"typ" => "other"}}})
        :ok = RequestSeal.Custody.release(jws_handle)
        ''',
        binding,
        "docs/guides/upgrading-to-2.0.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        {:ok, wrapping_handle} = RequestSeal.Custody.Local.generate({:jwe, "A256KW"}, [])
        {:ok, encrypted} = RequestSeal.JOSE.JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], "payload", wrapping_handle)

        jwe_policy = %{
          algorithms: ["A256KW"], encryption: ["A256GCM"], max_plaintext: 4096,
          timeout: 5_000, resolve_timeout: 1_000, unwrap_timeout: 1_000,
          protected: %{expected: %{}, permitted: []},
          key_resolver: fn _ -> {:ok, %{algorithm: "A256KW", key: wrapping_handle}} end
        }
        {:ok, %{plaintext: "payload", object: nil}} = RequestSeal.JOSE.JWE.decrypt(encrypted, jwe_policy)

        batch_policy =
          jwe_policy
          |> Map.put(:protected, %{permitted: []})
          |> Map.merge(%{max_tokens: 10, max_total_input: 65_536, max_total_plaintext: 40_960})

        {:ok, [{:ok, %{plaintext: "payload"}}]} =
          RequestSeal.JOSE.JWE.decrypt_many([%{token: encrypted, expected: %{}}], batch_policy)
        ''',
        binding,
        "docs/guides/upgrading-to-2.0.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        # Public, disposable example content-key bytes; never print a real CEK.
        example_cek = <<0::128>>
        {:ok, wrapped} = RequestSeal.Custody.wrap(wrapping_handle, example_cek)
        {:ok, [{:ok, ^example_cek}]} =
          RequestSeal.Custody.unwrap(wrapping_handle, [{wrapped.encrypted_key, %{}, 128}], timeout: 5_000)
        :ok = RequestSeal.Custody.release(wrapping_handle)
        ''',
        binding,
        "docs/guides/upgrading-to-2.0.md",
        5
      )

    binding =
      E.eval(
        ~S'''
        {:ok, %{"active" => true}} =
          RequestSeal.JOSE.decode_object(~s({"active":true}), max_bytes: 1024)
        {:error, %{reason: :duplicate_member, layer: :input}} =
          RequestSeal.JOSE.decode_object(~s({"active":true,"active":false}), max_bytes: 1024)
        ''',
        binding,
        "docs/guides/upgrading-to-2.0.md",
        6
      )

    assert is_list(binding)
    E.assert_fences("docs/guides/upgrading-to-2.0.md", 6)
  end
end
