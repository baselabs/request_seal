defmodule RequestSeal.GuideKeyCustodyTest do
  use ExUnit.Case, async: false
  alias RequestSeal.DocsExamples, as: E

  test "documented examples execute against real cryptography and integrations" do
    binding = []

    binding =
      E.eval(
        ~S'''
        {:ok, handle} = RequestSeal.Custody.Local.generate("ed25519", [])
        {:ok, key} = RequestSeal.Custody.public_key(handle)
        {:ok, thumbprint} = RequestSeal.PublicKey.thumbprint(key)
        ''',
        binding,
        "docs/guides/key-custody.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, signature} = RequestSeal.Custody.sign(handle, "exact bytes", timeout: 5_000)
        RequestSeal.Custody.verify(handle, "exact bytes", signature, timeout: 5_000)
        # => :ok
        RequestSeal.Custody.verify(handle, "changed bytes", signature)
        # => {:error, %RequestSeal.Custody.Error{reason: :invalid_signature, ...}}
        ''',
        binding,
        "docs/guides/key-custody.md",
        2
      )

    example_result = Keyword.fetch!(binding, :example_result)
    assert {:error, %RequestSeal.Custody.Error{reason: :invalid_signature}} = example_result

    assert :ok =
             RequestSeal.Custody.verify(
               Keyword.fetch!(binding, :handle),
               "exact bytes",
               Keyword.fetch!(binding, :signature)
             )

    binding =
      E.eval(
        ~S'''
        RequestSeal.Custody.Local.release(handle)
        # => :ok
        RequestSeal.Custody.sign(handle, "exact bytes")
        # => {:error, %RequestSeal.Custody.Error{reason: :key_not_found, ...}}
        ''',
        binding,
        "docs/guides/key-custody.md",
        3
      )

    example_result = Keyword.fetch!(binding, :example_result)
    assert {:error, %RequestSeal.Custody.Error{reason: :key_not_found}} = example_result
    assert is_list(binding)

    binding =
      E.eval(
        ~S'''
        {:ok, recipient_handle} =
          RequestSeal.Custody.Local.generate({:jwe, "RSA-OAEP-256"}, bits: 2048, timeout: 30_000)

        # Run this health check at startup, before accepting encrypted messages.
        {:ok, recipient_public} = RequestSeal.Custody.public_key(recipient_handle)

        {:ok, recipient_jwe} =
          RequestSeal.JOSE.JWE.encrypt(
            [{"alg", "RSA-OAEP-256"}, {"enc", "A256GCM"}],
            "recipient payload",
            recipient_public
          )

        recipient_policy = %{
          algorithms: ["RSA-OAEP-256"],
          encryption: ["A256GCM"],
          max_plaintext: 1_048_576,
          timeout: 5_000,
          resolve_timeout: 1000,
          unwrap_timeout: 1000,
          protected: %{expected: %{}, permitted: ~w(kid typ cty)},
          key_resolver: fn %{algorithm: "RSA-OAEP-256"} ->
            {:ok, %{algorithm: "RSA-OAEP-256", key: recipient_handle}}
          end
        }

        {:ok, recipient_result} = RequestSeal.JOSE.JWE.decrypt(recipient_jwe, recipient_policy)
        recipient_result.plaintext
        # => "recipient payload"
        :ok = RequestSeal.Custody.Local.release(recipient_handle)
        ''',
        binding,
        "docs/guides/key-custody.md",
        4
      )

    example_result = Keyword.fetch!(binding, :example_result)
    assert example_result == :ok
    assert Keyword.fetch!(binding, :recipient_result).plaintext == "recipient payload"
    handle = Keyword.fetch!(binding, :recipient_handle)

    assert {:error, %RequestSeal.Custody.Error{reason: :key_not_found}} =
             RequestSeal.Custody.public_key(handle)

    assert RequestSeal.JOSE.JWE.decrypt(
             Keyword.fetch!(binding, :recipient_jwe),
             Keyword.fetch!(binding, :recipient_policy)
           ) == {:error, RequestSeal.JOSE.Error.new(:decryption_failed, :crypto)}

    path =
      Path.join(
        System.tmp_dir!(),
        "request-seal-guide-seed-#{System.unique_integer([:positive])}"
      )

    {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
    File.write!(path, Base.url_encode64(seed, padding: false))
    File.chmod!(path, 0o600)
    on_exit(fn -> File.rm!(path) end)
    E.configure(:my_app, :signing_seed_file, path)

    binding =
      E.eval(
        ~S'''
        alias RequestSeal.Custody.Local.Owner
        seed_file = Application.fetch_env!(:my_app, :signing_seed_file)
        children = [
          {Owner,
           name: MyApp.Custody,
           keys: [signing: {"ed25519", {:file, seed_file, :base64url}}]}
        ]
        {:ok, supervisor} = Supervisor.start_link(children, strategy: :one_for_one)
        Owner.status(MyApp.Custody)
        # => %{signing: :ready}
        Owner.ready?(MyApp.Custody, :signing)
        # => true
        ''',
        binding,
        "docs/guides/key-custody.md",
        5
      )

    assert Keyword.fetch!(binding, :example_result)
    assert RequestSeal.Custody.Local.Owner.status(MyApp.Custody) == %{signing: :ready}

    binding =
      E.eval(
        ~S'''
        {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
        spec = %{
          label: "sig",
          signature_input: ~s[("@method" "@scheme" "@authority" "@path");alg="ed25519"],
          algorithm: "ed25519"
        }
        {:ok, handle} = RequestSeal.Custody.Local.Owner.fetch(MyApp.Custody, :signing)
        {:ok, signed} = RequestSeal.sign(message, spec, handle, signing_timeout: 5_000)
        Enum.map(signed.fields, & &1.name)
        # => ["Signature-Input", "Signature"]
        ''',
        binding,
        "docs/guides/key-custody.md",
        6
      )

    assert Keyword.fetch!(binding, :example_result) == ["Signature-Input", "Signature"]
    Supervisor.stop(Keyword.fetch!(binding, :supervisor))
    binding = []

    example =
      E.eval(
        ~S'''
        alias RequestSeal.{Custody, Message, SignatureBase}
        alias RequestSeal.Custody.Gate
        alias RequestSeal.Replay.ETS

        {:ok, store} = ETS.start_link(max_entries: 100)
        {:ok, message} = Message.request("GET", "https://example.test/builds", [], "")
        components = ~s[("@method" "@path")]
        {:ok, digest} = Gate.commitment(message, components)
        now = 1_700_000_000
        decision = %Gate.Admission{
          decision: "build-approval-1",
          commitment: digest,
          not_after: now + 30,
          nonce: "build-1"
        }

        config = %{
          port: fn _, _ -> {:allow, decision} end,
          once: {:store, ETS.store(store), "builds"},
          required_components: [~s["@method"], ~s["@path"]],
          max_lifetime: 30,
          clock: fn -> now end,
          skew: 0,
          tag: "build"
        }

        {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
        {:ok, signer} = Gate.new("ed25519", {:ed25519, seed}, config, issued_for: :build)
        params = components <> ~s[;created=1700000000;expires=1700000030;nonce="build-1";tag="build"]
        {:ok, base} = SignatureBase.build(message, params)
        sign_opts = [issued_for: :build, operation: :http]
        {:ok, _signature} = Custody.sign(signer, base, sign_opts)
        {:error, %{reason: :gate_spent}} = Custody.sign(signer, base, sign_opts)
        :ok = Custody.release(signer)
        :ok = GenServer.stop(store)
        ''',
        binding,
        "docs/guides/key-custody.md",
        7
      )

    assert Keyword.fetch!(example, :example_result) == :ok
    E.assert_fences("docs/guides/key-custody.md", 7)
  end
end
