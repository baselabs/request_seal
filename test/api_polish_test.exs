defmodule RequestSeal.APIPolishTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Crypto, Message}

  defp signer do
    secret = :crypto.strong_rand_bytes(32)
    fn alg, base -> Crypto.sign(alg, base, {:hmac, secret}) end
  end

  defp strict(components \\ ~s[("@method")]) do
    %{
      label: "sig",
      algorithm: "hmac-sha256",
      components: components,
      parameters: %{
        created: true,
        expires_in: 60,
        nonce: :random,
        alg: true,
        keyid: nil,
        tag: nil
      },
      digest: nil,
      field_schemas: %{}
    }
  end

  @tag :a1
  test "adapters reject nonce options while core signing accepts caller entropy" do
    nonce = :crypto.strong_rand_bytes(32)
    fun = signer()
    request = Finch.build(:get, "https://example.com/")

    assert {:error, %{reason: :invalid_options}} =
             RequestSeal.Finch.sign(request, strict(), fun, nonce: nonce)

    assert {:error, %{reason: :invalid_options}} =
             RequestSeal.Req.attach(Req.new(url: "https://example.com/"),
               sign: strict(),
               signer: fun,
               verify: :none,
               nonce: nonce
             )

    {:ok, message} = Message.request("GET", "https://example.com/", [], nil)
    assert {:ok, _} = RequestSeal.sign(message, strict(), fun, nonce: nonce)
  end

  @tag :a2
  test "unsupported components retain their own bounded reason" do
    {:ok, message} = Message.request("GET", "https://example.com/", [], nil)

    for components <- [~s[("host")], ~s[("x";tr)], ~s[("content-digest")]] do
      assert {:error, %RequestSeal.Error{reason: :unsupported_component, layer: :input}} =
               RequestSeal.sign(message, strict(components), signer())
    end
  end

  @tag :a2
  test "covered content length conflict is an invalid request" do
    {:ok, message} =
      Message.request("POST", "https://example.com/", [{"content-length", "999"}], "body")

    assert {:error, %RequestSeal.Error{reason: :invalid_request, layer: :input}} =
             RequestSeal.sign(message, strict(~s[("content-length")]), signer())
  end

  @tag :a3
  test "core defaults metadata and bounds expiry and clock" do
    {:ok, message} = Message.request("GET", "https://example.com/", [], nil)
    spec = %{label: "sig", algorithm: "hmac-sha256", components: ~s[("@method")], expires_in: 60}
    assert {:ok, signed} = RequestSeal.sign(message, spec, signer(), clock: fn -> 123 end)
    input = Enum.find(signed.fields, &(&1.name == "Signature-Input")).value
    assert input =~ ";created=123;expires=183;nonce="
    assert input =~ ~s[;alg="hmac-sha256"]
    refute input =~ "keyid="

    for expiry <- [nil, 0, -1, 1.5] do
      assert {:error, %{reason: :invalid_options}} =
               RequestSeal.sign(message, %{spec | expires_in: expiry}, signer())
    end

    assert {:error, %{reason: :invalid_options}} =
             RequestSeal.sign(message, Map.delete(spec, :expires_in), signer())

    assert {:error, %{reason: :invalid_options}} =
             RequestSeal.sign(message, strict(), signer(), clock: fn -> -1 end)
  end

  @tag :a3
  test "nested defaults and JWS algorithm defaults use actual Ed25519 signing" do
    {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = RequestSeal.Custody.Local.new({:jws, "EdDSA"}, {:ed25519, seed})
    on_exit(fn -> RequestSeal.Custody.Local.release(handle) end)
    {:ok, key} = RequestSeal.Custody.public_key(handle)
    {:ok, message} = Message.request("GET", "https://example.com/", [], nil)

    spec = %{
      label: "sig",
      algorithm: {:jws, "EdDSA"},
      components: ~s[("@method")],
      parameters: %{expires_in: 60}
    }

    assert {:ok, signed} = RequestSeal.sign(message, spec, handle)
    input = Enum.find(signed.fields, &(&1.name == "Signature-Input")).value
    refute input =~ ";alg="
    assert input =~ ";created="
    assert input =~ ";nonce="

    {:ok, policy} =
      RequestSeal.Policy.new(%{
        algorithms: [{:jws, "EdDSA"}],
        components: spec.components,
        key_resolver: fn _ -> {:ok, %{algorithm: {:jws, "EdDSA"}, key: key}} end,
        freshness: %{
          clock: fn -> System.system_time(:second) end,
          max_age: 60,
          skew: 0,
          require_expires: true
        },
        content: :not_required,
        replay: :not_required
      })

    assert {:ok, %{signature: %{crypto: :valid}}} =
             RequestSeal.verify(signed, policy, label: "sig")

    assert {:error, %{reason: :invalid_options}} =
             RequestSeal.sign(message, Map.put(spec, :alg, true), handle)
  end

  @tag :a4
  test "sign spec separates explicit input from core function and key handle" do
    Code.Typespec.fetch_specs(RequestSeal)
    |> elem(1)
    |> Enum.find(fn {name, _} -> name == {:sign, 4} end)
    |> then(fn {_, clauses} -> assert length(clauses) == 4 end)
  end

  @tag :a5
  test "builder normalizes origin like Finch and rejects fragments and invalid UTF-8" do
    assert {:error, %Message.Error{reason: :invalid_message}} =
             Message.request("GET", "https://example.com#frag", [], nil)

    assert {:ok, message} = Message.request("GET", "HTTPS://Example.COM:443/x", [], nil)

    assert {message.scheme, message.authority, message.raw_target} ==
             {"https", "example.com", "/x"}

    {:ok, finch} =
      RequestSeal.Finch.request_message(Finch.build(:get, "HTTPS://Example.COM:443/x"))

    assert {message.scheme, message.authority, message.raw_target} ==
             {finch.scheme, finch.authority, finch.raw_target}

    assert {:error, %Message.Error{reason: :invalid_message}} =
             Message.request("GET", <<"https://example.com/", 255>>, [], nil)
  end
end
