defmodule RequestSeal.GuideJsonObjectContentTest do
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
        "docs/guides/json-object-content.md",
        1
      )

    binding =
      E.eval(
        ~S'''
        {:ok, %{"active" => true, "count" => 3, "note" => nil}} =
          RequestSeal.JOSE.decode_object(~s({"active":true,"count":3,"note":null}), max_bytes: 1024)

        {:error, %{reason: :duplicate_member, layer: :input}} =
          RequestSeal.JOSE.decode_object(~s({"count":1,"count":2}), max_bytes: 1024)
        {:error, %{reason: :invalid_header, layer: :input}} =
          RequestSeal.JOSE.decode_object(~s({"count":1.5}), max_bytes: 1024)
        {:error, %{reason: :invalid_header, layer: :input}} = RequestSeal.JOSE.decode_object("[]", max_bytes: 1024)
        {:error, %{reason: :limit, layer: :input}} = RequestSeal.JOSE.decode_object("{}", max_bytes: 1)
        {:error, %{reason: :invalid_options, layer: :input}} = RequestSeal.JOSE.decode_object("{}", [])
        ''',
        binding,
        "docs/guides/json-object-content.md",
        2
      )

    binding =
      E.eval(
        ~S'''
        {:ok, handle} = RequestSeal.Custody.Local.generate({:jwe, "A256KW"}, [])
        header = [{"alg", "A256KW"}, {"enc", "A256GCM"}, {"cty", "application/json"}]
        bytes = ~s({"active":true,"count":3})
        {:ok, token} = RequestSeal.JOSE.JWE.encrypt(header, bytes, handle)

        policy = %{
          algorithms: ["A256KW"],
          encryption: ["A256GCM"],
          max_plaintext: 4096,
          timeout: 5_000,
          resolve_timeout: 1_000,
          unwrap_timeout: 1_000,
          protected: %{expected: %{"cty" => "application/json"}, permitted: []},
          key_resolver: fn _ -> {:ok, %{algorithm: "A256KW", key: handle}} end,
          content: :object
        }

        {:ok, result} = RequestSeal.JOSE.JWE.decrypt(token, policy)
        %{"active" => true, "count" => 3} = result.object
        ^bytes = result.plaintext
        :valid = result.recipient_integrity
        :not_evaluated = result.authorization
        ''',
        binding,
        "docs/guides/json-object-content.md",
        3
      )

    binding =
      E.eval(
        ~S'''
        {:ok, invalid_object_token} = RequestSeal.JOSE.JWE.encrypt(header, ~s({"count":1,"count":2}), handle)
        {:error, decode_error} = RequestSeal.JOSE.JWE.decrypt(invalid_object_token, policy)
        :duplicate_member = decode_error.reason
        :input = decode_error.layer
        false = Map.has_key?(decode_error, :plaintext)
        false = Map.has_key?(decode_error, :object)

        [protected, encrypted_key, iv, ciphertext, tag] = String.split(invalid_object_token, ".")
        <<first, rest::binary>> = Base.url_decode64!(tag, padding: false)
        changed_tag = Base.url_encode64(<<Bitwise.bxor(first, 1), rest::binary>>, padding: false)
        forged = Enum.join([protected, encrypted_key, iv, ciphertext, changed_tag], ".")
        {:error, %{reason: :decryption_failed, layer: :crypto}} = RequestSeal.JOSE.JWE.decrypt(forged, policy)
        ''',
        binding,
        "docs/guides/json-object-content.md",
        4
      )

    binding =
      E.eval(
        ~S'''
        batch_policy =
          policy
          |> Map.put(:protected, %{permitted: []})
          |> Map.merge(%{max_tokens: 2, max_total_input: 16_384, max_total_plaintext: 8192})

        items =
          for compact <- [token, invalid_object_token] do
            %{token: compact, expected: %{"cty" => "application/json"}}
          end

        {:ok, [
          {:ok, %{object: %{"active" => true, "count" => 3}, plaintext: ^bytes}},
          {:error, %{reason: :duplicate_member, layer: :input}}
        ]} = RequestSeal.JOSE.JWE.decrypt_many(items, batch_policy)

        :ok = RequestSeal.Custody.release(handle)
        ''',
        binding,
        "docs/guides/json-object-content.md",
        5
      )

    assert is_list(binding)
    E.assert_fences("docs/guides/json-object-content.md", 5)
  end
end
