defmodule RequestSeal.JOSEObjectTest do
  use ExUnit.Case, async: true
  alias RequestSeal.JOSE
  alias RequestSeal.JOSE.{Error, JWE}
  import RequestSeal.JOSEVectors
  doctest JOSE

  test "RFC 8259 object values and each inclusive bound decode" do
    # RFC 8259 section 13's object example; no authentication is claimed here.
    bytes =
      ~s({"Image":{"Width":800,"Height":600,"Title":"View from 15th Floor","Thumbnail":{"Url":"http://www.example.com/image/481989943","Height":125,"Width":100},"Animated":false,"IDs":[116,943,234,38793]}})

    assert {:ok, %{"Image" => %{"Width" => 800}}} =
             JOSE.decode_object(bytes, max_bytes: byte_size(bytes))

    for object <- [
          %{},
          %{"a" => %{"b" => [%{"c" => nil}]}},
          Map.new(1..64, &{"k#{&1}", true}),
          %{"a" => List.duplicate(false, 64)},
          %{String.duplicate("k", 16_384) => String.duplicate("x", 16_384)},
          %{"min" => -999_999_999_999_999, "max" => 999_999_999_999_999}
        ] do
      bytes = RequestSeal.JOSE.Support.json_encode(object)
      assert JOSE.decode_object(bytes, max_bytes: byte_size(bytes)) == {:ok, object}
    end

    bytes = "{}" <> String.duplicate(" ", 1_048_574)
    assert JOSE.decode_object(bytes, max_bytes: 1_048_576) == {:ok, %{}}
    assert JOSE.decode_object("{}\t\r\n", max_bytes: 5) == {:ok, %{}}
  end

  test "options are exactly one required bounded byte limit" do
    for opts <- [
          [],
          [max_bytes: 0],
          [max_bytes: 1_048_577],
          [max_bytes: 1.0],
          [max_bytes: nil],
          [max_bytes: 1, max_bytes: 2],
          [max_bytes: 2, other: true],
          [other: 2],
          %{max_bytes: 2},
          [{:max_bytes, 2} | :tail],
          nil
        ] do
      assert {:error, %Error{reason: :invalid_options, layer: :input}} =
               JOSE.decode_object("{}", opts)
    end

    assert {:error, %Error{reason: :limit}} = JOSE.decode_object("{}", max_bytes: 1)
  end

  test "duplicates, malformed JSON and every exceeded tree bound refuse" do
    cases =
      [
        {~s({"a":1,"a":2}), :duplicate_member},
        {~s({"a":{"x":1,"x":2}}), :duplicate_member},
        {~s({"a":[{"x":1,"\\u0078":2}]}), :duplicate_member},
        {~s({"a":1.0}), :invalid_header},
        {~s({"a":1e1}), :invalid_header},
        {~s({"a":1e9999}), :invalid_header},
        {~s({"a":1000000000000000}), :limit},
        {~s({"a":-1000000000000000}), :limit},
        {~s({"a":[[[[]]]]}), :limit},
        {"{" <> Enum.map_join(1..65, ",", &~s("k#{&1}":null)) <> "}", :limit},
        {~s({"a":[) <> Enum.map_join(1..65, ",", fn _ -> "null" end) <> "]}", :limit},
        {~s({"a":") <> String.duplicate("x", 16_385) <> ~s("}), :limit},
        {~s({") <> String.duplicate("k", 16_385) <> ~s(":true}), :limit},
        {<<123, 34, 255, 34, 58, 49, 125>>, :invalid_header},
        {<<123, 34, 97, 34, 58, 34, 255, 34, 125>>, :invalid_header},
        {~S({"a":"\uD800"}), :invalid_header}
      ] ++
        Enum.map(
          ["[]", "null", "true", "1", ~s("text"), "", "{", "{}x", "{}\v", "{}{}"],
          &{&1, :invalid_header}
        )

    for {bytes, reason} <- cases do
      assert {:error, %Error{reason: ^reason, layer: :input}} =
               JOSE.decode_object(bytes, max_bytes: 1_048_576)
    end

    assert {:error, %Error{reason: :invalid_header}} = JOSE.decode_object(nil, max_bytes: 10)

    assert {:error, %Error{reason: :limit}} =
             JOSE.decode_object(String.duplicate(" ", 1_048_577), max_bytes: 1_048_576)
  end

  test "authenticated object failures return only the decoder error in single and batch opens" do
    handle = local({:jwe, "A256KW"}, {:aes, :crypto.strong_rand_bytes(32)})

    p = %{
      algorithms: ["A256KW"],
      encryption: ["A256GCM"],
      max_plaintext: 65_536,
      timeout: 5000,
      resolve_timeout: 1000,
      unwrap_timeout: 1000,
      content: :object,
      protected: %{expected: %{}, permitted: []},
      key_resolver: fn _ -> {:ok, %{algorithm: "A256KW", key: handle}} end
    }

    batch =
      p
      |> Map.put(:protected, %{permitted: []})
      |> Map.merge(%{
        max_tokens: 10,
        max_total_input: 1_048_576,
        max_total_plaintext: 1_048_576
      })

    id = {__MODULE__, make_ref()}

    :ok =
      :telemetry.attach(
        id,
        [:request_seal, :jose, :content_authentication],
        &__MODULE__.event/4,
        self()
      )

    try do
      for bytes <- [~s({"a":1,"a":2}), "[]", ~s({"a":1000000000000000}), ~s({"a":[[[[]]]]})] do
        assert {:ok, token} = JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], bytes, handle)
        expected = JOSE.decode_object(bytes, max_bytes: p.max_plaintext)
        assert JWE.decrypt(token, p) == expected
        assert_receive {:authentication, :ok}
        assert JWE.decrypt_many([%{token: token, expected: %{}}], batch) == {:ok, [expected]}
        assert_receive {:authentication, :ok}
        {:error, error} = expected
        refute Map.has_key?(error, :plaintext)
        refute inspect(error) =~ bytes

        assert {:error, %{reason: :decryption_failed}} =
                 JWE.decrypt(replace(token, 4, enc(<<0::128>>)), p)

        assert_receive {:authentication, :failed}
      end

      bytes = ~s({"ok":true})
      assert {:ok, token} = JWE.encrypt([{"alg", "A256KW"}, {"enc", "A256GCM"}], bytes, handle)
      assert {:ok, %{object: %{"ok" => true}, plaintext: ^bytes}} = JWE.decrypt(token, p)
      assert_receive {:authentication, :ok}

      assert {:ok, [%{object: %{"ok" => true}, plaintext: ^bytes}]} =
               JWE.decrypt_many([%{token: token, expected: %{}}], batch)

      assert_receive {:authentication, :ok}

      # RFC 7516 A.1 authenticates published bytes, then refuses its non-JSON payload.
      vector = fixture("rfc7516.json")

      assert {:error, %{reason: :invalid_header}} =
               JWE.decrypt(
                 vector["compact"],
                 Map.put(jwe_policy(vector["key"], "RSA-OAEP", "A256GCM"), :content, :object)
               )

      assert_receive {:authentication, :ok}
    after
      :telemetry.detach(id)
    end
  end

  def event(_, _, %{outcome: outcome}, owner), do: send(owner, {:authentication, outcome})
end
