defmodule RequestSeal.PropertySupport do
  @moduledoc false
  # Generated grammar and cryptographic checks derive from public specifications:
  # https://www.rfc-editor.org/rfc/rfc9651.html
  # https://www.rfc-editor.org/rfc/rfc9421.html#section-2.5
  # https://www.rfc-editor.org/rfc/rfc7515.html
  # https://www.rfc-editor.org/rfc/rfc7516.html
  # https://www.rfc-editor.org/rfc/rfc7517.html
  # https://www.rfc-editor.org/rfc/rfc8259.html
  import StreamData
  alias RequestSeal.{Body, Crypto, FieldOccurrence, Message, PublicKey, TransportFacts}
  alias RequestSeal.StructuredFields.{Schema, Value}

  def schema(type) do
    {:ok, schema} =
      Schema.new(%{
        revision: :rfc9651,
        type: type,
        item_types: Schema.types(:rfc9651),
        inner_lists: true
      })

    schema
  end

  def bare do
    one_of([
      map(integer(-999_999_999_999_999..999_999_999_999_999), &{:integer, &1}),
      map(integer(-999_999_999_999_999..999_999_999_999_999), &{:date, &1}),
      map(boolean(), &{:boolean, &1}),
      map(binary(max_length: 40), &{:bytes, &1}),
      map(string(:ascii, max_length: 40), &{:string, &1}),
      map(string(:alphanumeric, max_length: 40), &{:token, "a" <> &1}),
      map(string(:utf8, max_length: 20), &{:display_string, &1}),
      # Canonical decimal representations retain scale on parse/serialize.
      map(integer(-999_999_999..999_999_999), fn n ->
        {:decimal, {n * 10 + if(n < 0, do: -1, else: 1), 1}}
      end)
    ])
  end

  # RFC 9651 Section 4.2.3.3: keys and parameter names share this grammar.
  def key_name do
    bind(member_of(Enum.to_list(?a..?z) ++ [?*]), fn first ->
      map(
        list_of(member_of(Enum.to_list(?a..?z) ++ Enum.to_list(?0..?9) ++ ~c"_-.*"),
          max_length: 15
        ),
        &List.to_string([first | &1])
      )
    end)
  end

  def parameters do
    uniq_list_of(tuple({key_name(), bare()}), max_length: 5, uniq_fun: &elem(&1, 0))
  end

  def ows, do: member_of(["", " ", "\t", " \t "])

  def parsing_dictionary do
    gen = tuple({key_name(), key_name(), integer(-100..100), integer(-100..100), ows()})

    map(gen, fn {key, parameter, first, last, whitespace} ->
      {key <>
         "=" <>
         Integer.to_string(first) <>
         ";" <>
         parameter <>
         "=1," <>
         whitespace <>
         key <> "=" <> Integer.to_string(last) <> ";" <> parameter <> "=2;" <> parameter <> "=3",
       %Value{
         type: :dictionary,
         value: [
           {key,
            %Value{type: :item, value: {:integer, last}, parameters: [{parameter, {:integer, 3}}]}}
         ]
       }}
    end)
  end

  def signature_case do
    map(
      tuple(
        {key_name(), string(:alphanumeric, min_length: 1, max_length: 12),
         member_of(["%2F", "%20", "%25", "%C3%A9"]), integer(-100..100)}
      ),
      fn {key, value, encoded, number} ->
        target = "/" <> value <> encoded <> "?q=" <> value <> encoded <> "&other=1"
        dictionary = key <> "=" <> Integer.to_string(number)

        components = [
          ~s["@path"],
          ~s["@query"],
          ~s["@query-param";name="q"],
          ~s["x-covered";sf],
          ~s["x-covered";bs],
          ~s["x-covered";key="#{key}"]
        ]

        %{
          message: message(dictionary, target),
          components: components,
          options: [field_schemas: %{"x-covered" => schema(:dictionary)}],
          key: key,
          dictionary: dictionary,
          number: number,
          target: target,
          query_value: value <> encoded
        }
      end
    )
  end

  def item do
    bind(bare(), fn value ->
      map(parameters(), &%Value{type: :item, value: value, parameters: &1})
    end)
  end

  def member do
    one_of([
      item(),
      bind(list_of(item(), max_length: 5), fn items ->
        map(parameters(), &%Value{type: :inner_list, value: items, parameters: &1})
      end)
    ])
  end

  def value(:item), do: item()
  def value(:list), do: map(list_of(member(), max_length: 8), &%Value{type: :list, value: &1})

  def value(:dictionary) do
    map(
      uniq_list_of(tuple({key_name(), member()}), max_length: 8, uniq_fun: &elem(&1, 0)),
      fn members ->
        %Value{type: :dictionary, value: members}
      end
    )
  end

  def change(bytes, index, mask \\ 1) do
    index = rem(index, byte_size(bytes))
    <<head::binary-size(^index), byte, tail::binary>> = bytes
    head <> <<Bitwise.bxor(byte, mask)>> <> tail
  end

  def message(value, target \\ "/path") do
    {:ok, field} = FieldOccurrence.new(%{name: "x-covered", value: value, section: :headers})
    {:ok, body} = Body.new(%{state: :unavailable})
    {:ok, transport} = TransportFacts.new(%{})

    {:ok, m} =
      Message.new(%{
        kind: :request,
        method: "POST",
        raw_target: target,
        target_form: :origin,
        scheme: "https",
        authority: "example.com",
        fields: [field],
        trailers: :unavailable,
        body: body,
        transport: transport
      })

    m
  end

  # Property seeds reproduce Ed25519 seeds and P-256 private scalars.
  # RSA key generation, ECDSA signing nonces, and JWE CEKs/IVs remain random.
  def keys(seed \\ 9421) do
    ed_seed = :crypto.hash(:sha256, :erlang.term_to_binary({:ed25519, seed}))
    {ed, ^ed_seed} = :crypto.generate_key(:eddsa, :ed25519, ed_seed)
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    hash = :crypto.hash(:sha256, :erlang.term_to_binary({:p256, seed}))
    scalar = <<rem(:binary.decode_unsigned(hash), order - 1) + 1::unsigned-big-size(256)>>
    {point, ^scalar} = :crypto.generate_key(:ecdh, :secp256r1, scalar)
    {:ok, ed_public} = PublicKey.import({:ed25519, ed}, :raw)
    {:ok, ec_public} = PublicKey.import({:ec, "P-256", point}, :raw)

    [
      {"ed25519", {:ed25519, ed_seed}, ed_public},
      {"ecdsa-p256-sha256", {:ec, "P-256", scalar}, ec_public}
    ]
  end

  def jose(seed \\ 7516) do
    [{_, material, public} | _] = keys(seed)
    signer = fn alg, base -> Crypto.sign(alg, base, material) end

    jws = %{
      algorithms: ["EdDSA"],
      timeout: 5000,
      key_resolver: fn _ -> {:ok, %{algorithm: "EdDSA", key: public}} end
    }

    # Caller-owned custody holds the CEK generated by the real encryptor.
    {:ok, owner} = Agent.start_link(fn -> nil end)

    wrap = fn "dir", cek ->
      Agent.update(owner, fn _ -> cek end)
      {:ok, %{encrypted_key: "", header: %{}}}
    end

    jwe = %{
      algorithms: ["dir"],
      encryption: ["A256GCM"],
      max_plaintext: 1_048_576,
      timeout: 5000,
      key_resolver: fn _ ->
        {:ok,
         %{
           algorithm: "dir",
           unwrap: fn ek, h ->
             RequestSeal.JOSE.KeyManagement.unwrap("dir", ek, h, {:cek, Agent.get(owner, & &1)})
           end
         }}
      end
    }

    %{signer: signer, jws: jws, jwe: jwe, wrap: wrap, owner: owner}
  end

  def source(type, attrs \\ %{}) do
    {:ok, source} =
      RequestSeal.Discovery.Source.new(
        Map.merge(
          %{type: type, location: "https://example.com/", require_signed_directory: false},
          attrs
        )
      )

    source
  end

  def jwks(count, seed \\ 7517) do
    keys =
      for i <- 1..count do
        private = :crypto.hash(:sha256, :erlang.term_to_binary({:jwks, seed, i}))
        {point, ^private} = :crypto.generate_key(:eddsa, :ed25519, private)
        {:ok, key} = PublicKey.import({:ed25519, point}, :raw)
        {:ok, jwk} = PublicKey.export(key, :jwk)
        jwk
      end

    :json.encode(%{"keys" => keys}) |> IO.iodata_to_binary()
  end
end
