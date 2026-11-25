defmodule RequestSeal.AssignedHTTPBaseTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Custody, FieldOccurrence, Message, Policy, SignatureBase}
  alias RequestSeal.Custody.{Context, Gate, Local}
  alias RequestSeal.Replay.ETS
  alias RequestSeal.StructuredFields.Schema

  @now 1_700_000_000
  @request_components ~w(@method @target-uri @authority @scheme @request-target @path @query)
  @fields [
    {"x-tab", "left\tright"},
    {"x-tab", ""},
    {"x-bin", <<255, 0x20>>},
    {"x-bin", ""},
    {"x-item", "\"item\";v=1"},
    {"x-list", "a, (b c)"},
    {"x-dict", "a=1, b=(x y);on"},
    {"x-modern", "@123"}
  ]

  test "builder bases round-trip through assigned signing, both verifiers and admission" do
    derived = Enum.map(@request_components, &~s["#{&1}"])
    request_components = derived ++ [~s["@query-param";name="q"]]

    field_components = [
      ~s["x-tab"],
      ~s["x-bin";bs],
      ~s["x-item";sf],
      ~s["x-list";sf],
      ~s["x-dict"],
      ~s["x-dict";bs],
      ~s["x-dict";sf],
      ~s["x-dict";key="b"],
      ~s["x-dict";sf;key="a"],
      ~s["x-modern";sf]
    ]

    schemas = %{
      "x-item" => schema(:item, :rfc8941),
      "x-list" => schema(:list, :rfc8941),
      "x-dict" => schema(:dictionary, :rfc8941),
      "x-modern" => schema(:item, :rfc9651)
    }

    url = "https://example.test:8443/items?q=a%20b"
    {:ok, request} = Message.request("GET", url, @fields, nil)
    request = %{request | trailers: trailers()}
    {:ok, response} = Message.response(204, @fields, nil, request: request)
    response = %{response | trailers: trailers()}

    request_ids =
      request_components ++ field_components ++ Enum.map(field_components, &(&1 <> ";tr"))

    response_fields =
      for field <- field_components, suffix <- ["", ";tr", ";req", ";tr;req"], do: field <> suffix

    response_ids =
      [~s["@status"]] ++ Enum.map(request_components, &(&1 <> ";req")) ++ response_fields

    {_, seed} = :crypto.generate_key(:eddsa, :ed25519)
    {:ok, handle} = Local.new("ed25519", {:ed25519, seed}, issued_for: :release)
    {:ok, public} = Custody.public_key(handle)
    store = start_supervised!({ETS, max_entries: 256})

    cases =
      for {message, ids} <- [{request, request_ids}, {response, response_ids}],
          components <- [ids | Enum.map(ids, &[&1])],
          do: {message, components}

    cases =
      cases ++
        [
          {%{request | target_form: :absolute, raw_target: url}, request_components},
          {%{request | method: "OPTIONS", target_form: :asterisk, raw_target: "*"}, derived},
          {%{request | method: "CONNECT", target_form: :authority, raw_target: request.authority},
           derived}
        ]

    for {{message, ids}, index} <- Enum.with_index(cases) do
      components = "(" <> Enum.join(ids, " ") <> ")"
      input = components <> ~s[;created=1700000000;expires=1700000030;nonce="once";tag="test"]
      {:ok, base} = SignatureBase.build(message, input, field_schemas: schemas)
      assert {:ok, _} = SignatureBase.parse(base)

      spec = %{
        label: "sig",
        algorithm: "ed25519",
        signature_input: input,
        issued_for: :release
      }

      assert {:ok, signed} = RequestSeal.sign(message, spec, handle, field_schemas: schemas)
      assert {:ok, _} = RequestSeal.verify(signed, policy(handle, schemas), label: "sig")
      assert {:ok, _} = RequestSeal.verify(signed, policy(public, schemas), label: "sig")

      {:ok, digest} = Gate.commitment(message, components, field_schemas: schemas)

      admission = %Gate.Admission{
        decision: Integer.to_string(index),
        commitment: digest,
        not_after: @now + 30
      }

      config = %{
        algorithm: "ed25519",
        port: fn _, _ -> {:allow, admission} end,
        once: {:store, ETS.store(store), "wire"},
        required_components: ids,
        max_lifetime: 30,
        clock: fn -> @now end,
        skew: 0,
        tag: "test"
      }

      assert {:ok, %Gate.Admitted{}} = Gate.check(base, config, context())
    end
  end

  defp trailers do
    for {name, value} <- @fields do
      {:ok, occurrence} = FieldOccurrence.new(%{name: name, value: value, section: :trailers})
      occurrence
    end
  end

  defp schema(type, revision) do
    {:ok, schema} =
      Schema.new(%{
        type: type,
        revision: revision,
        inner_lists: type != :item,
        item_types: Schema.types(revision)
      })

    schema
  end

  defp policy(key, schemas) do
    {:ok, policy} =
      Policy.new(%{
        algorithms: ["ed25519"],
        components: "()",
        content: :not_required,
        freshness: :not_evaluated,
        replay: :not_required,
        field_schemas: schemas,
        require_issued_for: :release,
        key_resolver: fn _ ->
          {:ok, %{algorithm: "ed25519", key: key, issued_for: :release}}
        end
      })

    policy
  end

  defp context do
    %Context{owner: self(), deadline: System.monotonic_time(:millisecond) + 5_000}
  end
end
