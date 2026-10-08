defmodule RequestSeal.StructuredFieldsPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties
  alias RequestSeal.StructuredFields, as: SF
  alias RequestSeal.PropertySupport, as: P
  @seed 9651
  @runs 300

  for type <- [:item, :list, :dictionary] do
    property "#{type} parse/serialize round-trips canonical values" do
      type = unquote(type)

      check all(
              value <- P.value(type),
              max_runs: @runs,
              max_run_time: :infinity,
              initial_seed: @seed
            ) do
        assert {:ok, bytes} = SF.serialize(value, P.schema(type))
        assert SF.parse(bytes, P.schema(type)) == {:ok, value}
        assert {:ok, ^bytes} = SF.serialize(value, P.schema(type))
      end
    end
  end

  property "generated key grammar, OWS and duplicate names preserve last values" do
    check all(
            {bytes, expected} <- P.parsing_dictionary(),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      assert SF.parse(bytes, P.schema(:dictionary)) == {:ok, expected}

      assert {:error, %SF.Error{reason: :duplicate_key}} =
               SF.parse_unique(bytes, P.schema(:dictionary), [])

      [{key, member}] = expected.value
      [{parameter, _}] = member.parameters
      assert Regex.match?(~r/^[a-z*][a-z0-9_.*-]*$/, key)
      assert Regex.match?(~r/^[a-z*][a-z0-9_.*-]*$/, parameter)
      [{parameter, {:integer, last}}] = member.parameters
      repeated = key <> "=1;" <> parameter <> "=2;" <> parameter <> "=" <> Integer.to_string(last)

      assert {:error, %SF.Error{reason: :duplicate_parameter}} =
               SF.parse_unique(repeated, P.schema(:dictionary), [])
    end
  end

  property "random bytes and mutations return only typed results" do
    check all(
            bytes <- binary(max_length: 2048),
            value <- P.value(:dictionary),
            index <- non_negative_integer(),
            mask <- integer(1..255),
            max_runs: @runs,
            max_run_time: :infinity,
            initial_seed: @seed
          ) do
      assert {:ok, valid} = SF.serialize(value, P.schema(:dictionary))
      mutated = if valid == "", do: <<mask>>, else: P.change(valid, index, mask)

      for input <- [bytes, mutated], type <- [:item, :list, :dictionary] do
        case SF.parse(input, P.schema(type)) do
          {:ok, %SF.Value{}} -> :ok
          {:error, %SF.Error{}} -> :ok
          other -> flunk("unexpected result: #{inspect(other)}")
        end
      end
    end
  end

  property "each lowered ceiling accepts exactly the boundary and rejects one more" do
    check all(n <- integer(2..30), max_runs: @runs, max_run_time: :infinity, initial_seed: @seed) do
      cases = [
        {:max_bytes, :list, "a" <> String.duplicate(" ", n - 1), "a" <> String.duplicate(" ", n)},
        {:max_members, :list, Enum.join(List.duplicate("a", n), ","),
         Enum.join(List.duplicate("a", n + 1), ",")},
        {:max_inner_items, :list, "(" <> Enum.join(List.duplicate("a", n), " ") <> ")",
         "(" <> Enum.join(List.duplicate("a", n + 1), " ") <> ")"},
        {:max_parameters, :item, "a" <> String.duplicate(";p", n),
         "a" <> String.duplicate(";p", n + 1)},
        {:max_nodes, :list, Enum.join(List.duplicate("a", n - 1), ","),
         Enum.join(List.duplicate("a", n), ",")},
        {:max_key_bytes, :dictionary, String.duplicate("a", n), String.duplicate("a", n + 1)},
        {:max_value_bytes, :item, String.duplicate("a", n), String.duplicate("a", n + 1)}
      ]

      for {limit, type, accepted, rejected} <- cases do
        assert {:ok, parsed} = SF.parse(accepted, P.schema(type), [{limit, n}])

        assert {:error, %SF.Error{reason: :limit}} =
                 SF.parse(rejected, P.schema(type), [{limit, n}])

        assert {:ok, _} = SF.serialize(parsed, P.schema(type), [{limit, n}])
      end

      # Grammar depth is fixed at three containers/items, rather than configurable.
      assert {:ok, _} = SF.parse("(" <> Integer.to_string(n) <> ")", P.schema(:list))

      assert {:error, %SF.Error{}} =
               SF.parse("((" <> Integer.to_string(n) <> "))", P.schema(:list))
    end
  end

  test "default ceilings and serialization reject ceiling plus one" do
    cases = [
      {:max_bytes, :list, "a" <> String.duplicate(" ", 65_535),
       "a" <> String.duplicate(" ", 65_536)},
      {:max_members, :list, Enum.join(List.duplicate("a", 1024), ","),
       Enum.join(List.duplicate("a", 1025), ",")},
      {:max_inner_items, :list, "(" <> Enum.join(List.duplicate("a", 256), " ") <> ")",
       "(" <> Enum.join(List.duplicate("a", 257), " ") <> ")"},
      {:max_parameters, :item, "a" <> String.duplicate(";p", 256),
       "a" <> String.duplicate(";p", 257)},
      {:max_nodes, :list, Enum.join(List.duplicate("a;p;q;r", 1023) ++ ["a;p;q"], ","),
       Enum.join(List.duplicate("a;p;q;r", 1024), ",")},
      {:max_key_bytes, :dictionary, String.duplicate("a", 256), String.duplicate("a", 257)},
      {:max_value_bytes, :item, String.duplicate("a", 16_384), String.duplicate("a", 16_385)}
    ]

    for {_limit, type, good, bad} <- cases do
      assert {:ok, _} = SF.parse(good, P.schema(type))
      assert {:error, %SF.Error{reason: :limit}} = SF.parse(bad, P.schema(type))
    end

    # Unique encounters exercise the serializer too, without parser deduplication.
    for {limit, type, good, bad, ceiling} <- [
          {:max_members, :list, "a,a", "a,a,a", 2},
          {:max_inner_items, :list, "(a a)", "(a a a)", 2},
          {:max_parameters, :item, "a;p;q", "a;p;q;r", 2},
          {:max_nodes, :list, "a", "a,a", 2},
          {:max_key_bytes, :dictionary, "aa", "aaa", 2},
          {:max_value_bytes, :item, "aa", "aaa", 2},
          {:max_bytes, :item, "aa", "aaa", 2}
        ] do
      assert {:ok, a} = SF.parse(good, P.schema(type))
      assert {:ok, b} = SF.parse(bad, P.schema(type))
      assert {:ok, _} = SF.serialize(a, P.schema(type), [{limit, ceiling}])

      assert {:error, %SF.Error{reason: :limit}} =
               SF.serialize(b, P.schema(type), [{limit, ceiling}])
    end
  end
end
