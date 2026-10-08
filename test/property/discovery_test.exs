defmodule RequestSeal.DiscoveryPropertyTest do
  use ExUnit.Case, async: true
  use ExUnitProperties
  alias RequestSeal.Discovery
  alias RequestSeal.Discovery.Error
  alias RequestSeal.PropertySupport, as: P
  @seed 7638
  @runs 300

  setup_all do: %{body: P.jwks(33, @seed)}

  for type <- [:jwks_uri, :directory] do
    property "#{type} random and mutated JSON never raises", %{body: body} do
      source = P.source(unquote(type), %{max_keys: 33})

      check all(
              bytes <- binary(max_length: 2048),
              index <- non_negative_integer(),
              mask <- integer(1..255),
              max_runs: @runs,
              max_run_time: :infinity,
              initial_seed: @seed
            ) do
        assert {:ok, keys} = Discovery.parse_body(body, source, 100)
        assert map_size(keys) == 33

        for input <- [bytes, P.change(body, index, mask)] do
          case Discovery.parse_body(input, source, 100) do
            {:ok, keys} when is_map(keys) -> :ok
            {:error, %Error{}} -> :ok
            other -> flunk("unexpected result: #{inspect(other)}")
          end
        end
      end
    end

    property "#{type} trailing bytes follow JSON whitespace grammar", %{body: body} do
      source = P.source(unquote(type), %{max_keys: 33})

      check all(
              suffix <- member_of(["\v", "\f", "\u00a0", "\u2003", <<0>>, "a"]),
              whitespace <- member_of([" ", "\t", "\r", "\n"]),
              max_runs: @runs,
              max_run_time: :infinity,
              initial_seed: @seed
            ) do
        assert {:ok, _} = Discovery.parse_body(body <> whitespace, source, 100)

        assert {:error, %Error{reason: :invalid_response}} =
                 Discovery.parse_body(body <> suffix, source, 100)
      end
    end

    property "#{type} key-count and body-byte boundaries hold", %{body: body} do
      all_keys = :json.decode(body)["keys"]

      check all(
              n <- integer(1..32),
              padding <- integer(0..512),
              max_runs: @runs,
              max_run_time: :infinity,
              initial_seed: @seed
            ) do
        source = P.source(unquote(type), %{max_keys: n})
        good = :json.encode(%{"keys" => Enum.take(all_keys, n)}) |> IO.iodata_to_binary()
        bad = :json.encode(%{"keys" => Enum.take(all_keys, n + 1)}) |> IO.iodata_to_binary()
        assert {:ok, keys} = Discovery.parse_body(good, source, 100)
        assert map_size(keys) == n
        assert {:error, %Error{reason: :limit}} = Discovery.parse_body(bad, source, 100)
        good = good <> String.duplicate(" ", padding)
        source = %{source | max_bytes: byte_size(good), max_decoded_bytes: byte_size(good)}
        assert {:ok, _} = Discovery.parse_body(good, source, 100)
        assert {:error, %Error{reason: :limit}} = Discovery.parse_body(good <> " ", source, 100)
      end
    end
  end

  test "body parsing refuses required directory proof and permits explicit unproven keys" do
    body = P.jwks(1)
    required = P.source(:directory, %{require_signed_directory: true})

    assert {:error, %Error{reason: :directory_unsigned}} =
             Discovery.parse_body(body, required, 100)

    for source <- [P.source(:directory), P.source(:jwks_uri, %{require_signed_directory: true})] do
      assert {:ok, keys} = Discovery.parse_body(body, source, 100)
      assert map_size(keys) == 1
    end
  end

  test "maximum key count and decoded body ceilings remain independently enforced" do
    body = P.jwks(256)
    keys = :json.decode(body)["keys"]
    too_many = :json.encode(%{"keys" => keys ++ [hd(keys)]}) |> IO.iodata_to_binary()

    for type <- [:jwks_uri, :directory] do
      source = P.source(type, %{max_keys: 256})
      assert {:ok, all} = Discovery.parse_body(body, source, 100)
      assert map_size(all) == 256
      assert {:error, %Error{reason: :limit}} = Discovery.parse_body(too_many, source, 100)
      source = %{source | max_decoded_bytes: byte_size(body)}
      assert {:ok, _} = Discovery.parse_body(body, source, 100)
      assert {:error, %Error{reason: :limit}} = Discovery.parse_body(body <> " ", source, 100)
    end
  end

  test "default key and body ceilings apply to both formats", %{body: body} do
    keys = :json.decode(body)["keys"]
    good = :json.encode(%{"keys" => Enum.take(keys, 32)}) |> IO.iodata_to_binary()

    for type <- [:jwks_uri, :directory] do
      source = P.source(type)
      assert {:ok, _} = Discovery.parse_body(good, source, 100)
      assert {:error, %Error{reason: :limit}} = Discovery.parse_body(body, source, 100)
      padded = good <> String.duplicate(" ", 65_536 - byte_size(good))
      assert {:ok, _} = Discovery.parse_body(padded, source, 100)
      assert {:error, %Error{reason: :limit}} = Discovery.parse_body(padded <> " ", source, 100)
    end
  end
end
