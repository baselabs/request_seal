# Owned integrations require Elixir 1.20 and are omitted on older lanes.
if Version.match?(System.version(), ">= 1.20.0") do
  defmodule RequestSeal.PublicAPIInventoryTest do
    use ExUnit.Case, async: true

    test "every documented module and entry exactly matches the reviewed public inventory" do
      for module <- [
            Req,
            Finch,
            Plug.Conn,
            Ash,
            AshHooks.Provider,
            Postgrex,
            AshOnetime.Transaction,
            RequestSeal.Req,
            RequestSeal.Finch,
            RequestSeal.Plug,
            RequestSeal.Ash,
            RequestSeal.AshHooks,
            RequestSeal.Replay.Postgres,
            RequestSeal.Replay.AshOnetime
          ] do
        Code.ensure_loaded!(module)
      end

      {:ok, modules} = :application.get_key(:request_seal, :modules)

      actual =
        modules
        |> Enum.sort()
        |> Enum.filter(fn module ->
          source = module.module_info(:compile) |> Keyword.fetch!(:source) |> List.to_string()
          String.contains?(source, "/lib/")
        end)
        |> Enum.flat_map(fn module ->
          Code.ensure_loaded!(module)
          {:docs_v1, _, _, _, moduledoc, _, entries} = Code.fetch_docs(module)

          if moduledoc == :hidden do
            []
          else
            exports =
              for {{kind, name, arity}, _, _, doc, _} <- entries,
                  doc != :hidden,
                  kind in [:function, :macro, :type, :callback, :macrocallback],
                  do: "#{kind} #{name}/#{arity}"

            [{inspect(module), Enum.sort(exports)}]
          end
        end)
        |> Map.new()

      expected = "test/fixtures/public_api_inventory.json" |> File.read!() |> :json.decode()
      differences = differences(expected, actual)
      assert differences == [], "Documented API drift:\n" <> Enum.join(differences, "\n")
    end

    defp differences(expected, actual) do
      (Map.keys(expected) ++ Map.keys(actual))
      |> Enum.uniq()
      |> Enum.sort()
      |> Enum.flat_map(fn module ->
        cond do
          not Map.has_key?(expected, module) ->
            ["added module #{module}" | Enum.map(actual[module], &"added #{module} #{&1}")]

          not Map.has_key?(actual, module) ->
            ["removed module #{module}" | Enum.map(expected[module], &"removed #{module} #{&1}")]

          true ->
            Enum.map(actual[module] -- expected[module], &"added #{module} #{&1}") ++
              Enum.map(expected[module] -- actual[module], &"removed #{module} #{&1}")
        end
      end)
    end
  end
end
