defmodule RequestSeal.Slice1ContractTest do
  use ExUnit.Case, async: true

  test "every stable dependency range starts at its locked version and ends at the next major" do
    lock = Mix.Dep.Lock.read()

    for {name, requirement, _options} <-
          Enum.map(Mix.Project.config()[:deps], fn
            {name, requirement} -> {name, requirement, []}
            dep -> dep
          end),
        name != :ash_onetime,
        {:hex, _, locked, _, _, _, _, _} = lock[name],
        version = Version.parse!(locked),
        version.major >= 1 do
      assert requirement == ">= #{locked} and < #{version.major + 1}.0.0", Atom.to_string(name)
    end
  end

  test "RFC 3394 ledger accounts for every upstream item with executable wrap and unwrap cases" do
    alias RequestSeal.Conformance, as: C
    index = C.json(File.read!("corpus/index.json"))
    ledger = C.json(File.read!("corpus/sources/rfc3394/ledger.json"))
    assert Enum.sort(Enum.map(ledger, & &1["item"])) == ~w(4.1 4.2 4.3 4.4 4.5 4.6)

    for row <- ledger do
      assert Map.has_key?(row, "case") != Map.has_key?(row, "excluded")
      entry = Enum.find(index["cases"], &(&1["id"] == row["case"]))
      assert entry
      case_ = C.json(File.read!(Path.join("corpus", entry["manifest"])))
      assert case_["surface"] == "key_management.aes_kw/v1"
      assert case_["class"] == if(row["item"] in ~w(4.2 4.4), do: "rejection", else: "byte_exact")

      for id <- [row["case"], row["case"] <> "-unwrap"] do
        entry = Enum.find(index["cases"], &(&1["id"] == id))
        case_ = C.json(File.read!(Path.join("corpus", entry["manifest"])))
        result = RequestSeal.Conformance.Surfaces.run("corpus", case_)

        if case_["class"] == "rejection" do
          assert {:error, %{reason: :algorithm_mismatch, layer: :key}} = result
        else
          assert {:ok, actual} = result
          assert actual == case_["expected"]
        end
      end
    end
  end
end
