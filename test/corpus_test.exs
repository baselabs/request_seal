defmodule RequestSeal.CorpusTest do
  use ExUnit.Case, async: false

  test "Appendix B.4 bases and transformations compare independently to published bytes" do
    alias RequestSeal.Conformance, as: C
    alias RequestSeal.Conformance.Surfaces

    vectors = C.json(File.read!("corpus/sources/rfc9421/rfc9421.json"))
    vector = Enum.find(vectors, &(&1["section"] == "B.4"))
    assert Surfaces.signature_base_item("corpus", vector)

    assert length(vector["transformations"]) == 5
    assert Enum.count(vector["transformations"], & &1["same_base"]) == 3

    for transformation <- vector["transformations"] do
      item = Map.merge(Map.take(vector, ["parameters", "base"]), transformation)
      assert Surfaces.signature_base_item("corpus", item)
      refute Surfaces.signature_base_item("corpus", Map.update!(item, "same_base", &(!&1)))
    end
  end

  test "the complete corpus executes once with no disagreements" do
    assert File.regular?("corpus/index.json"), "the corpus index must exist"
    assert {:ok, report} = RequestSeal.Conformance.run("corpus")
    assert report.executed + report.not_applicable == report.singles + report.batch_items
    assert report.not_applicable == report.not_applicable_declared
    assert report.disagreements == []

    IO.puts(
      "CORPUS singles=#{report.singles} batches=#{report.batches} batch_items=#{report.batch_items} asserted=#{report.batch_items - report.not_applicable} not_applicable_declared=#{report.not_applicable_declared} not_applicable_counted=#{report.not_applicable} executed=#{report.executed} disagreements=0"
    )
  end

  test "native protected surface executes expected and permitted acceptance and refusals" do
    alias RequestSeal.Conformance, as: C
    index = C.json(File.read!("corpus/index.json"))
    entries = Enum.filter(index["cases"], &(&1["surface"] == "jwe.protected/v1"))
    assert length(entries) >= 5

    for entry <- entries do
      case_ = C.json(File.read!(Path.join("corpus", entry["manifest"])))
      actual = RequestSeal.Conformance.Surfaces.run("corpus", case_)

      case case_["expected"] do
        %{"rule_id" => rule} ->
          assert {:error, error} = actual
          assert C.rule_id(error) == rule

        expected ->
          assert actual == {:ok, expected}
      end
    end
  end

  test "native batch surface isolates forged width-failed and released-key items" do
    alias RequestSeal.Conformance, as: C
    case_ = C.json(File.read!("corpus/cases/jwe/native-r7-isolation.json"))
    assert RequestSeal.Conformance.Surfaces.run("corpus", case_) == {:ok, case_["expected"]}
  end

  test "batch adapter rejects a resolver invocation without a declared index outcome" do
    alias RequestSeal.Conformance, as: C
    case_ = C.json(File.read!("corpus/cases/jwe/native-r7-isolation.json"))
    case_ = put_in(case_, ["inputs", "resolver"], [])

    assert catch_throw(RequestSeal.Conformance.Surfaces.run("corpus", case_)) ==
             {:corpus, :unexpected_resolver_call}
  end

  test "native embedded key cases cover require refuse and every refusal shape" do
    alias RequestSeal.Conformance, as: C
    index = C.json(File.read!("corpus/index.json"))
    entries = Enum.filter(index["cases"], &String.starts_with?(&1["id"], "jws/native-embedded-"))
    assert length(entries) >= 25

    for entry <- entries do
      case_ = C.json(File.read!(Path.join("corpus", entry["manifest"])))
      actual = RequestSeal.Conformance.Surfaces.run("corpus", case_)

      case case_["expected"] do
        %{"rule_id" => rule} ->
          assert {:error, error} = actual
          assert C.rule_id(error) == rule

        expected ->
          assert actual == {:ok, expected}
      end
    end
  end

  test "batch corpus routes identical headers with identical outcomes to one real handle" do
    alias RequestSeal.Conformance, as: C
    case_ = C.json(File.read!("corpus/cases/jwe/native-r7-isolation.json"))
    item = hd(case_["inputs"]["items"])
    first = hd(case_["expected"]["results"])

    inputs = %{
      "items" => [item, item],
      "keys" => Map.take(case_["inputs"]["keys"], ["0"]),
      "resolver" =>
        for(index <- 0..1, do: %{"index" => C.number(index), "outcome" => %{"key" => "0"}})
    }

    case_ = %{case_ | "inputs" => inputs}

    assert RequestSeal.Conformance.Surfaces.run("corpus", case_) ==
             {:ok, %{"results" => [first, Map.put(first, "index", C.number(1))]}}
  end

  test "batch corpus preserves malformed positional input without parsing it in the adapter" do
    alias RequestSeal.Conformance, as: C
    case_ = C.json(File.read!("corpus/cases/jwe/native-r7-isolation.json"))
    item = hd(case_["inputs"]["items"])
    first = hd(case_["expected"]["results"])

    inputs = %{
      "items" => [item, %{"token" => "not-a-token", "expected" => %{"pairs" => []}}],
      "keys" => Map.take(case_["inputs"]["keys"], ["0"]),
      "resolver" => [%{"index" => C.number(0), "outcome" => %{"key" => "0"}}]
    }

    case_ = %{case_ | "inputs" => inputs}

    assert RequestSeal.Conformance.Surfaces.run("corpus", case_) ==
             {:ok,
              %{
                "results" => [
                  first,
                  %{"index" => C.number(1), "rule_id" => "jose/input.invalid_serialization"}
                ]
              }}
  end
end
