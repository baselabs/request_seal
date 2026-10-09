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
end
