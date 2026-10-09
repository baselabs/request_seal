defmodule RequestSeal.CorpusValidationTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Conformance, as: C
  alias RequestSeal.Conformance.Canonical

  defp changed(fun) do
    root =
      Path.join(
        System.tmp_dir!(),
        "requestseal-corpus-validation-#{System.unique_integer([:positive])}"
      )

    try do
      File.cp_r!("corpus", root)
      # Start from the tracked corpus only: Finder may have written .DS_Store into a
      # macOS checkout, and each test plants its own.
      for path <- Path.wildcard(Path.join(root, "**/.DS_Store"), match_dot: true),
          do: File.rm_rf!(path)

      index = C.json(File.read!(Path.join(root, "index.json")))
      index = fun.(root, index)

      index =
        update_in(
          index,
          ["files"],
          &Enum.map(&1, fn f ->
            Map.put(f, "sha256", C.sha(File.read!(Path.join(root, f["path"]))))
          end)
        )

      raw = Canonical.encode(index)
      File.write!(Path.join(root, "index.json"), raw)
      C.run(root, index_sha256: C.sha(raw))
    after
      File.rm_rf!(root)
    end
  end

  defp manifest(root, index, id, fun) do
    e = Enum.find(index["cases"], &(&1["id"] == id))
    path = Path.join(root, e["manifest"])
    File.write!(path, Canonical.encode(fun.(C.json(File.read!(path)))))
    index
  end

  test "both consumers reject root files and unexpected root directories" do
    for path <- ["EXTRA.txt", "hidden/z.bin"] do
      assert {:error, :unlisted_file} =
               changed(fn root, index ->
                 File.mkdir_p!(Path.dirname(Path.join(root, path)))
                 File.write!(Path.join(root, path), "unlisted")

                 {output, status} =
                   System.cmd("python3", ["scripts/verify_corpus.py", root],
                     stderr_to_stdout: true
                   )

                 assert status != 0, output
                 index
               end)
    end
  end

  test "both consumers reject nonmetadata .DS_Store files" do
    for folder <- ["", "sources", "cases"],
        content <- [
          "unverified content",
          <<0, 0, 0, 1, "Bud">>,
          "prefix" <> <<0, 0, 0, 1, "Bud1">>
        ] do
      assert {:error, :unlisted_file} =
               changed(fn root, index ->
                 File.write!(Path.join([root, folder, ".DS_Store"]), content)
                 assert {:error, :unlisted_file} = C.run(root)
                 assert_python_rejects(root, "unlisted_file")
                 index
               end)
    end
  end

  test "both consumers reject .DS_Store directories" do
    for folder <- ["", "sources", "cases"] do
      assert {:error, :unlisted_file} =
               changed(fn root, index ->
                 path = Path.join([root, folder, ".DS_Store"])
                 File.mkdir_p!(path)
                 File.write!(Path.join(path, "unverified.txt"), "unverified content")
                 assert {:error, :unlisted_file} = C.run(root)
                 assert_python_rejects(root, "unlisted_file")
                 index
               end)
    end
  end

  test "both consumers reject .DS_Store symlinks" do
    for folder <- ["", "sources", "cases"] do
      assert {:error, :unlisted_file} =
               changed(fn root, index ->
                 path = Path.join([root, folder, ".DS_Store"])
                 File.ln_s!(Path.join(root, "index.json"), path)
                 assert {:error, :unlisted_file} = C.run(root)
                 assert_python_rejects(root, "unlisted_file")
                 index
               end)
    end
  end

  test "both consumers skip only empty files or Finder magic .DS_Store files" do
    for content <- ["", <<0, 0, 0, 1, "Bud1">>, <<0, 0, 0, 1, "Bud1", 0, 1, 2>>] do
      assert {:ok, _} =
               changed(fn root, index ->
                 for folder <- ["", "sources", "cases"] do
                   File.write!(Path.join([root, folder, ".DS_Store"]), content)
                 end

                 {output, status} =
                   System.cmd("python3", ["scripts/verify_corpus.py", root],
                     stderr_to_stdout: true
                   )

                 assert status == 0, output
                 assert output =~ "PASS: corpus canonical metadata"
                 index
               end)
    end
  end

  defp assert_python_rejects(root, reason) do
    {output, status} =
      System.cmd("python3", ["scripts/verify_corpus.py", root], stderr_to_stdout: true)

    assert status != 0, output
    assert output =~ reason
  end

  test "positive references require an existing other case and reviewed derivation" do
    for positive <- ["missing", "sign/signer-failed"] do
      assert {:error, :positive_reference} =
               changed(fn root, index ->
                 manifest(root, index, "sign/signer-failed", &Map.put(&1, "positive", positive))
               end)
    end

    assert {:error, :positive_evidence} =
             changed(fn root, index ->
               manifest(
                 root,
                 index,
                 "sign/signer-failed",
                 &Map.put(&1, "evidence_class", "published_vector")
               )
             end)
  end

  test "an override cannot name an absent upstream item" do
    index = C.json(File.read!("corpus/index.json"))

    e =
      Enum.find(index["cases"], fn e ->
        c = C.json(File.read!(Path.join("corpus", e["manifest"])))
        c["batch"] && c["batch"]["item_format"] == "wycheproof-aes-gcm/1"
      end)

    assert {:error, :overrides} =
             changed(fn root, index ->
               manifest(
                 root,
                 index,
                 e["id"],
                 &Map.put(&1, "overrides", %{
                   "absent" => %{"outcome" => "not_applicable", "reason" => "no such item"}
                 })
               )
             end)
  end

  test "unpinned upstream verdicts and pinned rules have independent effects" do
    data = C.json(File.read!("corpus/sources/wycheproof/aes_gcm_test.json"))

    {group, item} =
      Enum.find_value(data["testGroups"], fn g ->
        if g["keySize"] == 128,
          do:
            Enum.find_value(g["tests"], fn t ->
              if t["aad"] == "" and byte_size(t["iv"]) == 24 and t["result"] == "valid",
                do: {g, t}
            end)
      end)

    assert C.Surfaces.aes_gcm_item(group, item)
    refute C.Surfaces.aes_gcm_item(group, Map.put(item, "result", "invalid"))

    {group, item} =
      Enum.find_value(data["testGroups"], fn g ->
        if g["keySize"] == 192,
          do:
            Enum.find_value(g["tests"], fn t ->
              if t["aad"] == "", do: {g, t}
            end)
      end)

    override = %{
      "outcome" => "reject",
      "rule_id" => "jose/key.algorithm_mismatch",
      "clause" => "RFC 7518 Section 4.7; selected A128GCMKW/A256GCMKW set"
    }

    assert C.Surfaces.aes_gcm_item(group, item, override)

    refute C.Surfaces.aes_gcm_item(
             group,
             item,
             Map.put(override, "rule_id", "jose/input.invalid_iv")
           )
  end

  test "unoverridden Wycheproof shapes fail with the upstream item id" do
    aes = C.json(File.read!("corpus/sources/wycheproof/aes_gcm_test.json"))

    {group, item} =
      Enum.find_value(aes["testGroups"], fn g ->
        if g["keySize"] == 128,
          do:
            Enum.find_value(g["tests"], fn t ->
              if t["aad"] == "" and byte_size(t["iv"]) == 24 and t["result"] == "valid",
                do: {g, t}
            end)
      end)

    id = Integer.to_string(item["tcId"])

    for {g, t} <- [
          {Map.put(group, "keySize", 192), item},
          {group, Map.put(item, "aad", "00")},
          {group, Map.put(item, "label", "00")},
          {group, Map.put(item, "result", "acceptable")}
        ] do
      assert catch_throw(C.Surfaces.aes_gcm_item(g, t)) == {:corpus, {:unexpected_item_shape, id}}
    end

    rsa =
      C.json(File.read!("corpus/sources/wycheproof/rsa_oaep_2048_sha256_mgf1sha256_test.json"))

    group = hd(rsa["testGroups"])
    item = Enum.find(group["tests"], &(&1["label"] == "" and &1["result"] == "valid"))

    for t <- [
          Map.put(item, "label", "00"),
          Map.put(item, "aad", "00"),
          Map.put(item, "result", "acceptable")
        ] do
      assert catch_throw(C.Surfaces.rsa_oaep_item(group, t)) ==
               {:corpus, {:unexpected_item_shape, Integer.to_string(item["tcId"])}}
    end

    for {file, adapter} <- [
          {"ed25519_test.json", &C.Surfaces.ed25519_item/2},
          {"ecdsa_secp256r1_sha256_p1363_test.json", &C.Surfaces.ecdsa_item/2}
        ] do
      group = hd(C.json(File.read!("corpus/sources/wycheproof/" <> file))["testGroups"])
      item = hd(group["tests"]) |> Map.put("result", "acceptable")

      assert catch_throw(adapter.(group, item)) ==
               {:corpus, {:unexpected_item_shape, Integer.to_string(item["tcId"])}}
    end
  end

  test "declared not-applicable counts match the index and independently counted items" do
    for mode <- [:both, :manifest_only, :missing] do
      assert {:error, :not_applicable_count} =
               changed(fn root, index ->
                 id = "jwe/aes_gcm_test"
                 entry = Enum.find(index["cases"], &(&1["id"] == id))
                 path = Path.join(root, entry["manifest"])
                 case_ = C.json(File.read!(path))

                 count =
                   C.number(
                     Enum.count(case_["overrides"], fn {_, o} ->
                       o["outcome"] == "not_applicable"
                     end) + 1
                   )

                 batch =
                   if mode == :missing,
                     do: Map.delete(case_["batch"], "not_applicable"),
                     else: Map.put(case_["batch"], "not_applicable", count)

                 File.write!(path, Canonical.encode(Map.put(case_, "batch", batch)))

                 if mode == :both do
                   update_in(
                     index,
                     ["cases"],
                     &Enum.map(&1, fn e ->
                       if e["id"] == id, do: Map.put(e, "not_applicable", count), else: e
                     end)
                   )
                 else
                   index
                 end
               end)
    end
  end
end
