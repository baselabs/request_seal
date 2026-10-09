alias RequestSeal.Conformance, as: C
alias RequestSeal.Conformance.Canonical

{:ok, original} = C.run("corpus")

IO.puts(
  "BASELINE executed=#{original.executed} not_applicable=#{original.not_applicable} disagreements=0"
)

mutations = [
  {"expected_byte", :disagreement,
   fn root, index ->
     entry = Enum.find(index["cases"], &(&1["id"] == "jws/rfc7515-a-2"))
     path = Path.join(root, entry["manifest"])
     case_ = C.json(File.read!(path))
     <<first, rest::binary>> = C.bytes(case_["expected"]["payload"])

     case_ =
       put_in(case_, ["expected", "payload"], C.b64(<<Bitwise.bxor(first, 1), rest::binary>>))

     File.write!(path, Canonical.encode(case_))

     update_in(
       index,
       ["files"],
       &Enum.map(&1, fn f ->
         if f["path"] == entry["manifest"],
           do: Map.put(f, "sha256", C.sha(File.read!(path))),
           else: f
       end)
     )
   end},
  {"rule_id", :disagreement,
   fn root, index ->
     entry = Enum.find(index["cases"], &(&1["id"] == "profile/reserved-request-seal"))
     path = Path.join(root, entry["manifest"])

     case_ =
       C.json(File.read!(path)) |> put_in(["expected", "rule_id"], "core/input.invalid_options")

     File.write!(path, Canonical.encode(case_))

     update_in(
       index,
       ["files"],
       &Enum.map(&1, fn f ->
         if f["path"] == entry["manifest"],
           do: Map.put(f, "sha256", C.sha(File.read!(path))),
           else: f
       end)
     )
   end},
  {"listed_sha256", :file_digest,
   fn _, index -> put_in(index, ["files", Access.at(0), "sha256"], String.duplicate("0", 64)) end},
  {"missing_file", :missing_file,
   fn root, index ->
     File.rm!(Path.join(root, hd(index["files"])["path"]))
     index
   end},
  {"unlisted_file", :unlisted_file,
   fn root, index ->
     File.write!(Path.join(root, "unlisted.txt"), "unlisted")
     index
   end},
  {"ds_store_content", :unlisted_file,
   fn root, index ->
     File.write!(Path.join([root, "sources", ".DS_Store"]), "unverified content")
     index
   end},
  {"known_positive", :known_positive, fn _, index -> Map.delete(index, "known_positive") end},
  {"batch_count", :batch_count,
   fn root, index ->
     entry = Enum.find(index["cases"], &Map.has_key?(&1, "count"))
     path = Path.join(root, entry["manifest"])

     case_ =
       C.json(File.read!(path)) |> put_in(["batch", "count"], C.number(C.int(entry["count"]) + 1))

     File.write!(path, Canonical.encode(case_))

     index =
       update_in(
         index,
         ["cases"],
         &Enum.map(&1, fn e ->
           if e["id"] == entry["id"], do: Map.put(e, "count", case_["batch"]["count"]), else: e
         end)
       )

     update_in(
       index,
       ["files"],
       &Enum.map(&1, fn f ->
         if f["path"] == entry["manifest"],
           do: Map.put(f, "sha256", C.sha(File.read!(path))),
           else: f
       end)
     )
   end},
  {"positive_reference", :positive_reference,
   fn root, index ->
     entry = Enum.find(index["cases"], &(&1["id"] == "sign/signer-failed"))
     path = Path.join(root, entry["manifest"])
     case_ = C.json(File.read!(path)) |> Map.put("positive", "missing-case")
     File.write!(path, Canonical.encode(case_))

     update_in(
       index,
       ["files"],
       &Enum.map(&1, fn f ->
         if f["path"] == entry["manifest"],
           do: Map.put(f, "sha256", C.sha(File.read!(path))),
           else: f
       end)
     )
   end},
  {"positive_evidence", :positive_evidence,
   fn root, index ->
     entry = Enum.find(index["cases"], &(&1["id"] == "sign/signer-failed"))
     path = Path.join(root, entry["manifest"])
     case_ = C.json(File.read!(path)) |> Map.put("evidence_class", "published_vector")
     File.write!(path, Canonical.encode(case_))

     update_in(
       index,
       ["files"],
       &Enum.map(&1, fn f ->
         if f["path"] == entry["manifest"],
           do: Map.put(f, "sha256", C.sha(File.read!(path))),
           else: f
       end)
     )
   end},
  {"unexpected_item_shape", {:unexpected_item_shape, "1000001"},
   fn root, index ->
     entry = Enum.find(index["cases"], &(&1["id"] == "jwe/aes_gcm_test"))
     path = Path.join(root, entry["manifest"])
     case_ = C.json(File.read!(path))
     source = case_["batch"]["file"]
     data = C.json(File.read!(Path.join(root, source)))

     groups =
       Enum.map(data["testGroups"], fn g ->
         if g["keySize"] == 128 do
           item =
             Enum.find(
               g["tests"],
               &(&1["aad"] == "" and byte_size(&1["iv"]) == 24 and &1["result"] == "valid")
             )

           if item do
             item = item |> Map.put("tcId", 1_000_001) |> Map.put("aad", "00")
             Map.update!(g, "tests", &(&1 ++ [item]))
           else
             g
           end
         else
           g
         end
       end)

     # The pinned source has one 128-bit group with this shape.
     C.require!(
       Enum.count(for g <- groups, t <- g["tests"], t["tcId"] == 1_000_001, do: t) == 1,
       :mutation_shape
     )

     File.write!(
       Path.join(root, source),
       IO.iodata_to_binary(:json.encode(Map.put(data, "testGroups", groups)))
     )

     count = C.number(C.int(case_["batch"]["count"]) + 1)
     case_ = put_in(case_, ["batch", "count"], count)
     File.write!(path, Canonical.encode(case_))

     index =
       update_in(
         index,
         ["cases"],
         &Enum.map(&1, fn e ->
           if e["id"] == entry["id"], do: Map.put(e, "count", count), else: e
         end)
       )

     update_in(
       index,
       ["files"],
       &Enum.map(&1, fn f ->
         if f["path"] in [entry["manifest"], source],
           do: Map.put(f, "sha256", C.sha(File.read!(Path.join(root, f["path"])))),
           else: f
       end)
     )
   end},
  {"not_applicable_count", :not_applicable_count,
   fn root, index ->
     entry = Enum.find(index["cases"], &(&1["id"] == "jwe/aes_gcm_test"))
     path = Path.join(root, entry["manifest"])
     case_ = C.json(File.read!(path))

     count =
       C.number(
         Enum.count(case_["overrides"], fn {_, o} -> o["outcome"] == "not_applicable" end) + 1
       )

     File.write!(path, Canonical.encode(put_in(case_, ["batch", "not_applicable"], count)))

     index =
       update_in(
         index,
         ["cases"],
         &Enum.map(&1, fn e ->
           if e["id"] == entry["id"], do: Map.put(e, "not_applicable", count), else: e
         end)
       )

     update_in(
       index,
       ["files"],
       &Enum.map(&1, fn f ->
         if f["path"] == entry["manifest"],
           do: Map.put(f, "sha256", C.sha(File.read!(path))),
           else: f
       end)
     )
   end}
]

for {name, expected, mutate} <- mutations do
  root =
    Path.join(
      System.tmp_dir!(),
      "requestseal-corpus-mutation-#{System.unique_integer([:positive])}"
    )

  try do
    File.cp_r!("corpus", root)
    index = C.json(File.read!(Path.join(root, "index.json"))) |> then(&mutate.(root, &1))
    raw = Canonical.encode(index)
    File.write!(Path.join(root, "index.json"), raw)
    # Re-pin the deliberately changed test inventory so semantic mutations must
    # reach their own guard; the shipped corpus still uses the immutable pin.
    result = C.run(root, index_sha256: C.sha(raw))

    reason =
      case result do
        {:error, {:disagreements, disagreements, _}} when length(disagreements) == 1 ->
          :disagreement

        {:error, {:file_digest, _}} ->
          :file_digest

        {:error, {:unexpected_item_shape, id}} ->
          {:unexpected_item_shape, id}

        {:error, reason} when is_atom(reason) ->
          reason

        _ ->
          {:unexpected, result}
      end

    unless reason == expected,
      do: raise("#{name}: expected #{inspect(expected)}, got #{inspect(reason)}")

    IO.puts("REDPROOF #{name}: rejected #{inspect(reason)}")
  after
    File.rm_rf!(root)
  end
end

IO.puts("PASS: 12 corpus mutations rejected for their named reasons")
