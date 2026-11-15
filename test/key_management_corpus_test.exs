defmodule RequestSeal.KeyManagementCorpusTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Conformance, as: C

  test "RFC 7518 KDF and agreement surfaces execute independent corpus expectations" do
    for id <- [
          "key_management/rfc7518-appendix-c-kdf",
          "key_management/rfc7518-appendix-c-agree",
          "key_management/rfc7520-5-4-agree",
          "key_management/rfc7520-5-5-agree"
        ] do
      c = File.read!("corpus/cases/" <> id <> ".json") |> C.json()
      assert C.Surfaces.run("corpus", c) == {:ok, c["expected"]}
      changed = put_in(c, ["inputs", "apu"], C.b64("mutated party"))
      refute C.Surfaces.run("corpus", changed) == {:ok, c["expected"]}
    end
  end

  test "every vendored AES-KW and ECDH Wycheproof item is accounted for without duplicates" do
    ledger = File.read!("corpus/sources/wycheproof/ledger.json") |> C.json()

    items =
      for file <-
            ~w(aes_wrap_test.json ecdh_secp256r1_test.json ecdh_secp384r1_test.json x25519_test.json),
          g <- C.json(File.read!("corpus/sources/wycheproof/" <> file))["testGroups"],
          t <- g["tests"],
          do: file <> "/" <> Integer.to_string(t["tcId"])

    assert Enum.sort(Enum.map(ledger, & &1["item"])) == Enum.sort(items)
    assert Enum.all?(ledger, &(is_binary(&1["case"]) or is_binary(&1["excluded"])))
  end

  test "RFC 3394 ledger accounts for every upstream item with executable wrap and unwrap cases" do
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
