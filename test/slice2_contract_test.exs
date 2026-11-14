defmodule RequestSeal.Slice2ContractTest do
  use ExUnit.Case, async: false
  alias RequestSeal.Conformance, as: C

  test "RFC 7518 KDF and agreement surfaces execute independent corpus expectations" do
    for name <- [
          "rfc7518-appendix-c-kdf",
          "rfc7518-appendix-c-agree",
          "rfc7520-5-4-agree",
          "rfc7520-5-5-agree"
        ] do
      c = File.read!("corpus/cases/" <> name <> ".json") |> C.json()
      assert C.Surfaces.run("corpus", c) == {:ok, c["expected"]}
      changed = put_in(c, ["inputs", "apu"], C.b64("mutated party"))
      refute C.Surfaces.run("corpus", changed) == {:ok, c["expected"]}
    end
  end

  test "every newly vendored Wycheproof item is accounted for without duplicates" do
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
end
