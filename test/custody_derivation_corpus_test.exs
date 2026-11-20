defmodule RequestSeal.CustodyDerivationCorpusTest do
  use ExUnit.Case, async: true
  alias RequestSeal.{Custody, PublicKey}
  alias RequestSeal.Conformance, as: C
  alias RequestSeal.Custody.Local

  test "independent custody vectors cover every derivation family and bind domain bytes" do
    ledger = C.json(File.read!("corpus/sources/native-derive/ledger.json"))
    assert Enum.sort(Enum.map(ledger, & &1["item"])) ==
             ~w(aes128-key aes256-key ed25519-seed hmac-sha256-key p256-dhkem p384-dhkem x25519-dhkem)
    for row <- ledger do
      c = C.json(File.read!("corpus/cases/" <> row["case"] <> ".json"))
      assert C.Surfaces.run("corpus", c) == {:ok, c["expected"]}
      assert C.Surfaces.run("corpus", c) == {:ok, c["expected"]}
      changed = put_in(c, ["inputs", "domain"], C.b64(C.bytes(c["inputs"]["domain"]) <> <<0>>))
      refute C.Surfaces.run("corpus", changed) == {:ok, c["expected"]}
    end
  end

  test "published DHKEM vectors and independent P384 stage pin scalar and public bytes" do
    paths = Path.wildcard("corpus/cases/hpke/*.json")
    assert length(paths) == 7
    for path <- paths do
      c = C.json(File.read!(path))
      assert C.Surfaces.run("corpus", c) == {:ok, c["expected"]}
      changed = put_in(c, ["inputs", "ikm"], C.b64(C.bytes(c["inputs"]["ikm"]) <> <<0>>))
      refute C.Surfaces.run("corpus", changed) == {:ok, c["expected"]}
    end
  end

  test "prefix-free family framing defeats the draft symmetric and Ed25519 collision" do
    ikm = <<12::256>>
    domain = "example"
    label = "hmac-sha256-key"
    ed_domain = domain <> <<0>> <> label
    {:ok, parent} = Local.new({:derive, "hkdf-sha256"}, {:ikm, ikm})
    {:ok, symmetric} = Custody.derive(parent, "hmac-sha256", domain, timeout: 5000)
    {:ok, ed} = Custody.derive(parent, "ed25519", ed_domain, timeout: 5000)
    # Independent calculation from the known imported test IKM. No derived
    # material is exported by custody to make this comparison.
    prefix = "request-seal/derive/v1"
    family = "ed25519-seed"
    prk = :crypto.mac(:hmac, :sha256, prefix, ikm)
    info = prefix <> <<byte_size(family)::16, family::binary, byte_size(ed_domain)::16, ed_domain::binary>>
    ed_seed = :crypto.mac(:hmac, :sha256, prk, info <> <<1>>)
    {expected, _} = :crypto.generate_key(:eddsa, :ed25519, ed_seed)
    assert {:ok, %PublicKey{material: {:ed25519, ^expected}}} = Custody.public_key(ed)
    assert {:ok, tag} = Custody.sign(symmetric, "probe")
    refute tag == :crypto.mac(:hmac, :sha256, ed_seed, "probe")
    for handle <- [parent, symmetric, ed], do: assert(:ok == Custody.release(handle))
  end
end
