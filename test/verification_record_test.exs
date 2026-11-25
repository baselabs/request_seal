defmodule RequestSeal.VerificationRecordTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Conformance, Custody, DenySet, PublicKey, VerificationRecord}
  alias RequestSeal.Conformance.Surfaces
  alias RequestSeal.Discovery.Resolution

  @root "corpus"

  defp manifest(area, name) do
    File.read!("corpus/cases/#{area}/#{name}.json") |> Conformance.json()
  end

  test "captures the cryptographically verified RFC bytes only on request" do
    for name <- ["capture-ed25519", "capture-rsa-pss", "capture-restricted-rsa-pss"] do
      c = manifest("verification_record", name)
      assert {:ok, result} = Surfaces.verification_record(@root, c)
      assert result == c["expected"]
      assert {:ok, record} = VerificationRecord.decode(Conformance.bytes(result["bytes"]))
      assert :ok = VerificationRecord.reverify(record)
    end

    c = manifest("verify", "rfc9421-sig-b26")
    i = c["inputs"]
    message = Surfaces.case_message(@root, i)
    {:ok, key} = PublicKey.import(File.read!("test/fixtures/crypto/ed25519_public.pem"), :pem)
    policy = policy("ed25519", key)
    assert {:ok, verified} = RequestSeal.verify(message, policy, label: i["label"])
    refute Map.has_key?(verified.signature, :record_material)
    assert {:error, :not_accepted} = VerificationRecord.from_verification(verified)

    assert {:error, %{reason: :invalid_options}} =
             RequestSeal.verify(message, policy, label: i["label"], capture: :yes)

    assert {:ok, captured} = result =
             RequestSeal.verify(message, policy, label: i["label"], capture: true)

    {:ok, record} = VerificationRecord.from_verification(result)
    assert :ok = VerificationRecord.reverify(record)
    refute inspect(record) =~ "thumbprint"
    refute inspect(captured) =~ "record_material"

    assert {:error, :not_accepted} =
             VerificationRecord.from_verification(captured, directory: :invalid)

    assert {:error, :not_accepted} =
             VerificationRecord.from_verification(put_in(captured.signature.crypto, :invalid))

    assert {:error, :not_accepted} =
             VerificationRecord.from_verification(%{captured | authorization: :allowed})

    {:ok, thumbprint} = PublicKey.thumbprint(key)
    directory = %Resolution{
      key: key,
      thumbprint: thumbprint,
      fetched_at: 1_618_884_473,
      origin: "https://example.com"
    }

    assert {:ok, record} = VerificationRecord.from_verification(captured, directory: directory)
    assert {:ok, bytes} = VerificationRecord.encode(record)
    assert :ok = VerificationRecord.reverify(bytes)

    assert {:error, :not_accepted} =
             VerificationRecord.from_verification(captured,
               directory: %{directory | thumbprint: "different"}
             )

    assert {:error, :not_accepted} =
             VerificationRecord.from_verification(captured,
               directory: %{directory | origin: "https://example.com/path"}
             )
  end

  test "record validation rejects changed crypto and key identity even with recomputed digest" do
    for name <- ["bad-signature", "bad-base", "bad-thumbprint", "noncanonical"] do
      c = manifest("verification_record", name)
      bytes = Conformance.bytes(c["inputs"]["record"])
      assert {:error, :invalid_record} = VerificationRecord.decode(bytes)
      assert {:error, :invalid_record} = VerificationRecord.reverify(bytes)
    end
  end

  test "valid record mutations reject duplicate and unknown members at every object boundary" do
    positive = manifest("verification_record", "reverify-directory")
    bytes = Conformance.bytes(positive["inputs"]["record"])
    assert :ok = VerificationRecord.reverify(bytes)

    for boundary <- ~w(envelope record profile directory key jwk),
        defect <- ~w(duplicate unknown) do
      c = manifest("verification_record", "#{defect}-#{boundary}-member")
      mutated = Conformance.bytes(c["inputs"]["record"])
      assert mutated != bytes
      assert {:error, :invalid_record} = VerificationRecord.decode(mutated)
    end
  end

  test "retained fields require canonical occurrence framing even with valid signatures" do
    for name <- ["multi-byte-sequence", "final-empty-occurrence"] do
      positive = manifest("verification_record", name)
      valid = Conformance.bytes(positive["inputs"]["record"])
      assert {:ok, _} = VerificationRecord.decode(valid)
      assert :ok = VerificationRecord.reverify(valid)
    end

    for name <- ["noncanonical-byte-sequence", "noncanonical-leading-ows"] do
      negative = manifest("verification_record", name)
      invalid = Conformance.bytes(negative["inputs"]["record"])
      %{"digest" => digest, "record" => data} = :json.decode(invalid)
      %{"jwk" => jwk} = data["key"]
      assert map_size(data["key"]) == 1
      {:ok, key} = PublicKey.import(jwk, :jwk)
      assert PublicKey.export(key, :jwk) == {:ok, jwk}
      assert PublicKey.thumbprint(key) == {:ok, data["thumbprint"]}
      [_, wrapped] = :binary.split(invalid, ~s[,"record":])
      record_bytes = binary_part(wrapped, 0, byte_size(wrapped) - 1)
      assert Base.url_encode64(:crypto.hash(:sha256, record_bytes), padding: false) == digest

      base = Base.url_decode64!(data["base"], padding: false)
      signature = Base.url_decode64!(data["signature"], padding: false)
      assert :ok = RequestSeal.Crypto.verify("ed25519", base, signature, key)
      assert {:error, %{reason: :malformed}} = RequestSeal.SignatureBase.parse(base)
      assert {:error, :invalid_record} = VerificationRecord.decode(invalid)
      assert {:error, :invalid_record} = VerificationRecord.reverify(invalid)
    end
  end

  test "asymmetric custody capture works with or without a deny set" do
    {:ok, handle} = Custody.Local.generate("ed25519", [])
    {:ok, key} = Custody.public_key(handle)
    {:ok, message} = RequestSeal.Message.request("GET", "https://example.com/", [], nil)
    spec = %{label: "sig", algorithm: "ed25519", signature_input: ~s[("@method")]}
    {:ok, signed} = RequestSeal.sign(message, spec, handle)
    {:ok, empty} = DenySet.new([])
    p = policy("ed25519", handle)

    for deny <- [nil, empty] do
      assert {:ok, result} =
               RequestSeal.verify(signed, %{p | deny: deny}, label: "sig", capture: true)

      assert result.signature.record_material.key == key
      assert {:ok, record} = VerificationRecord.from_verification(result)
      assert {:ok, bytes} = VerificationRecord.encode(record)
      assert :ok = VerificationRecord.reverify(bytes)
    end

    assert :ok = Custody.release(handle)
  end

  test "decoder refuses invalid framing and malformed records" do
    for bytes <- [
          false,
          "",
          "{}",
          ~s({"digest":"","record":{"version":1.0}}),
          String.duplicate("[", 9) <> String.duplicate("]", 9),
          :binary.copy(" ", 2_097_153)
        ] do
      assert {:error, :invalid_record} = VerificationRecord.decode(bytes)
    end

    assert {:error, :invalid_record} = VerificationRecord.encode(%{})
    assert {:error, :invalid_record} = VerificationRecord.reverify(%{})
    assert {:error, :not_accepted} = VerificationRecord.from_verification(%{})
  end

  test "symmetric HTTP verification cannot capture retained material" do
    c = manifest("verification_record", "capture-symmetric")
    assert {:error, %{layer: :input, reason: :invalid_options}} =
             Surfaces.verification_record(@root, c)

    c = put_in(c, ["policy", "deny"], [])

    assert {:error, %{layer: :input, reason: :invalid_options}} =
             Surfaces.verification_record(@root, c)
  end

  defp policy(algorithm, key) do
    {:ok, p} =
      RequestSeal.Policy.new(%{
        algorithms: [algorithm],
        components: "()",
        key_resolver: fn _ -> {:ok, %{algorithm: algorithm, key: key}} end,
        content: :not_required,
        freshness: :not_evaluated,
        replay: :not_required
      })

    p
  end
end
