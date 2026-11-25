defmodule RequestSeal.VerificationRecordTest do
  use ExUnit.Case, async: true

  alias RequestSeal.{Conformance, PublicKey, VerificationRecord}
  alias RequestSeal.Conformance.Surfaces
  alias RequestSeal.Discovery.Resolution

  @root "corpus"

  defp manifest(area, name) do
    File.read!("corpus/cases/#{area}/#{name}.json") |> Conformance.json()
  end

  test "captures the cryptographically verified RFC bytes only on request" do
    for name <- ["capture-ed25519", "capture-rsa-pss"] do
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

  test "decoder refuses invalid framing and malformed records" do
    for bytes <- [
          false,
          "",
          "{}",
          ~s({"digest":"first","digest":"second","record":{}}),
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
