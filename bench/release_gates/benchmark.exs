Code.require_file("../../test/support/host_conditions.ex", __DIR__)

defmodule RequestSeal.ReleaseGateBenchmark do
  @moduledoc false
  alias RequestSeal.Test.HostConditions
  @warmups 30

  def run(mode, workload) do
    {page_samples, single_samples} =
      case mode do
        "release" -> {15, 2_000}
        "self-check" -> {3, 10}
      end

    object = %{
      "id" => "9b3270e2-43ad-4da4-88ef-4f3c6ed8970a",
      "revision" => 12,
      "title" => "An authenticated group of documents",
      "description" => "",
      "created_at" => "2026-01-01T12:00:00Z",
      "updated_at" => "2026-01-03T09:30:00Z",
      "archived_at" => :null,
      "parent" => :null,
      "labels" => ["shared", "reference"],
      "members" => [%{"id" => "public-example", "role" => "reader"}],
      "active" => true
    }

    description_size = 579 - byte_size(json(object))
    object = %{object | "description" => String.duplicate("d", description_size)}
    plaintext = json(object)
    579 = byte_size(plaintext)

    kek = :crypto.strong_rand_bytes(32)
    single_plaintext = :binary.copy("a", 32)
    single = token(kek, single_plaintext, 128)
    299 = byte_size(single)
    page = for _ <- 1..100, do: token(kek, plaintext, 331)
    true = Enum.all?(page, &(byte_size(&1) == 1_299))

    {open_page, open_single, valid_page?, close} = workload.(kek, page, single, object)

    try do
      %{
        page: measure(open_page, page_samples, valid_page?),
        single: measure(open_single, single_samples, &(&1 == single_plaintext)),
        otp: System.otp_release(),
        schedulers_online: System.schedulers_online(),
        version: to_string(Application.spec(:request_seal, :vsn))
      }
    after
      :ok = close.()
    end
  end

  defp measure(open, count, valid?) do
    Enum.each(1..@warmups, fn _ -> verify!(open.(), valid?) end)
    load_before = loadavg()
    cpu_before = HostConditions.cpu_stat()
    process_before = HostConditions.process_snapshot(:before)

    samples =
      for _ <- 1..count do
        start = System.monotonic_time(:nanosecond)
        result = open.()
        elapsed = System.monotonic_time(:nanosecond) - start
        verify!(result, valid?)
        elapsed / 1_000
      end

    process_after = HostConditions.process_snapshot(:after)
    cpu_after = HostConditions.cpu_stat()
    load_after = loadavg()

    %{
      median_us: median(samples),
      samples: length(samples),
      warmups: @warmups,
      load_before: load_before,
      load_after: load_after,
      cpu_before: cpu_before,
      cpu_after: cpu_after,
      process_before: process_before,
      process_after: process_after
    }
  end

  defp verify!(result, valid?) do
    unless valid?.(result), do: raise("workload did not recover the expected content")
  end

  defp median(samples) do
    sorted = Enum.sort(samples)
    middle = div(length(sorted), 2)

    if rem(length(sorted), 2) == 0,
      do: (Enum.at(sorted, middle - 1) + Enum.at(sorted, middle)) / 2,
      else: Enum.at(sorted, middle)
  end

  # RFC 7516 compact serialization and RFC 7518 §4.7 AES-GCM key wrapping.
  # Seal locally so both sides use one recipe independent of either library version.
  defp token(kek, plaintext, header_bytes) do
    cek = :crypto.strong_rand_bytes(32)
    wrap_iv = :crypto.strong_rand_bytes(12)
    {wrapped, wrap_tag} = :crypto.crypto_one_time_aead(:aes_256_gcm, kek, wrap_iv, cek, "", 16, true)

    fields = %{
      "alg" => "A256GCMKW",
      "enc" => "A256GCM",
      "cty" => "application/json",
      "iv" => b64(wrap_iv),
      "tag" => b64(wrap_tag),
      "padding" => ""
    }

    padding = String.duplicate("a", header_bytes - byte_size(json(fields)))
    protected = b64(json(%{fields | "padding" => padding}))
    iv = :crypto.strong_rand_bytes(12)

    {ciphertext, tag} =
      :crypto.crypto_one_time_aead(:aes_256_gcm, cek, iv, plaintext, protected, 16, true)

    Enum.join([protected, b64(wrapped), b64(iv), b64(ciphertext), b64(tag)], ".")
  end

  defp json(value), do: IO.iodata_to_binary(:json.encode(value))
  defp b64(bytes), do: Base.url_encode64(bytes, padding: false)
  defp loadavg, do: File.read!("/proc/loadavg") |> String.trim()
end
