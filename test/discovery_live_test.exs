defmodule RequestSeal.DiscoveryLiveTest do
  use ExUnit.Case, async: false
  alias RequestSeal.{Discovery, PublicKey}
  alias RequestSeal.Discovery.Source
  @tag :live_source
  test "deployed directory retains thumbprint IDs and explicit proof provenance" do
    Mix.ensure_application!(:ssl)
    {:ok, _} = Application.ensure_all_started(:ssl)

    roots =
      case System.get_env("REQUESTSEAL_DISCOVERY_CACERTS") do
        nil ->
          :os

        file ->
          :public_key.pem_decode(File.read!(file))
          |> Enum.map(fn {:Certificate, der, :not_encrypted} -> der end)
      end

    {:ok, source} =
      Source.new(%{
        type: :directory,
        location: "https://chatgpt.com",
        cacerts: roots,
        require_signed_directory: false
      })

    assert {:ok, set} = Discovery.fetch(source, timeout: 5_000)
    assert set.origin == "https://chatgpt.com"
    assert map_size(set.keys) > 0

    for {kid, resolution} <- set.keys do
      assert PublicKey.thumbprint(resolution.key) == {:ok, kid}
    end

    assert set.proof in [:signed, :unsigned]

    IO.puts(
      "Deployed directory: keys=#{map_size(set.keys)}; proof=#{set.proof}; freshness_seconds=#{set.expires_at - set.fetched_at}; decoded_sha256=#{set.revision}"
    )
  end
end
