defmodule RequestSeal.DiscoveryDNSIsolationTest do
  use ExUnit.Case, async: false

  test "real DNS rebinding exercises the discovery entry point in an isolated resolver" do
    {output, status} =
      System.cmd(
        "elixir",
        [
          "-pa",
          Application.app_dir(:request_seal, "ebin"),
          "test/support/discovery_dns_helper.exs"
        ],
        stderr_to_stdout: true
      )

    assert status == 0, output

    assert output =~
             "DNS rebinding: both families vetted; denied rebind rejected; tuple connect reached configured TLS publisher"
  end
end
