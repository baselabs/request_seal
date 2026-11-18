defmodule RequestSeal.JosePeers.MixProject do
  use Mix.Project

  def project do
    [
      app: :requestseal_jose_peers,
      version: "0.0.0",
      deps: [
        {:jose, "== 1.11.13"},
        {:mix_audit, "~> 2.1.5", runtime: false}
      ]
    ]
  end
end
