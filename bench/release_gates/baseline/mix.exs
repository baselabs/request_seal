defmodule RequestSeal.ReleaseGateBaseline.MixProject do
  use Mix.Project

  def project do
    [
      app: :requestseal_release_gate_baseline,
      version: "0.0.0",
      deps: [
        {:request_seal, "== 1.0.0"},
        {:mix_audit, "~> 2.1.5", runtime: false}
      ]
    ]
  end
end
