defmodule RequestSeal.ReleaseGateCandidate.MixProject do
  use Mix.Project

  def project do
    [
      app: :requestseal_release_gate_candidate,
      version: "0.0.0",
      deps: [
        {:request_seal, path: "../../.."},
        {:mix_audit, "~> 2.1.5", runtime: false}
      ]
    ]
  end
end
