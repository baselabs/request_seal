defmodule RequestSeal.APIReference.ReplayDiscoveryTest do
  use ExUnit.Case, async: true

  # RequestSeal.Replay.Claim is doctested by test/public_api_documentation_test.exs.
  doctest RequestSeal.Replay
  doctest RequestSeal.Replay.ETS
  doctest RequestSeal.Replay.Postgres

  # The ash_onetime adapter is compiled only where its optional dependency is present.
  if Code.ensure_loaded?(RequestSeal.Replay.AshOnetime) do
    doctest RequestSeal.Replay.AshOnetime
  end

  doctest RequestSeal.Discovery
  doctest RequestSeal.Discovery.Cache
  doctest RequestSeal.Discovery.KeySet
  doctest RequestSeal.Discovery.Source
end
