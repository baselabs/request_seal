# `doctest Mod` expands to `require Mod` while the test module body is expanded, so a
# runtime `if` inside the body cannot skip it. Doctests of modules compiled only with an
# optional dependency live in their own test modules, defined only when that module loads.
defmodule RequestSeal.APIReference.ReplayDiscoveryTest do
  use ExUnit.Case, async: true

  # RequestSeal.Replay.Claim is doctested by test/public_api_documentation_test.exs.
  doctest RequestSeal.Replay
  doctest RequestSeal.Replay.ETS

  doctest RequestSeal.Discovery
  doctest RequestSeal.Discovery.Cache
  doctest RequestSeal.Discovery.KeySet
  doctest RequestSeal.Discovery.Source
end

if Code.ensure_loaded?(RequestSeal.Replay.Postgres) do
  defmodule RequestSeal.APIReference.ReplayPostgresTest do
    use ExUnit.Case, async: true
    doctest RequestSeal.Replay.Postgres
  end
end

# ash_onetime requires Elixir 1.20; older toolchains do not compile the adapter.
if Code.ensure_loaded?(RequestSeal.Replay.AshOnetime) do
  defmodule RequestSeal.APIReference.ReplayAshOnetimeTest do
    use ExUnit.Case, async: true
    doctest RequestSeal.Replay.AshOnetime
  end
end
