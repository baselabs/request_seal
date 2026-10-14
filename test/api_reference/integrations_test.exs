# `doctest Mod` expands to `require Mod`, which the compiler resolves while expanding the
# test module body, before any runtime `if` in that body runs. A doctest of a module that
# is compiled only with an optional dependency therefore lives in its own test module,
# defined only when the documented module itself is loaded.
defmodule RequestSeal.APIReference.IntegrationsTest do
  use ExUnit.Case, async: true

  # These modules compile on every toolchain.
  doctest RequestSeal.Ash
  doctest RequestSeal.Ash.Scope
end

if Code.ensure_loaded?(RequestSeal.Finch) do
  defmodule RequestSeal.APIReference.FinchTest do
    use ExUnit.Case, async: true
    doctest RequestSeal.Finch
    doctest RequestSeal.Adapter.Error
  end
end

if Code.ensure_loaded?(RequestSeal.Req) do
  defmodule RequestSeal.APIReference.ReqTest do
    use ExUnit.Case, async: true
    doctest RequestSeal.Req
  end
end

if Code.ensure_loaded?(RequestSeal.Plug) do
  defmodule RequestSeal.APIReference.PlugTest do
    use ExUnit.Case, async: true
    doctest RequestSeal.Plug
    doctest RequestSeal.Plug.Capture
    doctest RequestSeal.Plug.Verify
    doctest RequestSeal.Plug.SignResponse
  end
end

# ash_hooks requires Elixir 1.20; older toolchains do not compile RequestSeal.AshHooks.
if Code.ensure_loaded?(RequestSeal.AshHooks) do
  defmodule RequestSeal.APIReference.AshHooksTest do
    use ExUnit.Case, async: true
    doctest RequestSeal.AshHooks
    doctest RequestSeal.AshHooks.Http
  end
end
