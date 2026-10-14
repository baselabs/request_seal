defmodule RequestSeal.APIReference.IntegrationsTest do
  use ExUnit.Case, async: true

  # Optional integrations compile only when their dependency is present.
  if Code.ensure_loaded?(Finch) do
    doctest RequestSeal.Finch
    doctest RequestSeal.Adapter.Error
  end

  if Code.ensure_loaded?(Req), do: doctest(RequestSeal.Req)

  if Code.ensure_loaded?(Plug.Conn) do
    doctest RequestSeal.Plug
    doctest RequestSeal.Plug.Capture
    doctest RequestSeal.Plug.Verify
    doctest RequestSeal.Plug.SignResponse
  end

  doctest RequestSeal.Ash
  doctest RequestSeal.Ash.Scope

  # ash_hooks requires Elixir 1.20; older toolchains omit it.
  if Code.ensure_loaded?(AshHooks.Provider) do
    doctest RequestSeal.AshHooks
    doctest RequestSeal.AshHooks.Http
  end
end
