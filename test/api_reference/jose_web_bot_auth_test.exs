defmodule RequestSeal.APIReference.JOSEWebBotAuthTest do
  use ExUnit.Case, async: true

  doctest RequestSeal.JOSE.KeyManagement
  doctest RequestSeal.JOSE.Nested
  doctest RequestSeal.WebBotAuth
  doctest RequestSeal.WebBotAuth.Policy
end
