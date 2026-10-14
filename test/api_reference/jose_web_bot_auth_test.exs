defmodule RequestSeal.APIReference.JOSEWebBotAuthTest do
  use ExUnit.Case, async: true

  # RequestSeal.JOSE.JWS and RequestSeal.JOSE.JWE are doctested in
  # test/public_api_documentation_test.exs.
  doctest RequestSeal.JOSE.KeyManagement
  doctest RequestSeal.JOSE.Nested
  doctest RequestSeal.WebBotAuth
  doctest RequestSeal.WebBotAuth.Policy
end
