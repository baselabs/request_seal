defmodule RequestSeal.APIReference.CoreTest do
  use ExUnit.Case, async: true

  # RequestSeal is doctested in test/dx_builder_test.exs and RequestSeal.Profile
  # in test/public_api_documentation_test.exs.
  doctest RequestSeal.Policy
  doctest RequestSeal.Quorum
  doctest RequestSeal.AcceptSignature
  doctest RequestSeal.SignatureBase
end
