defmodule RequestSeal.APIReference.MessageTest do
  use ExUnit.Case, async: true

  # RequestSeal.Message, FieldOccurrence, Body, and TransportFacts are doctested in
  # test/message_documentation_test.exs.
  doctest RequestSeal.StructuredFields
  doctest RequestSeal.StructuredFields.Schema
  doctest RequestSeal.Digest
end
