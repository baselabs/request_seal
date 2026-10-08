defmodule RequestSeal.MessageDocumentationTest do
  use ExUnit.Case, async: true
  doctest RequestSeal.Message
  doctest RequestSeal.FieldOccurrence
  doctest RequestSeal.Body
  doctest RequestSeal.TransportFacts
end
