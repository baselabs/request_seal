defmodule RequestSeal.JOSEBase64Test do
  use ExUnit.Case, async: true
  alias RequestSeal.JOSE.{Error, Support}

  test "RFC 4648 section 10 canonical unpadded vectors decode exactly" do
    for {wire, bytes} <- [
          {"", ""},
          {"Zg", "f"},
          {"Zm8", "fo"},
          {"Zm9v", "foo"},
          {"Zm9vYg", "foob"},
          {"Zm9vYmE", "fooba"},
          {"Zm9vYmFy", "foobar"}
        ] do
      assert Support.decode(wire) == bytes
      assert Support.b64(bytes) == wire
    end
  end

  test "RFC 4648 section 3.5 rejects every nonzero pad bit in one-byte tails" do
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    for first <- 0..63, tail <- 0..63, rem(tail, 16) != 0 do
      wire = <<:binary.at(alphabet, first), :binary.at(alphabet, tail)>>

      assert Support.safe(fn -> {:ok, Support.decode(wire)} end) ==
               {:error, Error.new(:invalid_base64, :input)}
    end
  end

  test "RFC 4648 section 3.5 rejects every nonzero pad bit in two-byte tails" do
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

    for middle <- 0..63, tail <- 0..63, rem(tail, 4) != 0 do
      wire = <<?A, :binary.at(alphabet, middle), :binary.at(alphabet, tail)>>

      assert Support.safe(fn -> {:ok, Support.decode(wire)} end) ==
               {:error, Error.new(:invalid_base64, :input)}
    end
  end

  test "JOSE refuses padding whitespace standard alphabet and impossible lengths" do
    for wire <- [
          "=m8",
          "Zm=8",
          "Zm8=",
          " Zm8",
          "Zm8\n",
          "+w",
          "/w",
          "Zg=",
          "Zg==",
          "Zg===",
          "A",
          "AAAAA"
        ] do
      assert Support.safe(fn -> {:ok, Support.decode(wire)} end) ==
               {:error, Error.new(:invalid_base64, :input)}
    end
  end
end
