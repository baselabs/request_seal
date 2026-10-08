defmodule RequestSeal.JOSEPeerTest do
  use ExUnit.Case, async: true
  import Bitwise

  test "peer input file and directory are private and removed on normal exit" do
    path =
      RequestSeal.JOSEPeer.with_input("{}", fn path ->
        assert_private(path)
        path
      end)

    refute File.exists?(path)
    refute File.exists?(Path.dirname(path))
  end

  test "peer input file and directory are private and removed on raise" do
    owner = self()

    assert_raise RuntimeError, "callback failed", fn ->
      RequestSeal.JOSEPeer.with_input("{}", fn path ->
        send(owner, {:input_path, path})
        assert_private(path)
        raise "callback failed"
      end)
    end

    assert_received {:input_path, path}
    refute File.exists?(path)
    refute File.exists?(Path.dirname(path))
  end

  defp assert_private(path) do
    assert File.read!(path) == "{}\n"
    assert band(File.stat!(path).mode, 0o777) == 0o600
    assert band(File.stat!(Path.dirname(path)).mode, 0o777) == 0o700
  end
end
