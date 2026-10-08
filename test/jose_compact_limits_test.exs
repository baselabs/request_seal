defmodule RequestSeal.JOSECompactLimitsTest do
  use ExUnit.Case, async: true
  alias RequestSeal.JOSE.{Error, Support}

  test "one-megabyte separator storm stops at the first excess segment" do
    input = :binary.copy(".", 1_048_576)

    for count <- [3, 5] do
      {:reductions, before} = Process.info(self(), :reductions)

      assert {:error, %Error{reason: :invalid_serialization}} =
               Support.safe(fn -> Support.compact(input, count) end)

      {:reductions, after_count} = Process.info(self(), :reductions)
      assert after_count - before < 10_000
    end
  end

  test "nested segment counting has the same fixed work bound" do
    input = :binary.copy(".", 1_048_576)
    {:reductions, before} = Process.info(self(), :reductions)
    refute Support.segment_count?(input, 3)
    {:reductions, after_count} = Process.info(self(), :reductions)
    assert after_count - before < 10_000
    assert Support.segment_count?("a.b.c", 3)
    refute Support.segment_count?("a.b.c.d", 3)
  end
end
