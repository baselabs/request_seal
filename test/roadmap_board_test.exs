defmodule RequestSeal.RoadmapBoardTest do
  @moduledoc false
  use ExUnit.Case, async: true

  # The board has exactly one four-column board and at most one two-column legend.
  # Every table line has its header's width; every roadmap row occurs once,
  # with one of six Status badges and exactly one matching counts line.
  # ROADMAP_PATH names another file, so the check can run against a scratch copy.

  @roadmap Path.expand("../docs/ROADMAP.md", __DIR__)
  @badges ["✅", "🟢", "🟡", "🔵", "⚪", "⛔"]
  @start "<!-- status-board:start -->"
  @finish "<!-- status-board:end -->"
  @legend_header ["Badge", "Meaning"]
  @board_header ["Status", "Row", "Where it stands", "Watch"]
  @row_headers [
    "| ID | Outcome | Acceptance | Waits on |",
    "| ID | Outcome | Acceptance | Evidence |"
  ]

  setup_all do
    text = File.read!(System.get_env("ROADMAP_PATH") || @roadmap)
    assert [_, rest] = String.split(text, @start), "exactly one board start marker"
    assert [board, tables] = String.split(rest, @finish), "exactly one board end marker"
    refute String.contains?(tables, @start), "exactly one board"

    board_tables = board_tables(board)
    entries = for [@board_header | rows] <- board_tables, row <- rows, do: row
    %{board: board, board_tables: board_tables, entries: entries, ids: row_ids(tables)}
  end

  test "the board holds one four-column board and at most one legend, each line at its width",
       %{board_tables: board_tables} do
    headers = Enum.map(board_tables, &hd/1)
    unknown = Enum.reject(headers, &(&1 in [@legend_header, @board_header]))
    assert unknown == [], "a table other than the legend or the board: #{inspect(unknown)}"
    assert Enum.count(headers, &(&1 == @board_header)) == 1, "exactly one board table"
    assert Enum.count(headers, &(&1 == @legend_header)) <= 1, "at most one legend table"

    misshapen =
      for [header | rows] <- board_tables, row <- rows, length(row) != length(header), do: row

    assert misshapen == [], "a line whose width differs from its table: #{inspect(misshapen)}"
  end

  test "every row appears on the board exactly once", %{entries: entries, ids: ids} do
    assert ids != [], "the roadmap has no rows"
    assert ids == Enum.uniq(ids), "row IDs must be unique: #{inspect(ids -- Enum.uniq(ids))}"
    names = Enum.map(entries, &Enum.at(&1, 1))

    assert names == Enum.uniq(names),
           "a board line repeats: #{inspect(names -- Enum.uniq(names))}"

    assert Enum.sort(names) == Enum.sort(ids),
           "board and rows differ: missing #{inspect(ids -- names)}, unknown #{inspect(names -- ids)}"
  end

  test "every Status is one of the six badges", %{entries: entries} do
    bad = Enum.reject(entries, fn [status | _] -> status in @badges end)

    assert bad == [],
           "Status outside the six badges: #{inspect(Enum.map(bad, &Enum.take(&1, 2)))}"
  end

  test "one counts line matches the board as a whole line", %{
    board: board,
    entries: entries,
    ids: ids
  } do
    statuses = Enum.map(entries, &hd/1)
    counts = Enum.map(@badges, fn badge -> {badge, Enum.count(statuses, &(&1 == badge))} end)
    assert Enum.sum(Enum.map(counts, &elem(&1, 1))) == length(ids)
    expected = "Counts: " <> Enum.map_join(counts, " · ", fn {badge, n} -> "#{badge} #{n}" end)
    lines = board |> String.split("\n") |> Enum.filter(&String.starts_with?(&1, "Counts:"))
    assert lines == [expected], "expected exactly #{inspect(expected)}, found #{inspect(lines)}"
  end

  defp row_ids(tables) do
    tables
    |> String.split("\n")
    |> Enum.reduce({nil, []}, fn line, {in_table, ids} ->
      cond do
        line in @row_headers -> {true, ids}
        in_table && String.starts_with?(line, "|") -> {true, [hd(cells(line)) | ids]}
        true -> {nil, ids}
      end
    end)
    |> elem(1)
    |> Enum.reverse()
    |> Enum.reject(&separator?/1)
  end

  defp board_tables(board) do
    board
    |> String.split("\n")
    |> Enum.chunk_by(&String.starts_with?(&1, "|"))
    |> Enum.filter(fn [line | _] -> String.starts_with?(line, "|") end)
    |> Enum.map(fn lines ->
      lines |> Enum.map(&cells/1) |> Enum.reject(fn row -> Enum.all?(row, &separator?/1) end)
    end)
  end

  defp cells(line),
    do: line |> String.trim() |> String.trim("|") |> String.split("|") |> Enum.map(&String.trim/1)

  defp separator?(cell), do: Regex.match?(~r/^:?-+:?$/, cell)
end
