defmodule RequestSeal.TripwireTest do
  @moduledoc """
  Public vendor-name and provider-term patterns scan tracked files and pending
  public files, including file paths and working-tree contents. Known-positive
  file controls exercise each pattern. Private terms are checked by a local
  pre-publish scan outside the repository, never by a tracked term list.
  """
  use ExUnit.Case, async: true

  @root Path.expand("..", __DIR__)
  @patterns [
    {~r/visa/i, "VISA"},
    {~r/cyber[\s_.-]*source/i, "Cyber-Source"},
    {~r/\btap\b/i, "TAP recognition"},
    {~r/tap[._]/i, "prefixTAP.Contract"},
    {~r/\btrusted[\s_.-]*agent\b/i, "Trusted\nAgent"},
    {~r/acceptance jwt/i, "ACCEPTANCE JWT"},
    {~r/envelope\.acceptance/i, "Envelope.Acceptance"},
    {~r/acceptance[\s_.-]*(current|legacy)/i, "AcceptanceCurrent"},
    {~r{/icc/}i, "/icc/v1"},
    {~r/\bicc\b/i, "ICC"},
    {~r/\bvic\b/i, "VIC"},
    {~r/\bmle\b/i, "MLE"},
    {~r/\bvpp\b/i, "VPP"},
    {~r/\bvdp\b/i, "VDP"}
  ]

  test "each scan pattern detects its known-positive file control" do
    for {pattern, sample} <- @patterns do
      with_control(sample, fn path ->
        assert {path, :contents, Regex.source(pattern)} in scan(public_paths())
      end)
    end
  end

  test "scan detects separated names, abbreviations, module names and route forms" do
    for sample <- [
          "Cyber Source",
          "Cyber-Source",
          "CYBER_SOURCE",
          "Cyber.Source",
          "trusted-agent",
          "Trusted\nAgent",
          "TrustedAgent",
          "Trusted_Agent",
          "Trusted.Agent",
          "TAP recognition",
          "RequestSeal.TAP.Recognition",
          "prefixTAP.Contract",
          "prefixTAP_Contract",
          "Envelope.Acceptance",
          "AcceptanceCurrent",
          "AcceptanceLegacy",
          "/icc/v1",
          "ICC",
          "VIC"
        ] do
      with_control(sample, fn path ->
        assert Enum.any?(scan(public_paths()), fn {hit, _, _} -> hit == path end)
      end)
    end
  end

  test "tracked and pending public files contain no removed profile references" do
    paths = public_paths()
    assert "README.md" in paths
    hits = scan(paths)
    assert hits == [], "Removed profile references:\n" <> inspect(hits)
  end

  defp public_paths do
    # Scan tracked files and pending public files before staging. The local
    # pre-publish scan outside the repository checks private terms and history.
    {output, status} =
      System.cmd("git", ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cd: @root
      )

    assert status == 0
    String.split(output, <<0>>, trim: true) |> Enum.uniq()
  end

  defp scan(paths) do
    for path <- paths,
        path != "test/tripwire_test.exs",
        File.regular?(Path.join(@root, path)),
        {kind, bytes} <- [path: path, contents: File.read!(Path.join(@root, path))],
        {pattern, _sample} <- @patterns,
        Regex.match?(pattern, bytes),
        do: {path, kind, Regex.source(pattern)}
  end

  defp with_control(sample, callback) do
    path = "test/profile-reference-control-#{System.unique_integer([:positive])}.txt"
    absolute = Path.join(@root, path)
    File.write!(absolute, sample)

    try do
      assert path in public_paths()
      callback.(path)
    after
      File.rm!(absolute)
    end

    refute File.exists?(absolute)
  end
end
