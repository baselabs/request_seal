defmodule RequestSeal.PublishHexTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO

  # Load the actual functions without executing the command-line entry point.
  {:__block__, _, [module | _]} =
    "scripts/publish_hex.exs" |> File.read!() |> Code.string_to_quoted!()

  Mix.Local.append_archives()
  Code.eval_quoted(module)

  defp staged do
    %{
      "status" => "staged",
      "checksum" => Base.encode16(:crypto.hash(:sha256, "package"), case: :lower),
      "html_url" => "https://hex.pm/dashboard/staged-releases/hexpm/request_seal/0.4.0",
      "expires_at" => "2026-11-30T00:00:00Z"
    }
  end

  test "all successful HTTP statuses classify staged package and docs responses by body" do
    for kind <- [:package, :docs], status <- [200, 201, 202, 204, 299] do
      assert {:staged, %{html_url: url, expires_at: expiry}} =
               PublishHex.accepted!(kind, {:ok, {status, %{}, staged()}})

      assert url == staged()["html_url"]
      assert expiry == staged()["expires_at"]
      assert :uploaded == PublishHex.accepted!(kind, {:ok, {status, %{}, %{}}})
    end
  end

  test "matching staged release stops before any planned package or docs upload" do
    state = PublishHex.staged_state!({:ok, {200, %{}, staged()}}, "package")
    assert {:staged, _} = state
    assert state == PublishHex.release_state!({:ok, {200, %{}, staged()}}, "package")

    for uploads <- [[:package, :docs], [:package], [:docs], []] do
      error =
        assert_raise Mix.Error, fn ->
          PublishHex.remaining_uploads!("0.4.0", uploads, state)
        end

      assert Exception.message(error) ==
               "Hex release 0.4.0 is staged for approval; approve it on hex.pm, then dispatch again"
    end

    notice =
      capture_io(fn ->
        assert_raise Mix.Error, PublishHex.staged_message("0.4.0"), fn ->
          PublishHex.stop_if_staged!("0.4.0", state)
        end
      end)

    assert notice ==
             "::notice::Hex approval pending at #{staged()["html_url"]} " <>
               "(expires at #{staged()["expires_at"]})\n"
  end

  test "staged and served checksums must equal the inspected package before selection" do
    for body <- [staged(), %{"has_docs" => false, "retirement" => nil}] do
      for checksum <- [nil, "different", String.duplicate("0", 64)] do
        error =
          assert_raise Mix.Error, fn ->
            PublishHex.release_state!(
              {:ok, {200, %{}, Map.put(body, "checksum", checksum)}},
              "package"
            )
          end

        assert Exception.message(error) == "Hex release SHA-256 differs; refusing replacement"
      end
    end
  end

  test "served packages are never uploaded again, including after staged approval" do
    for has_docs <- [false, true] do
      body = staged() |> Map.delete("status") |> Map.put("has_docs", has_docs)
      state = PublishHex.release_state!({:ok, {200, %{}, body}}, "package")
      assert state == {:served, has_docs}

      for uploads <- [[:package, :docs], [:docs]] do
        assert PublishHex.remaining_uploads!("0.4.0", uploads, state) ==
                 if(has_docs, do: [], else: [:docs])
      end

      assert :ok == PublishHex.stop_if_staged!("0.4.0", state)
    end

    assert :missing == PublishHex.staged_state!({:ok, {404, %{}, nil}}, "package")

    assert [:package, :docs] ==
             PublishHex.remaining_uploads!("0.4.0", [:package, :docs], :missing)

    assert_raise Mix.Error, ~r/disappeared after planning/, fn ->
      PublishHex.remaining_uploads!("0.4.0", [:docs], :missing)
    end

    retired = staged() |> Map.put("retirement", %{"reason" => "security"})

    assert_raise Mix.Error, "Hex release is retired; publication refused", fn ->
      PublishHex.release_state!({:ok, {200, %{}, retired}}, "package")
    end
  end

  test "uncertain reads and upload failures refuse without returning response contents" do
    for response <- [
          {:ok, {403, %{}, "untrusted response"}},
          {:error, "untrusted response"},
          :failed
        ] do
      for fun <- [
            fn -> PublishHex.accepted!(:package, response) end,
            fn -> PublishHex.release_state!(response, "package") end,
            fn -> PublishHex.staged_state!(response, "package") end
          ] do
        error = assert_raise Mix.Error, fun
        refute Exception.message(error) =~ "untrusted response"
        assert Exception.message(error) =~ "Hex "
      end
    end

    for status <- ["approved", "expired", "rejected", "unknown"] do
      response = {:ok, {200, %{}, Map.put(staged(), "status", status)}}

      assert_raise Mix.Error, "Hex staged release read refused (HTTP 200)", fn ->
        PublishHex.staged_state!(response, "package")
      end
    end

    for field <- ["html_url", "expires_at"] do
      assert_raise Mix.Error, "Hex staged release approval metadata is invalid", fn ->
        PublishHex.accepted!(:package, {:ok, {201, %{}, Map.delete(staged(), field)}})
      end
    end

    assert_raise Mix.Error, "Hex package upload refused (HTTP 403)", fn ->
      PublishHex.accepted!(:package, {:ok, {403, %{}, nil}})
    end
  end

  test "a loaded project refuses before reading archives or a publication key" do
    assert_raise Mix.Error, "Upload must run outside a Mix project", fn ->
      PublishHex.run!(["package-and-docs", "0.4.0", "absent-package", "absent-docs"])
    end
  end
end
