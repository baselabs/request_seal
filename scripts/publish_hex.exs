# Upload inspected archives only. Invoke from a directory with no mix.exs:
# mix run --no-mix-exs --no-start publish_hex.exs UPLOAD VERSION PACKAGE DOCS
# Hex API: https://github.com/hexpm/hex/tree/v2.7.0/lib/hex/api
defmodule PublishHex do
  @moduledoc false

  def context! do
    if File.exists?("mix.exs") or Mix.Project.get() != nil,
      do: Mix.raise("Upload must run outside a Mix project")

    :ok
  end

  def run!([upload, version, package_path, docs_path]) do
    context!()
    unless upload in ["package-and-docs", "docs"], do: Mix.raise("Invalid upload selection")
    {:ok, _} = Version.parse(version)
    package = File.read!(package_path)
    docs = File.read!(docs_path)
    key = System.fetch_env!("HEX_API_KEY")
    if key == "", do: Mix.raise("Publication key is absent")
    Mix.Local.append_archives()
    Hex.start()
    auth = [key: key]
    state = read_release!(version, package, auth)
    stop_if_staged!(version, state)
    uploads = if upload == "package-and-docs", do: [:package, :docs], else: [:docs]
    uploads = remaining_uploads!(version, uploads, state)

    state =
      Enum.reduce(uploads, :uploaded, fn kind, state ->
        result =
          request(fn ->
            case kind do
              :package ->
                Hex.API.Release.publish(nil, package, auth, fn _ -> :ok end, replace: false)

              :docs ->
                Hex.API.ReleaseDocs.publish(nil, "request_seal", version, docs, auth)
            end
          end)

        state = upload_state!(kind, state, result, package)
        if state == :uploaded, do: IO.puts("Hex #{kind} upload accepted")
        state
      end)

    stop_if_staged!(version, state)

    IO.puts("Upload step complete; unkeyed read-back must verify both archives")
    :ok
  end

  def run!(_), do: Mix.raise("Expected upload selection, version, package archive and docs archive")

  # A served lookup does not expose a pending release. Only an explicit staged
  # 404 also permits a new upload. Both reads use the upload step's own auth.
  defp read_release!(version, package, auth) do
    response =
      request(fn -> Hex.API.Release.get(nil, "request_seal", version, auth) end)

    case response do
      {:ok, {404, _, _}} ->
        url =
          Hex.State.fetch!(:api_url) <>
            "/packages/request_seal/releases/#{version}/staged"

        request(fn -> Hex.API.Release.get_staged(url, auth) end)
        |> staged_state!(package)

      _ ->
        release_state!(response, package)
    end
  end

  defp request(fun) do
    fun.()
  rescue
    _ -> :failed
  catch
    _, _ -> :failed
  end

  def staged_state!({:ok, {404, _, _}}, _package), do: :missing

  def staged_state!({:ok, {200, _, %{"status" => "staged"}}} = response, package),
    do: release_state!(response, package)

  def staged_state!(response, _package), do: refused!("staged release read", response)

  # Pure response decisions never print response bodies, headers or credentials.
  def release_state!({:ok, {200, _, body}}, package) when is_map(body) do
    if body["retirement"] != nil, do: Mix.raise("Hex release is retired; publication refused")

    unless is_binary(body["checksum"]) and String.downcase(body["checksum"]) == sha256(package),
      do: Mix.raise("Hex release SHA-256 differs; refusing replacement")

    case body do
      %{"status" => "staged"} -> staged(body)
      %{"has_docs" => has_docs} when is_boolean(has_docs) -> {:served, has_docs}
      _ -> Mix.raise("Hex release state is invalid; publication refused")
    end
  end

  def release_state!(response, _package), do: refused!("release read", response)

  def remaining_uploads!(version, _uploads, {:staged, _}),
    do: Mix.raise(staged_message(version))

  def remaining_uploads!(_version, _uploads, {:served, true}), do: []

  def remaining_uploads!(_version, uploads, {:served, false}),
    do: List.delete(uploads, :package)

  def remaining_uploads!(_version, uploads, :missing) do
    unless :package in uploads,
      do: Mix.raise("Hex release disappeared after planning; publication refused")

    unless :docs in uploads,
      do: Mix.raise("Hex new release requires a docs upload plan; publication refused")

    uploads
  end

  # Only a package staged by this invocation may receive its planned docs.
  def upload_state!(:package, :uploaded, response, _package) do
    case accepted!(:package, response) do
      {:staged, metadata} -> {:awaiting_docs, metadata}
      :uploaded -> :uploaded
    end
  end

  def upload_state!(
        :docs,
        {:awaiting_docs, _},
        {:ok,
         {status, _, %{"status" => "staged", "kind" => "release", "checksum" => checksum} = body}},
        package
      )
      when status in 200..299 do
    unless is_binary(checksum) and String.downcase(checksum) == sha256(package),
      do: staged_docs_refused!()

    staged(body)
  end

  def upload_state!(:docs, {:awaiting_docs, _}, _response, _package),
    do: staged_docs_refused!()

  def upload_state!(:docs, :uploaded, response, _package), do: accepted!(:docs, response)

  defp staged_docs_refused!,
    do:
      Mix.raise(
        "Hex staged release documentation did not join the inspected package; publication refused"
      )

  # Hex 2.7.0 hex.publish classifies every 2xx by body status, not HTTP 202.
  def accepted!(_kind, {:ok, {status, _, %{"status" => "staged"} = body}})
      when status in 200..299,
      do: staged(body)

  def accepted!(_kind, {:ok, {status, _, _}}) when status in 200..299, do: :uploaded
  def accepted!(kind, response), do: refused!("#{kind} upload", response)

  defp staged(%{"html_url" => url, "expires_at" => expiry})
       when is_binary(url) and is_binary(expiry),
       do: {:staged, %{html_url: url, expires_at: expiry}}

  defp staged(_), do: Mix.raise("Hex staged release approval metadata is invalid")

  def staged_message(version),
    do: "Hex release #{version} is staged for approval; approve it on hex.pm, then dispatch again"

  def stop_if_staged!(version, {:staged, metadata} = state) do
    IO.puts(
      "::notice::Hex approval pending at #{notice_text(metadata.html_url)} " <>
        "(expires at #{notice_text(metadata.expires_at)})"
    )

    remaining_uploads!(version, [], state)
  end

  def stop_if_staged!(_version, {:awaiting_docs, _}), do: staged_docs_refused!()

  def stop_if_staged!(_version, _state), do: :ok

  defp notice_text(text) do
    text
    |> String.replace("%", "%25")
    |> String.replace("\r", "%0D")
    |> String.replace("\n", "%0A")
  end

  defp refused!(label, {:ok, {status, _, _}}) when is_integer(status),
    do: Mix.raise("Hex #{label} refused (HTTP #{status})")

  defp refused!(label, _), do: Mix.raise("Hex #{label} failed")

  defp sha256(bytes), do: :crypto.hash(:sha256, bytes) |> Base.encode16(case: :lower)
end

PublishHex.run!(System.argv())
