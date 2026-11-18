# Upload inspected archives only. Invoke from a directory with no mix.exs:
# mix run --no-mix-exs --no-start publish_hex.exs UPLOAD VERSION PACKAGE DOCS
# Hex API: https://github.com/hexpm/hex/tree/v2.7.0/lib/hex/api
if File.exists?("mix.exs") or Mix.Project.get() != nil,
  do: Mix.raise("Upload must run outside a Mix project")

[upload, version, package_path, docs_path] = System.argv()
unless upload in ["package-and-docs", "docs"], do: Mix.raise("Invalid upload selection")
{:ok, _} = Version.parse(version)
key = System.fetch_env!("HEX_API_KEY")
if key == "", do: Mix.raise("Publication key is absent")
Hex.start()

auth = [key: key]
# Do not inspect an API error: it may contain request headers or credentials.
expect_uploaded = fn
  {:ok, {status, _, _}} when status in [200, 201] -> :ok
  {:ok, {202, _, _}} -> Mix.raise("Hex upload is held for approval; approve it and dispatch again")
  {:ok, {status, _, _}} -> Mix.raise("Hex upload refused (HTTP #{status})")
  _ -> Mix.raise("Hex upload failed")
end

if upload == "package-and-docs" do
  Hex.API.Release.publish(nil, File.read!(package_path), auth, fn _ -> :ok end, replace: false)
  |> expect_uploaded.()
end

Hex.API.ReleaseDocs.publish(nil, "request_seal", version, File.read!(docs_path), auth)
|> expect_uploaded.()

IO.puts("Uploaded the inspected archives selected by the unkeyed plan: #{upload}")
