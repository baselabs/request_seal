# Upload inspected archives only. Invoke from a directory with no mix.exs:
# mix run --no-mix-exs --no-start publish_hex.exs VERSION PACKAGE DOCS
# Hex API: https://github.com/hexpm/hex/tree/v2.7.0/lib/hex/api
if File.exists?("mix.exs") or Mix.Project.get() != nil,
  do: Mix.raise("Upload must run outside a Mix project")

[version, package_path, docs_path] = System.argv()
{:ok, _} = Version.parse(version)
package = File.read!(package_path)
docs = File.read!(docs_path)
key = System.fetch_env!("HEX_API_KEY")
if key == "", do: Mix.raise("Publication key is absent")
Hex.start()

auth = [key: key]
# Do not inspect an API error: it may contain request headers or credentials.
expect_uploaded = fn
  {:ok, {status, _, _}} when status in [200, 201] -> :ok
  {:ok, {status, _, _}} -> Mix.raise("Hex upload refused (HTTP #{status})")
  _ -> Mix.raise("Hex upload failed")
end

Hex.API.Release.publish(nil, package, auth) |> expect_uploaded.()
Hex.API.ReleaseDocs.publish(nil, "request_seal", version, docs, auth) |> expect_uploaded.()
IO.puts("Uploaded the inspected package and documentation archives")
