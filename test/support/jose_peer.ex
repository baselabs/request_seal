defmodule RequestSeal.JOSEPeer do
  @moduledoc false

  def with_input(input, callback) do
    dir =
      Path.join(
        System.tmp_dir!(),
        "requestseal-peer-#{Base.encode16(:crypto.strong_rand_bytes(16), case: :lower)}"
      )

    File.mkdir!(dir)

    try do
      File.chmod!(dir, 0o700)
      path = Path.join(dir, "input.json")
      {:ok, file} = :file.open(String.to_charlist(path), [:write, :binary, :exclusive])

      try do
        File.chmod!(path, 0o600)
        :ok = :file.write(file, input <> "\n")
      after
        :ok = :file.close(file)
      end

      callback.(path)
    after
      File.rm_rf!(dir)
    end
  end

  def run(path) do
    System.cmd(
      "node",
      [
        "--input-type=module",
        "-e",
        "import fs from 'node:fs'; process.stdin.push(fs.readFileSync(process.argv[1])); process.stdin.push(null); await import('./test/support/jose_webcrypto_peer.mjs');",
        path
      ],
      stderr_to_stdout: true
    )
  end
end
