"""Reproduce public peer vectors or check both directions with exact tool pins.

npm jose 6.2.17 and Erlang jose 1.11.13 are tooling only, pinned by version and
by content: scripts/jose_libraries/package-lock.json carries the npm tarball's
integrity and scripts/jose_libraries/mix.lock the Hex checksums, so a changed
artifact fails to install. Installations and Mix.install state live in a
TemporaryDirectory and are removed on every exit.
Use --generate once to replace the checked-in independent fixture set; the
normal gate checks those fixtures and fresh RequestSeal output with both peers.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import shutil
import tempfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "corpus/sources/cross-jose/vectors.json"


def run(argv, env, cwd=ROOT):
    subprocess.run([str(x) for x in argv], cwd=cwd, env=env, check=True, timeout=300)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate", action="store_true")
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="requestseal-jose-peers-") as temp:
        temp = Path(temp)
        env = dict(os.environ, MIX_INSTALL_DIR=str(temp / "mix-install"))
        for name in ("package.json", "package-lock.json"):
            shutil.copy(ROOT / "scripts/jose_libraries" / name, temp / name)
        run(["npm", "ci", "--prefix", temp, "--ignore-scripts", "--no-audit", "--no-fund"], env)
        env["REQUESTSEAL_NPM_JOSE"] = str(temp / "node_modules/jose/dist/webapi/index.js")
        node = ["node", ROOT / "scripts/jose_libraries/npm.mjs"]
        erlang = ["elixir", ROOT / "scripts/jose_libraries/erlang.exs"]
        if options.generate:
            npm, erl = temp / "npm.json", temp / "erlang.json"
            run(node + ["make", "-", npm], env)
            run(erlang + ["make", "-", erl], env, cwd=temp)
            SOURCE.parent.mkdir(parents=True, exist_ok=True)
            SOURCE.write_text(json.dumps(json.loads(npm.read_text()) + json.loads(erl.read_text()), indent=2) + "\n")
        produced = temp / "request-seal.json"
        run(["mix", "run", "--no-start", ROOT / "scripts/jose_libraries/request_seal.exs", SOURCE, produced], env)
        run(node + ["verify", produced, "-"], env)
        run(erlang + ["verify", produced, "-"], env, cwd=temp)
        print("PASS both directions: npm jose 6.2.17 and Erlang jose 1.11.13; isolated tools removed", flush=True)


if __name__ == "__main__":
    main()
