"""Verify canonical corpus metadata and the complete file digest inventory."""
import hashlib
from pathlib import Path
import sys
from corpus_json import canonical, decode


def verify(root):
    if sorted(p.name for p in root.iterdir()) != ["cases", "index.json", "sources"]:
        raise ValueError("unlisted_file")
    if any(p.is_symlink() for p in root.rglob("*")):
        raise ValueError("unsafe_path")
    raw = (root / "index.json").read_bytes()
    index = decode(raw)
    if canonical(index) != raw or index["format"] != "request-seal-conformance-corpus-index/1":
        raise ValueError("invalid_index")
    paths = [v["path"] for v in index["files"]]
    actual = sorted(str(p.relative_to(root)) for folder in ("sources", "cases")
                    for p in (root / folder).rglob("*") if p.is_file())
    if paths != actual or len(set(paths)) != len(paths):
        raise ValueError("file_inventory")
    for entry in index["files"]:
        path = root / entry["path"]
        if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
            raise ValueError("unsafe_path")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("file_digest: " + entry["path"])
        if entry["path"].startswith("cases/") and canonical(decode(data)) != data:
            raise ValueError("noncanonical_manifest")
    ids = [v["id"] for v in index["cases"]]
    manifests = [v["manifest"] for v in index["cases"]]
    if len(ids) != len(set(ids)) or len(manifests) != len(set(manifests)):
        raise ValueError("duplicate_case")
    if sorted(manifests) != [p for p in paths if p.startswith("cases/")]:
        raise ValueError("case_inventory")
    if index.get("known_positive") not in ids:
        raise ValueError("known_positive")
    for entry in index["cases"]:
        case = decode((root / entry["manifest"]).read_bytes())
        for k in ("id", "surface", "class"):
            if case[k] != entry[k]:
                raise ValueError("case_metadata")
        if "batch" in case and case["batch"]["count"] != entry.get("count"):
            raise ValueError("batch_count")
    print("PASS: corpus canonical metadata and " + str(len(paths)) + " file digests")


if __name__ == "__main__":
    verify(Path(sys.argv[1] if len(sys.argv) > 1 else "corpus"))
