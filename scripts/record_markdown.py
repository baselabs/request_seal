#!/usr/bin/env python3
"""Refresh the synthetic Markdown corpus from GitHub's public GFM renderer."""
import argparse
import datetime
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys

from processes import install_signal_handlers, run

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "test/fixtures/markdown_destinations.json"


class RenderedLinks(HTMLParser):
    """Record unique authored hrefs, excluding renderer-owned navigation."""
    def __init__(self):
        super().__init__()
        self.hrefs = set()
        self.blocks = set()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"table", "blockquote", "li", "pre", "code", "h1", "h2", "h3"}:
            self.blocks.add(tag)
        if (tag == "a" and "href" in attrs and "data-footnote-ref" not in attrs
                and "data-footnote-backref" not in attrs and attrs.get("class") != "anchor"):
            self.hrefs.add(attrs["href"])


def render(markdown):
    # Only the explicitly synthetic corpus fields reach the public API. No
    # documentation, changelog, Git tree, or caller-provided file is submitted.
    for match in re.finditer(r"(?:https?://|(?=www\.))([A-Za-z0-9.-]+)", markdown):
        host = match[1].lower()
        if host not in {"example.com", "www.example.com", "request-seal.hexdocs.pm", "hexdocs.pm",
                        "hex.pm", "github.com", "raw.githubusercontent.com"}:
            raise ValueError("synthetic corpus URLs must use example.com or RequestSeal's public URLs")
    result = run(["gh", "api", "markdown", "-f", "mode=gfm", "-f", "text=" + markdown],
                 capture_output=True, text=True, timeout=60)
    parser = RenderedLinks()
    parser.feed(result.stdout)
    return {"github_hrefs": sorted(parser.hrefs), "github_blocks": sorted(parser.blocks)}


def main():
    install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", action="append", help="Refresh only this named synthetic sample (repeatable)")
    args = parser.parse_args()
    corpus = json.loads(CORPUS.read_text())
    if corpus["source"] != "synthetic":
        raise ValueError("only the committed synthetic corpus may be submitted")
    if args.sample and set(args.sample) - {sample["name"] for sample in corpus["samples"]}:
        raise ValueError("unknown synthetic sample name")
    for sample in corpus["samples"]:
        if args.sample and sample["name"] not in args.sample:
            continue
        sample.update(render(sample["markdown"]))
        if sample.get("outside_definitions"):
            document = sample["markdown"] + "\n\n## Earlier release\n\n" + sample["outside_definitions"]
            sample["github_document_hrefs"] = render(document)["github_hrefs"]
        print("Recorded " + sample["name"], flush=True)
    corpus["recorded_on"] = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    CORPUS.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Markdown recording failed: {error}", file=sys.stderr)
        sys.exit(1)
