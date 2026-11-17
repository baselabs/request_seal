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
import time

from processes import install_signal_handlers, run
import release

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "test/fixtures/markdown_destinations.json"
RATE_RESERVE = 1500
BATCH_SIZE = 20
CALL_PAUSE = 0.25


def contain(inline, container, variation):
    if container == "list":
        return "- " + inline
    if container == "quote":
        return "> " + inline
    if container == "table":
        return "| " + inline.replace("|", "\\|") + " |\n|---|"
    if container == "footnote":
        return f"Use [^container{variation}].\n\n[^container{variation}]: " + inline
    return inline


def combinatorial_samples():
    """Ordered pairs in both arrangements; distribute them across containers.

    Escape is a family: each of its pairs expands every delimiter, rather than
    sampling only one escape. Container assignment rotates independently of
    order and arrangement, keeping the reference set to a few hundred samples.
    """
    url = "https://example.com/interaction"
    constructs = {
        "inline": ("[", "](" + url + ")"),
        "reference": ("[", "][ref]"),
        "collapsed": ("[", "][]"),
        "shortcut": ("[", "]"),
        "http-angle": ("<https://example.com/", ">"),
        "ftp-angle": ("<ftp://example.com/", ">"),
        "mailto-angle": ("<mailto:", "@example.com>"),
        "email-angle": ("<", "@example.com>"),
        "https-bare": ("https://example.com/", ""),
        "www-bare": ("www.example.com/", ""),
        "code": ("`", "`"),
        "escape": ("", ""),
        "html": ('<span title="', '">text</span>'),
        "footnote": ("[^", "]"),
        "literal-angle": ("<", ""),
    }
    containers = ("paragraph", "list", "quote", "table", "footnote")
    delimiters = "[]()<>`|!\\*_~\"'"
    for left_index, (left, left_parts) in enumerate(constructs.items()):
        for right_index, (right, right_parts) in enumerate(constructs.items()):
            if left == right:
                continue
            for arrangement_index, arrangement in enumerate(("adjacent", "overlap")):
                container = containers[(left_index + 2 * right_index + arrangement_index) % len(containers)]
                parts, url_parts = [], []
                for variation, delimiter in enumerate(delimiters if "escape" in (left, right) else (None,)):
                    a, b = ("\\" + delimiter, "") if left == "escape" else left_parts
                    c, d = ("\\" + delimiter, "") if right == "escape" else right_parts
                    if arrangement == "adjacent":
                        inline = (a + ("" if left == "literal-angle" else "x") + b +
                                  c + ("" if right == "literal-angle" else "x") + d)
                    else:
                        inline = a + c + url + b + d
                    tail = " https://request-seal.hexdocs.pm/2.3.4/readme.html tail `"
                    parts.append(contain(inline + tail, container, variation))
                    url_parts.append(contain(a + url + b + c + "x" + d + tail, container, variation))
                # All reference forms use the same public destination. In the
                # overlap arrangement labels can become syntactically invalid;
                # that interaction is intentional, and is rendered verbatim.
                definitions = []
                if "reference" in (left, right):
                    definitions.append("[ref]: " + url)
                if {left, right} & {"collapsed", "shortcut"}:
                    definitions.append("[x]: " + url)
                if "footnote" in (left, right):
                    definitions.append("[^x]: " + url)
                suffix = "\n\n" + "\n\n".join(definitions) if definitions else ""
                sample = {"name": f"pair-{left}-{right}-{arrangement}",
                          "construct": f"{left} / {right} / {arrangement} / {container}",
                          "pair": [left, right], "arrangement": arrangement, "container": container,
                          "markdown": "\n\n".join(parts) + suffix}
                # Label/code/escape/HTML pairs have no URL in either delimiter
                # form. Place the URL directly in their shared inline text,
                # so every pair probes a URL at the construct interaction.
                if arrangement == "adjacent" and "example.com" not in "".join((*left_parts, *right_parts)):
                    sample = {**sample, "name": sample["name"] + "-url-boundary",
                              "markdown": "\n\n".join(url_parts) + suffix}
                yield sample
    yield from literal_angle_samples()


def literal_angle_samples():
    """Failed angle tokens next to each URL family in every inline container."""
    for container in ("paragraph", "quote", "list", "table", "footnote"):
        for kind, target in (("www-lower", "www.example.com/path"), ("www-upper", "WWW.example.com/path"),
                             ("http", "http://example.com/path"), ("https", "https://example.com/path"),
                             ("email", "user@example.com")):
            for form, inline in (("unclosed", "<" + target), ("nested", "<<" + target + ">")):
                yield {"name": f"literal-angle-{kind}-{form}-{container}",
                       "construct": "unmatched angle / " + kind + " / " + form + " / " + container,
                       "angle_class": kind, "container": container, "markdown": contain(inline, container, 0)}


def require_budget(calls):
    result = run(["gh", "api", "rate_limit"], capture_output=True, text=True, timeout=60)
    remaining = json.loads(result.stdout)["resources"]["core"]["remaining"]
    if remaining - calls < RATE_RESERVE:
        raise ValueError(f"GitHub core rate limit: {remaining} remaining; stopping to preserve "
                         f"{RATE_RESERVE}. Recorded samples are saved; rerun to resume.")


def expected_outcome(sample, version):
    """An accepted sample must match its recorded renderer, never bless drift."""
    outside = {release.reference_label(match[1]) for match in
               release.REFERENCE_START.finditer(sample.get("outside_definitions", ""))}
    try:
        targets = release.release_destinations(sample["markdown"], version, all_reference_labels=outside)
    except ValueError as error:
        reason = str(error).split(": ", 1)[-1]
        # Retain the named authoring rejection, without tying the reference
        # case to a particular source line or destination's spelling.
        for name in ("autolink destination encoding", "encoding in an extended autolink",
                     "literal angle before an extended autolink", "uppercase extended autolink",
                     "extended email autolink after literal angle",
                     "unused link reference definition", "unused footnote definition",
                     "multiline reference label", "backtick fence info string",
                     "reference definition in a container", "nested block in a footnote definition",
                     "footnote continuation", "table in a container", "raw HTML", "HTML comment",
                     "requires a definition inside the released section", "ambiguous destination syntax",
                     "unsupported URL scheme", "canonical"):
            if name in reason:
                return {"reject": re.escape(name)}
        return {"reject": re.escape(reason)}
    hrefs = sorted({"http://" + target if target.startswith("www.") else target for target in targets})
    if hrefs != sample["github_hrefs"]:
        raise ValueError(f"{sample['name']}: accepted destinations differ from the recorded renderer; "
                         "fix the extractor or add a named construct rejection before resuming")
    return {"destinations": sorted(set(targets))}


def pending_recordings(samples):
    """Queue each missing rendering separately, including outside definitions."""
    for sample in samples:
        if "github_hrefs" not in sample:
            yield sample, "github_hrefs", sample["markdown"]
        if sample.get("outside_definitions") and "github_document_hrefs" not in sample:
            document = sample["markdown"] + "\n\n## Earlier release\n\n" + sample["outside_definitions"]
            yield sample, "github_document_hrefs", document


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
    for match in re.finditer(r"(?:https?://|(?=www\.))([A-Za-z0-9.-]+)", markdown, re.I):
        host = match[1].lower()
        if host not in {"example.com", "www.example.com", "request-seal.hexdocs.pm", "hexdocs.pm",
                        "hex.pm", "github.com", "www.github.com", "raw.githubusercontent.com"}:
            raise ValueError("synthetic corpus URLs must use example.com or RequestSeal's public URLs")
    result = run(["gh", "api", "markdown", "-f", "mode=gfm", "-f", "text=" + markdown],
                 capture_output=True, text=True, timeout=60)
    time.sleep(CALL_PAUSE)
    parser = RenderedLinks()
    parser.feed(result.stdout)
    return {"github_hrefs": sorted(parser.hrefs), "github_blocks": sorted(parser.blocks)}


def main():
    install_signal_handlers()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", action="append", help="Record only this named synthetic sample (repeatable)")
    parser.add_argument("--combinatorial", action="store_true", help="Add the generated ordered-pair section")
    args = parser.parse_args()
    corpus = json.loads(CORPUS.read_text())
    if corpus["source"] != "synthetic":
        raise ValueError("only the committed synthetic corpus may be submitted")
    if args.combinatorial:
        by_name = {sample["name"]: sample for sample in corpus["samples"]}
        for sample in combinatorial_samples():
            if sample["name"] in by_name:
                if sample["markdown"] != by_name[sample["name"]]["markdown"]:
                    raise ValueError("recorded sample changed; give its new input a new sample name")
            else:
                corpus["samples"].append(sample)
    if args.sample and set(args.sample) - {sample["name"] for sample in corpus["samples"]}:
        raise ValueError("unknown synthetic sample name")
    pending = [sample for sample in corpus["samples"] if not args.sample or sample["name"] in args.sample]
    for sample in pending:
        if "github_hrefs" in sample and "expected" not in sample:
            sample["expected"] = expected_outcome(sample, corpus["version"])
    CORPUS.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n")
    recordings = list(pending_recordings(pending))
    if not recordings:
        require_budget(0)
    for index, (sample, field, markdown) in enumerate(recordings):
        if index % BATCH_SIZE == 0:
            require_budget(min(BATCH_SIZE, len(recordings) - index))
        rendered = render(markdown)
        if field == "github_hrefs":
            sample.update(rendered)
        else:
            sample[field] = rendered["github_hrefs"]
        corpus["recorded_on"] = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
        CORPUS.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n")
        if field == "github_hrefs" and "expected" not in sample:
            sample["expected"] = expected_outcome(sample, corpus["version"])
            CORPUS.write_text(json.dumps(corpus, indent=2, ensure_ascii=False) + "\n")
        print("Recorded " + sample["name"] + " " + field, flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Markdown recording failed: {error}", file=sys.stderr)
        sys.exit(1)
