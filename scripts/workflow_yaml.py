"""Read the deliberately restricted YAML used by workflow policy checks.

Only block mappings/sequences, string scalars, literal/folded blocks, and
single-line scalar flow sequences are supported. Unsupported YAML fails closed;
this is not a general YAML loader. Keys and scalar types never get coerced.
"""
import re


def _fail(line, reason):
    raise ValueError(f"<line {line}>: {reason}")


def _quoted(text, start, line):
    quote = text[start]
    value = []
    i = start + 1
    escapes = {"\\": "\\", '"': '"', "n": "\n", "t": "\t"}
    while i < len(text):
        char = text[i]
        if char == quote:
            if quote == "'" and text[i:i + 2] == "''":
                value.append("'")
                i += 2
                continue
            return "".join(value), i + 1
        if quote == '"' and char == "\\":
            i += 1
            if i == len(text) or text[i] not in escapes:
                _fail(line, "unsupported double-quoted escape")
            char = escapes[text[i]]
        value.append(char)
        i += 1
    _fail(line, "unterminated quoted scalar")


def _expression_end(text, start, line):
    i = start + 3
    while i < len(text):
        if text[i:i + 2] == "}}":
            return i + 2
        if text[i] in "\"'":
            _, i = _quoted(text, i, line)
        else:
            i += 1
    _fail(line, "unterminated expression")


def _plain(text, line, flow=False):
    if not text or text[0] in "&*!":
        _fail(line, "anchors, aliases, and tags are forbidden")
    if text[0] in "|>[@`%,]}" or text in {"---", "..."} or re.match(r"[-?:](?: |$)", text):
        _fail(line, "unsupported scalar syntax")
    i = 0
    while i < len(text):
        if text.startswith("${{", i):
            i = _expression_end(text, i, line)
            continue
        char = text[i]
        if char == "#" and (i == 0 or text[i - 1] == " "):
            return text[:i].rstrip()
        if char in "{}" or (flow and char in "[],"):
            _fail(line, "flow mappings and nested flow collections are forbidden")
        if char == ":" and (i + 1 == len(text) or text[i + 1] == " "):
            _fail(line, "mapping separator inside a plain scalar")
        i += 1
    return text.rstrip()


def _flow(text, line):
    values = []
    i = 1
    while True:
        while i < len(text) and text[i] == " ":
            i += 1
        if i == len(text):
            _fail(line, "unterminated flow sequence")
        if text[i] == "]":
            return values, i + 1
        if text[i] in "\"'":
            value, i = _quoted(text, i, line)
        else:
            start = i
            while i < len(text) and text[i] not in ",]":
                if text.startswith("${{", i):
                    i = _expression_end(text, i, line)
                else:
                    i += 1
            raw = text[start:i].rstrip()
            value = _plain(raw, line, flow=True)
            if value != raw:
                _fail(line, "comment before flow sequence closes")
        values.append(value)
        while i < len(text) and text[i] == " ":
            i += 1
        if i == len(text) or text[i] not in ",]":
            _fail(line, "expected flow sequence comma or closing bracket")
        if text[i] == "]":
            return values, i + 1
        i += 1


def _scalar(text, line):
    if text.startswith(("'", '"')):
        value, end = _quoted(text, 0, line)
    elif text.startswith("["):
        value, end = _flow(text, line)
    else:
        return _plain(text, line)
    tail = text[end:]
    if tail and not (tail.startswith(" ") and (not tail.strip() or tail.lstrip().startswith("#"))):
        _fail(line, "unexpected text after scalar")
    return value


class _Parser:
    def __init__(self, text):
        # Split on LF only. Every other line break (a lone CR, NEL, LS, PS) is refused anywhere,
        # block scalar content included: another YAML parser would break a line there, so a
        # block scalar could otherwise end early and carry structure this parser never sees.
        text = text.replace("\r\n", "\n")
        self.final_newline = text.endswith("\n")
        self.lines = text.split("\n")
        for number, raw in enumerate(self.lines, 1):
            if any(char in raw for char in ("\r", "\x85", "\u2028", "\u2029")):
                _fail(number, "line breaks other than LF and CRLF are forbidden")
        if self.lines[-1] == "":
            self.lines.pop()
        self.i = 0

    def peek(self):
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            line = self.i + 1
            if any(char in raw for char in ("\t", "\r", "\x85", "\u2028", "\u2029")) or any(ord(c) < 32 for c in raw):
                _fail(line, "only spaces are allowed outside block scalar content")
            body = raw.lstrip(" ")
            if not body or body.startswith("#"):
                self.i += 1
                continue
            if re.match(r"(?:---|\.\.\.)(?: |$)", body):
                _fail(line, "document markers are forbidden")
            return len(raw) - len(body), body, line
        return None

    def pair(self, body, line):
        match = re.match(r"([A-Za-z0-9_-]+):(.*)$", body)
        if not match:
            _fail(line, "expected a plain mapping key; quoted, complex, and merge keys are forbidden")
        key, value = match.groups()
        if value and not value.startswith(" "):
            _fail(line, "mapping value requires a space after ':'")
        return key, value.lstrip(" ")

    def block_scalar(self, style, indent):
        start = self.i
        while self.i < len(self.lines):
            raw = self.lines[self.i]
            if raw.strip(" ") and len(raw) - len(raw.lstrip(" ")) <= indent:
                break
            self.i += 1
        content = self.lines[start:self.i]
        nonblank = [raw for raw in content if raw.strip(" ")]
        if not nonblank:
            return ""
        margin = len(nonblank[0]) - len(nonblank[0].lstrip(" "))
        for offset, raw in enumerate(content):
            if raw.strip(" ") and len(raw) - len(raw.lstrip(" ")) < margin:
                _fail(start + offset + 1, "block scalar content is under-indented")
        content = [raw[margin:] for raw in content]
        # Clip trailing empty lines; preserve a missing final line break at EOF.
        last = max(index for index, raw in enumerate(content) if raw)
        final_break = start + last < len(self.lines) - 1 or self.final_newline
        content = content[:last + 1]
        if style[0] == "|":
            value = "\n".join(content)
        else:
            nonempty = [index for index, raw in enumerate(content) if raw]
            value = "\n" * nonempty[0]
            for position, index in enumerate(nonempty):
                raw = content[index]
                value += raw
                if position + 1 < len(nonempty):
                    following = nonempty[position + 1]
                    more_indented = raw.startswith((" ", "\t")) or content[following].startswith((" ", "\t"))
                    blanks = following - index - 1
                    value += "\n" * (blanks + 1) if more_indented else "\n" * blanks if blanks else " "
        return value + ("\n" if final_break and not style.endswith("-") else "")

    def value(self, raw, indent, line):
        if not raw or raw.startswith("#"):
            nested = self.peek()
            return self.block(nested[0]) if nested and nested[0] > indent else ""
        if re.fullmatch(r"[|>]-?(?: +#.*)?", raw):
            return self.block_scalar(raw.split(" ", 1)[0], indent)
        return _scalar(raw, line)

    def mapping(self, indent, first=None):
        result = {}
        while True:
            if first:
                body, line = first
                first = None
            else:
                entry = self.peek()
                if not entry or entry[0] < indent:
                    break
                if entry[0] != indent:
                    _fail(entry[2], "unexpected mapping indentation")
                _, body, line = entry
                self.i += 1
            key, raw = self.pair(body, line)
            if key in result:
                _fail(line, f"duplicate key {key!r}")
            result[key] = self.value(raw, indent, line)
        return result

    def block(self, indent):
        entry = self.peek()
        if not entry[1].startswith("- ") and entry[1] != "-":
            return self.mapping(indent)
        result = []
        while True:
            entry = self.peek()
            if not entry or entry[0] < indent:
                return result
            if entry[0] != indent or not (entry[1].startswith("- ") or entry[1] == "-"):
                _fail(entry[2], "unexpected sequence indentation or item")
            _, body, line = entry
            raw = body[1:].lstrip(" ")
            self.i += 1
            if re.match(r"[A-Za-z0-9_-]+:", raw):
                item_indent = indent + len(body) - len(raw)
                result.append(self.mapping(item_indent, (raw, line)))
            else:
                # Quoted/complex/merge keys cannot masquerade as scalar items.
                result.append(self.value(raw, indent, line))


def load(text):
    """Return one workflow mapping or raise ValueError with the offending line."""
    parser = _Parser(text)
    entry = parser.peek()
    if entry is None:
        return {}
    if entry[0] != 0:
        _fail(entry[2], "top-level mapping must start at column one")
    result = parser.block(0)
    if not isinstance(result, dict):
        _fail(entry[2], "workflow must be a mapping")
    trailing = parser.peek()
    if trailing:
        _fail(trailing[2], "unexpected trailing structure")
    return result
