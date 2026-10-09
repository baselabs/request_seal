"""RFC 8785 encoding for the corpus's number-free I-JSON profile.

All semantic numbers use tagged decimal strings. Untagged JSON numbers are
refused, avoiding any host-dependent numeric conversion. Object names sort by
UTF-16 code units; arrays retain order; Unicode strings retain their bytes.
"""
import json


def canonical(value):
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, str):
        value.encode("utf-16-be")  # Refuse lone surrogates (I-JSON).
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()
    if isinstance(value, list):
        return b"[" + b",".join(canonical(v) for v in value) + b"]"
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ValueError("JSON member names must be strings")
        keys = sorted(value, key=lambda k: k.encode("utf-16-be"))
        return b"{" + b",".join(canonical(k) + b":" + canonical(value[k]) for k in keys) + b"}"
    raise ValueError("Corpus numbers must be tagged strings")


def decode(data):
    def pairs(items):
        result = {}
        for k, v in items:
            if k in result:
                raise ValueError("Duplicate JSON member")
            result[k] = v
        return result
    return json.loads(data, object_pairs_hook=pairs)
