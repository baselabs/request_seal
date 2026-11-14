"""Derive native JOSE policy cases from public RFC and pinned peer vectors.

This script never calls RequestSeal or computes an expected cryptographic result.
Positive bytes come unchanged from the corpus's published/peer sources. Negative
headers change one public admission predicate and retain the original signature.
Run with python3 -B so importing the inventory tooling leaves no bytecode cache.
"""
import base64
import json
from pathlib import Path
from corpus_json import canonical
from import_ecdh_vectors import refresh

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"
PATHS = []


def enc(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def dec(value):
    return base64.urlsafe_b64decode(value + "===")


def pairs(value):
    return {"pairs": [[k, v] for k, v in sorted(value.items())]}


def number(value):
    return {"int": str(value)}


def source(rfc, section):
    return {"document": "RFC " + rfc, "section": section,
            "url": "https://www.rfc-editor.org/rfc/rfc" + rfc + ".html#section-" + section}


def case(name, surface, inputs, expected, src, derivation, positive=None, policy=None):
    id_ = surface.split(".")[0] + "/native-" + name
    data = {"format": "request-seal-conformance-case/1", "id": id_,
            "surface": surface, "class": "rejection" if "rule_id" in expected else "verify_only",
            "evidence_class": "reviewed_derivation", "source": src,
            "derivation": derivation, "inputs": inputs, "expected": expected}
    if positive:
        data["positive"] = positive
    if policy:
        data["policy"] = policy
    path = "cases/" + id_ + ".json"
    (CORPUS / path).write_bytes(canonical(data))
    PATHS.append("corpus/" + path)
    return id_


def changed(token, fn):
    parts = token.split(".")
    header = json.loads(dec(parts[0]))
    fn(header)
    parts[0] = enc(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode())
    return ".".join(parts)


def replace(token, i, value):
    parts = token.split("."); parts[i] = value
    return ".".join(parts)


def protected():
    vector = json.loads((CORPUS / "sources/rfc7520/5_6.direct_encryption_using_aes-gcm.json").read_text())
    token = vector["output"]["compact"]
    header = json.loads(dec(token.split(".")[0]))
    kid = header["kid"]
    src = source("7516", "5.2")
    why = "RFC 7516 protected-header processing with an explicit closed member and exact public-context policy; checks precede key resolution. No decryption claim."
    def add(name, policy, rule=None, positive=None):
        return case("r6-" + name, "jwe.protected/v1", {"token": token, "policy": policy},
                    {"rule_id": "jose/input." + rule} if rule else {"accepted": True}, src, why, positive)
    base = add("expected", {"expected": pairs({"kid": kid}), "permitted": []})
    add("permitted", {"expected": pairs({}), "permitted": ["kid"]})
    add("unexpected-member", {"expected": pairs({}), "permitted": []}, "unexpected_member", base)
    add("missing-expected", {"expected": pairs({"typ": "JWT"}), "permitted": ["kid"]}, "protected_mismatch", base)
    add("different-expected", {"expected": pairs({"kid": "different"}), "permitted": []}, "protected_mismatch", base)
    invalid = {
        "overlap": {"expected": pairs({"kid": kid}), "permitted": ["kid"]},
        "duplicate-permitted": {"expected": pairs({}), "permitted": ["kid", "kid"]},
        "oversized-expected": {"expected": pairs({"kid": "x" * 16_384}), "permitted": []},
        "too-many-expected": {"expected": pairs({"field" + str(i): "x" for i in range(65)}), "permitted": []},
        "too-many-permitted": {"expected": pairs({}), "permitted": ["field" + str(i) for i in range(65)]},
    }
    for member in ("alg", "enc", "iv", "tag", "epk", "apu", "apv"):
        for where in ("expected", "permitted"):
            invalid[where + "-reserved-" + member] = {"expected": pairs({member: "x"} if where == "expected" else {}), "permitted": [member] if where == "permitted" else []}
    for name, policy in invalid.items():
        add(name, policy, "invalid_policy", base)

    nested = changed(token, lambda h: h.update(context={"counter": 7, "enabled": True}))
    policy = {"expected": pairs({"context": {"counter": number(7), "enabled": True}}), "permitted": ["kid"]}
    nested_base = case("r6-exact-json", "jwe.protected/v1", {"token": nested, "policy": policy}, {"accepted": True}, src, why + " The public context object is an authored header mutation; integers use the corpus's tagged representation.")
    policy["expected"] = pairs({"context": {"counter": True, "enabled": True}})
    case("r6-json-type-mismatch", "jwe.protected/v1", {"token": nested, "policy": policy}, {"rule_id": "jose/input.protected_mismatch"}, src, why + " Boolean true does not equal integer seven.", nested_base)


def batch():
    rows = json.loads((CORPUS / "sources/cross-jose/vectors.json").read_text())
    # Different protected headers make the public resolver request identify its
    # declared index without assuming concurrent callback invocation order.
    selected = [rows[i] for i in (8, 11, 0, 15, 9, 1)]
    items = [{"token": r["token"], "expected": pairs({})} for r in selected]
    items[1]["token"] = replace(items[1]["token"], 4, enc(bytes(16)))
    items[2]["token"] = replace(items[2]["token"], 1, "AA")
    keys = {}
    for i, r in enumerate(selected):
        if i == 2: continue
        value = r["key"]
        material = {"format": "jwk", "value": pairs(value)} if value["kty"] != "oct" else {"format": "raw", "value": {"b64": value["k"]}}
        keys[str(i)] = {"algorithm": {"kind": "jwe", "name": r["alg"]}, "capabilities": ["unwrap"], "material": material, "state": "released" if i == 3 else "live"}
    resolver = [{"index": number(i), "outcome": {"key": str(i)}} for i in (0, 1, 3)]
    resolver += [{"index": number(4), "outcome": "error"}, {"index": number(5), "outcome": "raise"}]
    expected = [{"index": number(0), "plaintext": {"b64": selected[0]["plaintext"]}}]
    expected += [{"index": number(i), "rule_id": "jose/crypto.decryption_failed"} for i in (1, 2, 3)]
    expected += [{"index": number(4), "rule_id": "jose/key.unknown_key"}, {"index": number(5), "rule_id": "jose/key.key_resolver_failed"}]
    items.append({"token": "not-a-token", "expected": pairs({})})
    expected.append({"index": number(6), "rule_id": "jose/input.invalid_serialization"})
    case("r7-isolation", "jwe.decrypt_many/v1", {"items": items, "keys": keys, "resolver": resolver}, {"results": expected}, source("7516", "5.2"), "Positional isolation using pinned npm jose 6.2.17 vectors in sources/cross-jose/vectors.json (rows 8, 11, 0, 15, 9, 1). Item 1 has a forged tag; item 2 has a forbidden direct-ECDH encrypted-key width and no resolver entry; item 3 uses a genuinely released Local handle. Items 4 and 5 exercise the explicit caller resolver error and exception boundaries. Item 6 is malformed compact input with no resolver entry. Item 0 retains its independent peer plaintext.")
    case("r7-shared-handle", "jwe.decrypt_many/v1",
         {"items": [items[0], items[0]], "keys": {"0": keys["0"]},
          "resolver": [{"index": number(i), "outcome": {"key": "0"}} for i in range(2)]},
         {"results": [{"index": number(i), "plaintext": {"b64": selected[0]["plaintext"]}} for i in range(2)]},
         source("7516", "5.2"), "Repeat the unchanged pinned npm jose vector at sources/cross-jose/vectors.json row 8. Both positions select the same named real Local handle, so they share one unwrap call; callback order does not affect identical outcomes. Both independent source plaintexts are preserved.")



def embedded():
    # RFC 9449 section 4.1 figure 2, with RFC 8792 line wrapping removed.
    token = "".join([
        "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6Ik",
        "VDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCR",
        "nMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JE",
        "QSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIj",
        "oiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwia",
        "WF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg",
        "4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"])
    jwk = json.loads(dec(token.split(".")[0]))["jwk"]
    src = source("9449", "4.3")
    why = "RFC 9449 section 4.1 figure 2 supplies the unchanged positive signature and payload; sections 4.2 and 4.3 require the embedded public signature key. Rejection changes one public predicate, decided before signature verification, under RequestSeal's explicit embedded-key selection. This exercises the key primitive only, not DPoP claims or authorization."
    def add(name, token_, rule=None, mode="require", resolver="embedded", algorithms=None, positive=None):
        policy = {"algorithms": algorithms or ["ES256"], "timeout": number(30_000), "protected": {"expected": pairs({"typ": "dpop+jwt"}), "permitted": [], "embedded_key": mode}}
        return case("embedded-" + name, "jws.verify", {"compact": token_, "resolver": resolver}, {"rule_id": "jose/" + rule} if rule else {"valid": True, "payload": {"b64": token_.split(".")[1]}}, src, why, positive, policy)
    base = add("require", token)
    add("refuse", token, "input.unsupported_header", mode="refuse", positive=base)
    shapes = {"not-object": [], "null": None, "string": "not a key", "boolean": True, "integer": 7, "unsupported-ec-curve": dict(jwk, crv="P-521"), "unsupported-okp-curve": {"kty":"OKP", "crv":"Ed448", "x":"AA"}, "large-rsa": {"kty":"RSA", "n":enc(bytes([1]) + bytes([255]) * 1024), "e":"AQAB"}, "missing-member": {k:v for k,v in jwk.items() if k != "x"}, "bad-import": dict(jwk, x="!"), "bad-ec": dict(jwk, x="AA", y="AA"), "bad-okp": {"kty":"OKP", "crv":"Ed25519", "x":"AA"}, "oct": {"kty":"oct", "k":"AA"}, "x25519": {"kty":"OKP", "crv":"X25519", "x":enc(bytes(32))}, "small-rsa": {"kty":"RSA", "n":"AQ", "e":"Aw"}}
    for name, value in shapes.items():
        add(name, changed(token, lambda h: h.update(jwk=value)), "input.invalid_header", positive=base)
    add("missing", changed(token, lambda h: h.pop("jwk")), "input.invalid_header", positive=base)
    for member in ("d", "p", "q", "dp", "dq", "qi", "oth", "k", "kid", "use", "key_ops", "alg", "x5c"):
        add("member-" + member, changed(token, lambda h: h["jwk"].update({member:"AA"})), "input.invalid_header", positive=base)
    add("binding", changed(token, lambda h: h.update(alg="RS256")), "key.algorithm_mismatch", algorithms=["RS256"], positive=base)
    for resolver in ("public", "handle", "closure", "null"):
        add("require-" + resolver, token, "key.key_resolver_failed", resolver=resolver, positive=base)
    add("refuse-sentinel", changed(token, lambda h: h.pop("jwk")), "key.key_resolver_failed", mode="refuse", positive=base)
    add("invalid-signature", replace(token, 2, enc(bytes(64))), "crypto.invalid_signature", positive=base)
    # Refuse also has a positive: the RFC 7515 RS256 JWS without an embedded key.
    vector = json.loads((CORPUS / "sources/rfc7515/rfc7515.json").read_text())["A.2"]
    case("embedded-refuse-without-jwk", "jws.verify",
         {"compact": vector["compact"], "key": {"ref": {"file": "sources/rfc7515/rfc7515.json", "pointer": "/A.2/key"}}, "resolver": "public"},
         {"valid": True, "payload": {"b64": vector["compact"].split(".")[1]}}, source("7515", "A.2"),
         "The unchanged RFC 7515 Appendix A.2 RS256 signature is accepted with explicit refusal of embedded keys and the published public key.",
         policy={"algorithms": ["RS256"], "timeout": number(30_000), "protected": {"expected": pairs({}), "permitted": [], "embedded_key": "refuse"}})



def main():
    protected(); batch(); embedded(); refresh()
    config = ROOT / ".gitleaks.toml"
    text = config.read_text()
    marker = "# Native policy cases derived from public JOSE vectors."
    if marker in text: text = text[:text.index(marker)]
    text += "\n" + marker + "\n[[allowlists]]\ndescription = \"Native JOSE policy and isolation cases carrying published or pinned peer compact vectors and explicit rejection mutations\"\npaths = [\n"
    text += "".join("  '''^" + p.replace(".", r"\.") + "$''',\n" for p in sorted(PATHS))
    config.write_text(text + "]\n")
    print("Native JOSE cases:", len(PATHS))


if __name__ == "__main__":
    main()
