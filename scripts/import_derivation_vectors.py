"""Reproduce independent RFC 9180 and custody derivation vectors without Elixir.

Only Python's standard library is used. No RequestSeal result supplies an
expectation. This is fixture generation, not an external-conformance claim for
the RequestSeal-specific framing. RFC 9180's pinned publication has no P-384
vectors; that KEM is independently derived from Section 7.1.3 here.
"""
import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from corpus_json import canonical

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "corpus"
UPSTREAM = "https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json"
PREFIX = b"request-seal/derive/v1"
CURVES = {
    16: ("sha256", 32, "P-256", int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
         int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
         int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
         int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)),
    17: ("sha384", 48, "P-384", int("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16),
         int("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16),
         int("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
         int("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16)),
}


def mac(hash, key, value):
    return hmac.digest(key, value, hash)


def expand(hash, prk, info, size):
    output, previous = b"", b""
    for counter in range(1, 256):
        previous = mac(hash, prk, previous + info + bytes([counter]))
        output += previous
        if len(output) >= size:
            return output[:size]
    raise ValueError("HKDF length")


def ec_public(kem, scalar):
    _, size, _, p, _, x, y = CURVES[kem]
    def add(a, b):
        if a is None: return b
        if b is None: return a
        x1, y1 = a; x2, y2 = b
        if x1 == x2 and (y1 + y2) % p == 0: return None
        numerator, denominator = (3*x1*x1-3, 2*y1) if a == b else (y2-y1, x2-x1)
        slope = numerator * pow(denominator, -1, p) % p
        xx = (slope*slope-x1-x2) % p
        return xx, (slope*(x1-xx)-y1) % p
    point, base, k = None, (x, y), int.from_bytes(scalar, "big")
    while k:
        if k & 1: point = add(point, base)
        base = add(base, base); k >>= 1
    return b"\x04" + b"".join(v.to_bytes(size, "big") for v in point)


def x_public(scalar):
    p = 2**255-19
    k = int.from_bytes(scalar, "little") & ((1 << 255)-8) | (1 << 254)
    x1, x2, z2, x3, z3, swap = 9, 1, 0, 9, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1; swap ^= kt
        if swap: x2, x3, z2, z3 = x3, x2, z3, z2
        swap = kt
        a = (x2+z2) % p; aa = a*a % p; b = (x2-z2) % p; bb = b*b % p
        e = (aa-bb) % p; c = (x3+z3) % p; d = (x3-z3) % p
        da = d*a % p; cb = c*b % p
        x3 = (da+cb)**2 % p; z3 = x1*(da-cb)**2 % p
        x2 = aa*bb % p; z2 = e*(aa+121665*e) % p
    if swap: x2, x3, z2, z3 = x3, x2, z3, z2
    return (x2*pow(z2, -1, p) % p).to_bytes(32, "little")


def ed_public(seed):
    p = 2**255-19
    d = -121665*pow(121666, -1, p) % p
    y = 4*pow(5, -1, p) % p
    xx = (y*y-1)*pow(d*y*y+1, -1, p) % p
    x = pow(xx, (p+3)//8, p)
    if (x*x-xx) % p: x = x*pow(2, (p-1)//4, p) % p
    if x & 1: x = p-x
    def add(a, b):
        x1, y1 = a; x2, y2 = b; product = d*x1*x2*y1*y2 % p
        return ((x1*y2+y1*x2)*pow(1+product, -1, p) % p,
                (y1*y2+x1*x2)*pow(1-product, -1, p) % p)
    scalar = int.from_bytes(hashlib.sha512(seed).digest()[:32], "little") & ((1 << 254)-8) | (1 << 254)
    point, base = (0, 1), (x, y)
    while scalar:
        if scalar & 1: point = add(point, base)
        base = add(base, base); scalar >>= 1
    return (point[1] | (point[0] & 1) << 255).to_bytes(32, "little")


def hpke(kem, ikm):
    hash, size = ("sha256", 32) if kem == 32 else CURVES[kem][:2]
    suite = b"KEM" + kem.to_bytes(2, "big")
    prk = mac(hash, b"", b"HPKE-v1"+suite+b"dkp_prk"+ikm)
    def labeled(label, info):
        return expand(hash, prk, size.to_bytes(2, "big")+b"HPKE-v1"+suite+label+info, size)
    if kem == 32:
        sk = labeled(b"sk", b"")
        return sk, x_public(sk)
    for counter in range(256):
        sk = labeled(b"candidate", bytes([counter]))
        if 0 < int.from_bytes(sk, "big") < CURVES[kem][4]:
            return sk, ec_public(kem, sk)
    raise ValueError("DHKEM rejection sampling")


def gf(a, b):
    product = 0
    for _ in range(8):
        if b & 1: product ^= a
        a = ((a << 1) ^ (0x11b if a & 128 else 0)) & 255
        b >>= 1
    return product


def sbox(x):
    inverse = 0 if x == 0 else 1
    if x:
        for _ in range(254): inverse = gf(inverse, x)
    value = inverse
    for rotation in range(1, 5): value ^= ((inverse << rotation) | (inverse >> (8-rotation))) & 255
    return value ^ 0x63


SBOX = [sbox(x) for x in range(256)]


def aes(key, block):
    nk = len(key)//4; rounds = nk+6; rcon = 1
    words = [list(key[i:i+4]) for i in range(0, len(key), 4)]
    for i in range(nk, 4*(rounds+1)):
        temp = words[-1][:]
        if i % nk == 0:
            temp = [SBOX[x] for x in temp[1:]+temp[:1]]; temp[0] ^= rcon; rcon = gf(rcon, 2)
        elif nk == 8 and i % nk == 4: temp = [SBOX[x] for x in temp]
        words.append([a ^ b for a, b in zip(words[i-nk], temp)])
    def key_round(state, r):
        return [a ^ b for a, b in zip(state, sum(words[4*r:4*r+4], []))]
    state = key_round(list(block), 0)
    for r in range(1, rounds+1):
        state = [SBOX[x] for x in state]
        state = [state[4*((c+row) % 4)+row] for c in range(4) for row in range(4)]
        if r < rounds:
            mixed = []
            for c in range(4):
                a, b, cc, d = state[4*c:4*c+4]
                mixed += [gf(a,2)^gf(b,3)^cc^d, a^gf(b,2)^gf(cc,3)^d,
                          a^b^gf(cc,2)^gf(d,3), gf(a,3)^b^cc^gf(d,2)]
            state = mixed
        state = key_round(state, r)
    return bytes(state)


def wrap(key, cek):
    a = b"\xa6"*8; rows = [cek[i:i+8] for i in range(0, len(cek), 8)]
    for j in range(6):
        for i in range(len(rows)):
            b = aes(key, a+rows[i]); a = (int.from_bytes(b[:8], "big") ^ (len(rows)*j+i+1)).to_bytes(8,"big")
            rows[i] = b[8:]
    return a+b"".join(rows)


def b64(value):
    return {"b64": base64.urlsafe_b64encode(value).decode().rstrip("=")}


def pairs(value):
    return {"pairs": [list(pair) for pair in sorted(value.items())]}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(data))


def manifest(id, surface, inputs, expected, source, derivation=None):
    case = dict(format="request-seal-conformance-case/1", id=id, surface=surface,
                evidence_class="reviewed_derivation" if derivation else "published_vector",
                source=source, inputs=inputs, expected=expected)
    case["class"] = "byte_exact"
    if derivation: case["derivation"] = derivation
    write(CORPUS / "cases" / (id+".json"), case)


def main():
    # Published sanity checks of the independent reference primitives, before
    # using them to produce any RequestSeal-specific expectation.
    assert wrap(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5"
    for name in ("rfc3394-4-1", "rfc3394-4-3", "rfc3394-4-5", "rfc3394-4-6"):
        vector = json.loads((CORPUS/"cases/key_management"/(name+".json")).read_text())
        def decode(tag): return base64.urlsafe_b64decode(tag["b64"] + "="*(-len(tag["b64"]) % 4))
        assert wrap(decode(vector["inputs"]["kek"]), decode(vector["inputs"]["key_data"])) == decode(vector["expected"]["wrapped"])
    prk = mac("sha256", bytes(range(13)), b"\x0b"*22)
    assert expand("sha256", prk, bytes(range(0xf0, 0xfa)), 42).hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    assert ed_public(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")).hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    source = {"document":"RFC 9180", "section":"7.1.3 and Appendix A",
              "url":"https://www.rfc-editor.org/rfc/rfc9180.html#section-7.1.3"}
    extracted = CORPUS/"sources/rfc9180/derive-key-pairs.json"
    if extracted.exists():
        selected = json.loads(extracted.read_text())
    else:
        with urllib.request.urlopen(UPSTREAM, timeout=20) as response: upstream = json.load(response)
        selected, seen = [], set()
        for index, row in enumerate(upstream):
            kem = row["kem_id"]
            if kem not in (16, 32): continue
            for role in ("E", "R", "S"):
                if "ikm"+role not in row or (kem, role) in seen: continue
                seen.add((kem, role))
                selected.append({"item":f"{index}/{role}","kem_id":kem,"ikm":row["ikm"+role],
                                 "sk":row["sk"+role+"m"],"pk":row["pk"+role+"m"]})
        extracted.write_text(json.dumps(selected, sort_keys=True, separators=(",", ":")))
    for row in selected:
        ikm, sk, pk = (bytes.fromhex(row[field]) for field in ("ikm", "sk", "pk"))
        kem = row["kem_id"]; role = row["item"].split("/")[-1].lower()
        assert hpke(kem, ikm) == (sk, pk)
        manifest(f"hpke/rfc9180-{kem}-{role}", "hpke.derive_key_pair/v1",
                 {"kem_id":{"int":str(kem)},"ikm":b64(ikm)}, {"sk":b64(sk),"pk":b64(pk)}, source)
    write(CORPUS/"sources/rfc9180/ledger.json", [{"item":r["item"],"case":f"hpke/rfc9180-{r['kem_id']}-{r['item'].split('/')[-1].lower()}"} for r in selected])
    sk, pk = hpke(17, bytes(range(48)))
    manifest("hpke/p384-independent", "hpke.derive_key_pair/v1", {"kem_id":{"int":"17"},"ikm":b64(bytes(range(48)))},
             {"sk":b64(sk),"pk":b64(pk)}, source,
             "Independent Python standard-library implementation of RFC 9180 Section 7.1.3, KEM 0x0011, SHA-384. The RFC's pinned vectors do not include P-384; this is not a published vector.")
    parent = bytes(range(32)); domain = b"example-domain"; records = []
    families = [("x25519-dhkem",32,32),("p256-dhkem",32,16),("p384-dhkem",48,17),
                ("ed25519-seed",32,None),("hmac-sha256-key",32,None),("aes128-key",16,None),("aes256-key",32,None)]
    for family, size, kem in families:
        label = family.encode(); info = PREFIX+len(label).to_bytes(2,"big")+label+len(domain).to_bytes(2,"big")+domain
        okm = expand("sha256", mac("sha256", PREFIX, parent), info, size)
        curve = None
        if kem:
            _, public = hpke(kem, okm)
            curve = "X25519" if kem == 32 else CURVES[kem][2]
            algorithm = {"kind":"jwe","name":"ECDH-ES+A256KW"}
            if kem == 32: jwk = {"kty":"OKP","crv":curve,"x":b64(public)["b64"]}
            else:
                width = CURVES[kem][1]
                jwk = {"kty":"EC","crv":curve,"x":b64(public[1:1+width])["b64"],"y":b64(public[1+width:])["b64"]}
            expected = {"public_key":pairs(jwk)}; probe = None
        elif family == "ed25519-seed":
            algorithm = {"kind":"http","name":"ed25519"}; probe = None
            expected = {"public_key":pairs({"kty":"OKP","crv":"Ed25519","x":b64(ed_public(okm))["b64"]})}
        elif family == "hmac-sha256-key":
            algorithm = {"kind":"http","name":"hmac-sha256"}; probe = {"message":b64(b"derive probe")}
            expected = {"tag":b64(mac("sha256", okm, b"derive probe"))}
        else:
            algorithm = {"kind":"jwe","name":"A128KW" if size == 16 else "A256KW"}; probe = {"cek":b64(bytes(range(16)))}
            expected = {"wrapped":b64(wrap(okm, bytes(range(16))))}
        inputs = {"parent_ikm":b64(parent),"target":{"algorithm":algorithm,"curve":curve},"domain":b64(domain)}
        if probe: inputs["probe"] = probe
        manifest("custody/"+family,"custody.derive/v1", inputs, expected,
                 {"document":"RFC 5869 and RFC 9180", "section":"RFC 5869 Sections 2.2-2.3; RFC 9180 Section 7.1.3",
                  "url":"https://www.rfc-editor.org/rfc/rfc5869.html#section-2"},
                 "RequestSeal framing in public ADR 0026: salt request-seal/derive/v1; info prefix || u16be family length || family || u16be domain length || domain. Independently computed by scripts/import_derivation_vectors.py; symmetric expectations are operation results, never exported child keys.")
        records.append({"item":family,"case":"custody/"+family})
    write(CORPUS/"sources/native-derive/ledger.json", records)
    for origin in ("rfc9180","native-derive"):
        folder = CORPUS/"sources"/origin
        (folder/"SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest()+"  "+p.name+"\n" for p in sorted(folder.iterdir()) if p.is_file() and p.name != "SHA256SUMS"))
    # Refresh the closed inventory without rerunning any other vector importer.
    index = json.loads((CORPUS/"index.json").read_text())
    index["cases"] = []
    for path in sorted((CORPUS/"cases").rglob("*.json")):
        c = json.loads(path.read_text()); entry = {k:c[k] for k in ("id","surface","class")}
        entry["manifest"] = path.relative_to(CORPUS).as_posix()
        if "batch" in c: entry.update({k:c["batch"][k] for k in ("count","not_applicable")})
        index["cases"].append(entry)
    index["files"] = sorted([{"path":p.relative_to(CORPUS).as_posix(),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for folder in ("cases","sources") for p in (CORPUS/folder).rglob("*") if p.is_file() and p.name != ".DS_Store"], key=lambda r:r["path"])
    write(CORPUS/"index.json", index)
    pin = hashlib.sha256((CORPUS/"index.json").read_bytes()).hexdigest()
    (ROOT/"test/support/conformance_pin.ex").write_text('defmodule RequestSeal.Conformance.Pin do\n  @moduledoc false\n  def sha256, do: "'+pin+'"\nend\n')
    print("PASS: independent public primitive vectors; generated 14 derivation cases and refreshed corpus pin")


if __name__ == "__main__":
    main()
