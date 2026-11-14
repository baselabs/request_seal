"""Import independent public ECDH vectors and refresh the closed corpus inventory.

No expected result is obtained from RequestSeal. Wycheproof files are copied
unchanged at the commit in their provenance; RFC values are transcribed from
the cited publications. Cross-library values come from check_jose_libraries.py.
"""
import base64
import hashlib
import json
from pathlib import Path
from corpus_json import canonical

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"


def b64(value):
    return {"b64": base64.urlsafe_b64encode(value).decode().rstrip("=")}


def encoded(value):
    return {"b64": value}


def pairs(value):
    return {"pairs": [[k, v] for k, v in sorted(value.items())]}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(data))


def case(name, surface, inputs, expected, source, rejection=False):
    write(CORPUS / "cases" / (name + ".json"), {
        "format": "request-seal-conformance-case/1", "id": name,
        "surface": surface, "class": "rejection" if rejection else "byte_exact",
        "evidence_class": "published_vector", "source": source,
        "inputs": inputs, "expected": expected})


def ref(file, pointer):
    return {"ref": {"file": file, "pointer": pointer}}


def imports():
    source = {"url": "https://www.rfc-editor.org/rfc/rfc7518.html#appendix-C", "section": "C"}
    z = bytes([158,86,217,29,129,113,53,211,114,131,66,131,191,132,38,156,251,49,110,163,218,128,106,72,246,218,167,121,140,254,144,196])
    recipient = {"kty":"EC", "crv":"P-256", "x":"weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ", "y":"e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck", "d":"VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"}
    epk = {"kty":"EC", "crv":"P-256", "x":"gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0", "y":"SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps"}
    kdf = {"z": b64(z), "algorithm_id":"A128GCM", "apu":b64(b"Alice"), "apv":b64(b"Bob"), "keydatalen":{"int":"128"}}
    case("rfc7518-appendix-c-kdf", "key_management.ecdh_kdf/v1", kdf, {"output":encoded("VqqN6vgjbSBcIijNcacQGg")}, source)
    agree = {"alg":"ECDH-ES", "enc":"A128GCM", "recipient":pairs({k:v for k,v in recipient.items() if k != "d"}), "recipient_private":pairs(recipient), "ephemeral_private":encoded("0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo"), "apu":b64(b"Alice"), "apv":b64(b"Bob")}
    case("rfc7518-appendix-c-agree", "key_management.agree/v1", agree, {"cek":encoded("VqqN6vgjbSBcIijNcacQGg"), "encrypted_key":b64(b""), "epk":pairs(epk)}, source)
    write(CORPUS / "sources/rfc7518/vectors.json", [{"item":"C-kdf", "inputs":kdf}, {"item":"C-agree", "inputs":agree}])
    write(CORPUS / "sources/rfc7518/ledger.json", [{"item":"C-kdf", "case":"rfc7518-appendix-c-kdf"}, {"item":"C-agree", "case":"rfc7518-appendix-c-agree"}])
    rows = []
    for file in sorted((CORPUS / "sources/rfc7520").glob("*.json")):
        if file.name == "ledger.json":
            continue
        v = json.loads(file.read_text())
        prefix = file.name.split(".")[0].replace("_", "-")
        src = {"file":"sources/rfc7520/" + file.name, "url":"https://www.rfc-editor.org/rfc/rfc7520.html#section-" + prefix.replace("-", ".")}
        if prefix in ("5-4", "5-5"):
            name = "rfc7520-" + prefix + "-agree"
            private = v["input"]["key"]
            epk = {k:v for k,v in v["encrypting_key"]["epk"].items() if k != "d"}
            i = {"alg":v["input"]["alg"], "enc":v["input"]["enc"], "recipient":pairs({k:v for k,v in private.items() if k not in ("d", "kid", "use")}), "recipient_private":ref(src["file"], "/input/key"), "ephemeral_private":encoded(v["encrypting_key"]["epk"]["d"]), "apu":b64(b""), "apv":b64(b"")}
            cek = v["generated"].get("cek", v["encrypting_key"].get("cek"))
            if prefix == "5-4": i["cek"] = encoded(cek)
            case(name, "key_management.agree/v1", i, {"cek":encoded(cek), "encrypted_key":encoded(v["encrypting_key"].get("encrypted_key", "")), "epk":pairs(epk)}, src)
            rows.append({"item":file.name, "case":name})
        elif prefix == "5-7":
            name = "rfc7520-5-7-gcmkw-stage"
            rows.append({"item":file.name,"case":name})
            write(CORPUS/"cases"/(name+".json"), {"format":"request-seal-conformance-batch/1", "id":name, "surface":"jwe.decrypt", "class":"mixed", "evidence_class":"published_vector", "source":src, "batch":{"file":src["file"], "item_format":"rfc7520-gcmkw/1", "count":{"int":"1"}, "not_applicable":{"int":"0"}}})
        else:
            rows.append({"item":file.name,"excluded":"Outside this slice's ECDH vector set; existing corpus retains its prior coverage."})
        if prefix in ("5-4", "5-5", "5-7"):
            case("rfc7520-"+prefix+"-envelope", "jwe.decrypt", {"compact":b64(v["output"]["compact"].encode()), "key":ref(src["file"], "/input/key")}, {"valid":True,"payload":b64(v["input"]["plaintext"].encode())} if prefix=="5-4" else {"rule_id":"jose/input.algorithm_not_permitted"}, src, prefix!="5-4")
            p=CORPUS/"cases"/("rfc7520-"+prefix+"-envelope.json")
            c=json.loads(p.read_text());c["policy"]={"algorithms":[v["input"]["alg"]],"encryption":["A128GCM"]};write(p,c)
    write(CORPUS / "sources/rfc7520/ledger.json", rows)

    ledger = []
    for file, fmt in [("aes_wrap_test.json","wycheproof-aes-kw/1"), ("ecdh_secp256r1_test.json","wycheproof-ecdh/1"), ("ecdh_secp384r1_test.json","wycheproof-ecdh/1"), ("x25519_test.json","wycheproof-x25519/1")]:
        data=json.loads((CORPUS / "sources/wycheproof" / file).read_text())
        name="wycheproof-"+file.removesuffix("_test.json").replace("_","-")
        overrides={}
        for g in data["testGroups"]:
            for t in g["tests"]:
                item=file+"/"+str(t["tcId"])
                if (file=="aes_wrap_test.json" and g["keySize"]==192) or (fmt=="wycheproof-ecdh/1" and t["result"]=="valid" and "CompressedPoint" in t["flags"]):
                    reason="192-bit KEKs are outside A128KW/A256KW." if file=="aes_wrap_test.json" else "Compressed EC points are outside the uncompressed public-key contract."
                    ledger.append({"item":item,"excluded":reason})
                    overrides[str(t["tcId"])]={"outcome":"not_applicable","reason":reason}
                else:
                    ledger.append({"item":item,"case":name})
                    if "ZeroSharedSecret" in t["flags"] or (file=="aes_wrap_test.json" and t["result"]=="acceptable") or (fmt=="wycheproof-ecdh/1" and t["result"]=="acceptable"):
                        overrides[str(t["tcId"])]={"outcome":"reject","rule_id":"jose/crypto.decryption_failed","clause":"Strict public-key encoding and nonzero agreement; RFC 3394 requires at least 16 key-data bytes."}
        c={"format":"request-seal-conformance-batch/1","id":name,"surface":"key_management.aes_kw/v1" if file=="aes_wrap_test.json" else "key_management.agree/v1","class":"mixed","evidence_class":"published_vector","source":{"file":"sources/wycheproof/"+file,"url":"https://github.com/C2SP/wycheproof/tree/12fd3aaf33eb5fa1f52e026912ee00c054f9d984"},"batch":{"file":"sources/wycheproof/"+file,"item_format":fmt,"count":{"int":str(data["numberOfTests"])},"not_applicable":{"int":str(sum(x["outcome"]=="not_applicable" for x in overrides.values()))}},"overrides":overrides}
        write(CORPUS/"cases"/(name+".json"),c)
    write(CORPUS/"sources/wycheproof/ledger.json",ledger)


def other_sources():
    # RFC 7748 section 6.1 and RFC 8037 A.6 share these published values.
    x = {"name":"6.1", "public":"de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f", "private":"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", "shared":"4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", "result":"valid"}
    write(CORPUS/"sources/rfc7748/vectors.json", [x])
    y = dict(x, name="A.6", epk={"kty":"OKP", "crv":"X25519", "x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"})
    write(CORPUS/"sources/rfc8037/x25519.json", [y])
    for origin, name, file, fmt, item in [("rfc7748","rfc7748-6-1","vectors.json","rfc7748-x25519/1","6.1"),("rfc8037","rfc8037-a-6","x25519.json","rfc8037-epk/1","A.6")]:
        write(CORPUS/"cases"/(name+".json"), {"format":"request-seal-conformance-batch/1","id":name,"surface":"key_management.agree/v1","class":"mixed","evidence_class":"published_vector","source":{"url":"https://www.rfc-editor.org/rfc/"+origin+".html","section":item},"batch":{"file":"sources/"+origin+"/"+file,"item_format":fmt,"count":{"int":"1"},"not_applicable":{"int":"0"}}})
        rows = [{"item":item,"case":name}]
        if origin=="rfc8037": rows.insert(0,{"item":"A.1","excluded":"Ed25519 source is retained by the existing signature corpus; this ledger covers ECDH additions."})
        write(CORPUS/("sources/"+origin+"/ledger.json"),rows)
    path=CORPUS/"sources/cross-jose/vectors.json"
    if path.exists():
        rows=[]
        for index, row in enumerate(json.loads(path.read_text())):
            name="cross-jose-"+str(index)
            item="/".join([row["provider"],row["alg"],row["enc"],row["key"].get("crv","oct")])
            source={"file":"sources/cross-jose/vectors.json","section":str(index),"url":"https://github.com/panva/jose" if row["provider"].startswith("npm") else "https://github.com/potatosalad/erlang-jose"}
            case(name,"jwe.decrypt",{"compact":b64(row["token"].encode()),"key":ref(source["file"],"/"+str(index)+"/key")},{"valid":True,"payload":encoded(row["plaintext"])},source)
            p=CORPUS/"cases"/(name+".json");c=json.loads(p.read_text());c["policy"]={"algorithms":[row["alg"]],"encryption":[row["enc"]]};write(p,c)
            rows.append({"item":item,"case":name})
            if "agreement" in row:
                a=row["agreement"];key=row["key"]
                i={"alg":row["alg"],"enc":row["enc"],"recipient":pairs({k:v for k,v in key.items() if k!="d"}),"recipient_private":ref(source["file"],"/"+str(index)+"/key"),"ephemeral_private":encoded(a["ephemeral_private"]),"apu":encoded(a["apu"]),"apv":encoded(a["apv"])}
                if row["alg"]!="ECDH-ES": i["cek"]=encoded(a["cek"])
                case(name+"-agree","key_management.agree/v1",i,{"cek":encoded(a["cek"]),"encrypted_key":encoded(a["encrypted_key"]),"epk":pairs(a["epk"])},source)
        write(CORPUS/"sources/cross-jose/ledger.json",rows)


def refresh():
    for source in ("rfc3394", "rfc7518", "rfc7520", "rfc7748", "rfc8037", "wycheproof", "cross-jose"):
        folder=CORPUS/"sources"/source
        (folder/"SHA256SUMS").write_text("".join(hashlib.sha256(p.read_bytes()).hexdigest()+"  "+p.name+"\n" for p in sorted(folder.iterdir()) if p.is_file() and p.name not in ("SHA256SUMS", ".DS_Store")))
    index=json.loads((CORPUS/"index.json").read_text())
    index["cases"]=[]
    for p in sorted((CORPUS/"cases").rglob("*.json")):
        c=json.loads(p.read_text()); entry={k:c[k] for k in ("id","surface","class")};entry["manifest"]=p.relative_to(CORPUS).as_posix()
        if "batch" in c: entry.update({k:c["batch"][k] for k in ("count","not_applicable")})
        index["cases"].append(entry)
    index["files"]=[{"path":p.relative_to(CORPUS).as_posix(),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()} for folder in ("cases","sources") for p in sorted((CORPUS/folder).rglob("*")) if p.is_file() and p.name!=".DS_Store"]
    index["files"].sort(key=lambda x:x["path"])
    write(CORPUS/"index.json", index)
    pin=ROOT/"test/support/conformance_pin.ex"
    pin.write_text('defmodule RequestSeal.Conformance.Pin do\n  @moduledoc false\n  def sha256, do: "'+hashlib.sha256((CORPUS/"index.json").read_bytes()).hexdigest()+'"\nend\n')


if __name__ == "__main__":
    imports()
    other_sources()
    refresh()
