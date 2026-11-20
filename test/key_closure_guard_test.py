"""Source-only mutation guard for every removed caller-code key surface."""
from collections import Counter
from pathlib import Path
import importlib.util
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("reason_lexer", ROOT / "scripts/check_error_reasons.py")
lexer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lexer)

# Callback admission unrelated to key operations stays explicit. The full call,
# including arity, is pinned so adding a new caller-code branch fails closed.
ALLOWED = {
    'lib/request_seal/accept_signature.ex': {'chooser1': 1},
    'lib/request_seal/ash.ex': {'actor1': 1, 'tenant1': 1},
    'lib/request_seal/ash_hooks.ex': {'fun2': 1, 'signing[:clock]0': 1},
    'lib/request_seal/custody/local.ex': {'handle.ref0': 1},
    'lib/request_seal/custody.ex': {'ref0': 1, 'handle.ref0': 1, 'callback0': 1},
    'lib/request_seal/discovery/support.ex': {'clock0': 1},
    'lib/request_seal/jose/jwe/bounds.ex': {'v': 1},
    'lib/request_seal/jose/jwe/codec.ex': {':erlang.map_get(:key_resolver,p)1': 1},
    'lib/request_seal/jose/support.ex': {'p.key_resolver1': 1},
    'lib/request_seal/plug/sign_response.ex': {'callback1': 1},
    'lib/request_seal/plug/verify.ex': {'policy0': 1, 'function0': 1},
    'lib/request_seal/policy.ex': {'p.key_resolver1': 1, 'clock0': 1},
    'lib/request_seal/replay.ex': {'fun1': 1},
    'lib/request_seal/req.ex': {'into2': 1, 'b1': 1, 'fun1': 1, 'fun2': 1},
    'lib/request_seal/signing.ex': {'Keyword.get(opts,:clock,fn->System.system_time(:second)end)0': 1, 'enumerable': 1},
    'lib/request_seal/web_bot_auth/policy.ex': {'p.agents1': 1, 'fun1': 1},
}


def violations(sources):
    errors = []
    for path, source in sources.items():
        ts = lexer.tokens(source)
        actual = Counter("".join("".join(a) for a in lexer.arguments(ts, i + 1))
                         for i, t in enumerate(ts[:-1]) if t == "is_function" and ts[i + 1] == "(")
        extra = actual - Counter(ALLOWED.get(path, {}))
        if extra:
            errors.append(path + ": forbidden function admission " + repr(extra))
        if re.search(r"\b(?:key|signer|recipient)\s*\.\s*\(", source):
            errors.append(path + ": key closure invocation")
        if re.search(r"\bFunctionCustodian\b|@type\s+(?:signer|verify_fun)\b|Policy\.(?:signer|verify_fun)\(", source):
            errors.append(path + ": removed closure contract")
    generated = sources.get("lib/request_seal/signing.ex", "").split("  def sign(message,", 1)[-1].split("  # Both HTTP", 1)[0]
    if re.search(r"\bfn\b", generated):
        errors.append("generated metadata signing manufactures a closure")
    return errors


class KeyClosureGuardTest(unittest.TestCase):
    def sources(self):
        return {str(p.relative_to(ROOT)): p.read_text() for p in (ROOT / "lib").rglob("*.ex")}

    def test_no_key_closure_surface_remains(self):
        self.assertEqual([], violations(self.sources()))

    def test_each_forbidden_surface_is_caught_by_its_own_mutation(self):
        surfaces = [
            ("HTTP explicit signer", "lib/request_seal/authentication.ex", "  def sign(message,", "is_function(signer, 2)"),
            ("HTTP verification key", "lib/request_seal/authentication.ex", "  defp resolve(policy,", "is_function(key, 3)"),
            ("generated metadata signer", "lib/request_seal/signing.ex", "  def sign(message,", "fn _, _ -> :ok end"),
            ("Web Bot Auth signer", "lib/request_seal/web_bot_auth.ex", "  def sign(message,", "is_function(signer, 2)"),
            ("Accept-Signature handles", "lib/request_seal/accept_signature.ex", "  def fulfill(message,", "is_function(handles, 2)"),
            ("Req signer", "lib/request_seal/req.ex", "    def attach(request,", "is_function(signer, 2)"),
            ("Finch signer", "lib/request_seal/finch.ex", "    def sign(request,", "is_function(signer, 2)"),
            ("Plug response signer", "lib/request_seal/plug/sign_response.ex", "    def init(opts)", "is_function(signer, 2)"),
            ("JWS signer", "lib/request_seal/jose/jws.ex", "  def sign(header,", "is_function(signer, 2)"),
            ("JWS exact protected signer", "lib/request_seal/jose/jws.ex", "  def sign_protected(", "is_function(signer, 2)"),
            ("JWS verification key", "lib/request_seal/jose/jws.ex", "  defp verify_internal(", "is_function(key, 3)"),
            ("JWE wrapper", "lib/request_seal/jose/jwe.ex", "  defp wrap_recipient(", "is_function(recipient, 2)"),
            ("JWE unwrapper", "lib/request_seal/jose/jwe/resolver.ex", "  def ", "is_function(unwrap, 2)"),
            ("shared JOSE signer", "lib/request_seal/jose/support.ex", "  def sign(%KeyHandle{}", "is_function(signer, 2)"),
        ]
        sources = self.sources()
        for name, path, anchor, mutation in surfaces:
            with self.subTest(surface=name):
                source = sources[path]
                self.assertEqual(1 if anchor != "  def " else source.count(anchor), source.count(anchor))
                self.assertIn(anchor, source)
                at = source.index(" do", source.index(anchor)) + 3
                changed = dict(sources, **{path: source[:at] + "\n    " + mutation + source[at:]})
                self.assertNotEqual([], violations(changed))

    def test_removed_policy_types_and_direct_invocations_are_caught(self):
        sources = self.sources()
        for path, mutation in [
            ("lib/request_seal/policy.ex", "@type signer :: function()"),
            ("lib/request_seal/policy.ex", "@type verify_fun :: function()"),
            ("lib/request_seal/web_bot_auth/policy.ex", "@type signer :: function()"),
            ("lib/request_seal/jose/support.ex", "signer.(alg, bytes)"),
            ("lib/request_seal/authentication.ex", "key.(alg, bytes, signature)"),
        ]:
            with self.subTest(mutation=mutation):
                changed = dict(sources, **{path: sources[path] + "\n" + mutation})
                self.assertNotEqual([], violations(changed))


if __name__ == "__main__":
    unittest.main()
