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
    'lib/request_seal/custody/gate.ex': {'config.port2': 1, 'config.clock0': 1, 'config.record2': 1},
    'lib/request_seal/custody/local.ex': {'handle.ref0': 1},
    'lib/request_seal/custody/ssh_agent.ex': {'ref0': 1},
    'lib/request_seal/custody.ex': {'ref0': 1, 'handle.ref0': 1, 'callback0': 1},
    'lib/request_seal/discovery/support.ex': {'clock0': 1},
    'lib/request_seal/idempotency/ets.ex': {'clock0': 1},  # Store clock under the operation deadline.
    'lib/request_seal/jose/jwe/bounds.ex': {'v': 1},
    'lib/request_seal/jose/jwe/codec.ex': {':erlang.map_get(:key_resolver,p)1': 1},
    'lib/request_seal/jose/support.ex': {'p.key_resolver1': 1},
    'lib/request_seal/plug/scope.ex': {'opts.principal_tenant1': 1},
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
        # Restore a removed admission or invoke the key function at the real
        # dispatch site. These mutate production expressions, never a comment
        # or an otherwise unused is_function statement.
        surfaces = [
            ("HTTP explicit signer", "lib/request_seal/authentication.ex", "  def sign(message,",
             "is_struct(signer, KeyHandle)", "(is_function(signer, 2) or is_struct(signer, KeyHandle))"),
            ("HTTP verification key", "lib/request_seal/authentication.ex", "  defp resolve(policy,",
             "match?(%PublicKey{}, key) or match?(%KeyHandle{}, key)",
             "match?(%PublicKey{}, key) or is_function(key, 3)"),
            ("generated metadata signer", "lib/request_seal/signing.ex", "  def sign(message,",
             "           signer,", "           fn algorithm, base -> signer.(algorithm, base) end,"),
            ("Web Bot Auth signer", "lib/request_seal/web_bot_auth.ex", "  def sign(message,",
             "is_struct(signer, RequestSeal.KeyHandle)", "is_function(signer, 2)"),
            ("Accept-Signature handles", "lib/request_seal/accept_signature.ex", "  def fulfill(message,",
             "handles?(handles)", "is_function(handles, 2)"),
            ("Req signer", "lib/request_seal/req.ex", "    def attach(request,",
             "match?(%RequestSeal.KeyHandle{}, opts[:signer])", "is_function(opts[:signer], 2)"),
            ("Finch signer", "lib/request_seal/finch.ex", "    def sign(request,",
             "Signing.sign(message, spec, signer, opts)", "signer.(spec.algorithm, message)"),
            ("Plug response signer", "lib/request_seal/plug/sign_response.ex", "    def init(opts)",
             "match?(%KeyHandle{}, opts[:signer])", "is_function(opts[:signer], 2)"),
            ("JWS signer", "lib/request_seal/jose/jws.ex", "  def sign(header,",
             "Support.sign(signer, alg, base, timeout, purpose)", "callback(fn -> signer.({:jws, alg}, base) end, :signer_failed, :crypto)"),
            ("JWS exact protected signer", "lib/request_seal/jose/jws.ex", "  def sign_protected(",
             "Support.sign(signer, alg, base, timeout, purpose)", "callback(fn -> signer.({:jws, alg}, base) end, :signer_failed, :crypto)"),
            ("JWS verification key", "lib/request_seal/jose/jws.ex", "  defp verify_internal(",
             "      case key do", "      case key do\n        fun when is_function(fun, 3) -> fun.({:jws, alg}, base, signature)"),
            ("JWE wrapper", "lib/request_seal/jose/jwe.ex", "  defp wrap_recipient(",
             "        _ ->\n          fail(:invalid_options)",
             "        fun when is_function(fun, 2) -> fun.(alg, cek)\n        _ ->\n          fail(:invalid_options)"),
            ("JWE unwrapper", "lib/request_seal/jose/jwe/resolver.ex", "  defp normalize(_, _)",
             "  defp normalize(_, _)",
             "  defp normalize({:ok, %{algorithm: a, unwrap: unwrap}}, a) when is_function(unwrap, 2), do: unwrap.(a, <<>>)\n  defp normalize(_, _)"),
            ("shared JOSE signer", "lib/request_seal/jose/support.ex", "  def sign(_, _, _, _, _)",
             "  def sign(_, _, _, _, _), do: fail(:invalid_options)",
             "  def sign(signer, alg, bytes, _, _), do: signer.({:jws, alg}, bytes)"),
        ]
        sources = self.sources()
        self.assertEqual([], violations(sources))
        invocation_cases = {
            "Finch signer", "JWS signer", "JWS exact protected signer", "shared JOSE signer",
            "generated metadata signer",
        }
        for name, path, anchor, before, after in surfaces:
            with self.subTest(surface=name):
                source = sources[path]
                self.assertEqual(1, source.count(anchor))
                at = source.index(before, source.index(anchor))
                changed_source = source[:at] + after + source[at + len(before):]
                self.assertNotEqual(source, changed_source)
                changed = dict(sources, **{path: changed_source})
                actual = violations(changed)
                if name in invocation_cases:
                    expected = [path + ": key closure invocation"]
                    if name == "generated metadata signer":
                        expected.append("generated metadata signing manufactures a closure")
                    self.assertEqual(expected, actual)
                else:
                    self.assertEqual(1, len(actual), actual)
                    self.assertTrue(actual[0].startswith(path + ": forbidden function admission "), actual)

    def test_removed_policy_types_and_direct_invocations_are_caught(self):
        sources = self.sources()
        self.assertEqual([], violations(sources))
        for path, mutation in [
            ("lib/request_seal/policy.ex", "@type signer :: function()"),
            ("lib/request_seal/policy.ex", "@type verify_fun :: function()"),
            ("lib/request_seal/web_bot_auth/policy.ex", "@type signer :: function()"),
            ("lib/request_seal/jose/support.ex", "signer.(alg, bytes)"),
            ("lib/request_seal/authentication.ex", "key.(alg, bytes, signature)"),
        ]:
            with self.subTest(mutation=mutation):
                changed = dict(sources, **{path: sources[path] + "\n" + mutation})
                reason = "removed closure contract" if mutation.startswith("@type") else "key closure invocation"
                self.assertEqual([path + ": " + reason], violations(changed))


if __name__ == "__main__":
    unittest.main()
