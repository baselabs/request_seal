#!/usr/bin/env python3
"""Compare source-emitted error reasons with closed types and the error guide.

This is a source check: no Elixir runtime or project compilation is invoked.
Helper arguments are inspected before throws/catches erase their provenance.
"""
from collections import Counter, defaultdict
from pathlib import Path
from bisect import bisect_right
import json
import re

ROOT = Path(__file__).resolve().parents[1]
KINDS = ('core', 'signature_base', 'jose', 'custody', 'replay', 'discovery',
         'digest', 'message', 'adapter', 'crypto', 'structured_fields')
MODULES = {kind: 'RequestSeal.' + ('' if kind == 'core' else {
    'signature_base': 'SignatureBase', 'jose': 'JOSE', 'structured_fields': 'StructuredFields'
}.get(kind, kind.title()) + '.') + 'Error' for kind in KINDS}
ERROR_FILES = {kind: 'lib/request_seal/' + ('' if kind == 'core' else kind + '/') + 'error.ex'
               for kind in KINDS}
# One primary helper vocabulary per source family. Explicit foreign Error structs
# and qualified constructor calls below always override the primary family.
FAMILIES = {
    'core': ['lib/request_seal.ex', 'lib/request_seal/authentication.ex',
             'lib/request_seal/accept_signature.ex', 'lib/request_seal/ash.ex',
             'lib/request_seal/policy.ex', 'lib/request_seal/profile.ex',
             'lib/request_seal/web_bot_auth.ex', 'lib/request_seal/web_bot_auth/policy.ex'],
    'signature_base': ['lib/request_seal/signature_base.ex'],
    'jose': ['lib/request_seal/jose.ex', 'lib/request_seal/jose/**/*.ex', 'lib/request_seal/jose/*.ex'],
    'custody': ['lib/request_seal/custody.ex', 'lib/request_seal/custody/**/*.ex',
                'lib/request_seal/custody/*.ex'],
    'replay': ['lib/request_seal/replay.ex', 'lib/request_seal/replay/*.ex'],
    'discovery': ['lib/request_seal/discovery.ex', 'lib/request_seal/discovery/*.ex'],
    'digest': ['lib/request_seal/digest.ex'],
    'message': ['lib/request_seal/message.ex', 'lib/request_seal/message/validation.ex',
                'lib/request_seal/body.ex', 'lib/request_seal/field_occurrence.ex',
                'lib/request_seal/transport_facts.ex'],
    'adapter': ['lib/request_seal/signing.ex', 'lib/request_seal/adapter/*.ex',
                'lib/request_seal/req.ex', 'lib/request_seal/finch.ex', 'lib/request_seal/plug/*.ex'],
    'crypto': ['lib/request_seal/crypto.ex', 'lib/request_seal/crypto/*.ex',
               'lib/request_seal/public_key.ex'],
    'structured_fields': ['lib/request_seal/structured_fields.ex',
                          'lib/request_seal/structured_fields/*.ex',
                          'lib/request_seal/signature_fields.ex'],
}
# Definitions whose return values carry a reason through a variable or function
# call. Collect their output atoms as well as the ordinary reason arguments.
# signing.ex:32-35; custody/ssh_agent.ex:222-236; replay.ex:205-208.
REASON_RETURNS = {'fault', 'socket_error', 'reply_error', 'authentication_reason'}

TOKEN = re.compile(r'''\s+|<<|>>|~[A-Za-z]/(?:\\.|[^/\\])*/[a-zA-Z]*|~[A-Za-z]\((?:\\.|[^)\\])*\)[a-zA-Z]*|\#[^\n]*|(?:~[A-Za-z])?(?:"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\')|(?:~[A-Za-z])?"(?:\\.|[^"\\])*"|~[A-Za-z]\[(?:\\.|[^\]\\])*\][a-zA-Z]*|:[a-zA-Z_][\w?!]*|[A-Za-z_][\w?!]*(?:\.[A-Za-z_][\w?!]*)*|::|->|[^\s]''')


class Token(str):
    def __new__(cls, value, line):
        token = super().__new__(cls, value)
        token.line = line
        return token


def tokens(source):
    newlines = [m.start() for m in re.finditer('\n', source)]
    return [Token(m[0], 1 + bisect_right(newlines, m.start())) for m in TOKEN.finditer(source)
            if not m[0].isspace() and not m[0].startswith('#')]


def arguments(ts, start):
    """Read balanced call arguments, including anonymous-function bodies."""
    depth, block, args, current = [], 0, [], []
    for token in ts[start + 1:]:
        if token in ('(', '[', '{', '<<'):
            depth.append(token)
        elif token in (')', ']', '}', '>>'):
            if not depth:
                return args + [current]
            depth.pop()
        if token == 'fn':
            block += 1
        elif token == 'end' and block:
            block -= 1
        if token == ',' and not depth and not block:
            args.append(current)
            current = []
        else:
            current.append(token)
    raise ValueError('unbalanced source call: ' + ' '.join(ts[max(0,start-2):start+20]))


def kind_of(name, default):
    name = name.removeprefix('RequestSeal.')
    if name == 'Error':
        return 'core' if default == 'core' else default
    for kind, module in MODULES.items():
        if name == module.removeprefix('RequestSeal.'):
            return kind
    if name in ('SF.Error', 'StructuredFields.Error'):
        return 'structured_fields'
    return None


def reason_values(expr):
    if len(expr) == 1 and re.fullmatch(r':[a-z_][\w?!]*', expr[0]):
        return {expr[0][1:]}
    # Default parameters and conditional reason selections carry literal outputs.
    if 'if' in expr or '\\' in expr:
        return {token[1:] for token in expr if re.fullmatch(r':[a-z_][\w?!]*', token)}
    return set()


def source_reasons(source, kind, path="", flows=None):

    ts = tokens(source)
    emitted = defaultdict(set)
    # The tokens in docs, specs and type declarations are never emission evidence.
    clean, i = [], 0
    while i < len(ts):
        if ts[i] == '@' and i + 1 < len(ts) and ts[i + 1] in (
                'doc', 'moduledoc', 'typedoc', 'spec', 'type', 'opaque', 'callback', 'reasons'):
            i += 2
            # Attributes end at a newline, which the lexer intentionally discards.
            # Specs/types may span lines: skip until the next declaration/attribute.
            while i < len(ts) and ts[i] not in ('@', 'def', 'defp', 'defdelegate', 'defmodule', 'defstruct', 'defexception'):
                i += 1
        else:
            clean.append(ts[i]); i += 1
    ts = clean
    for i, token in enumerate(ts):
        if i + 1 < len(ts) and ts[i + 1] == '(':
            name = token.rsplit('.', 1)[-1]
            receiver = token.rsplit('.', 1)[0] if '.' in token else ''
            target = kind
            for family, module in MODULES.items():
                prefix = module.removesuffix('Error')
                if receiver.startswith(prefix) and receiver.endswith('Support'):
                    target = family
            if receiver.endswith('Error'):
                target = kind_of(receiver, kind)
                # Fully qualified core constructors override a family's Error alias.
                if receiver == 'RequestSeal.Error': target = 'core'
            if receiver.endswith('Validation'): target = 'message'
            index = None
            if name in ('fail', 'error') and (not receiver or receiver.endswith(('Support', 'Signing', 'Codec', 'Validation'))): index = 0
            if name == 'new' and receiver.endswith('Error'): index = 0
            if name == 'ensure' and (not receiver or receiver.endswith(('Support', 'Signing', 'Codec'))): index = 1
            if name == 'construct' and receiver.endswith('Validation'): index = 3
            if name == 'safe' and (not receiver or receiver.endswith('Support')):
                index = 0 if target == 'crypto' else 1
            if name == 'validated!' and kind == 'jose': index = 1
            if name == 'callback': index = 2 if path.endswith('/ash.ex') else 1
            if name == 'serialize' and not receiver and kind == 'signature_base': index = 2
            if name == 'error' and receiver == 'Codec': target = 'jose'
            if index is not None:
                args = arguments(ts, i + 1)
                if len(args) > index:
                    if target is not None:
                        values = reason_values(args[index])
                        emitted[target].update(values)
                        definition = i > 0 and ts[i-1] in ('def', 'defp', 'defdelegate')
                        if flows is not None and not values and args[index] != ['_'] and not definition:
                            flows.append({'file': path, 'line': token.line,
                                          'expression': ' '.join(args[index]), 'kind': target})
            if name in REASON_RETURNS and i and ts[i-1] in ('def', 'defp'):
                # The output atoms of these mapping clauses (not their guard inputs).
                tail = ts[i + 1:]
                try:
                    begin = tail.index('do')
                except ValueError:
                    continue
                end = next((j for j in range(begin+1, len(tail)) if tail[j] in ('def', 'defp', '@', 'end')), len(tail))
                emitted['core' if name == 'authentication_reason' else kind].update(reason_values(tail[begin+1:end]))
        # Literal throw helpers carry a tag followed by their error reason.
        if token == 'throw' and ts[i+1:i+3] == ['(', '{']:
            fields = arguments(ts, i+2)
            tags = {':replay_error': 'replay', ':signature_base': 'signature_base',
                    ':structured_fields': 'structured_fields', ':digest': 'digest',
                    ':crypto_error': 'crypto', ':custody_error': 'custody',
                    ':jose_error': 'jose', ':adapter': 'adapter',
                    ':authentication_error': 'core', ':discovery_error': 'discovery'}
            if len(fields) > 1 and len(fields[0]) == 1 and fields[0][0] in tags:
                emitted[tags[fields[0][0]]].update(reason_values(fields[1]))
        # Explicit reason literals on an error struct, including rejection branches.
        if token == '%' and i + 2 < len(ts) and ts[i+2] == '{' and ts[i+1].endswith('Error'):
            args = arguments(ts, i + 2)
            for field in args:
                if field[:2] == ['reason', ':']:
                    target = 'core' if ts[i+1] == 'RequestSeal.Error' else kind_of(ts[i+1], kind)
                    if target is not None:
                        values = reason_values(field[2:])
                        emitted[target].update(values)
                        if flows is not None and not values:
                            flows.append({'file': path, 'line': ts[i+1].line,
                                          'expression': ' '.join(field[2:]), 'kind': target})
    return emitted


def declared_reasons(source):
    # Read a literal union or the closed @reasons list used to construct the union.
    match = re.search(r'@type reason\s*::\s*(.*?)(?=\n\s*@|\nend)', source, re.S)
    if not match:
        raise ValueError('missing documented @type reason union')
    expression = match[1]
    if 'unquote' in expression:
        match = re.search(r'@reasons\s+~w\((.*?)\)a', source, re.S)
        if not match:
            raise ValueError('reason union must use a literal @reasons list')
        return match[1].split()
    members = expression.strip().split('|')
    if not all(re.fullmatch(r'\s*:[a-z_][\w?!]*\s*', member) for member in members):
        raise ValueError('reason union must contain only literal atoms')
    return [member.strip()[1:] for member in members]


def check(root=ROOT):
    emitted = defaultdict(set)
    covered, flows = set(), []
    families = list(FAMILIES.items()) + [('core', ['lib/**/*.ex'])]
    for kind, patterns in families:
        files = {p for pattern in patterns for p in root.glob(pattern)} - covered
        covered.update(files)
        for path in sorted(files):
            if path.as_posix().endswith('/error.ex'): continue
            for target, values in source_reasons(path.read_text(), kind, path.relative_to(root).as_posix(), flows).items():
                emitted[target].update(values)
    guide = (root / 'docs/guides/errors.md').read_text()
    errors = []
    allowlist_path = root / 'test/fixtures/error_reason_flows.json'
    allowed = json.loads(allowlist_path.read_text()) if allowlist_path.is_file() else []
    actual_flows = {json.dumps(flow, sort_keys=True) for flow in flows}
    allowed_flows = {json.dumps({k: flow[k] for k in ('file', 'line', 'expression', 'kind')}, sort_keys=True)
                     for flow in allowed}
    for site in sorted(actual_flows - allowed_flows):
        errors.append('Unlisted variable reason flow: ' + site)
    for site in sorted(allowed_flows - actual_flows):
        errors.append('Stale variable reason flow: ' + site)
    for flow in allowed:
        emitted[flow['kind']].update(flow['allows'])
        if not flow.get('comment') or f"{flow['file']}:{flow['line']}" not in flow['comment']:
            errors.append('Variable reason allowlist needs a source-line comment: ' + str(flow))
    for kind in KINDS:
        module = MODULES[kind]
        try:
            declared = declared_reasons((root / ERROR_FILES[kind]).read_text())
        except ValueError as error:
            errors.append(f'{module}: {error}'); continue
        documented = re.search(r'^### ' + re.escape(module) + r'\n(.*?)(?=\n### |\Z)', guide, re.M | re.S)
        documented = re.findall(r'`:([a-z_][\w?!]*)`', documented[1]) if documented else []
        for label, reasons in [('type', declared), ('guide', documented)]:
            counts = Counter(reasons)
            for reason, count in sorted(counts.items()):
                if count != 1: errors.append(f'{module}: {label} repeats :{reason} ({count} times)')
            for reason in sorted(emitted[kind] - set(reasons)):
                errors.append(f'{module}: emitted :{reason} missing from {label}')
            for reason in sorted(set(reasons) - emitted[kind]):
                errors.append(f'{module}: {label} documents unemitted :{reason}')
    return errors, emitted


if __name__ == '__main__':
    errors, _ = check()
    if errors:
        raise SystemExit('\n'.join(errors))
    print('PASS: eleven error vocabularies match source, closed types, and guide exactly')
