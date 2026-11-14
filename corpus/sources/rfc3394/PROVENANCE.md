<!-- Status: current · Kind: reference · Updated: 2026-11-13 · Governed by: RFC 3394 · Review when: upstream errata or corpus encoding changes -->

# RFC 3394 vectors

Source: https://www.rfc-editor.org/rfc/rfc3394.txt, sections 4.1 through 4.6.
`rfc3394.txt` retains the published source. `vectors.json` transcribes its KEK,
key data, and ciphertext into the existing unpadded Base64url byte tags.
Expected bytes are published values, independent of RequestSeal.

`ledger.json` lists all six upstream examples. Each points to its wrap case;
the corresponding `-unwrap` case exercises the published inverse. Sections 4.2
and 4.4 have 192-bit KEKs and assert the supported algorithms' exact-size refusal.
No upstream item is silently omitted. The RFC copyright statement is in LICENSE.
