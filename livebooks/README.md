<!-- Status: current · Kind: guide · Updated: 2026-10-14 · Governed by: public architecture and accepted ADRs · Review when: the referenced contract or implementation changes -->

# Executable Livebooks

Open the `.livemd` files in [Livebook](https://livebook.dev), or run all of them through the repository gate:

```sh
python3 scripts/check.py --notebooks-only
```

Each notebook installs RequestSeal 0.5.0 from Hex, generates its own keys, and asserts every result, so a changed outcome stops it. None needs a secret, account, server, or network peer beyond the Hex install.

| Notebook | What it covers |
| --- | --- |
| [Inspect RequestSeal](environment.livemd) | Installation, the pinned Elixir/OTP runtime, Ed25519 support, public entry points, and supported HTTP signature algorithms. |
| [Verify a published HTTP signature](rfc-ed25519.livemd) | RFC 9421's published Ed25519 vector, checked directly with OTP and then rebuilt and verified through a RequestSeal policy; freshness, unsigned-digest, altered-path, and unknown-label rejections. |
| [Sign and verify HTTP messages](sign-and-verify.livemd) | Key handles, request signing with a covered body digest, policy verification, a changed-body rejection, a response bound to its request, single-use requests with the ETS replay store, a two-signer quorum, and key release. |
| [Verify signed webhooks in a Plug pipeline](plug-webhook.livemd) | A `Plug.Router` receiver with Capture, Parsers, and Verify, driven by `Plug.Test`: a signed request accepted, unsigned and altered requests rejected with 401. Also installs `:plug`. |
| [Sign and verify a Web Bot Auth agent](web-bot-auth.livemd) | Web Bot Auth protocol-00 signing with path coverage, held-key verification, and changed-page, unknown-key, and unsigned rejections. |
| [Sign JWS and encrypt JWE envelopes](jose.livemd) | Compact JWS signing and verification, a JWS nested in a JWE, an RSA-OAEP recipient key handle, and the bounded JOSE errors. |

## How the gate runs them

The checker parses each notebook with Livebook's own importer and Elixir exporter, refuses unsupported cells and branched sections instead of skipping them, and runs each export in a fresh Elixir process limited to 300 seconds and 1 MiB of output. It replaces the Hex install of RequestSeal with the local checkout, so the gate tests the code in the repository; the [release runbook](../docs/operations/releases.md) separately installs the published package in a clean project. The cells shown are the exact code executed.

These runs prove the library's behavior on locally generated keys and published vectors. They are not interactive UI checks and do not prove acceptance by a deployed peer; see [testing and evidence](../docs/guides/testing.md) for those evidence classes.
