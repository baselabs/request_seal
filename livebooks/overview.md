# Executable Livebooks

Open the `.livemd` files in [Livebook](https://livebook.dev), or run all of them through the repository gate:

```sh
python3 scripts/check.py --notebooks-only
```

Each notebook installs RequestSeal from Hex, generates its own keys, and asserts every result, so a changed outcome stops it. None needs a secret, account, server, or network peer beyond the Hex install.

| Notebook | What it covers |
| --- | --- |
| [Inspect RequestSeal](environment.livemd) | Installation, a supported Elixir/OTP runtime, Ed25519 support, public entry points, and supported HTTP signature algorithms. |
| [Verify a published HTTP signature](rfc-ed25519.livemd) | RFC 9421's published Ed25519 vector, checked directly with OTP and then rebuilt and verified through a RequestSeal policy; freshness, unsigned-digest, altered-path, and unknown-label rejections. |
| [Sign and verify HTTP messages in Livebook](sign-and-verify.livemd) | Key handles, request signing with a covered body digest, policy verification, a changed-body rejection, a response bound to its request, single-use requests with the ETS replay store, and key release. |
| [Verify signed webhooks in a Plug pipeline](plug-webhook.livemd) | A `Plug.Router` receiver with Capture, Parsers, and Verify, driven by `Plug.Test`: a signed request accepted, unsigned and altered requests rejected with 401. Also installs `:plug`. |
| [Sign and verify a Web Bot Auth agent](web-bot-auth.livemd) | Web Bot Auth protocol-00 signing with path coverage, held-key verification, and changed-page, unknown-key, and unsigned rejections. |
| [JWS inside JWE in Livebook](jose.livemd) | Compact JWS signing and verification, a JWS nested in a JWE, an RSA-OAEP recipient key handle, and the bounded JOSE errors. |

The gate checks notebook imports, exported code coverage, assertions, and completion
against the checkout within time and output limits.
Local assertions establish neither interactive UI behavior nor deployed-peer acceptance; see [testing and evidence](../docs/guides/testing.md).
