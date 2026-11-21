# Executable Livebooks

Open the `.livemd` files in [Livebook](https://livebook.dev). Repository qualification runs the notebook gate on GitHub-hosted runners:

```sh
python3 scripts/check.py --notebooks-only
```

Each notebook installs the 2.0 line from Hex, uses generated custody handles or cited public test keys, and asserts every result, so a changed outcome stops it. None needs a secret, account, server, or network peer beyond the Hex install.

| Notebook | What it covers |
| --- | --- |
| [Inspect RequestSeal](environment.livemd) | Installation, a supported Elixir/OTP runtime, Ed25519 support, public entry points, and supported HTTP signature algorithms. |
| [Verify a published HTTP signature](rfc-ed25519.livemd) | RFC 9421's published Ed25519 vector, checked directly with OTP and then rebuilt and verified through a RequestSeal policy; freshness, unsigned-digest, altered-path, and unknown-label rejections. |
| [Sign and verify HTTP messages in Livebook](sign-and-verify.livemd) | Generated key handles, committed derivation, request signing with a covered body digest, policy verification, a changed-body rejection, a response bound to its request, single-use requests with the ETS replay store, and key release. |
| [Verify signed webhooks in a Plug pipeline](plug-webhook.livemd) | A `Plug.Router` receiver with Capture, Parsers, and Verify, driven by `Plug.Test`: a signed request accepted, unsigned and altered requests rejected with 401. Also installs `:plug`. |
| [Sign and verify a Web Bot Auth agent](web-bot-auth.livemd) | Web Bot Auth protocol-00 signing with path coverage, held-key verification, and changed-page, unknown-key, and unsigned rejections. |
| [JWS inside JWE in Livebook](jose.livemd) | Compact JWS signing and verification, a JWS nested in a JWE, a generated RSA-OAEP recipient key handle, strict authenticated object content, and bounded JOSE errors. |
| [ECDH-ES agreement and JWE in Livebook](ecdh-es.livemd) | A published X25519 public-key check; direct ECDH-ES and both key-wrap variants over P-256, P-384, and X25519; encryption to public keys, custody decryption, tampering, malformed ephemeral keys, wrong curves, and policy rejections. |
| [Bounded JWE batches in Livebook](jwe-batch.livemd) | Published AES key-wrap bytes, ordered `decrypt_many/2` results, binary and object content, positional rejections, outer failures, grouping by handle, resolver expiry, caller cancellation, and released handles. |

The gate checks notebook imports, exported code coverage, assertions, and completion
against a fresh install of the inspected packed archive within time and output limits.
Local assertions establish neither interactive UI behavior nor deployed-peer acceptance; see [testing and evidence](../docs/guides/testing.md).
