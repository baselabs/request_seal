# Executable Livebooks

**Status:** current · **Kind:** guide · **Updated:** 2026-10-06 · **Governed by:** public architecture and accepted ADRs · **Review when:** the referenced contract or implementation changes

Open the `.livemd` files in Livebook, or execute their code through the repository gate:

```sh
python3 scripts/check.py --notebooks-only
```

- [Verify a published HTTP signature](rfc-ed25519.livemd) runs the real OTP primitive against
  RFC 9421's independent Ed25519 vector, then rejects altered message and signature bytes.
- [Inspect the local library](environment.livemd) installs this actual checkout and inspects
  its module, toolchain and cryptographic prerequisites without claiming an unbuilt API.

For local installation, set `REQUESTSEAL_PATH` to your clone. The gate sets it to the checkout
it is testing. No author-machine path is embedded. The shipped notebooks need no secret,
service, provider registration or payment data. Their source cells are the actual executed
inputs, not copied success output.

The checker uses Livebook's importer and Elixir exporter, refuses unsupported cells/branches
instead of silently skipping them, and executes each export in a fresh Elixir process.
Do not confuse headless computation with interactive UI verification or external conformance.
The RFC notebook is a cryptographic baseline; it does not exercise a RequestSeal parser or profile.

See [testing and evidence](../docs/guides/testing.md) for the execution contract.
Credential-bearing notebooks must use named secrets, redact output, document real endpoints,
and never send a payment or create infrastructure simply because the reader opens them.
