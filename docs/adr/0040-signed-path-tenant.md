# 0040 — Bind tenant context to the signed path

Status: Accepted.

## Context

[RFC 9421 Section 2.2.6](https://www.rfc-editor.org/rfc/rfc9421.html#section-2.2.6)
covers the case-sensitive path bytes. Router parameters alone do not establish
that a tenant selector was covered by the verified signature.

## Decision

After Plug verification, require unparameterized `@path`. Check that the
captured path and Plug's segment split agree. Match the path in its original
spelling using unreserved ASCII. Refuse percent escapes, empty segments and
dot segments. Tenant captures use lowercase tokens or lowercase UUID text.
[RFC 3986 Section 2](https://www.rfc-editor.org/rfc/rfc3986.html#section-2)
defines percent encoding and unreserved characters.

Reject competing headers and recursively inspect query and parsed body maps
and lists. A nonempty body requires a configured parser that fully consumes
the captured bytes before verification. The principal lookup runs within a
finite deadline and must return exactly the selected tenant.

Pass the resulting tenant to the existing Ash scope construction. The resource's
multitenancy strategy and policies decide which data operations may proceed.
Tenant agreement supplies context. Signer attribution remains a separate
property of the selected verification profile or trusted configuration.

## Alternatives

Reading merged parameters would allow query or body fields to compete with the
path. A tenant selected solely by the principal could silently override a
different authenticated path.

## Consequences

Apply the plug after Verify and any relevant body parsers. The binding is
specific to one connection and fails closed when repeated or deverified.
