# Formats and stability

Two promises, stated separately, because they are different things.

## The bytes never change meaning

From the first published version: no version byte, label, key-derivation
parameter or signed-byte layout ever changes meaning, and readers for every
published format stay supported. **Anything you encrypt with any published
version will decrypt with every later one.**

A format is a versioned thing. The AEAD blob starts with `0x01`; the
classical seal with `0x03`, the hybrid seal with `0x02`; a signed member row
is `{ v: 3 }`; a mailbox bundle `{ v: 2 }`. A new format is a new version
byte beside the old one, never a change to the old one. Every label the
engine derives a key or a context from is `<namespace>/<purpose>/v<n>`, and
three labels of retired formats are refused in every namespace so they can
never be reused by accident.

How a format is allowed to change: as a **pending decision** in the
repository's `DECISIONS.md`, with the reasoning, decided by the maintainer
before any code, and recorded with the date. The record of every format
decision so far is on the [decisions](decisions.html) page; the formats
themselves are in each package's formats page ([identity](packages/identity-formats.html),
[access](packages/access-formats.html), [mailbox](packages/mailbox-formats.html)).

## The API may change until 1.0

Function names and options may change in any 0.x minor release. Every such
change is listed in the package's `CHANGELOG.md` with a migration note; patch
releases never break. The packages move in lockstep: one engine version to
pin, one to name in a bug report.

## What a fixture is

A fixture is a set of bytes an earlier version wrote — a sealed blob, a
signature, a derived key — frozen in the repository and never regenerated.
Every later version must open and reproduce it, so a changed label, version
byte, parameter or layout turns a test red instead of making stored data
silently unreadable. A new format gets new fixtures beside the old ones.
Published test vectors (RFC 5869, RFC 8032, RFC 5903, RFC 7914, NIST's
AES-GCM, the X-Wing drafts) run through the public API, never through a
re-implementation in a test file.
