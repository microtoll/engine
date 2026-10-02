# Security policy

Microtoll Engine is security software: sign-in, key handling, access control
and revocation for end-to-end-encrypted apps. If you have found a weakness
in it, thank you for reading this first.

## Reporting

- Write to **security@microtoll.dev**. Never open a public issue for a
  security problem.
- Say which package and version, what you did, what happened, and what you
  expected. A proof of concept is welcome; user data is not — please do not
  include anyone's real content or keys.
- If you want your report encrypted, ask for the current key in a first,
  content-free message; the key's fingerprint is published in this file once
  the project is public.

## What to expect

- An acknowledgement within **seven days**.
- A fix, or a written statement of why there will not be one, within
  **ninety days** of the report, sooner where the fix is simple. Where a fix
  changes a stored format, the format rules still apply:
  readers for every published format stay supported.
- Credit in the release notes, if you want it. There is no bounty: nothing
  in this project is financial, by rule.
- Coordinated disclosure: we ask that you give us the ninety days before
  publishing, and we will tell you the release date in advance.

## Scope

**In scope:** the packages under `packages/` (`crypto-core`, `identity`,
`access`, `mailbox`, `blind-store`, `mcp`), the reference deployment under
`deploy/`, the examples, and the documents that describe what they protect
(`THREATMODEL.md` and each package's `FORMATS.md`). A gap between what the
threat model claims and what the code does is in scope even if nothing is
"exploited".

**Out of scope:** applications built on the engine (report to their
owners), the docs site's hosting, and the limits the threat model
already states (`THREATMODEL.md` §2: traffic shape, a compromised device,
script injection into a page that holds keys).

## Verifying a release

Release tags are signed with the maintainer's key; the public key is
published here when the first release is made, and every published package
carries npm provenance linking it to the tagged commit and the workflow that
built it.
