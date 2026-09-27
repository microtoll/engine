# Changelog — @microtoll/mailbox

Until 1.0, the API may change in any minor release and every such change is
listed with a migration note; the bytes the package writes never change
meaning (DECISIONS.md D-04).

## 0.1.1 — 2026-09-27

No change to the code or the formats. `repository` in package.json, which npm requires for a provenance publish. Published through the release workflow with npm provenance (launch item 8); 0.1.0 had been published by hand.

## 0.1.0 — 2026-09-27

The first release. The publish gate opened on 2026-09-27 (`DECISIONS.md`, D-01); every package is published in lockstep at 0.1.0 (D-41). The formats are frozen from this version (D-04).

- Documentation and comments made self-contained; no change to behaviour or formats.
- Frozen version-2 fixtures (`test/fixtures/frozen-v2.json`) and the generator that wrote them; no format change.

### M3b (2026-09-25, inside M5; D-40)
- The pairwise label (`mailboxId`, pinned by the crypto-core fixture file),
  the epochs, direct invitations and acknowledgements, sending, collection,
  withdrawal and status.
- **Bundle version 2** (`FORMATS.md` §2): the signature binds the purpose
  label, the mailbox label and the recipient key, so a bundle re-sealed into
  another mailbox or for another recipient verifies for nobody.
- The mailbox messages (`send-invite`, `poll-invites`, `consume-invite`,
  `watch-invites`, the `invite-live` push; names fixed by D-27) and the live
  wake-up.
- Test tooling: the mailbox protocol as an extension of the identity
  package's server stand-in.
