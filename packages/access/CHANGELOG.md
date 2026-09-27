# Changelog — @microtoll/access

Until 1.0, the API may change in any minor release and every such change is
listed with a migration note; the bytes the package writes never change
meaning (DECISIONS.md D-04).

## 0.1.1 — 2026-09-27

No change to the code or the formats. `repository` in package.json, which npm requires for a provenance publish. Published through the release workflow with npm provenance (launch item 8); 0.1.0 had been published by hand.

## 0.1.0 — 2026-09-27

The first release. The publish gate opened on 2026-09-27 (`DECISIONS.md`, D-01); every package is published in lockstep at 0.1.0 (D-41). The formats are frozen from this version (D-04).

- Documentation and comments made self-contained; no change to behaviour or formats.
- Frozen version-2 fixtures (`test/fixtures/frozen-v2.json`) and the generator that wrote them; no format change.
- **API change:** the example grant rule is renamed `goingGrantDue` (same
  behaviour: a verified or quiet row that says "going" and has not opted
  out). **Migration:** import `goingGrantDue` instead of the old name.

### M4 additions (2026-09-25)
- The client side of blind-store's selector query and live watches:
  `queryObjects`, `watchObjects`, `unwatchObjects`, `watchImminent`,
  `onLiveObject`; and `deletePointer` for a pointer to an object that is
  gone. The selector fields on the wire are the engine's (`collection`,
  `selector`, `windowStart`, `windowEnd`, `rosterMembersOnly`; D-33), passed
  through `createObjectMessage` and `updateObject` as before.
- `decodeObjectWire` returns `adminCapabilityHash: null` from the real
  server, which no longer sends it (it was a stable per-object token handed
  to everyone who received the object in a cover-traffic reply); the field
  stays for a host that sends one.
- **Format correction (D-37):** the pointer's additional authenticated data
  binds the account's routing public key, not the object id. The server
  returns an account's pointers without an id (its table has no object
  column, by design), so the M3 binding could never be opened on a fresh
  device; the notes example found it. `pointerCodec.build(identity, values)`
  and `pointerCodec.open(identity, sealed)` take the account; the object id
  is read from inside. No pointer had been written outside tests.

### M3 (2026-09-25)
- The object model (D-30): objects, members, owners and co-owners, with
  four protections built in: the admin capability travels in padded seats
  and is replaced on every rotation; one grant rule serves the owner's sweep
  and rotation; the server refuses a rotation at the wrong epoch or one that
  does not name every active row; and a row that cannot have come from an
  honest client is set aside and never sealed to.
- **Formats, version 2** (D-31; `FORMATS.md` §3): signature purpose labels
  (`sig/member-row/v2`, `sig/share-link/v2`); additional authenticated data
  on content, second tier, member rows, pointers and share-link payloads.
- Objects, member rows (named and quiet), pointers with an extension table,
  admin seats and the admin box, the read capability, two-tier disclosure
  (grants, the sweep, the viewer's merge), removal with key rotation
  (expected epoch, completeness, set-aside rows, the grant rule at
  rotation), the member's pointer refresh, share links (create, redeem,
  the creator's record), the display rule, and the client side of the
  object, member, pointer and link messages.
- Test tooling: the object protocol as an extension of the identity
  package's server stand-in (the contract `blind-store` keeps).
