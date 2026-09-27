# @microtoll/access — the object model and the hardening design (M3)

**Status:** decided 2026-09-25 (DECISIONS.md D-30, D-31, D-32): the design below is what M3 builds.

## 1. What the access layer is, in one paragraph

An **object** (an event, a document, a group) has one random symmetric key,
`K_object`. Its **content** is sealed under that key; an optional **second
tier** (`K_detail`, an address, say) is sealed under its own random key and
granted person by person. **Members** each have a row: a signed envelope
sealed under `K_object`, and a copy of `K_object` sealed to their sealing key.
A member's own note about the object (the key, the epoch, their capability
secrets) is a **pointer**, sealed under their `K_master_symm`. The server
authorises writes by **capability secrets** it holds only the hashes of: admin
(a random secret carried in a sealed seat), read (derived from `K_object`),
row (random per row), and link management (random per link). **Share links**
carry `K_object` in a payload sealed under a key derived from a token that
never reaches the server. **Removal** rotates every key and re-seals every
remaining row in one server transaction that checks the epoch and that every
active row was named. **Revocation** of a link deletes its row only.

## 2. Decision D-30: the object model

The object model answers D-13 (a generic collection model) with five rules:
an epoch on every write, a rotation the server refuses unless it names every
active row, an admin capability replaced on every rotation and carried in
padded seats, rows that cannot have come from an honest client set aside, and
one rule for who gets the second tier. Version 2 adds additional
authenticated data to the object-layer seals (§3).

**The parts:**

| Part | Notes |
|---|---|
| object, `K_object`, `objectId` | a client-generated UUID |
| content | JSON the app owns; the package owns `adminSeats`, `adminBox`, `detailGrants`, `ownerSigningKey` |
| second tier, `K_detail`, `hasDetail` | the **split** is caller-supplied: `split(content) → { preview, detail }`; what goes in the second tier is the app's choice |
| member row | a signed envelope (named) or an unsigned one (quiet), sealed under `K_object` |
| `grantDue(row) → boolean` | caller-supplied: who is owed the second tier. The package ships an example rule: "verified or quiet, going, not opted out" |
| pointer | the package owns `objectId`, `kObject`, `keyEpoch`, `rowCapabilitySecret`, `adminCapabilitySecret`, `quietRotationKey`, `quietRotationKemSeed`, `sharedLinks`, `invitedBy`; the app's fields (a status mirror, a notification flag, …) ride through a registered extension table |
| owner, co-owner | holders of the admin capability |
| the **coarse selector** | an opaque app value the server indexes (M4); not the package's |
| admin seats, admin box | `ADMIN_SEAT_BUCKET` 4, seat plaintext 256 bytes, box bucket 1024 bytes |
| quiet row (`v: 2`) | a per-object P-256 (+ KEM) rotation key in the pointer |
| share link | token in the URL fragment; hashed token, N uses, expiry, management secret |
| direct invite, ack | **`@microtoll/mailbox`** (M3b): the bundle formats, and the binding of the mailbox and the recipient into the signature, live there |

**Some wire message names say "event"** (`create-event`, `rotate-event-key`,
…) because they are the server protocol `blind-store` speaks (D-27); the
package's function names are generic.

**What the package does not do:** decide who is granted the second tier
(`grantDue`), split content (`split`), choose link expiry or group sizes, hold
invites for people without accounts, render anything, or fetch anything itself
(it builds messages and opens replies; the transport is the app's, as in
identity).

## 3. Decision D-31: the hardening (formats version 2)

Every item adds binding with primitives crypto-core already has
(`frameContext`, `sha256`, AEAD v1's additional authenticated data); no
primitive, mode or KDF changes. Labels come from the profile, so a v1 blob can
never be mistaken for v2.

### 3.1 Purpose labels on signatures

| Signature | Version 2 signs |
|---|---|
| member row | `frameContext("<ns>/sig/member-row/v2", uuidBytes(objectId), uuidBytes(rowId)) ‖ UTF-8(payloadJson)` |
| share link | `frameContext("<ns>/sig/share-link/v2", hashedTokenBytes32) ‖ UTF-8(payloadJson)` |
| direct invite / ack (mailbox, M3b) | `frameContext("<ns>/sig/invite/v2", mailboxLabel32, SHA-256(recipientKey)) ‖ UTF-8(payloadJson)` — the mailbox and the recipient are in the signature, so a bundle re-sealed into another mailbox or for another recipient verifies for nobody (D-40; the collection-side check stays too). Built in `@microtoll/mailbox`, `FORMATS.md` §2 |

The frame's fixed-length parts (UUIDs as 16 bytes, a hash as 32) and the
NUL-terminated label mean no field can shift into another and no signature
made for one purpose verifies for another. Version 1 signed text fields
joined by NUL bytes (or the payload alone) with no purpose label, so nothing
stopped a signature made for one purpose being offered for another; this
package does not read version 1. The signed
envelope keeps the outer shape `{ v, payloadJson, sig }` with `v: 3`, so a
reader knows which message to rebuild; `v: 2` stays the quiet row.

### 3.2 Additional authenticated data on the object-layer seals

| Seal | Key | Context (version 2) | Prevents |
|---|---|---|---|
| content | `K_object` | `frameContext("<ns>/aad/object-content/v2", objectId, u32be(epoch))` | content moved between objects, or an earlier epoch's content replayed after a rotation under the same… (the key changes at rotation; the epoch binding is belt and braces and lets a reader assert the epoch it was told) |
| second tier | `K_detail` | `frameContext("<ns>/aad/object-detail/v2", objectId, u32be(epoch))` | same |
| member row | `K_object` | `frameContext("<ns>/aad/member-row/v2", objectId, uuidBytes(rowId))` | a row's ciphertext presented under another row id (the signature already binds the row id for named rows; this covers quiet and legacy rows too) |
| pointer | `K_master_symm` | `frameContext("<ns>/aad/pointer/v2", routingPublicKey)` (D-37, M4: the account, not the object id — the server returns an account's pointers without an id, so a binding that needed one could never be opened on a fresh device; the object id is inside the sealed pointer) | a pointer moved to another account, or another `K_master_symm` blob presented as a pointer |
| share-link payload | token-derived key | `frameContext("<ns>/aad/share-link/v2", hashedTokenBytes32)` | a payload served under another link's hash |
| admin box | `K_adminbox` | `frameContext("<ns>/object-adminbox/v1", objectId, u32be(epoch))` | a box moved to another object, or an earlier epoch's box replayed |

Rotation re-encrypts each remaining row byte-for-byte under the new key with
the same row context, so signatures survive it.

**Not bound, stated plainly:** the sealed copy of `K_object` per member
(`encryptedSharedEventKey` on the wire) is an ECIES seal, which binds the recipient's
key and its version but takes no additional data; binding the row would need
an ECIES v4 in crypto-core, which is out of scope. A server that moves a
member's sealed key to another of the same member's rows gains nothing the
member could not do.

### 3.3 Not changed by version 2

The admin seats and box (frozen sizes), quiet rows, the seal-target chooser
(a quiet row's per-object keys first, a fresh hybrid key before the classical
one, a stale advertisement treated as absent), the set-aside rule, the grant
rule's shape, the pointer's compare-and-heal on a lagging epoch, link tokens
(160 bits), capability secrets (256 bits, SHA-256 on the server), and every
wire message.

## 4. Decision D-32: what M3 ships and what waits

**M3, `@microtoll/access`:**
- object creation; sealing `K_object` to a member; the read capability;
  member rows (named, quiet, legacy readers); pointers with the extension
  table; admin seats and the admin box; the rotation plan and the member's
  pointer refresh; two-tier disclosure (split by the caller; grants, the
  sweep, the viewer's merge); share links (create, redeem, revoke, the
  creator's record, stats); the unverified display rule as a pure function
  over opened rows; the message builders and reply openers for the object
  wire (`create-event`, `join-event`, `fetch-event-members`,
  `rotate-event-key`, `create-participation`, `update-participation`,
  `update-event`, `delete-event`, `delete-participation`, the four link
  messages).
- Tests: the adversarial suite the build plan names, each case against the
  in-process server stand-in extended with the object messages (the same
  stand-in identity uses, so the contract stays one).
- Fixtures: the version-2 contexts frozen in this package's tests;
  crypto-core's frozen fixtures (`test/fixtures/frozen-v1.json`) pin the
  read capability and the detail-grant label. This package's
  `test/fixtures/frozen-v2.json` holds version-2 bytes it wrote (content,
  second tier and grants, named and quiet rows, pointers, admin seats and
  box, share links, and their hybrid variants), which every later version
  must open and reproduce.

**Waits:** direct invites and acknowledgements (mailbox, M3b); contacts and
favourites (app or mailbox); product features that ride in rows or content
as app fields (a first-time flag, repeat grants, proposals, signals) stay the
app's.

## 5. The adversarial suite (build plan M3), mapped

| Requirement | Cases |
|---|---|
| A removed member's old key cannot read post-rotation writes | new content, new detail, every resealed row and sealed key; the server refuses a write at the old epoch; the removed co-owner's admin secret refused; an incomplete plan refused as stale; a substituted old row set aside and never sealed to |
| A revoked link cannot be redeemed | revoke → not-found; expiry → expired; N uses then exhausted; a concurrent last use taken once; stats absent after revoke |
| An already-redeemed link is unaffected | a pointer holder still reads after revoke; and IS cut off by a later rotation |
| A forged signature is flagged unverified | a bit-flipped, truncated or wrong-key signature on a row and on a link; a row lifted to another row id or object; a v2 quiet row carrying identity claims is still quiet, not verified; the display rule strips name and keys |
| Holding the object never yields the second tier | a `K_object`-only holder cannot open the detail; a link holder cannot; a rotation grants only to the owner, co-owners, rows `grantDue` says and rows that held a grant; a grant label is object-scoped |
