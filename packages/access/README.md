# @microtoll/access

Sharing something with a group without the server being able to read it: one
random key per object, sealed person by person; membership rows the server
authorises by capability, never by identity; share links whose secret never
reaches the server; removal that re-keys everything in one checked
transaction; signed rows so nobody can pass for anyone else; and a second
tier (two-tier disclosure: an address, say) granted only to those the app
says. Web Crypto only; depends on `@microtoll/crypto-core` and
`@microtoll/identity`.

**Status:** published as `@microtoll/access` on npm. Formats are version 2
(`FORMATS.md`).

## The model in one paragraph

An **object** has `K_object` (32 random bytes). Its **content** is sealed
under it. An optional **second tier** is sealed under its own random
`K_detail`, never derived from `K_object`, and granted per recipient inside
the content. Each **member** has a row: a signed envelope under `K_object`
and a copy of `K_object` sealed to their key. A member's own **pointer**
(the key, the epoch, their capability secrets) is sealed under their
`K_master_symm`. **Capabilities** the server holds only hashes of: admin (in
padded seats inside the content), read (derived from `K_object`), row (random
per row) and link management. **Share links** carry `K_object` under a key
derived from a token that stays in the URL fragment. **Removal** rotates
every key and re-seals every remaining row; the server refuses the plan
unless it names every active row at the expected epoch. **Revoking** a link
deletes its row only: whoever already redeemed keeps what they hold.

## Five-minute quickstart

```js
import { createCryptoCore } from '@microtoll/crypto-core';
import { createIdentitySession /* … */ } from '@microtoll/identity';
import { createAccess, goingGrantDue, oneOf } from '@microtoll/access';

const cc = createCryptoCore({ namespace: 'myapp' });
const access = createAccess({
  cryptoCore: cc,
  pointerFields: { myStatus: { wire: 'myStatus', ...oneOf(['going', 'interested']) } },   // your fields
  split: (content) => { const { address, ...preview } = content; return { preview, detail: { address } }; },
  merge: (preview, detail) => ({ ...preview, ...(detail || {}) }),
  grantDue: goingGrantDue,                                    // who is owed the second tier
});

// The owner creates an object (an event, a document, a group) with a hidden address.
const created = await access.createObject({ identity: me, content: { title: 'Book club', address: '12 Secret St' }, twoTier: true });
await access.createObjectMessage(ws, created, { /* your coarse selector fields */ });

// A share link for the group chat: the secret stays after the '#'.
const link = await access.createShareLink({ objectId: created.objectId, kObjectRaw: created.kObjectRaw, maxUses: 10, expiresAt, creator: me, creatorName: 'Ada' });
await access.publishShareLink(ws, link);
const url = `${location.origin}/#token=${link.token}`;

// Someone opens it: read access, then a first reaction makes them a member.
const payload = await access.redeemShareLinkMessage(ws, await access.hashToken(token));
const { objectId, kObjectRaw, creatorName } = await access.redeemShareLink(token, payload);
await access.joinObject(ws, { objectId, pointer: await access.buildReadOnlyPointer({ identity: me, objectId, kObjectRaw, keyEpoch }) });
const first = await access.buildFirstReaction({ identity: me, objectId, kObjectRaw, keyEpoch, content: { status: 'going' } });
await access.createMemberRow(ws, { objectId, row: first.row, pointerId, pointer: first.pointer, readCapabilitySecret: first.readCapabilitySecret });

// The roster, with the display rule applied: verified rows show; quiet rows show no identity; unverified rows show nothing.
const roster = access.roster(await access.openRows({ kObjectRaw, objectId, rows: await access.fetchMembers(ws, objectId, { readCapabilitySecret }) }));

// Removing someone: a new key for everyone else, in one checked transaction.
const plan = await access.buildRotationPlan({ objectId, identity: me, oldKObjectRaw, oldEpoch, content, rows, remove: [rowId], selfRowId, twoTier: { detailOpened: true } });
await access.rotateObjectKey(ws, objectId, adminCapabilitySecret, plan);
```

## What the app supplies

- **`pointerFields`**: the app's own fields in a member's pointer (mirrors
  for badges and lists), each `{ wire, seal, open }`.
- **`split`** and **`merge`**: what goes in the second tier, and how the two
  parts come back together for someone who holds a grant.
- **`grantDue`**: which roster entries are owed the second tier.
  `goingGrantDue` is an example rule: a verified or quiet row that says
  "going" and has not opted out.
- **The coarse selector**: the plaintext blind-store indexes objects by
  (`collection`, a fixed-length `selector`, an optional `windowStart` and
  `windowEnd`; for example a region code and dates), passed through
  untouched in `createObjectMessage` and `updateObject`, and queried with
  `queryObjects` — the cover-traffic query: decrypt what you hold keys for,
  discard the rest, never ask by a list of ids. `watchObjects`,
  `watchImminent` and `onLiveObject` are the live half.
- **The transport** (a WebSocket-like object) and everything on screen.

## Tests

`npm test`: 29 tests, all through the public API, including the adversarial
suite (`THREATMODEL.md` §5 maps them).

## Formats and scope

- **Formats version 2**: purpose labels on the member-row and
  share-link signatures; additional authenticated data on content, second
  tier, member rows, pointers and link payloads. The per-member sealed copy
  of `K_object` is an ECIES seal without extra data (stated in the threat
  model). Envelope `v: 3` is the signed row; `v: 2` the quiet row; an
  envelope with any other version, or none, is refused.
- **Generic names**: object, member row, owner, `K_object`. Some wire
  message and field names say "event" (`create-event`, `eventUserId`): they
  are the server protocol.
- **The split, the merge, the grant rule and the pointer's app fields are
  supplied by the app**; the package knows nothing of what the content means.
- **Admin box label** is `<ns>/object-adminbox/v1` (`FORMATS.md` §3.2).
- **Direct invites, acknowledgements, contacts and favourites** are not here
  (they are in `@microtoll/mailbox`); nor are product features that ride in rows or content.
- **`openRows` skips a row that will not open** rather than surfacing it;
  the rotation plan is where an unreadable row is reported (set aside).
