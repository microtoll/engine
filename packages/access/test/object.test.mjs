// Objects, the second tier and its grants, and crypto-core's frozen fixtures
// for the two derivations whose labels are version 1 (the read capability and
// the detail-grant label).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCryptoCore } from '@microtoll/crypto-core';
import { createIdentity } from '@microtoll/identity';
import * as ac from '../src/index.js';
import { cc, makeAccess } from './helpers.mjs';

const fx = JSON.parse(readFileSync(new URL('../../crypto-core/test/fixtures/frozen-v1.json', import.meta.url), 'utf8'));

test('the read capability and the detail-grant label match the frozen fixtures', async () => {
  // The fixtures were written under their own namespace; build the instance from it.
  const fcc = createCryptoCore({ namespace: fx.namespace });
  const kObject = fcc.fromHex(fx.access.kEvent);
  assert.equal(fcc.toHex(await ac.readCapability(fcc, kObject)), fx.access.readCapability);
  assert.equal(await ac.hashCapability(fcc, await ac.readCapability(fcc, kObject)), fx.access.readCapabilityHash);
  const alice = await fcc.importSealingKeyPair(fx.eciesV3.recipientJwk);
  assert.equal(await ac.detailGrantLabel(fcc, kObject, alice.publicKeyRaw), fx.access.detailGrantLabelForAlice);
});

test('createObject: the owner opens content, row, seat and pointer with their own keys; capabilities are independent', async () => {
  const access = makeAccess();
  const owner = await createIdentity(cc);
  const c = await access.createObject({ identity: owner, content: { title: 'Book club' }, ownerRowContent: { status: 'going' } });
  const { kObjectKey } = await ac.unwrapObjectKey(cc, owner.identity, c.ownerRow.encryptedObjectKey);
  const content = await ac.openContent(cc, kObjectKey, c.objectId, 1, c.encryptedContent);
  assert.equal(content.title, 'Book club');
  assert.equal(content.ownerSigningKey, cc.toBase64Url(owner.identitySigning.publicKeyRaw));
  assert.equal(content.adminSeats.length, 4);
  const row = await ac.openMemberRow(cc, kObjectKey, c.objectId, c.ownerRow.rowId, c.ownerRow.encryptedRow);
  assert.equal(row.verified, true);
  const pointer = await access.pointerCodec.open(owner, c.pointer);
  assert.deepEqual(pointer.kObject, c.kObjectRaw);
  assert.deepEqual(pointer.adminCapabilitySecret, c.adminCapabilitySecret);
  assert.deepEqual((await ac.openAdminSeat(cc, owner, content, c.objectId, 1)).adminCapabilitySecret, c.adminCapabilitySecret);
  assert.notEqual(cc.toHex(c.adminCapabilitySecret), cc.toHex(c.ownerRow.rowCapabilitySecret));
  assert.equal(c.encryptedDetail, null);
  // Content is bound to the object and epoch.
  await assert.rejects(ac.openContent(cc, kObjectKey, c.objectId, 2, c.encryptedContent));
  const other = await createIdentity(cc);
  await assert.rejects(ac.unwrapObjectKey(cc, other.identity, c.ownerRow.encryptedObjectKey), 'a wrong member cannot unwrap');
});

test('two-tier: a K_object-only holder cannot open the second tier; the owner can; a link holder sees the preview', async () => {
  const access = makeAccess();
  const owner = await createIdentity(cc); const lurker = await createIdentity(cc);
  const c = await access.createObject({ identity: owner, content: { title: 'x', address: '12 Secret Street' }, twoTier: true });
  assert.ok(c.encryptedDetail);
  const kObjectKey = await cc.importSymmetricKey(c.kObjectRaw);
  const preview = await ac.openContent(cc, kObjectKey, c.objectId, 1, c.encryptedContent);
  assert.equal(preview.address, undefined);
  assert.equal(preview.locationIsApproximate, true);
  assert.equal(Object.keys(preview.detailGrants).length, 1);
  const seen = await access.openForViewer({ kObjectRaw: c.kObjectRaw, objectId: c.objectId, epoch: 1, preview, encryptedDetail: c.encryptedDetail, viewer: { identity: owner } });
  assert.equal(seen.address, '12 Secret Street');
  assert.equal(seen.locationIsApproximate, undefined, 'the default merge keeps the detail\'s truth');
  const notSeen = await access.openForViewer({ kObjectRaw: c.kObjectRaw, objectId: c.objectId, epoch: 1, preview, encryptedDetail: c.encryptedDetail, viewer: { identity: lurker } });
  assert.equal(notSeen.address, undefined);
  // Holding K_object and the detail ciphertext: no grant, no key. K_detail is never derived from K_object.
  assert.equal(await ac.openDetailGrant(cc, c.kObjectRaw, preview.detailGrants, ac.identityGrantKeys(lurker)), null);
});

test('the sweep grants only rows the grant rule says (going, not opted out, verified or quiet), never twice, and admins', async () => {
  const access = makeAccess();
  const owner = await createIdentity(cc); const going = await createIdentity(cc); const interested = await createIdentity(cc); const co = await createIdentity(cc);
  const c = await access.createObject({ identity: owner, content: { title: 'x', address: 'A' }, twoTier: true });
  const kObjectKey = await cc.importSymmetricKey(c.kObjectRaw);
  const preview = await ac.openContent(cc, kObjectKey, c.objectId, 1, c.encryptedContent);
  const rows = [];
  for (const [who, content] of [[going, { status: 'going' }], [interested, { status: 'interested' }], [co, { status: 'not going' }]]) {
    const r = await access.buildMemberRow({ identity: who, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content });
    rows.push({ rowId: r.rowId, keyEpoch: 1, encryptedRow: r.encryptedRow });
  }
  const quiet = await access.buildQuietMemberRow({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  rows.push({ rowId: quiet.row.rowId, keyEpoch: 1, encryptedRow: quiet.row.encryptedRow });
  const entries = access.roster(await access.openRows({ kObjectRaw: c.kObjectRaw, objectId: c.objectId, rows }));
  const grants = await access.planDetailGrantSweep({ kObjectRaw: c.kObjectRaw, kDetailRaw: c.kDetailRaw, existingGrants: preview.detailGrants, entries, adminSigningKeys: new Set([cc.toBase64Url(co.identitySigning.publicKeyRaw)]) });
  assert.equal(Object.keys(grants).length, 4, 'owner + going + quiet going + the admin');
  const merged = { ...preview, detailGrants: grants };
  const sees = async (viewer) => (await access.openForViewer({ kObjectRaw: c.kObjectRaw, objectId: c.objectId, epoch: 1, preview: merged, encryptedDetail: c.encryptedDetail, viewer })).address;
  assert.equal(await sees({ identity: going }), 'A');
  assert.equal(await sees({ identity: co }), 'A');
  assert.equal(await sees({ identity: interested }), undefined, '"interested" is not a commitment');
  assert.equal(await sees({ identity: quiet.quietRotationKey && { identityKem: null }, quietRotationKey: quiet.quietRotationKey, quietRotationKemSeed: quiet.quietRotationKemSeed }), 'A', 'a quiet responder is granted through their per-object key');
  assert.equal(await access.planDetailGrantSweep({ kObjectRaw: c.kObjectRaw, kDetailRaw: c.kDetailRaw, existingGrants: grants, entries }), null, 'idempotent: nothing to do');
  // Labels are object-scoped: the same person in two objects has two unrelated labels.
  const other = await access.createObject({ identity: owner, content: { title: 'y', address: 'B' }, twoTier: true });
  assert.notEqual(await ac.detailGrantLabel(cc, c.kObjectRaw, going.identity.publicKeyRaw), await ac.detailGrantLabel(cc, other.kObjectRaw, going.identity.publicKeyRaw));
});

test('first reaction: named or quiet, the row and the replacement pointer carry the secret; a read-only pointer has no row secret', async () => {
  const access = makeAccess();
  const owner = await createIdentity(cc); const guest = await createIdentity(cc);
  const c = await access.createObject({ identity: owner, content: { title: 'x' } });
  const ro = await access.buildReadOnlyPointer({ identity: guest, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, invitedBy: { signingKey: 'k', via: 'link' } });
  const opened = await access.pointerCodec.open(guest, ro);
  assert.equal(opened.rowCapabilitySecret, null); assert.equal(opened.invitedBy.via, 'link');
  const first = await access.buildFirstReaction({ identity: guest, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' }, existingPointer: opened });
  const p2 = await access.pointerCodec.open(guest, first.pointer);
  assert.deepEqual(p2.rowCapabilitySecret, first.row.rowCapabilitySecret); assert.equal(p2.invitedBy.via, 'link', 'carried through');
  assert.deepEqual(first.readCapabilitySecret, await ac.readCapability(cc, c.kObjectRaw));
  const q = await access.buildFirstReaction({ identity: guest, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' }, quiet: true, existingPointer: opened });
  const p3 = await access.pointerCodec.open(guest, q.pointer);
  assert.ok(p3.quietRotationKey);
  const kObjectKey = await cc.importSymmetricKey(c.kObjectRaw);
  assert.equal((await ac.openMemberRow(cc, kObjectKey, c.objectId, q.row.rowId, q.row.encryptedRow)).quiet, true);
  const { kObjectRaw } = await ac.unwrapObjectKey(cc, await ac.quietRotationKeys(cc, p3.quietRotationKey, p3.quietRotationKemSeed), q.row.encryptedObjectKey);
  assert.deepEqual(kObjectRaw, c.kObjectRaw, 'the quiet member\'s sealed copy opens with the per-object key');
});
