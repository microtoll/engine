// The adversarial suite against the server stand-in: links, redemption,
// revocation, removal and what the server refuses.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as ac from '../src/index.js';
import { cc, makeAccess, makeServer, person } from './helpers.mjs';

const later = () => new Date(Date.now() + 86400000).toISOString();
const selector = { collection: 'events', selector: 'abcde', windowStart: '2026-10-01', windowEnd: '2026-10-01' };

async function publishedObject(server, access, owner, content = { title: 'x' }, extra = {}) {
  const c = await access.createObject({ identity: owner.identity, content, ownerRowContent: { status: 'going' }, ...extra });
  await access.createObjectMessage(owner.ws, c, selector);
  return c;
}

test('a link holder reads and lists the roster; after revoke the link is not-found; the holder keeps reading; a later removal cuts them off', async () => {
  const server = makeServer(); const access = makeAccess();
  const owner = await person(server); const guest = await person(server);
  const c = await publishedObject(server, access, owner);
  const link = await ac.createShareLink(cc, { objectId: c.objectId, kObjectRaw: c.kObjectRaw, maxUses: 1, expiresAt: later(), creator: owner.identity, creatorName: 'Ada', keyEpoch: 1 });
  await access.publishShareLink(owner.ws, link);
  // The guest redeems, gets read access, and can list who is there through the derived capability.
  const payload = await access.redeemShareLinkMessage(guest.ws, link.hashedToken);
  const redeemed = await ac.redeemShareLink(cc, link.token, payload);
  assert.equal(redeemed.creatorName, 'Ada');
  const ro = await access.buildReadOnlyPointer({ identity: guest.identity, objectId: c.objectId, kObjectRaw: redeemed.kObjectRaw, keyEpoch: 1 });
  await access.joinObject(guest.ws, { objectId: c.objectId, pointer: ro });
  const fetched = await access.fetchObject(guest.ws, c.objectId);
  const kObjectKey = await cc.importSymmetricKey(redeemed.kObjectRaw);
  assert.equal((await ac.openContent(cc, kObjectKey, c.objectId, fetched.keyEpoch, fetched.encryptedContent)).title, 'x');
  const members = await access.fetchMembers(guest.ws, c.objectId, { readCapabilitySecret: await ac.readCapability(cc, redeemed.kObjectRaw) });
  assert.equal(members.length, 1);
  // Revoke: a second redemption is refused; the guest still reads.
  assert.equal(await access.revokeShareLink(owner.ws, link.hashedToken, link.manageSecret), 1);
  await assert.rejects(access.redeemShareLinkMessage(guest.ws, link.hashedToken), (e) => e.reason === 'not-found');
  assert.equal((await ac.openContent(cc, kObjectKey, c.objectId, 1, (await access.fetchObject(guest.ws, c.objectId)).encryptedContent)).title, 'x');
  // The guest reacts, becoming a member; then the owner removes them.
  const first = await access.buildFirstReaction({ identity: guest.identity, objectId: c.objectId, kObjectRaw: redeemed.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  const pointers = await access.fetchPointers(guest.ws);
  await access.createMemberRow(guest.ws, { objectId: c.objectId, row: first.row, pointerId: pointers[0].pointerId, pointer: first.pointer, readCapabilitySecret: first.readCapabilitySecret });
  const rows = await access.fetchMembers(owner.ws, c.objectId, { adminCapabilitySecret: c.adminCapabilitySecret });
  assert.equal(rows.length, 2);
  const plan = await access.buildRotationPlan({ objectId: c.objectId, identity: owner.identity, oldKObjectRaw: c.kObjectRaw, oldEpoch: 1, content: c.previewContent, rows, remove: [first.row.rowId], selfRowId: c.ownerRow.rowId });
  assert.equal(await access.rotateObjectKey(owner.ws, c.objectId, c.adminCapabilitySecret, plan), 2);
  const after = await access.fetchObject(guest.ws, c.objectId);
  await assert.rejects(ac.openContent(cc, kObjectKey, c.objectId, after.keyEpoch, after.encryptedContent), 'the old key opens nothing new');
  await assert.rejects(access.fetchMembers(guest.ws, c.objectId, { readCapabilitySecret: await ac.readCapability(cc, redeemed.kObjectRaw) }), (e) => e.reason === 'unauthorized');
  await assert.rejects(access.fetchMyRow(guest.ws, c.objectId, first.row.rowCapabilitySecret), (e) => e.reason === 'not-found');
});

test('N uses then exhausted; expired; stats only for the creator; a recipient cannot revoke', async () => {
  const server = makeServer(); const access = makeAccess();
  const owner = await person(server); const a = await person(server); const b = await person(server);
  const c = await publishedObject(server, access, owner);
  const link = await ac.createShareLink(cc, { objectId: c.objectId, kObjectRaw: c.kObjectRaw, maxUses: 2, expiresAt: later() });
  await access.publishShareLink(owner.ws, link);
  await access.redeemShareLinkMessage(a.ws, link.hashedToken);
  await access.redeemShareLinkMessage(b.ws, link.hashedToken);
  await assert.rejects(access.redeemShareLinkMessage(b.ws, link.hashedToken), (e) => e.reason === 'exhausted');
  const stats = await access.fetchShareLinkStats(owner.ws, [{ hashedToken: link.hashedToken, manageSecret: link.manageSecret }]);
  assert.equal(stats[0].useCount, 2);
  assert.deepEqual(await access.fetchShareLinkStats(a.ws, [{ hashedToken: link.hashedToken, manageSecret: cc.randomBytes(32) }]), [], 'no management secret, no answer');
  assert.equal(await access.revokeShareLink(a.ws, link.hashedToken, cc.randomBytes(32)), 0, 'a recipient cannot revoke');
  const expired = await ac.createShareLink(cc, { objectId: c.objectId, kObjectRaw: c.kObjectRaw, expiresAt: new Date(Date.now() + 50).toISOString() });
  await access.publishShareLink(owner.ws, expired);
  await new Promise((r) => setTimeout(r, 60));
  await assert.rejects(access.redeemShareLinkMessage(a.ws, expired.hashedToken), (e) => e.reason === 'expired');
  await assert.rejects(access.publishShareLink(owner.ws, { ...link, hashedToken: 'ab'.repeat(32), maxUses: 999 }), (e) => e.reason === 'invalid');
});

test('the server refuses: a join without the key, a stale-epoch write, an old admin secret, an incomplete or stale plan', async () => {
  const server = makeServer(); const access = makeAccess();
  const owner = await person(server); const bob = await person(server); const eve = await person(server);
  const c = await publishedObject(server, access, owner);
  const bobRow = await access.buildMemberRow({ identity: bob.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  const bobPtr = await access.buildReadOnlyPointer({ identity: bob.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1 });
  await assert.rejects(access.joinObject(bob.ws, { objectId: c.objectId, pointer: bobPtr, row: bobRow, readCapabilitySecret: cc.randomBytes(32) }), (e) => e.reason === 'unauthorized');
  await access.joinObject(bob.ws, { objectId: c.objectId, pointer: bobPtr, row: bobRow, readCapabilitySecret: c.readCapabilitySecret });
  const eveRow = await access.buildMemberRow({ identity: eve.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  await access.joinObject(eve.ws, { objectId: c.objectId, pointer: await access.buildReadOnlyPointer({ identity: eve.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1 }), row: eveRow, readCapabilitySecret: c.readCapabilitySecret });
  const rows = await access.fetchMembers(owner.ws, c.objectId, { adminCapabilitySecret: c.adminCapabilitySecret });
  assert.equal(rows.length, 3);
  // An incomplete plan (Bob's row omitted) is refused as stale; nothing changes.
  const incomplete = await access.buildRotationPlan({ objectId: c.objectId, identity: owner.identity, oldKObjectRaw: c.kObjectRaw, oldEpoch: 1, content: c.previewContent, rows: rows.filter((r) => r.rowId !== bobRow.rowId), remove: [eveRow.rowId], selfRowId: c.ownerRow.rowId });
  await assert.rejects(access.rotateObjectKey(owner.ws, c.objectId, c.adminCapabilitySecret, incomplete), (e) => e.reason === 'stale');
  assert.equal((await access.fetchObject(owner.ws, c.objectId)).keyEpoch, 1);
  const plan = await access.buildRotationPlan({ objectId: c.objectId, identity: owner.identity, oldKObjectRaw: c.kObjectRaw, oldEpoch: 1, content: c.previewContent, rows, remove: [eveRow.rowId], selfRowId: c.ownerRow.rowId });
  assert.equal(await access.rotateObjectKey(owner.ws, c.objectId, c.adminCapabilitySecret, plan), 2);
  // A plan built on the old epoch is stale; the old admin secret no longer authorises anything.
  await assert.rejects(access.rotateObjectKey(owner.ws, c.objectId, plan.adminCapabilitySecret, plan), (e) => e.reason === 'stale');
  await assert.rejects(access.updateObject(owner.ws, { objectId: c.objectId, adminCapabilitySecret: c.adminCapabilitySecret, keyEpoch: 2, encryptedContent: plan.encryptedContent, selector }), (e) => e.reason === 'unauthorized');
  await assert.rejects(access.deleteObject(owner.ws, c.objectId, c.adminCapabilitySecret), (e) => e.reason === 'unauthorized');
  // Eve's row capability now opens nothing; Bob's write at the old epoch is stale, at the new one fine after he heals his pointer.
  await assert.rejects(access.updateMemberRowMessage(eve.ws, { objectId: c.objectId, rowCapabilitySecret: eveRow.rowCapabilitySecret, encryptedRow: eveRow.encryptedRow, keyEpoch: 1 }), (e) => e.reason === 'unauthorized');
  await assert.rejects(access.updateMemberRowMessage(bob.ws, { objectId: c.objectId, rowCapabilitySecret: bobRow.rowCapabilitySecret, encryptedRow: bobRow.encryptedRow, keyEpoch: 1 }), (e) => e.reason === 'stale');
  const mine = await access.fetchMyRow(bob.ws, c.objectId, bobRow.rowCapabilitySecret);
  assert.equal(mine.keyEpoch, 2);
  const healed = await access.refreshPointerAfterRotation({ identity: bob.identity, objectId: c.objectId, myRow: mine, existingPointer: await access.pointerCodec.open(bob.identity, bobPtr) });
  assert.deepEqual(healed.kObjectRaw, plan.newKObjectRaw);
  const newKey = await cc.importSymmetricKey(healed.kObjectRaw);
  const opened = await ac.openMemberRow(cc, newKey, c.objectId, mine.rowId, mine.encryptedRow);
  const edited = await ac.updateMemberRow(cc, newKey, bob.identity, c.objectId, mine.rowId, { status: 'interested' }, opened.payload);
  await access.updateMemberRowMessage(bob.ws, { objectId: c.objectId, rowCapabilitySecret: bobRow.rowCapabilitySecret, encryptedRow: edited, keyEpoch: 2 });
  // Bob leaves; the owner deletes the object with the new secret.
  assert.equal(await access.deleteMyRow(bob.ws, c.objectId, bobRow.rowCapabilitySecret), true);
  await access.deleteObject(owner.ws, c.objectId, plan.adminCapabilitySecret);
  await assert.rejects(access.fetchObject(owner.ws, c.objectId), (e) => e.reason === 'not-found');
});

test('the display rule over a live roster: verified, quiet and unverified rows', async () => {
  const server = makeServer(); const access = makeAccess();
  const owner = await person(server); const bob = await person(server);
  const c = await publishedObject(server, access, owner);
  const q = await access.buildFirstReaction({ identity: bob.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going', name: 'Bob' }, quiet: true });
  await access.joinObject(bob.ws, { objectId: c.objectId, pointer: q.pointer, row: q.row, readCapabilitySecret: q.readCapabilitySecret });
  // A forged row: Mallory signs with her own key but claims Bob's signing key.
  const mallory = await person(server);
  const forgedIdentity = { ...mallory.identity, identitySigning: { privateKey: mallory.identity.identitySigning.privateKey, publicKeyRaw: bob.identity.identitySigning.publicKeyRaw } };
  const forged = await access.buildMemberRow({ identity: forgedIdentity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going', name: 'Bob' } });
  await access.joinObject(mallory.ws, { objectId: c.objectId, pointer: await access.buildReadOnlyPointer({ identity: mallory.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1 }), row: forged, readCapabilitySecret: c.readCapabilitySecret });
  const rows = await access.fetchMembers(owner.ws, c.objectId, { adminCapabilitySecret: c.adminCapabilitySecret });
  const roster = access.roster(await access.openRows({ kObjectRaw: c.kObjectRaw, objectId: c.objectId, rows }));
  const byId = new Map(roster.map((e) => [e.id, e]));
  assert.equal(byId.get(c.ownerRow.rowId).verified, true);
  assert.equal(byId.get(q.row.rowId).quiet, true); assert.equal(byId.get(q.row.rowId).content.name, 'Bob'); assert.equal(byId.get(q.row.rowId).identitySigningKeyRaw, null);
  const f = byId.get(forged.rowId);
  assert.equal(f.verified, false); assert.equal(f.quiet, false); assert.equal(f.content, null, 'no name, no status, no keys from a forged row');
});
