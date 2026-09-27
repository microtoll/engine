// Removal, without a server: what a plan carries, what it sets aside, and who
// can read what afterwards.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity } from '@microtoll/identity';
import * as ac from '../src/index.js';
import { cc, makeAccess } from './helpers.mjs';

async function room({ twoTier = false } = {}) {
  const access = makeAccess();
  const owner = await createIdentity(cc); const bob = await createIdentity(cc); const eve = await createIdentity(cc);
  const c = await access.createObject({ identity: owner, content: { title: 'x', address: 'A' }, ownerRowContent: { status: 'going' }, twoTier });
  const kObjectKey = await cc.importSymmetricKey(c.kObjectRaw);
  const bobRow = await access.buildMemberRow({ identity: bob, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  const eveRow = await access.buildMemberRow({ identity: eve, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  const quiet = await access.buildQuietMemberRow({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  const rows = [c.ownerRow, bobRow, eveRow, quiet.row].map((r) => ({ rowId: r.rowId, keyEpoch: 1, encryptedRow: r.encryptedRow, encryptedObjectKey: r.encryptedObjectKey }));
  const preview = await ac.openContent(cc, kObjectKey, c.objectId, 1, c.encryptedContent);
  let content = preview;
  if (twoTier) content = await access.openForViewer({ kObjectRaw: c.kObjectRaw, objectId: c.objectId, epoch: 1, preview, encryptedDetail: c.encryptedDetail, viewer: { identity: owner } });
  return { access, owner, bob, eve, quiet, c, rows, content, bobRow, eveRow };
}

test('removing Eve: Bob and the quiet member get the new key, Eve does not, the read capability and admin capability change', async () => {
  const r = await room();
  const plan = await r.access.buildRotationPlan({ objectId: r.c.objectId, identity: r.owner, oldKObjectRaw: r.c.kObjectRaw, oldEpoch: 1, content: r.content, rows: r.rows, remove: [r.eveRow.rowId], selfRowId: r.c.ownerRow.rowId });
  assert.equal(plan.newEpoch, 2); assert.equal(plan.expectedEpoch, 1);
  assert.deepEqual(plan.removedRowIds, [r.eveRow.rowId]); assert.deepEqual(plan.setAside, []);
  assert.equal(plan.updates.length, 3);
  const forBob = plan.updates.find((u) => u.rowId === r.bobRow.rowId);
  const { kObjectRaw } = await ac.unwrapObjectKey(cc, r.bob.identity, forBob.encryptedObjectKey);
  assert.deepEqual(kObjectRaw, plan.newKObjectRaw);
  const newKey = await cc.importSymmetricKey(plan.newKObjectRaw);
  assert.equal((await ac.openMemberRow(cc, newKey, r.c.objectId, r.bobRow.rowId, forBob.encryptedRow)).verified, true, 'Bob\'s signature survived');
  const forQuiet = plan.updates.find((u) => u.rowId === r.quiet.row.rowId);
  const q = await ac.unwrapObjectKey(cc, await ac.quietRotationKeys(cc, r.quiet.quietRotationKey, r.quiet.quietRotationKemSeed), forQuiet.encryptedObjectKey);
  assert.deepEqual(q.kObjectRaw, plan.newKObjectRaw);
  for (const u of plan.updates) await assert.rejects(ac.unwrapObjectKey(cc, r.eve.identity, u.encryptedObjectKey), 'Eve cannot unwrap any new copy');
  const oldKey = await cc.importSymmetricKey(r.c.kObjectRaw);
  await assert.rejects(ac.openContent(cc, oldKey, r.c.objectId, 2, plan.encryptedContent), 'the old key does not open the new content');
  assert.notEqual(plan.readCapabilityHash, r.c.readCapabilityHash);
  assert.notEqual(plan.adminCapabilityHash, r.c.adminCapabilityHash);
  const newContent = await ac.openContent(cc, newKey, r.c.objectId, 2, plan.encryptedContent);
  assert.deepEqual((await ac.openAdminSeat(cc, r.owner, newContent, r.c.objectId, 2)).adminCapabilitySecret, plan.adminCapabilitySecret);
  assert.equal(await ac.openAdminSeat(cc, r.eve, newContent, r.c.objectId, 2), null);
});

test('a removed co-owner gets no new seat; a co-owner who stays does', async () => {
  const r = await room();
  const kObjectKey = await cc.importSymmetricKey(r.c.kObjectRaw);
  const bobEntry = ac.adminEntryForIdentity(cc, r.bob, r.bobRow.rowId); const eveEntry = ac.adminEntryForIdentity(cc, r.eve, r.eveRow.rowId);
  let content = r.content;
  for (const g of [bobEntry, eveEntry]) {
    const g2 = await ac.addCoOwner(cc, r.owner, content, { objectId: r.c.objectId, epoch: 1, adminCapabilitySecret: r.c.adminCapabilitySecret, grantee: g, selfRowId: r.c.ownerRow.rowId });
    content = { ...content, adminSeats: g2.adminSeats, adminBox: g2.adminBox };
  }
  assert.equal((await ac.readAdmins(cc, r.eve, content, r.c.objectId, 1)).admins.length, 3);
  const plan = await r.access.buildRotationPlan({ objectId: r.c.objectId, identity: r.owner, oldKObjectRaw: r.c.kObjectRaw, oldEpoch: 1, content, rows: r.rows, remove: [r.eveRow.rowId], selfRowId: r.c.ownerRow.rowId });
  assert.equal(plan.admins, 2);
  const newContent = await ac.openContent(cc, await cc.importSymmetricKey(plan.newKObjectRaw), r.c.objectId, 2, plan.encryptedContent);
  assert.deepEqual((await ac.openAdminSeat(cc, r.bob, newContent, r.c.objectId, 2)).adminCapabilitySecret, plan.adminCapabilitySecret);
  assert.equal(await ac.openAdminSeat(cc, r.eve, newContent, r.c.objectId, 2), null);
  void kObjectKey;
});

test('rows that cannot have come from an honest client are set aside and never sealed to; the rotator\'s own bad row stops everything', async () => {
  const r = await room();
  const kObjectKey = await cc.importSymmetricKey(r.c.kObjectRaw);
  // Eve's old signed row presented under Bob's row id (a server substitution).
  const eveInner = await cc.openSymmetric(kObjectKey, r.eveRow.encryptedRow, ac.rowContext(cc, r.c.objectId, r.eveRow.rowId));
  const substituted = await cc.sealSymmetric(kObjectKey, eveInner, ac.rowContext(cc, r.c.objectId, r.bobRow.rowId));
  // A named envelope with its signature stripped.
  const bobEnv = JSON.parse(new TextDecoder().decode(await cc.openSymmetric(kObjectKey, r.bobRow.encryptedRow, ac.rowContext(cc, r.c.objectId, r.bobRow.rowId))));
  const strippedId = '99999999-9999-4999-8999-999999999999';
  const stripped = await cc.sealSymmetric(kObjectKey, new TextEncoder().encode(JSON.stringify({ v: 3, payloadJson: bobEnv.payloadJson })), ac.rowContext(cc, r.c.objectId, strippedId));
  const unreadableId = '88888888-8888-4888-8888-888888888888';
  const rows = [
    r.rows[0], // owner
    { rowId: r.bobRow.rowId, keyEpoch: 1, encryptedRow: substituted },
    { rowId: strippedId, keyEpoch: 1, encryptedRow: stripped },
    { rowId: unreadableId, keyEpoch: 1, encryptedRow: cc.randomBytes(80) },
    r.rows[3], // quiet
  ];
  const plan = await r.access.buildRotationPlan({ objectId: r.c.objectId, identity: r.owner, oldKObjectRaw: r.c.kObjectRaw, oldEpoch: 1, content: r.content, rows, selfRowId: r.c.ownerRow.rowId });
  assert.deepEqual(plan.setAside.map((s) => s.reason).sort(), ['bad-signature', 'unreadable', 'unsigned-envelope']);
  assert.deepEqual(plan.updates.map((u) => u.rowId).sort(), [r.c.ownerRow.rowId, r.quiet.row.rowId].sort(), 'the quiet row is carried; the three are not');
  for (const u of plan.updates) await assert.rejects(ac.unwrapObjectKey(cc, r.eve.identity, u.encryptedObjectKey), 'the new key never reaches Eve');
  assert.ok(plan.removedRowIds.includes(r.bobRow.rowId) && plan.removedRowIds.includes(strippedId) && plan.removedRowIds.includes(unreadableId));
  await assert.rejects(r.access.buildRotationPlan({ objectId: r.c.objectId, identity: r.owner, oldKObjectRaw: r.c.kObjectRaw, oldEpoch: 1, content: r.content, rows: [{ rowId: r.c.ownerRow.rowId, keyEpoch: 1, encryptedRow: cc.randomBytes(80) }], selfRowId: r.c.ownerRow.rowId }), (e) => e.code === 'rotation-self-set-aside');
});

test('two-tier: after a removal only the owner, admins, "going" rows and earlier grant holders open the new address; a preview-only device cannot rotate', async () => {
  const r = await room({ twoTier: true });
  const interested = await createIdentity(cc);
  const iRow = await r.access.buildMemberRow({ identity: interested, objectId: r.c.objectId, kObjectRaw: r.c.kObjectRaw, keyEpoch: 1, content: { status: 'interested' } });
  const rows = [...r.rows, { rowId: iRow.rowId, keyEpoch: 1, encryptedRow: iRow.encryptedRow }];
  const plan = await r.access.buildRotationPlan({ objectId: r.c.objectId, identity: r.owner, oldKObjectRaw: r.c.kObjectRaw, oldEpoch: 1, content: r.content, rows, remove: [r.eveRow.rowId], selfRowId: r.c.ownerRow.rowId, twoTier: { detailOpened: true } });
  assert.ok(plan.encryptedDetail && plan.newKDetailRaw);
  const newKey = await cc.importSymmetricKey(plan.newKObjectRaw);
  const preview = await ac.openContent(cc, newKey, r.c.objectId, 2, plan.encryptedContent);
  const sees = async (viewer) => (await r.access.openForViewer({ kObjectRaw: plan.newKObjectRaw, objectId: r.c.objectId, epoch: 2, preview, encryptedDetail: plan.encryptedDetail, viewer })).address;
  assert.equal(await sees({ identity: r.owner }), 'A');
  assert.equal(await sees({ identity: r.bob }), 'A', 'going');
  assert.equal(await sees({ quietRotationKey: r.quiet.quietRotationKey, quietRotationKemSeed: r.quiet.quietRotationKemSeed }), 'A', 'quiet going');
  assert.equal(await sees({ identity: interested }), undefined, 'interested');
  assert.equal(await sees({ identity: r.eve }), undefined, 'removed');
  // Eve held the old K_detail: the old detail no longer exists under the new epoch's context, and the new one she cannot open.
  await assert.rejects(ac.openDetail(cc, await cc.importSymmetricKey(r.c.kDetailRaw), r.c.objectId, 2, plan.encryptedDetail));
  await assert.rejects(r.access.buildRotationPlan({ objectId: r.c.objectId, identity: r.owner, oldKObjectRaw: r.c.kObjectRaw, oldEpoch: 1, content: r.content, rows, twoTier: { detailOpened: false } }), (e) => e.code === 'rotation-needs-detail');
});
