import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity } from '@microtoll/identity';
import * as ac from '../src/index.js';
import { cc } from './helpers.mjs';

const objectId = '11111111-2222-4333-8444-555555555555';

test('a new object carries one seat for its owner, padded to four; the owner opens it, nobody else does; the box lists only the owner', async () => {
  const owner = await createIdentity(cc); const other = await createIdentity(cc);
  const adminCapabilitySecret = cc.randomBytes(32);
  const block = await ac.newAdminBlock(cc, owner, { objectId, epoch: 1, adminCapabilitySecret });
  assert.equal(block.adminSeats.length, ac.ADMIN_SEAT_BUCKET);
  const seat = await ac.openAdminSeat(cc, owner, block, objectId, 1);
  assert.deepEqual(seat.adminCapabilitySecret, adminCapabilitySecret);
  assert.equal(await ac.openAdminSeat(cc, other, block, objectId, 1), null);
  assert.equal(await ac.openAdminSeat(cc, owner, block, objectId, 2), null, 'another epoch');
  const read = await ac.readAdmins(cc, owner, block, objectId, 1);
  assert.equal(read.admins.length, 1);
  assert.equal(read.admins[0].signingKey, cc.toBase64Url(owner.identitySigning.publicKeyRaw));
  // Every seat is a real seal of the same length, so a member counts seats and never admins.
  const lengths = new Set(block.adminSeats.map((s) => cc.fromBase64Url(s).length));
  assert.equal(lengths.size, 1);
});

test('addCoOwner gives the grantee a seat with the SAME capability; a second grant changes nothing; a stale capability is refused', async () => {
  const owner = await createIdentity(cc); const co = await createIdentity(cc);
  const adminCapabilitySecret = cc.randomBytes(32);
  const content = await ac.newAdminBlock(cc, owner, { objectId, epoch: 1, adminCapabilitySecret });
  const grantee = ac.adminEntryForIdentity(cc, co, null);
  const r = await ac.addCoOwner(cc, owner, content, { objectId, epoch: 1, adminCapabilitySecret, grantee });
  assert.equal(r.added, true);
  const next = { adminSeats: r.adminSeats, adminBox: r.adminBox };
  assert.deepEqual((await ac.openAdminSeat(cc, co, next, objectId, 1)).adminCapabilitySecret, adminCapabilitySecret);
  assert.equal((await ac.readAdmins(cc, co, next, objectId, 1)).admins.length, 2);
  assert.equal((await ac.addCoOwner(cc, owner, next, { objectId, epoch: 1, adminCapabilitySecret, grantee })).added, false);
  await assert.rejects(ac.addCoOwner(cc, owner, next, { objectId, epoch: 1, adminCapabilitySecret: cc.randomBytes(32), grantee }), (e) => e.code === 'stale');
});

test('the admin box context and the seat plaintext size are frozen; malformed entries are refused', async () => {
  const ctx = ac.adminBoxContext(cc, objectId, 7);
  assert.equal(cc.toHex(ctx), cc.toHex(cc.concatBytes(new TextEncoder().encode('example/object-adminbox/v1'), new Uint8Array([0]), cc.uuidBytes(objectId), cc.u32be(7))));
  assert.equal(ac.ADMIN_SEAT_PLAINTEXT_BYTES, 256); assert.equal(ac.ADMIN_BOX_BUCKET_BYTES, 1024);
  assert.throws(() => ac.checkAdminEntry(cc, { signingKey: 'short', identityPublicKey: cc.toBase64Url(cc.randomBytes(65)), rowId: null }), /signingKey/);
  assert.throws(() => ac.checkAdminEntry(cc, { signingKey: cc.toBase64Url(cc.randomBytes(32)), identityPublicKey: cc.toBase64Url(cc.randomBytes(65)), rowId: 'nope' }), /rowId/);
});
