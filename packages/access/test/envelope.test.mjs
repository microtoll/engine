// Member rows (v2): the signed envelope, the quiet row, the binding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity } from '@microtoll/identity';
import * as ac from '../src/index.js';
import { cc } from './helpers.mjs';

const objectId = '11111111-2222-4333-8444-555555555555';
const rowId = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const otherRow = 'aaaaaaaa-bbbb-4ccc-8ddd-000000000000';
const otherObject = '11111111-2222-4333-8444-000000000000';

test('a named row round-trips, verifies, and carries the author\'s two public keys', async () => {
  const me = await createIdentity(cc);
  const kRaw = cc.generateSymmetricKey(); const k = await cc.importSymmetricKey(kRaw);
  const sealed = await ac.sealMemberRow(cc, k, me, objectId, rowId, { status: 'going', name: 'Ada' });
  const opened = await ac.openMemberRow(cc, k, objectId, rowId, sealed);
  assert.equal(opened.verified, true);
  assert.equal(opened.quiet, false);
  assert.equal(opened.payload.status, 'going');
  assert.equal(cc.toHex(opened.identitySigningKeyRaw), cc.toHex(me.identitySigning.publicKeyRaw));
  assert.equal(cc.toHex(opened.identityPublicKeyRaw), cc.toHex(me.identity.publicKeyRaw));
  assert.equal(cc.toHex(opened.sealTargetKeyRaw), cc.toHex(me.identity.publicKeyRaw));
});

test('the signature is bound to the object and row: a row lifted elsewhere is unverified; a flipped bit is unverified', async () => {
  const me = await createIdentity(cc);
  const kRaw = cc.generateSymmetricKey(); const k = await cc.importSymmetricKey(kRaw);
  const sealed = await ac.sealMemberRow(cc, k, me, objectId, rowId, { status: 'going' });
  // Same key, same object, different row id: the AAD refuses the ciphertext outright.
  await assert.rejects(ac.openMemberRow(cc, k, objectId, otherRow, sealed));
  await assert.rejects(ac.openMemberRow(cc, k, otherObject, rowId, sealed));
  // Re-seal the inner envelope under another row id (a server cannot; a malicious co-holder of K could): the signature fails.
  const inner = await cc.openSymmetric(k, sealed, ac.rowContext(cc, objectId, rowId));
  const lifted = await cc.sealSymmetric(k, inner, ac.rowContext(cc, objectId, otherRow));
  const opened = await ac.openMemberRow(cc, k, objectId, otherRow, lifted);
  assert.equal(opened.verified, false);
  assert.equal(opened.signed, true);
  const env = JSON.parse(new TextDecoder().decode(inner));
  const sig = cc.fromBase64Url(env.sig); sig[10] ^= 1;
  const flipped = await cc.sealSymmetric(k, new TextEncoder().encode(JSON.stringify({ ...env, sig: cc.toBase64Url(sig) })), ac.rowContext(cc, objectId, rowId));
  assert.equal((await ac.openMemberRow(cc, k, objectId, rowId, flipped)).verified, false);
});

test('a member cannot impersonate another by copying their signing key into their own row', async () => {
  const alice = await createIdentity(cc); const mallory = await createIdentity(cc);
  const kRaw = cc.generateSymmetricKey(); const k = await cc.importSymmetricKey(kRaw);
  const forged = { ...mallory, identitySigning: { privateKey: mallory.identitySigning.privateKey, publicKeyRaw: alice.identitySigning.publicKeyRaw } };
  const sealed = await ac.sealMemberRow(cc, k, forged, objectId, rowId, { name: 'Alice' });
  const opened = await ac.openMemberRow(cc, k, objectId, rowId, sealed);
  assert.equal(opened.verified, false);
  assert.equal(ac.rosterEntry(rowId, 1, opened).content, null, 'the display rule shows nothing');
});

test('a quiet row names nobody, is never verified, and is never rendered as unverified; identity claims inside it do not count', async () => {
  const kRaw = cc.generateSymmetricKey(); const k = await cc.importSymmetricKey(kRaw);
  const keys = await ac.generateQuietRotationKeys(cc);
  const sealed = await ac.sealQuietMemberRow(cc, k, objectId, rowId, keys.publicKeyRaw, { status: 'going', identitySigningKey: 'claimed', name: 'x' });
  const opened = await ac.openMemberRow(cc, k, objectId, rowId, sealed);
  assert.equal(opened.quiet, true);
  assert.equal(opened.verified, false);
  assert.equal(opened.identitySigningKeyRaw, null);
  assert.equal(cc.toHex(opened.rotationPublicKeyRaw), cc.toHex(keys.publicKeyRaw));
  assert.equal(cc.toHex(opened.sealTargetKeyRaw), cc.toHex(keys.publicKeyRaw));
  const entry = ac.rosterEntry(rowId, 1, opened);
  assert.equal(entry.quiet, true); assert.equal(entry.content.status, 'going'); assert.equal(entry.identitySigningKeyRaw, null);
  await assert.rejects(ac.sealQuietMemberRow(cc, k, objectId, rowId, new Uint8Array(32), {}), /rotation key/);
});

test('resealing under a new key keeps the signature; an edit re-signs; a quiet row stays quiet through edits', async () => {
  const me = await createIdentity(cc);
  const k1 = await cc.importSymmetricKey(cc.generateSymmetricKey()); const k2 = await cc.importSymmetricKey(cc.generateSymmetricKey());
  const sealed = await ac.sealMemberRow(cc, k1, me, objectId, rowId, { status: 'going' });
  const moved = await ac.resealMemberRow(cc, k1, k2, objectId, rowId, sealed);
  assert.equal((await ac.openMemberRow(cc, k2, objectId, rowId, moved)).verified, true);
  await assert.rejects(ac.openMemberRow(cc, k1, objectId, rowId, moved));
  const prev = (await ac.openMemberRow(cc, k1, objectId, rowId, sealed)).payload;
  const edited = await ac.updateMemberRow(cc, k1, me, objectId, rowId, { status: 'interested' }, prev);
  const o = await ac.openMemberRow(cc, k1, objectId, rowId, edited);
  assert.equal(o.verified, true); assert.equal(o.payload.status, 'interested');
  const keys = await ac.generateQuietRotationKeys(cc);
  const quiet = await ac.sealQuietMemberRow(cc, k1, objectId, rowId, keys.publicKeyRaw, { status: 'going' });
  const qprev = (await ac.openMemberRow(cc, k1, objectId, rowId, quiet)).payload;
  const qedited = await ac.updateMemberRow(cc, k1, me, objectId, rowId, { status: 'not going' }, qprev);
  assert.equal((await ac.openMemberRow(cc, k1, objectId, rowId, qedited)).quiet, true);
  const named = await ac.updateMemberRow(cc, k1, me, objectId, rowId, {}, qprev, { becomeNamed: true });
  const n = await ac.openMemberRow(cc, k1, objectId, rowId, named);
  assert.equal(n.verified, true);
  assert.equal(cc.toHex(n.sealTargetKeyRaw), cc.toHex(keys.publicKeyRaw), 'the rotation key is still preferred until the next rotation');
});

test('chooseMemberSealTarget: quiet keys first, a fresh hybrid key before classical, a stale one treated as absent', () => {
  const p256 = cc.toBase64Url(cc.randomBytes(65)); const kem = cc.toBase64Url(cc.randomBytes(1216));
  const rot = cc.toBase64Url(cc.randomBytes(65)); const rotKem = cc.toBase64Url(cc.randomBytes(1216));
  const now = Date.parse('2026-09-25');
  assert.equal(cc.toBase64Url(ac.chooseMemberSealTarget(cc, { rotationPublicKey: rot, rotationKemPublicKey: rotKem, identityPublicKey: p256 }, now)), rotKem);
  assert.equal(cc.toBase64Url(ac.chooseMemberSealTarget(cc, { rotationPublicKey: rot, identityPublicKey: p256 }, now)), rot);
  assert.equal(cc.toBase64Url(ac.chooseMemberSealTarget(cc, { identityPublicKey: p256, identityKemKey: kem, identityKemKeyAt: '2026-09-01' }, now)), kem);
  assert.equal(cc.toBase64Url(ac.chooseMemberSealTarget(cc, { identityPublicKey: p256, identityKemKey: kem, identityKemKeyAt: '2026-01-01' }, now)), p256, 'stale');
  assert.equal(cc.toBase64Url(ac.chooseMemberSealTarget(cc, { identityPublicKey: p256, identityKemKey: kem }, now)), p256, 'undated is stale');
  assert.throws(() => ac.chooseMemberSealTarget(cc, {}), /no key/);
});

test('the signing message and row context are frozen (change-detectors)', () => {
  const m = ac.rowSigningMessage(cc, objectId, rowId, '{"a":1}');
  const expected = cc.concatBytes(new TextEncoder().encode('example/sig/member-row/v2'), new Uint8Array([0]), cc.uuidBytes(objectId), cc.uuidBytes(rowId), new TextEncoder().encode('{"a":1}'));
  assert.equal(cc.toHex(m), cc.toHex(expected));
  const ctx = ac.rowContext(cc, objectId, rowId);
  assert.equal(cc.toHex(ctx), cc.toHex(cc.concatBytes(new TextEncoder().encode('example/aad/member-row/v2'), new Uint8Array([0]), cc.uuidBytes(objectId), cc.uuidBytes(rowId))));
});
