// Frozen fixtures: the version-2 bytes an earlier version of this package
// wrote (test/tooling/generate-frozen-fixtures.mjs, never regenerated), which
// every later version must open, and whose deterministic parts it must
// reproduce. A changed label, version byte, parameter or layout fails here
// instead of silently making shared objects unreadable. Everything is checked
// through the package's public API; the hybrid cases run through
// crypto-core's test-only platform shim, as crypto-core's own fixtures do.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCryptoCore } from '@microtoll/crypto-core';
import { identityFromRootKey, adoptSealingKey } from '@microtoll/identity';
import { installPqShim } from '../../crypto-core/test/tooling/pq-test-shim.mjs';
import * as ac from '../src/index.js';

const fx = JSON.parse(readFileSync(new URL('./fixtures/frozen-v2.json', import.meta.url), 'utf8'));
const cc = createCryptoCore({ namespace: fx.namespace });
const H = cc.fromHex;
const text = (b) => new TextDecoder().decode(b);
const flip = (hex, at) => { const b = H(hex); b[at] ^= 1; return b; };
const OBJECT_ID = fx.object.objectId;
const EPOCH = fx.object.epoch;
const kObjectKey = () => cc.importSymmetricKey(H(fx.object.kObject));

/** A frozen account: keys derived from the stored root, the stored sealing key adopted, every public key as frozen. */
async function frozenAccount(core, a) {
  const identity = await identityFromRootKey(core, H(a.rootKey));
  await adoptSealingKey(core, identity, { sealingKey: a.sealingKeyJwk });
  assert.equal(core.toHex(identity.identity.publicKeyRaw), a.identityPublicKey);
  assert.equal(core.toHex(identity.identitySigning.publicKeyRaw), a.identitySigningPublicKey);
  assert.equal(core.toHex(identity.routing.publicKeyRaw), a.routingPublicKey);
  return identity;
}
const accounts = async () => ({
  owner: await frozenAccount(cc, fx.accounts.owner),
  member: await frozenAccount(cc, fx.accounts.member),
  quietMember: await frozenAccount(cc, fx.accounts.quietMember),
});

test('every version-2 context and signed message reproduces byte for byte, each under its own label (FORMATS.md §3.1, §3.2)', async () => {
  const { owner, member, quietMember } = await accounts();
  const payloadOf = (envelope) => JSON.parse(envelope).payloadJson;
  const pinned = [
    [fx.labels.content, ac.contentContext(cc, OBJECT_ID, EPOCH), fx.object.contentContext],              // objectId ‖ u32be(epoch)
    [fx.labels.detail, ac.detailContext(cc, OBJECT_ID, EPOCH), fx.object.detailContext],
    [fx.labels.adminBox, ac.adminBoxContext(cc, OBJECT_ID, EPOCH), fx.admin.adminBoxContext],            // still "object-adminbox/v1" (§3.2)
    [fx.labels.memberRow, ac.rowContext(cc, OBJECT_ID, fx.rows.owner.rowId), fx.rows.owner.context],     // objectId ‖ rowId, 16 bytes each
    [fx.labels.memberRow, ac.rowContext(cc, OBJECT_ID, fx.rows.member.rowId), fx.rows.member.context],
    [fx.labels.memberRow, ac.rowContext(cc, OBJECT_ID, fx.rows.quiet.rowId), fx.rows.quiet.context],
    [fx.labels.memberRowSignature, ac.rowSigningMessage(cc, OBJECT_ID, fx.rows.owner.rowId, payloadOf(fx.rows.owner.envelope)), fx.rows.owner.signedMessage],
    [fx.labels.memberRowSignature, ac.rowSigningMessage(cc, OBJECT_ID, fx.rows.member.rowId, payloadOf(fx.rows.member.envelope)), fx.rows.member.signedMessage],
    [fx.labels.pointer, ac.pointerContext(cc, owner.routing.publicKeyRaw), fx.pointers.owner.context],   // the account, not the object (D-37)
    [fx.labels.pointer, ac.pointerContext(cc, member.routing.publicKeyRaw), fx.pointers.member.context],
    [fx.labels.pointer, ac.pointerContext(cc, quietMember.routing.publicKeyRaw), fx.pointers.quietMember.context],
  ];
  for (const link of Object.values(fx.shareLinks)) {
    pinned.push([fx.labels.shareLink, ac.linkContext(cc, link.hashedToken), link.context]);             // hashedToken, 32 bytes
    pinned.push([fx.labels.shareLinkSignature, ac.linkSigningMessage(cc, link.hashedToken, payloadOf(link.envelope)), link.signedMessage]);
  }
  for (const [label, got, frozen] of pinned) {
    assert.equal(cc.toHex(got), frozen);
    // The frame starts with the NUL-terminated purpose label, so no context can be taken for another.
    assert.ok(frozen.startsWith(cc.toHex(new TextEncoder().encode(label)) + '00'), `${label} heads its context`);
  }
  assert.equal(new Set(Object.values(fx.labels)).size, Object.keys(fx.labels).length, 'eight distinct labels');
  assert.deepEqual({
    envelopeSigned: ac.ENVELOPE_SIGNED, envelopeQuiet: ac.ENVELOPE_QUIET,
    adminSeatBucket: ac.ADMIN_SEAT_BUCKET, adminSeatPlaintextBytes: ac.ADMIN_SEAT_PLAINTEXT_BYTES, adminBoxBucketBytes: ac.ADMIN_BOX_BUCKET_BYTES,
    pqKemAdvertMaxAgeMs: ac.PQ_KEM_ADVERT_MAX_AGE_MS,
  }, fx.constants);
});

test('the read capability and every capability hash reproduce', async () => {
  const read = await ac.readCapability(cc, H(fx.object.kObject));
  assert.equal(cc.toHex(read), fx.object.readCapability);
  assert.equal(await ac.hashCapability(cc, read), fx.object.readCapabilityHash);
  assert.equal(await ac.hashCapability(cc, H(fx.admin.adminCapabilitySecret)), fx.admin.adminCapabilityHash);
  for (const row of Object.values(fx.rows)) assert.equal(await ac.hashCapability(cc, H(row.rowCapabilitySecret)), row.rowCapabilityHash);
  for (const link of Object.values(fx.shareLinks)) assert.equal(await ac.hashCapability(cc, H(link.manageSecret)), link.manageCapabilityHash);
});

test('the content and the second tier open under their own object and epoch only; the grants reach the right people (FORMATS.md §3.2)', async () => {
  const { owner, member } = await accounts();
  const key = await kObjectKey();
  const detailKey = await cc.importSymmetricKey(H(fx.object.kDetail));
  assert.deepEqual(await ac.openContent(cc, key, OBJECT_ID, EPOCH, H(fx.object.encryptedContent)), fx.object.preview);
  assert.deepEqual(await ac.openDetail(cc, detailKey, OBJECT_ID, EPOCH, H(fx.object.encryptedDetail)), fx.object.detail);
  await assert.rejects(ac.openContent(cc, key, OBJECT_ID, EPOCH + 1, H(fx.object.encryptedContent)), 'another epoch');
  await assert.rejects(ac.openContent(cc, key, fx.rows.owner.rowId, EPOCH, H(fx.object.encryptedContent)), 'another object');
  await assert.rejects(ac.openDetail(cc, detailKey, OBJECT_ID, EPOCH + 1, H(fx.object.encryptedDetail)), 'another epoch');
  await assert.rejects(ac.openContent(cc, key, OBJECT_ID, EPOCH, flip(fx.object.encryptedContent, 40)), 'a flipped byte');
  // Grant labels: HKDF(K_object, "<ns>/detail-grant/v1" ‖ 0x00 ‖ SHA-256(recipient key)), base64url.
  assert.equal(await ac.detailGrantLabel(cc, H(fx.object.kObject), owner.identity.publicKeyRaw), fx.object.detailGrantLabels.owner);
  assert.equal(await ac.detailGrantLabel(cc, H(fx.object.kObject), member.identity.publicKeyRaw), fx.object.detailGrantLabels.member);
  assert.deepEqual(Object.keys(fx.object.preview.detailGrants).sort(), Object.values(fx.object.detailGrantLabels).sort());
  const view = (viewer) => ac.openForViewer(cc, {
    kObjectRaw: H(fx.object.kObject), objectId: OBJECT_ID, epoch: EPOCH,
    preview: fx.object.preview, encryptedDetail: H(fx.object.encryptedDetail), viewer,
  });
  assert.deepEqual(await view({ identity: member }), { ...fx.object.preview, ...fx.object.detail });
  const stranger = await identityFromRootKey(cc, cc.generateSymmetricKey());
  assert.deepEqual(await view({ identity: stranger }), fx.object.preview, 'no grant: the preview, untouched');
});

test('the admin seats and box: each admin\'s seat opens to the frozen capability and box key; the sizes are the frozen buckets', async () => {
  const { owner, member } = await accounts();
  const expectSeat = (read, admins) => {
    assert.ok(read, 'the seat opens');
    assert.equal(cc.toHex(read.seat.adminCapabilitySecret), fx.admin.adminCapabilitySecret);
    assert.equal(cc.toHex(read.seat.kAdminboxRaw), fx.admin.kAdminbox);
    assert.deepEqual(read.admins, admins);
  };
  expectSeat(await ac.readAdmins(cc, owner, fx.object.preview, OBJECT_ID, EPOCH), fx.admin.admins);
  assert.equal(await ac.readAdmins(cc, member, fx.object.preview, OBJECT_ID, EPOCH), null, 'not an admin');
  assert.equal(await ac.openAdminSeat(cc, owner, fx.object.preview, OBJECT_ID, EPOCH + 1), null, 'the seat names its epoch');
  await assert.rejects(ac.openAdminBox(cc, H(fx.admin.kAdminbox), OBJECT_ID, EPOCH + 1, fx.object.preview.adminBox), 'the box is bound to its epoch');
  // A member counts seats, never admins: a multiple of the bucket, every seat the same size.
  const seatLengths = fx.object.preview.adminSeats.map((s) => cc.fromBase64Url(s).length);
  assert.equal(seatLengths.length, ac.ADMIN_SEAT_BUCKET);
  assert.equal(new Set(seatLengths).size, 1);
  // AEAD v1 of the box padded to its bucket: version byte, 12-byte nonce, 1024 bytes, 16-byte tag.
  assert.equal(cc.fromBase64Url(fx.object.preview.adminBox).length, 1 + 12 + ac.ADMIN_BOX_BUCKET_BYTES + 16);
  // A co-owner: the same capability and box key, a box listing both, a seat each.
  const coOwned = { ...fx.object.preview, ...fx.coOwned };
  const both = [...fx.admin.admins, ac.adminEntryForIdentity(cc, member, fx.rows.member.rowId)];
  expectSeat(await ac.readAdmins(cc, owner, coOwned, OBJECT_ID, EPOCH), both);
  expectSeat(await ac.readAdmins(cc, member, coOwned, OBJECT_ID, EPOCH), both);
  assert.equal(fx.coOwned.adminSeats.length, ac.ADMIN_SEAT_BUCKET);
});

test('the named rows open verified; the envelope inside is the frozen one and its signature reproduces (FORMATS.md §3.1)', async () => {
  const all = await accounts();
  const key = await kObjectKey();
  for (const [who, row] of [['owner', fx.rows.owner], ['member', fx.rows.member]]) {
    const author = all[who];
    const envelope = JSON.parse(row.envelope);
    assert.equal(envelope.v, ac.ENVELOPE_SIGNED);
    assert.equal(text(await cc.openSymmetric(key, H(row.encryptedRow), ac.rowContext(cc, OBJECT_ID, row.rowId))), row.envelope);
    const opened = await ac.openMemberRow(cc, key, OBJECT_ID, row.rowId, H(row.encryptedRow));
    assert.equal(opened.verified, true);
    assert.equal(opened.quiet, false);
    assert.deepEqual(opened.payload, JSON.parse(envelope.payloadJson));
    assert.equal(cc.toHex(opened.identitySigningKeyRaw), cc.toHex(author.identitySigning.publicKeyRaw));
    assert.equal(cc.toHex(opened.sealTargetKeyRaw), cc.toHex(author.identity.publicKeyRaw));
    // Ed25519 is deterministic (RFC 8032 §5.1.6): the author's key over the same bytes gives the same signature.
    const message = ac.rowSigningMessage(cc, OBJECT_ID, row.rowId, envelope.payloadJson);
    assert.equal(cc.toBase64Url(await cc.signBytes(author.identitySigning.privateKey, message)), envelope.sig);
    assert.equal(await cc.verifyBytes(author.identitySigning.publicKeyRaw, message, cc.fromBase64Url(envelope.sig)), true);
    const badSig = cc.fromBase64Url(envelope.sig); badSig[10] ^= 1;
    assert.equal(await cc.verifyBytes(author.identitySigning.publicKeyRaw, message, badSig), false);
    assert.equal(await cc.verifyBytes(author.identitySigning.publicKeyRaw, ac.rowSigningMessage(cc, OBJECT_ID, fx.rows.quiet.rowId, envelope.payloadJson), cc.fromBase64Url(envelope.sig)), false, 'lifted to another row id');
    await assert.rejects(ac.openMemberRow(cc, key, OBJECT_ID, fx.rows.quiet.rowId, H(row.encryptedRow)), 'presented under another row id');
    await assert.rejects(ac.openMemberRow(cc, key, OBJECT_ID, row.rowId, flip(row.encryptedRow, 40)), 'a flipped byte');
    const { kObjectRaw } = await ac.unwrapObjectKey(cc, author.identity, H(row.encryptedObjectKey));
    assert.equal(cc.toHex(kObjectRaw), fx.object.kObject);
    assert.equal(H(row.encryptedObjectKey)[0], cc.ECIES_VERSION_3);
    assert.equal(ac.rosterEntry(row.rowId, EPOCH, opened).verified, true);
  }
});

test('the quiet row opens quiet and unsigned; the rotation key its pointer keeps unwraps K_object', async () => {
  const q = fx.rows.quiet;
  const key = await kObjectKey();
  assert.equal(JSON.parse(q.envelope).v, ac.ENVELOPE_QUIET);
  assert.equal('sig' in JSON.parse(q.envelope), false);
  assert.equal(text(await cc.openSymmetric(key, H(q.encryptedRow), ac.rowContext(cc, OBJECT_ID, q.rowId))), q.envelope);
  const opened = await ac.openMemberRow(cc, key, OBJECT_ID, q.rowId, H(q.encryptedRow));
  assert.equal(opened.quiet, true);
  assert.equal(opened.verified, false);
  assert.equal(opened.identityPublicKeyRaw, null);
  assert.equal(cc.toHex(opened.rotationPublicKeyRaw), q.rotationPublicKey);
  assert.equal(cc.toHex(opened.sealTargetKeyRaw), q.rotationPublicKey);
  const rotationKeys = await ac.quietRotationKeys(cc, q.quietRotationKey, null);
  assert.equal(cc.toHex((await ac.unwrapObjectKey(cc, rotationKeys, H(q.encryptedObjectKey))).kObjectRaw), fx.object.kObject);
  const entry = ac.rosterEntry(q.rowId, EPOCH, opened);
  assert.equal(entry.quiet, true);
  assert.equal(entry.identitySigningKeyRaw, null);
});

test('the pointers open for their own account only, and carry the frozen wire keys (FORMATS.md §3.2)', async () => {
  const all = await accounts();
  const codec = ac.createPointerCodec(cc, { myStatus: { wire: fx.pointers.extension.myStatus.wire, ...ac.oneOf(fx.pointers.extension.myStatus.oneOf) } });
  // The core wire keys are frozen (pointer.js, coreFields); the app's key follows them.
  assert.deepEqual(Object.values(ac.coreFields(cc)).map((f) => f.wire), fx.pointers.coreWireKeys);
  const b = (hexOrNull) => (hexOrNull === null ? null : cc.toHex(hexOrNull));
  for (const who of ['owner', 'member', 'quietMember']) {
    const p = fx.pointers[who];
    const identity = all[who];
    assert.equal(text(await cc.openSymmetric(identity.masterSymmKey, H(p.sealed), ac.pointerContext(cc, identity.routing.publicKeyRaw))), p.plaintext);
    const raw = JSON.parse(p.plaintext);
    assert.deepEqual(Object.keys(raw), [...fx.pointers.coreWireKeys, 'myStatus']);
    const opened = await codec.open(identity, H(p.sealed));
    assert.equal(opened.objectId, OBJECT_ID);
    assert.equal(cc.toHex(opened.kObject), fx.object.kObject);
    assert.equal(opened.keyEpoch, EPOCH);
    assert.equal(b(opened.rowCapabilitySecret), fx.rows[who === 'quietMember' ? 'quiet' : who].rowCapabilitySecret);
    assert.equal(b(opened.adminCapabilitySecret), who === 'owner' ? fx.admin.adminCapabilitySecret : null);
    assert.deepEqual(opened.sharedLinks, raw.sharedLinks);
    assert.deepEqual(opened.invitedBy, raw.invitedBy);
    assert.deepEqual(opened.quietRotationKey, who === 'quietMember' ? fx.rows.quiet.quietRotationKey : null);
    assert.equal(opened.quietRotationKemSeed, null);
    assert.equal(opened.myStatus, raw.myStatus);
    await assert.rejects(codec.open(all[who === 'owner' ? 'member' : 'owner'], H(p.sealed)), 'moved to another account');
    await assert.rejects(codec.open(identity, flip(p.sealed, 40)), 'a flipped byte');
  }
  assert.deepEqual(JSON.parse(fx.pointers.owner.plaintext).sharedLinks, [fx.shareLinks.signed.record]);
});

test('the share links redeem from the token alone; the signed one verifies and its signature reproduces (FORMATS.md §3.1, §3.2)', async () => {
  const { owner } = await accounts();
  const { signed, unsigned } = fx.shareLinks;
  for (const link of [signed, unsigned]) {
    assert.equal(await ac.hashToken(cc, link.token), link.hashedToken);
    assert.equal(ac.tokenFromFragment(`#token=${link.token}`), link.token);
    const envelope = JSON.parse(link.envelope);
    assert.equal(envelope.v, 2);
    const payload = JSON.parse(envelope.payloadJson);
    const redeemed = await ac.redeemShareLink(cc, link.token, H(link.encryptedPayload));
    assert.equal(redeemed.objectId, payload.objectId);
    assert.equal(redeemed.objectId, OBJECT_ID);
    assert.equal(cc.toHex(redeemed.kObjectRaw), fx.object.kObject);
    assert.equal(cc.toBase64Url(redeemed.kObjectRaw), payload.kObject);
    await assert.rejects(ac.redeemShareLink(cc, link.token, flip(link.encryptedPayload, 40)), 'a flipped byte');
    assert.deepEqual(ac.normaliseLinkRecords([link.record])[0], { ...link.record, manageable: true, shareable: true });
  }
  // Signed: the creator is recognised, and Ed25519 reproduces the signature over the frozen message.
  const redeemed = await ac.redeemShareLink(cc, signed.token, H(signed.encryptedPayload));
  assert.equal(redeemed.verified, true);
  assert.equal(redeemed.creatorName, 'Ada');
  assert.equal(cc.toHex(redeemed.creatorSigningKeyRaw), fx.accounts.owner.identitySigningPublicKey);
  const { payloadJson, sig } = JSON.parse(signed.envelope);
  assert.equal(cc.toBase64Url(await cc.signBytes(owner.identitySigning.privateKey, ac.linkSigningMessage(cc, signed.hashedToken, payloadJson))), sig);
  assert.equal(await cc.verifyBytes(owner.identitySigning.publicKeyRaw, ac.linkSigningMessage(cc, unsigned.hashedToken, payloadJson), cc.fromBase64Url(sig)), false, 'lifted into another link');
  // Unsigned: usable, and nobody's.
  const anonymous = await ac.redeemShareLink(cc, unsigned.token, H(unsigned.encryptedPayload));
  assert.equal(anonymous.verified, false);
  assert.equal(anonymous.creatorName, null);
  assert.equal(JSON.parse(unsigned.envelope).sig, null);
  // One link's payload under another link's token: the key and the context both refuse it.
  await assert.rejects(ac.redeemShareLink(cc, unsigned.token, H(signed.encryptedPayload)));
});

test('hybrid: the rows, the object key, the admin seat and the grant sealed to the KEM key still open (through the test shim)', async () => {
  const uninstall = installPqShim();
  try {
    const pq = createCryptoCore({ namespace: fx.namespace, hybridSealing: true });
    const h = fx.hybrid;
    const me = await frozenAccount(pq, h.account);
    assert.equal(pq.toHex(me.identityKem.publicKeyRaw), h.account.identityKemPublicKey, 'the KEM key derived from the root');
    const key = await kObjectKey();

    // A named row advertising the KEM key, dated; after PQ_KEM_ADVERT_MAX_AGE_MS the advert is stale and the classical key is the target.
    const envelope = JSON.parse(h.row.envelope);
    const payload = JSON.parse(envelope.payloadJson);
    assert.equal(pq.toHex(pq.fromBase64Url(payload.identityKemKey)), h.account.identityKemPublicKey);
    const advertised = Date.parse(payload.identityKemKeyAt);
    const fresh = await ac.openMemberRow(pq, key, OBJECT_ID, h.row.rowId, H(h.row.encryptedRow), advertised);
    assert.equal(fresh.verified, true);
    assert.equal(pq.toHex(fresh.identityKemKeyRaw), h.account.identityKemPublicKey);
    assert.equal(pq.toHex(fresh.sealTargetKeyRaw), h.account.identityKemPublicKey);
    const stale = await ac.openMemberRow(pq, key, OBJECT_ID, h.row.rowId, H(h.row.encryptedRow), advertised + ac.PQ_KEM_ADVERT_MAX_AGE_MS + 1);
    assert.equal(stale.identityKemKeyRaw, null);
    assert.equal(pq.toHex(stale.sealTargetKeyRaw), h.account.identityPublicKey);
    const message = ac.rowSigningMessage(pq, OBJECT_ID, h.row.rowId, envelope.payloadJson);
    assert.equal(pq.toHex(message), h.row.signedMessage);
    assert.equal(pq.toBase64Url(await pq.signBytes(me.identitySigning.privateKey, message)), envelope.sig);
    assert.equal(H(h.row.encryptedObjectKey)[0], pq.ECIES_VERSION_2);
    const both = { classical: me.identity, kem: me.identityKem.privateKey };
    assert.equal(pq.toHex((await ac.unwrapObjectKey(pq, both, H(h.row.encryptedObjectKey))).kObjectRaw), fx.object.kObject);
    await assert.rejects(ac.unwrapObjectKey(pq, me.identity, H(h.row.encryptedObjectKey)), (e) => e.code === 'pq-key-unavailable');

    // A quiet row with a hybrid rotation key, which comes first as the seal target.
    const quiet = await ac.openMemberRow(pq, key, OBJECT_ID, h.quietRow.rowId, H(h.quietRow.encryptedRow));
    assert.equal(quiet.quiet, true);
    assert.equal(pq.toHex(quiet.sealTargetKeyRaw), h.quietRow.rotationKemPublicKey);
    assert.equal(text(await pq.openSymmetric(key, H(h.quietRow.encryptedRow), ac.rowContext(pq, OBJECT_ID, h.quietRow.rowId))), h.quietRow.envelope);
    const rotationKeys = await ac.quietRotationKeys(pq, h.quietRow.quietRotationKey, H(h.quietRow.quietRotationKemSeed));
    assert.equal(pq.toHex((await ac.unwrapObjectKey(pq, rotationKeys, H(h.quietRow.encryptedObjectKey))).kObjectRaw), fx.object.kObject);

    // The admin seat sealed to the KEM key, and the box that lists the KEM key.
    const read = await ac.readAdmins(pq, me, h.admin, OBJECT_ID, EPOCH);
    assert.ok(read, 'the hybrid seat opens');
    assert.equal(pq.toHex(read.seat.adminCapabilitySecret), fx.admin.adminCapabilitySecret);
    assert.equal(pq.toHex(read.seat.kAdminboxRaw), fx.admin.kAdminbox);
    assert.deepEqual(read.admins, h.admin.admins);

    // The grant sealed to the KEM key.
    assert.equal(await ac.detailGrantLabel(pq, H(fx.object.kObject), me.identityKem.publicKeyRaw), h.detailGrantLabel);
    assert.deepEqual(Object.keys(h.detailGrants), [h.detailGrantLabel]);
    assert.equal(pq.toHex(await ac.openDetailGrant(pq, H(fx.object.kObject), h.detailGrants, ac.identityGrantKeys(me))), fx.object.kDetail);
  } finally {
    uninstall();
  }
});
