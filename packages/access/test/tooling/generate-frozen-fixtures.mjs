// Writes test/fixtures/frozen-v2.json ONCE, and then never again.
//
//   node packages/access/test/tooling/generate-frozen-fixtures.mjs
//
// The file holds the version-2 bytes this package wrote (FORMATS.md §3), under
// the test namespace "example": every later version must open them and
// reproduce every deterministic value in them, so a changed label, version
// byte, parameter or layout turns test/fixtures.test.mjs red instead of
// silently making shared objects unreadable. It refuses to overwrite the
// file. A NEW format gets a new entry beside the old ones (or a new file),
// never a regenerated one.
//
// The object is assembled from the same exported parts createObject uses,
// with fixed ids, keys and capability secrets, so every context and every
// signature in the file is reproducible. The sealing keys are generated (they
// are never derived) and stored as JWKs; random AEAD nonces and ECIES
// ephemeral keys stay random, and those blobs are stored and must open. The
// hybrid section goes through crypto-core's test-only platform shim, as
// crypto-core's own frozen fixtures do. Every key in the file is a throwaway
// made for it.
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import { identityFromRootKey, adoptSealingKey } from '@microtoll/identity';
import { installPqShim } from '../../../crypto-core/test/tooling/pq-test-shim.mjs';
import * as ac from '../../src/index.js';

const OUT = fileURLToPath(new URL('../fixtures/frozen-v2.json', import.meta.url));
if (existsSync(OUT)) {
  console.error(`${OUT} exists and is frozen. Nothing was written.`);
  process.exit(1);
}

const NAMESPACE = 'example';
const cc = createCryptoCore({ namespace: NAMESPACE });
const hex = cc.toHex;
const b64u = cc.toBase64Url;
const text = (b) => new TextDecoder().decode(b);
const bytes = (start) => Uint8Array.from({ length: 32 }, (_, i) => (start + i) & 0xff);

// Fixed inputs.
const OBJECT_ID = '6f1c2a3b-4d5e-4f60-8a71-92b3c4d5e6f7';
const OWNER_ROW_ID = '0a1b2c3d-4e5f-4a6b-8c7d-8e9fa0b1c2d3';
const MEMBER_ROW_ID = '1b2c3d4e-5f6a-4b7c-9d8e-9fa0b1c2d3e4';
const QUIET_ROW_ID = '2c3d4e5f-6a7b-4c8d-ae9f-a0b1c2d3e4f5';
const HYBRID_ROW_ID = '3d4e5f6a-7b8c-4d9e-bfa0-b1c2d3e4f5a6';
const HYBRID_QUIET_ROW_ID = '4e5f6a7b-8c9d-4eaf-80b1-c2d3e4f5a6b7';
const EPOCH = 1;
const K_OBJECT = bytes(0x11);
const K_DETAIL = bytes(0x31);
const K_ADMINBOX = bytes(0x51);
const ADMIN_CAPABILITY = bytes(0x71);
const ROW_CAPABILITY = { owner: bytes(0x91), member: bytes(0xb1), quiet: bytes(0xd1) };
const ROOT = { owner: bytes(0x01), member: bytes(0x21), quiet: bytes(0x41), hybrid: bytes(0x61) };
const LINK_EXPIRES_AT = '2026-10-27T00:00:00.000Z';

/** An account from a fixed root, with a freshly generated sealing key whose JWK the file keeps. */
async function account(core, root) {
  const identity = await identityFromRootKey(core, root);
  const sealing = await core.generateSealingKeyPair();
  await adoptSealingKey(core, identity, { sealingKey: sealing.jwk });
  return {
    identity,
    frozen: {
      rootKey: hex(root), sealingKeyJwk: sealing.jwk,
      identityPublicKey: hex(identity.identity.publicKeyRaw),
      identitySigningPublicKey: hex(identity.identitySigning.publicKeyRaw),
      routingPublicKey: hex(identity.routing.publicKeyRaw),
    },
  };
}

// What a sealed row carries inside, read with the package's own row context,
// so the fixture records the exact envelope bytes as well as the blob.
async function rowEnvelope(kObjectKey, rowId, encryptedRow) {
  return text(await cc.openSymmetric(kObjectKey, encryptedRow, ac.rowContext(cc, OBJECT_ID, rowId)));
}

async function namedRow(kObjectKey, author, rowId, content, rowCapability) {
  const encryptedRow = await ac.sealMemberRow(cc, kObjectKey, author, OBJECT_ID, rowId, content);
  const envelope = await rowEnvelope(kObjectKey, rowId, encryptedRow);
  const { payloadJson } = JSON.parse(envelope);
  return {
    rowId,
    context: hex(ac.rowContext(cc, OBJECT_ID, rowId)),
    signedMessage: hex(ac.rowSigningMessage(cc, OBJECT_ID, rowId, payloadJson)),
    envelope,
    encryptedRow: hex(encryptedRow),
    encryptedObjectKey: hex(await ac.sealObjectKeyForMember(cc, author.identity.publicKeyRaw, K_OBJECT)),
    rowCapabilitySecret: hex(rowCapability),
    rowCapabilityHash: await ac.hashCapability(cc, rowCapability),
  };
}

const owner = await account(cc, ROOT.owner);
const member = await account(cc, ROOT.member);
const quietMember = await account(cc, ROOT.quiet);
const kObjectKey = await cc.importSymmetricKey(K_OBJECT);
const kDetailKey = await cc.importSymmetricKey(K_DETAIL);

const out = {
  source: `Frozen by test/tooling/generate-frozen-fixtures.mjs on 2026-09-27 under namespace "${NAMESPACE}". Never regenerated or edited.`,
  namespace: NAMESPACE,
  labels: {
    content: cc.label('aad/object-content', 2),
    detail: cc.label('aad/object-detail', 2),
    memberRow: cc.label('aad/member-row', 2),
    memberRowSignature: cc.label('sig/member-row', 2),
    pointer: cc.label('aad/pointer', 2),
    shareLink: cc.label('aad/share-link', 2),
    shareLinkSignature: cc.label('sig/share-link', 2),
    adminBox: cc.label('object-adminbox', 1),
  },
  constants: {
    envelopeSigned: ac.ENVELOPE_SIGNED, envelopeQuiet: ac.ENVELOPE_QUIET,
    adminSeatBucket: ac.ADMIN_SEAT_BUCKET, adminSeatPlaintextBytes: ac.ADMIN_SEAT_PLAINTEXT_BYTES, adminBoxBucketBytes: ac.ADMIN_BOX_BUCKET_BYTES,
    pqKemAdvertMaxAgeMs: ac.PQ_KEM_ADVERT_MAX_AGE_MS,
  },
  accounts: { owner: owner.frozen, member: member.frozen, quietMember: quietMember.frozen },
  object: {
    objectId: OBJECT_ID, epoch: EPOCH, kObject: hex(K_OBJECT), kDetail: hex(K_DETAIL),
    contentContext: hex(ac.contentContext(cc, OBJECT_ID, EPOCH)),
    detailContext: hex(ac.detailContext(cc, OBJECT_ID, EPOCH)),
    readCapability: hex(await ac.readCapability(cc, K_OBJECT)),
    readCapabilityHash: await ac.hashCapability(cc, await ac.readCapability(cc, K_OBJECT)),
  },
};

// --- admin seats and the admin box (FORMATS.md §2, §3.2) ----------------------
const ownerAdmin = ac.adminEntryForIdentity(cc, owner.identity, OWNER_ROW_ID);
const adminSeats = await ac.buildAdminSeats(cc, [ownerAdmin], { objectId: OBJECT_ID, epoch: EPOCH, adminCapabilitySecret: ADMIN_CAPABILITY, kAdminboxRaw: K_ADMINBOX });
const adminBox = await ac.sealAdminBox(cc, K_ADMINBOX, OBJECT_ID, EPOCH, [ownerAdmin]);
out.admin = {
  adminCapabilitySecret: hex(ADMIN_CAPABILITY),
  adminCapabilityHash: await ac.hashCapability(cc, ADMIN_CAPABILITY),
  kAdminbox: hex(K_ADMINBOX),
  adminBoxContext: hex(ac.adminBoxContext(cc, OBJECT_ID, EPOCH)),
  admins: [ownerAdmin],
};

// --- two-tier disclosure: the grants, the content, the second tier -------------
const detailGrants = await ac.buildDetailGrants(cc, K_OBJECT, K_DETAIL, [owner.identity.identity.publicKeyRaw, member.identity.identity.publicKeyRaw]);
const preview = {
  title: 'Picnic', startsAt: '2026-10-03T12:00:00Z', area: 'Riverside', locationIsApproximate: true,
  ownerSigningKey: b64u(owner.identity.identitySigning.publicKeyRaw),
  adminSeats, adminBox, detailGrants,
};
const detail = { address: '1 Example Street' };
out.object.detailGrantLabels = {
  owner: await ac.detailGrantLabel(cc, K_OBJECT, owner.identity.identity.publicKeyRaw),
  member: await ac.detailGrantLabel(cc, K_OBJECT, member.identity.identity.publicKeyRaw),
};
out.object.preview = preview;
out.object.detail = detail;
out.object.encryptedContent = hex(await ac.sealContent(cc, kObjectKey, OBJECT_ID, EPOCH, preview));
out.object.encryptedDetail = hex(await ac.sealDetail(cc, kDetailKey, OBJECT_ID, EPOCH, detail));

// --- a co-owner: the box lists two admins, and every seat is sealed again ------
const coOwned = await ac.addCoOwner(cc, owner.identity, preview, {
  objectId: OBJECT_ID, epoch: EPOCH, adminCapabilitySecret: ADMIN_CAPABILITY,
  grantee: ac.adminEntryForIdentity(cc, member.identity, MEMBER_ROW_ID),
});
out.coOwned = { adminSeats: coOwned.adminSeats, adminBox: coOwned.adminBox };

// --- member rows: named (owner, member) and quiet --------------------------------
out.rows = {
  owner: await namedRow(kObjectKey, owner.identity, OWNER_ROW_ID, { status: 'going' }, ROW_CAPABILITY.owner),
  member: await namedRow(kObjectKey, member.identity, MEMBER_ROW_ID, { status: 'interested', note: 'bringing bread' }, ROW_CAPABILITY.member),
};
const rotation = await ac.generateQuietRotationKeys(cc);
if (rotation.kemSeed !== null) throw new Error('the classical section must not have a hybrid key');
const quietRow = await ac.sealQuietMemberRow(cc, kObjectKey, OBJECT_ID, QUIET_ROW_ID, rotation.publicKeyRaw, { status: 'going' });
out.rows.quiet = {
  rowId: QUIET_ROW_ID,
  context: hex(ac.rowContext(cc, OBJECT_ID, QUIET_ROW_ID)),
  quietRotationKey: rotation.jwk,
  rotationPublicKey: hex(rotation.publicKeyRaw),
  envelope: await rowEnvelope(kObjectKey, QUIET_ROW_ID, quietRow),
  encryptedRow: hex(quietRow),
  encryptedObjectKey: hex(await ac.sealObjectKeyForMember(cc, rotation.publicKeyRaw, K_OBJECT)),
  rowCapabilitySecret: hex(ROW_CAPABILITY.quiet),
  rowCapabilityHash: await ac.hashCapability(cc, ROW_CAPABILITY.quiet),
};

// --- share links: signed by the owner, and unsigned ----------------------------
// The payload key is the crypto-core-frozen url-invite derivation of the
// token; the envelope inside is read here only to record it.
async function linkEnvelope(link) {
  const key = await cc.deriveAesKey(new TextEncoder().encode(link.token), 'url-invite');
  return text(await cc.openSymmetric(key, link.encryptedPayload, ac.linkContext(cc, link.hashedToken)));
}
async function frozenLink(options) {
  const link = await ac.createShareLink(cc, { objectId: OBJECT_ID, kObjectRaw: K_OBJECT, expiresAt: LINK_EXPIRES_AT, keyEpoch: EPOCH, ...options });
  const envelope = await linkEnvelope(link);
  return {
    token: link.token,
    hashedToken: link.hashedToken,
    context: hex(ac.linkContext(cc, link.hashedToken)),
    signedMessage: hex(ac.linkSigningMessage(cc, link.hashedToken, JSON.parse(envelope).payloadJson)),
    envelope,
    encryptedPayload: hex(link.encryptedPayload),
    maxUses: link.maxUses,
    expiresAt: link.expiresAt,
    manageSecret: hex(link.manageSecret),
    manageCapabilityHash: link.manageCapabilityHash,
    record: link.record,
  };
}
out.shareLinks = {
  signed: await frozenLink({ maxUses: 5, creator: owner.identity, creatorName: 'Ada', label: 'group chat' }),
  unsigned: await frozenLink({ maxUses: 1 }),
};

// --- pointers, with one app field in the extension table ------------------------
// The pointer's wire keys are frozen (pointer.js, coreFields): the raw
// plaintext is recorded so the test can pin every key by name.
const codec = ac.createPointerCodec(cc, { myStatus: { wire: 'myStatus', ...ac.oneOf(['going', 'interested', 'not going']) } });
async function frozenPointer(who, values) {
  const sealed = await codec.build(who.identity, values);
  const plaintext = text(await cc.openSymmetric(who.identity.masterSymmKey, sealed, ac.pointerContext(cc, who.identity.routing.publicKeyRaw)));
  return { context: hex(ac.pointerContext(cc, who.identity.routing.publicKeyRaw)), plaintext, sealed: hex(sealed) };
}
out.pointers = {
  coreWireKeys: Object.values(ac.coreFields(cc)).map((f) => f.wire),
  extension: { myStatus: { wire: 'myStatus', oneOf: ['going', 'interested', 'not going'] } },
  owner: await frozenPointer(owner, {
    objectId: OBJECT_ID, kObject: K_OBJECT, keyEpoch: EPOCH, rowCapabilitySecret: ROW_CAPABILITY.owner,
    adminCapabilitySecret: ADMIN_CAPABILITY, sharedLinks: [out.shareLinks.signed.record], myStatus: 'going',
  }),
  member: await frozenPointer(member, {
    objectId: OBJECT_ID, kObject: K_OBJECT, keyEpoch: EPOCH, rowCapabilitySecret: ROW_CAPABILITY.member,
    invitedBy: { name: 'Ada', signingKey: b64u(owner.identity.identitySigning.publicKeyRaw) }, myStatus: 'interested',
  }),
  quietMember: await frozenPointer(quietMember, {
    objectId: OBJECT_ID, kObject: K_OBJECT, keyEpoch: EPOCH, rowCapabilitySecret: ROW_CAPABILITY.quiet,
    quietRotationKey: rotation.jwk, quietRotationKemSeed: null, myStatus: 'going',
  }),
};

// --- hybrid, through the test-only platform shim ------------------------------
// A member whose account has a hybrid KEM key (derived from the root) and
// advertises it: the named row carries identityKemKey and the date it was
// advertised, K_object and the admin seat are sealed to the KEM key (ECIES
// v2), and a quiet row carries a hybrid rotation key.
const uninstall = installPqShim();
const pq = createCryptoCore({ namespace: NAMESPACE, hybridSealing: true });
const hybrid = await account(pq, ROOT.hybrid);
if (!hybrid.identity.identityKem) throw new Error('the shim did not provide the hybrid KEM');
hybrid.frozen.identityKemPublicKey = hex(hybrid.identity.identityKem.publicKeyRaw);
const hybridRow = await ac.sealMemberRow(pq, kObjectKey, hybrid.identity, OBJECT_ID, HYBRID_ROW_ID, { status: 'going' });
const hybridRowEnvelope = await rowEnvelope(kObjectKey, HYBRID_ROW_ID, hybridRow);
const hybridAdmin = ac.adminEntryForIdentity(pq, hybrid.identity, HYBRID_ROW_ID);
const hybridRotation = await ac.generateQuietRotationKeys(pq);
if (!hybridRotation.kemSeed) throw new Error('the shim did not provide a hybrid rotation key');
const hybridQuietRow = await ac.sealQuietMemberRow(pq, kObjectKey, OBJECT_ID, HYBRID_QUIET_ROW_ID, hybridRotation.publicKeyRaw, { status: 'going' }, hybridRotation.kemPublicKeyRaw);
out.hybrid = {
  account: hybrid.frozen,
  row: {
    rowId: HYBRID_ROW_ID,
    signedMessage: hex(ac.rowSigningMessage(pq, OBJECT_ID, HYBRID_ROW_ID, JSON.parse(hybridRowEnvelope).payloadJson)),
    envelope: hybridRowEnvelope,
    encryptedRow: hex(hybridRow),
    encryptedObjectKey: hex(await ac.sealObjectKeyForMember(pq, hybrid.identity.identityKem.publicKeyRaw, K_OBJECT)),
  },
  quietRow: {
    rowId: HYBRID_QUIET_ROW_ID,
    quietRotationKey: hybridRotation.jwk,
    quietRotationKemSeed: hex(hybridRotation.kemSeed),
    rotationKemPublicKey: hex(hybridRotation.kemPublicKeyRaw),
    envelope: await rowEnvelope(kObjectKey, HYBRID_QUIET_ROW_ID, hybridQuietRow),
    encryptedRow: hex(hybridQuietRow),
    encryptedObjectKey: hex(await ac.sealObjectKeyForMember(pq, hybridRotation.kemPublicKeyRaw, K_OBJECT)),
  },
  admin: {
    admins: [hybridAdmin],
    adminSeats: await ac.buildAdminSeats(pq, [hybridAdmin], { objectId: OBJECT_ID, epoch: EPOCH, adminCapabilitySecret: ADMIN_CAPABILITY, kAdminboxRaw: K_ADMINBOX }),
    adminBox: await ac.sealAdminBox(pq, K_ADMINBOX, OBJECT_ID, EPOCH, [hybridAdmin]),
  },
  detailGrantLabel: await ac.detailGrantLabel(pq, K_OBJECT, hybrid.identity.identityKem.publicKeyRaw),
  detailGrants: await ac.buildDetailGrants(pq, K_OBJECT, K_DETAIL, [hybrid.identity.identityKem.publicKeyRaw]),
};
uninstall();

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log('wrote', OUT, Object.keys(out).join(', '));
