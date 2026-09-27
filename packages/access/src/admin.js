/**
 * Who runs an object: admin seats and the admin box. The admin capability
 * travels in padded seats and is replaced on every rotation, so a removed
 * admin keeps no power over the object and a member cannot count the admins:
 *
 *   adminSeats  base64url strings, a multiple of ADMIN_SEAT_BUCKET, in random
 *               order. One per admin: sealToRecipient(their key, the JSON
 *               {v:1, objectId, epoch, adminCap, kAdminbox} padded with spaces
 *               to ADMIN_SEAT_PLAINTEXT_BYTES). The rest are dummies: real
 *               seals, to throwaway keys, of random bytes of the same length,
 *               so a member counts seats and never admins.
 *   adminBox    sealSymmetric(K_adminbox, the JSON {v:1, admins:[{signingKey,
 *               identityPublicKey, rowId, identityKemKey?, identityKemKeyAt?}]}
 *               padded to a multiple of ADMIN_BOX_BUCKET_BYTES), with AAD
 *               frameContext("<ns>/object-adminbox/v1", objectId, u32be(epoch)).
 *
 * Both sit in the content, so they are under K_object as well. K_adminbox is
 * random and travels only inside the seats. The admin capability and
 * K_adminbox are replaced on EVERY rotation.
 */
import { chooseMemberSealTarget } from './envelope.js';

export const ADMIN_SEAT_BUCKET = 4;
export const ADMIN_SEAT_PLAINTEXT_BYTES = 256;
export const ADMIN_BOX_BUCKET_BYTES = 1024;
const AAD_ADMINBOX = 'object-adminbox';
const UUID_TEXT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

export function adminBoxContext(cc, objectId, epoch) {
  return cc.frameContext(cc.label(AAD_ADMINBOX, 1), cc.uuidBytes(objectId), cc.u32be(epoch));
}

function padToBucket(text, bucket) {
  const bytes = utf8.encode(text);
  const size = Math.max(bucket, Math.ceil(bytes.length / bucket) * bucket);
  const out = new Uint8Array(size).fill(0x20);
  out.set(bytes);
  return out;
}

function isB64uOfLength(cc, v, n) {
  if (typeof v !== 'string') return false;
  try { return cc.fromBase64Url(v).length === n; } catch { return false; }
}

/** One admin as the box lists them, checked. */
export function checkAdminEntry(cc, a) {
  if (!a || typeof a !== 'object') throw new Error('admin box: not an entry');
  if (!isB64uOfLength(cc, a.signingKey, 32)) throw new Error('admin box: signingKey');
  if (!isB64uOfLength(cc, a.identityPublicKey, cc.P256_PUBLIC_KEY_BYTES)) throw new Error('admin box: identityPublicKey');
  if (a.rowId !== null && a.rowId !== undefined && !(typeof a.rowId === 'string' && UUID_TEXT.test(a.rowId))) throw new Error('admin box: rowId');
  const entry = { signingKey: a.signingKey, identityPublicKey: a.identityPublicKey, rowId: a.rowId ? a.rowId.toLowerCase() : null };
  if (a.identityKemKey !== undefined && a.identityKemKey !== null) {
    if (!isB64uOfLength(cc, a.identityKemKey, cc.PQ_KEM_PUBLIC_KEY_BYTES)) throw new Error('admin box: identityKemKey');
    entry.identityKemKey = a.identityKemKey;
    entry.identityKemKeyAt = typeof a.identityKemKeyAt === 'string' ? a.identityKemKeyAt : null;
  }
  return entry;
}

export function adminEntryForIdentity(cc, identity, rowId = null) {
  const kem = identity.identityKem;
  return checkAdminEntry(cc, {
    signingKey: cc.toBase64Url(identity.identitySigning.publicKeyRaw),
    identityPublicKey: cc.toBase64Url(identity.identity.publicKeyRaw),
    rowId: rowId || null,
    ...(kem ? { identityKemKey: cc.toBase64Url(kem.publicKeyRaw), identityKemKeyAt: new Date().toISOString().slice(0, 10) } : {}),
  });
}

/** An admin entry from a VERIFIED row's payload, or null when it names no usable keys. */
export function adminEntryFromPayload(cc, payload, rowId) {
  if (!payload || !payload.identitySigningKey || !payload.identityPublicKey) return null;
  try {
    return checkAdminEntry(cc, {
      signingKey: payload.identitySigningKey, identityPublicKey: payload.identityPublicKey, rowId: rowId || null,
      ...(payload.identityKemKey ? { identityKemKey: payload.identityKemKey, identityKemKeyAt: payload.identityKemKeyAt || null } : {}),
    });
  } catch { return null; }
}

export async function sealAdminBox(cc, kAdminboxRaw, objectId, epoch, admins) {
  const checked = admins.map((a) => checkAdminEntry(cc, a));
  const key = await cc.importSymmetricKey(kAdminboxRaw);
  return cc.toBase64Url(await cc.sealSymmetric(key, padToBucket(JSON.stringify({ v: 1, admins: checked }), ADMIN_BOX_BUCKET_BYTES), adminBoxContext(cc, objectId, epoch)));
}

export async function openAdminBox(cc, kAdminboxRaw, objectId, epoch, sealedB64u) {
  const key = await cc.importSymmetricKey(kAdminboxRaw);
  const bytes = await cc.openSymmetric(key, cc.fromBase64Url(sealedB64u), adminBoxContext(cc, objectId, epoch));
  const box = JSON.parse(fromUtf8.decode(bytes));
  if (!box || box.v !== 1 || !Array.isArray(box.admins)) throw new Error('admin box: not a version 1 box');
  return box.admins.map((a) => checkAdminEntry(cc, a));
}

async function sealAdminSeat(cc, targetKeyRaw, { objectId, epoch, adminCapabilitySecret, kAdminboxRaw }) {
  const json = JSON.stringify({ v: 1, objectId, epoch, adminCap: cc.toBase64Url(adminCapabilitySecret), kAdminbox: cc.toBase64Url(kAdminboxRaw) });
  if (utf8.encode(json).length > ADMIN_SEAT_PLAINTEXT_BYTES) throw new Error('admin seat content is longer than its fixed size');
  const plaintext = new Uint8Array(ADMIN_SEAT_PLAINTEXT_BYTES).fill(0x20);
  plaintext.set(utf8.encode(json));
  return cc.toBase64Url(await cc.sealToRecipient(targetKeyRaw, plaintext));
}

async function dummyAdminSeat(cc) {
  const nobody = await cc.generateSealingKeyPair();
  return cc.toBase64Url(await cc.sealToPublicKey(nobody.publicKeyRaw, cc.randomBytes(ADMIN_SEAT_PLAINTEXT_BYTES)));
}

/** The key an admin's seat is sealed to: the same chooser as K_object. */
export function adminSeatTarget(cc, entry) {
  return chooseMemberSealTarget(cc, entry);
}

/** One seat per admin, padded with dummies to a multiple of ADMIN_SEAT_BUCKET, in random order. */
export async function buildAdminSeats(cc, admins, { objectId, epoch, adminCapabilitySecret, kAdminboxRaw }) {
  const seats = [];
  for (const a of admins) seats.push(await sealAdminSeat(cc, adminSeatTarget(cc, checkAdminEntry(cc, a)), { objectId, epoch, adminCapabilitySecret, kAdminboxRaw }));
  while (seats.length === 0 || seats.length % ADMIN_SEAT_BUCKET !== 0) seats.push(await dummyAdminSeat(cc));
  for (let i = seats.length - 1; i > 0; i--) {
    const j = globalThis.crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [seats[i], seats[j]] = [seats[j], seats[i]];
  }
  return seats;
}

/** This account's keys, strongest first, in the shape the grant and seat readers want. */
export function identityGrantKeys(identity) {
  if (!identity) return [];
  const keys = [];
  if (identity.identityKem) keys.push({ publicKeyRaw: identity.identityKem.publicKeyRaw, privateKey: identity.identityKem.privateKey, kem: true });
  if (identity.identity) keys.push({ publicKeyRaw: identity.identity.publicKeyRaw, privateKey: identity.identity.privateKey, kem: false });
  return keys;
}

/** Opens a blob sealed to one of several candidate keys; null when none opens it. */
export async function openWithAnyKey(cc, candidates, blob) {
  for (const c of candidates) {
    if (!c || !c.publicKeyRaw || !c.privateKey) continue;
    try {
      if (blob[0] === cc.ECIES_VERSION_2) { if (!c.kem) continue; return await cc.openWithKemPrivateKey(c.privateKey, blob); }
      if (c.kem) continue;
      return await cc.openWithPrivateKey(c, blob);
    } catch { /* the next key */ }
  }
  return null;
}

/** This account's seat, or null (an ordinary answer: this account does not run the object). */
export async function openAdminSeat(cc, identity, content, objectId, epoch) {
  if (!identity || !content || !Array.isArray(content.adminSeats)) return null;
  const candidates = identityGrantKeys(identity);
  for (const seatB64u of content.adminSeats) {
    let bytes;
    try { bytes = await openWithAnyKey(cc, candidates, cc.fromBase64Url(seatB64u)); } catch { continue; }
    if (!bytes) continue;
    let seat;
    try { seat = JSON.parse(fromUtf8.decode(bytes)); } catch { continue; }
    if (!seat || seat.v !== 1 || seat.objectId !== objectId || seat.epoch !== epoch) continue;
    if (!isB64uOfLength(cc, seat.adminCap, 32) || !isB64uOfLength(cc, seat.kAdminbox, 32)) continue;
    return { adminCapabilitySecret: cc.fromBase64Url(seat.adminCap), kAdminboxRaw: cc.fromBase64Url(seat.kAdminbox) };
  }
  return null;
}

/** The admin list, for an account that holds a seat; null otherwise. */
export async function readAdmins(cc, identity, content, objectId, epoch) {
  const seat = await openAdminSeat(cc, identity, content, objectId, epoch);
  if (!seat || typeof content.adminBox !== 'string') return null;
  try { return { seat, admins: await openAdminBox(cc, seat.kAdminboxRaw, objectId, epoch, content.adminBox) }; } catch { return null; }
}

/** A new object's admin material: the creator's seat and a box listing only them. */
export async function newAdminBlock(cc, identity, { objectId, epoch, adminCapabilitySecret, selfRowId = null }) {
  const kAdminboxRaw = cc.generateSymmetricKey();
  const admins = [adminEntryForIdentity(cc, identity, selfRowId)];
  return {
    adminSeats: await buildAdminSeats(cc, admins, { objectId, epoch, adminCapabilitySecret, kAdminboxRaw }),
    adminBox: await sealAdminBox(cc, kAdminboxRaw, objectId, epoch, admins),
  };
}

/**
 * Makes someone a co-owner: the box gains them and every seat is sealed again
 * with the SAME capability and K_adminbox (a grant is not a rotation).
 * Returns { adminSeats, adminBox, added }.
 */
export async function addCoOwner(cc, identity, content, { objectId, epoch, adminCapabilitySecret, grantee, selfRowId = null }) {
  const entry = checkAdminEntry(cc, grantee);
  const read = await readAdmins(cc, identity, content, objectId, epoch);
  let admins, kAdminboxRaw;
  if (read) {
    if (cc.toHex(read.seat.adminCapabilitySecret) !== cc.toHex(adminCapabilitySecret)) throw Object.assign(new Error('the object was re-keyed since this was loaded'), { code: 'stale' });
    admins = read.admins; kAdminboxRaw = read.seat.kAdminboxRaw;
  } else {
    admins = [adminEntryForIdentity(cc, identity, selfRowId)]; kAdminboxRaw = cc.generateSymmetricKey();
  }
  if (admins.some((a) => a.signingKey === entry.signingKey)) return { adminSeats: content.adminSeats, adminBox: content.adminBox, added: false };
  admins = [...admins, entry];
  return {
    adminSeats: await buildAdminSeats(cc, admins, { objectId, epoch, adminCapabilitySecret, kAdminboxRaw }),
    adminBox: await sealAdminBox(cc, kAdminboxRaw, objectId, epoch, admins),
    added: true,
  };
}
