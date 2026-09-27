/**
 * Member rows: signed envelopes sealed under K_object, the quiet row and the
 * seal-target chooser, in formats version 2 (FORMATS.md §3, D-31):
 *
 *   named row  { v: 3, payloadJson, sig }   sig = Ed25519(identity signing key,
 *                frameContext("<ns>/sig/member-row/v2", objectId, rowId) ‖ UTF-8(payloadJson))
 *   quiet row  { v: 2, payloadJson }         no identity, no signature; a per-object rotation key
 *   sealed     AEAD v1 under K_object with AAD frameContext("<ns>/aad/member-row/v2", objectId, rowId)
 *
 * payloadJson parses to the app's content plus, for a named row,
 * identityPublicKey and identitySigningKey (and a dated identityKemKey where
 * the runtime has one), or for a quiet row rotationPublicKey (and
 * rotationKemPublicKey). The signed bytes are stored verbatim as a string and
 * never re-serialised, so rotation can re-encrypt another member's row without
 * breaking their signature.
 *
 * verified:false is an ordinary state to render, never a throw. Callers must
 * never display a name or any identity claim from a row that is not verified.
 */

export const ENVELOPE_QUIET = 2;
export const ENVELOPE_SIGNED = 3;
export const PQ_KEM_ADVERT_MAX_AGE_MS = 60 * 24 * 60 * 60 * 1000;
const SIG_MEMBER_ROW = 'sig/member-row';
const AAD_MEMBER_ROW = 'aad/member-row';
const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

export function rowContext(cc, objectId, rowId) {
  return cc.frameContext(cc.label(AAD_MEMBER_ROW, 2), cc.uuidBytes(objectId), cc.uuidBytes(rowId));
}

/** The exact bytes a member-row signature covers. */
export function rowSigningMessage(cc, objectId, rowId, payloadJson) {
  return cc.concatBytes(cc.frameContext(cc.label(SIG_MEMBER_ROW, 2), cc.uuidBytes(objectId), cc.uuidBytes(rowId)), utf8.encode(payloadJson));
}

/** A missing or unparseable date counts as STALE: the safe answer is the classical seal. */
export function isKemAdvertStale(isoDate, now = Date.now()) {
  if (typeof isoDate !== 'string') return true;
  const t = Date.parse(isoDate);
  return Number.isNaN(t) || (now - t) > PQ_KEM_ADVERT_MAX_AGE_MS;
}

/**
 * Which public key K_object is sealed to for this member: a quiet row's
 * per-object keys first (they name no account), hybrid before classical at
 * each step, a stale advertisement treated as absent. One function for
 * rotation and grants alike, so no member silently lands on the weaker path.
 */
export function chooseMemberSealTarget(cc, payload, now = Date.now()) {
  if (!payload) throw new Error('member row names no key to seal to');
  if (payload.rotationKemPublicKey) return cc.fromBase64Url(payload.rotationKemPublicKey);
  if (payload.rotationPublicKey) return cc.fromBase64Url(payload.rotationPublicKey);
  if (payload.identityKemKey && !isKemAdvertStale(payload.identityKemKeyAt, now)) return cc.fromBase64Url(payload.identityKemKey);
  if (!payload.identityPublicKey) throw new Error('member row names no key to seal to');
  return cc.fromBase64Url(payload.identityPublicKey);
}

/** Seals one named row, signed by its author (a full identity: sealing key for rotation, signing key for authorship). */
export async function sealMemberRow(cc, kObjectKey, authorIdentity, objectId, rowId, content) {
  const kem = authorIdentity.identityKem;
  const payloadJson = JSON.stringify({
    ...content,
    identityPublicKey: cc.toBase64Url(authorIdentity.identity.publicKeyRaw),
    identitySigningKey: cc.toBase64Url(authorIdentity.identitySigning.publicKeyRaw),
    ...(kem ? { identityKemKey: cc.toBase64Url(kem.publicKeyRaw), identityKemKeyAt: new Date().toISOString().slice(0, 10) } : {}),
  });
  const sig = await cc.signBytes(authorIdentity.identitySigning.privateKey, rowSigningMessage(cc, objectId, rowId, payloadJson));
  const envelope = { v: ENVELOPE_SIGNED, payloadJson, sig: cc.toBase64Url(sig) };
  return cc.sealSymmetric(kObjectKey, utf8.encode(JSON.stringify(envelope)), rowContext(cc, objectId, rowId));
}

/** Seals one quiet row: no identity, no signature, a per-object rotation key (and its hybrid twin where the runtime can). */
export async function sealQuietMemberRow(cc, kObjectKey, objectId, rowId, rotationPublicKeyRaw, content, rotationKemPublicKeyRaw = null) {
  if (!(rotationPublicKeyRaw instanceof Uint8Array) || rotationPublicKeyRaw.length !== cc.P256_PUBLIC_KEY_BYTES) {
    throw new Error(`a quiet row needs a ${cc.P256_PUBLIC_KEY_BYTES}-byte rotation key, or rotation would lock this member out`);
  }
  if (rotationKemPublicKeyRaw && rotationKemPublicKeyRaw.length !== cc.PQ_KEM_PUBLIC_KEY_BYTES) throw new Error('rotationKemPublicKey has the wrong length');
  const payloadJson = JSON.stringify({
    ...content,
    rotationPublicKey: cc.toBase64Url(rotationPublicKeyRaw),
    ...(rotationKemPublicKeyRaw ? { rotationKemPublicKey: cc.toBase64Url(rotationKemPublicKeyRaw) } : {}),
  });
  return cc.sealSymmetric(kObjectKey, utf8.encode(JSON.stringify({ v: ENVELOPE_QUIET, payloadJson })), rowContext(cc, objectId, rowId));
}

/**
 * A fresh per-object key pair for a quiet row: the private JWK (and hybrid
 * seed) go in the member's pointer, the public halves in the row. Nothing
 * links either to the account.
 */
export async function generateQuietRotationKeys(cc) {
  const { privateKey, publicKeyRaw, jwk } = await cc.generateSealingKeyPair();
  const kemSeed = cc.randomBytes(32);
  const kem = await cc.kemKeyPairFromSeed(kemSeed);
  return { jwk, privateKey, publicKeyRaw, kemSeed: kem ? kemSeed : null, kemPrivateKey: kem ? kem.privateKey : null, kemPublicKeyRaw: kem ? kem.publicKeyRaw : null };
}

/** Both private halves of a quiet row's keys, from the pointer, in the shape unwrapObjectKey wants. */
export async function quietRotationKeys(cc, jwk, kemSeed = null) {
  const kem = kemSeed ? await cc.kemKeyPairFromSeed(kemSeed) : null;
  return { classical: await cc.importSealingKeyPair(jwk), kem: kem ? kem.privateKey : null };
}

/**
 * Opens and checks one row. Returns
 *   { verified, signed, quiet, payload, identityPublicKeyRaw, identitySigningKeyRaw,
 *     rotationPublicKeyRaw, identityKemKeyRaw, sealTargetKeyRaw }
 * Throws only when the ciphertext does not open or is not an envelope at
 * all; a signature that fails is `verified: false`, never a throw.
 */
export async function openMemberRow(cc, kObjectKey, objectId, rowId, sealed, now = Date.now()) {
  const bytes = await cc.openSymmetric(kObjectKey, sealed, rowContext(cc, objectId, rowId));
  const outer = JSON.parse(fromUtf8.decode(bytes));
  if (!outer || typeof outer.payloadJson !== 'string') throw new Error('not a member-row envelope');
  const payload = JSON.parse(outer.payloadJson);
  if (outer.v === ENVELOPE_QUIET) {
    return {
      verified: false, signed: false, quiet: true, payload,
      identityPublicKeyRaw: null, identitySigningKeyRaw: null,
      rotationPublicKeyRaw: payload.rotationPublicKey ? cc.fromBase64Url(payload.rotationPublicKey) : null,
      identityKemKeyRaw: null,
      sealTargetKeyRaw: safeTarget(cc, payload, now),
    };
  }
  if (outer.v !== ENVELOPE_SIGNED) throw new Error(`unsupported member-row envelope version ${outer.v}`);
  const identitySigningKeyRaw = payload.identitySigningKey ? cc.fromBase64Url(payload.identitySigningKey) : null;
  const identityPublicKeyRaw = payload.identityPublicKey ? cc.fromBase64Url(payload.identityPublicKey) : null;
  const signed = Boolean(identitySigningKeyRaw && typeof outer.sig === 'string');
  const verified = signed && await cc.verifyBytes(identitySigningKeyRaw, rowSigningMessage(cc, objectId, rowId, outer.payloadJson), cc.fromBase64Url(outer.sig));
  return {
    verified, signed, quiet: false, payload, identityPublicKeyRaw, identitySigningKeyRaw,
    rotationPublicKeyRaw: null,
    identityKemKeyRaw: payload.identityKemKey && !isKemAdvertStale(payload.identityKemKeyAt, now) ? cc.fromBase64Url(payload.identityKemKey) : null,
    sealTargetKeyRaw: safeTarget(cc, payload, now),
  };
}

function safeTarget(cc, payload, now) {
  try { return chooseMemberSealTarget(cc, payload, now); } catch { return null; }
}

/** Re-encrypts a row under a new K_object without touching a single inner byte, so its signature survives. */
export async function resealMemberRow(cc, oldKObjectKey, newKObjectKey, objectId, rowId, sealed) {
  const bytes = await cc.openSymmetric(oldKObjectKey, sealed, rowContext(cc, objectId, rowId));
  return cc.sealSymmetric(newKObjectKey, bytes, rowContext(cc, objectId, rowId));
}

/**
 * A member's own edit: the change set merged over the previous plaintext, so
 * fields other writers own survive. A quiet row stays quiet unless the member
 * chooses to be named (`becomeNamed`); becoming named keeps the rotation keys
 * in the payload, because the stored sealed copy of K_object is still sealed
 * to them until the next rotation.
 */
export async function updateMemberRow(cc, kObjectKey, authorIdentity, objectId, rowId, changes, previousPayload = null, { becomeNamed = false } = {}) {
  const merged = { ...(previousPayload || {}), ...changes };
  if (merged.rotationPublicKey && !becomeNamed) {
    return sealQuietMemberRow(cc, kObjectKey, objectId, rowId, cc.fromBase64Url(merged.rotationPublicKey), merged,
      merged.rotationKemPublicKey ? cc.fromBase64Url(merged.rotationKemPublicKey) : null);
  }
  return sealMemberRow(cc, kObjectKey, authorIdentity, objectId, rowId, merged);
}

/**
 * The display rule, as a pure function over an opened row: a verified row
 * exposes its content and keys; a quiet row its content and no keys; an
 * unverified row nothing but its id. `pick` chooses which content fields the
 * app shows (default: all).
 */
export function rosterEntry(rowId, keyEpoch, opened, { pick = (payload) => payload } = {}) {
  if (opened.verified) {
    return { id: rowId, keyEpoch, verified: true, quiet: false, content: pick(opened.payload), identitySigningKeyRaw: opened.identitySigningKeyRaw, identityPublicKeyRaw: opened.identityPublicKeyRaw, sealTargetKeyRaw: opened.sealTargetKeyRaw };
  }
  if (opened.quiet) {
    return { id: rowId, keyEpoch, verified: false, quiet: true, content: pick(opened.payload), identitySigningKeyRaw: null, identityPublicKeyRaw: null, sealTargetKeyRaw: opened.sealTargetKeyRaw };
  }
  return { id: rowId, keyEpoch, verified: false, quiet: false, content: null, identitySigningKeyRaw: null, identityPublicKeyRaw: null, sealTargetKeyRaw: null };
}
