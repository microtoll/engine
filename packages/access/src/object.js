/**
 * Objects: the key, the content, the second tier and its grants, the
 * capabilities, the owner's grant sweep, the viewer's merge, and the builders
 * for creating an object, joining one and reacting to one; formats version 2
 * (FORMATS.md §3):
 *
 *   content     AEAD v1 under K_object, AAD frameContext("<ns>/aad/object-content/v2", objectId, u32be(epoch))
 *   second tier AEAD v1 under K_detail, AAD frameContext("<ns>/aad/object-detail/v2", objectId, u32be(epoch))
 *   read cap    HKDF(K_object, "<ns>/read/v1"); the server keeps SHA-256 of it
 *   grant       detailGrants[label] = sealToRecipient(recipientKey, K_detail),
 *               label = base64url(HKDF(K_object, "<ns>/detail-grant/v1" ‖ 0x00 ‖ SHA-256(recipientKey)))
 *
 * K_detail is random and NEVER derived from K_object: derived, every link
 * holder would have it and the second tier would be readable by exactly the
 * people it is hidden from.
 */
import { sealMemberRow, sealQuietMemberRow, generateQuietRotationKeys, chooseMemberSealTarget, openMemberRow } from './envelope.js';
import { newAdminBlock, identityGrantKeys, openWithAnyKey } from './admin.js';

const AAD_CONTENT = 'aad/object-content';
const AAD_DETAIL = 'aad/object-detail';
const PURPOSE_READ = 'read';
const PURPOSE_DETAIL_GRANT = 'detail-grant';
const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

export const contentContext = (cc, objectId, epoch) => cc.frameContext(cc.label(AAD_CONTENT, 2), cc.uuidBytes(objectId), cc.u32be(epoch));
export const detailContext = (cc, objectId, epoch) => cc.frameContext(cc.label(AAD_DETAIL, 2), cc.uuidBytes(objectId), cc.u32be(epoch));

export async function sealContent(cc, kObjectKey, objectId, epoch, content) {
  return cc.sealSymmetric(kObjectKey, utf8.encode(JSON.stringify(content)), contentContext(cc, objectId, epoch));
}
export async function openContent(cc, kObjectKey, objectId, epoch, sealed) {
  return JSON.parse(fromUtf8.decode(await cc.openSymmetric(kObjectKey, sealed, contentContext(cc, objectId, epoch))));
}
export async function sealDetail(cc, kDetailKey, objectId, epoch, detail) {
  return cc.sealSymmetric(kDetailKey, utf8.encode(JSON.stringify(detail)), detailContext(cc, objectId, epoch));
}
export async function openDetail(cc, kDetailKey, objectId, epoch, sealed) {
  return JSON.parse(fromUtf8.decode(await cc.openSymmetric(kDetailKey, sealed, detailContext(cc, objectId, epoch))));
}

/** The read capability, derived from K_object so every legitimate holder can recompute it; the server keeps only its hash. */
export async function readCapability(cc, kObjectRaw) {
  return cc.deriveBits(kObjectRaw, PURPOSE_READ);
}
export async function hashCapability(cc, secret) {
  return cc.toHex(await cc.sha256(secret));
}
export async function newCapability(cc) {
  const secret = cc.randomBytes(32);
  return { secret, hash: await hashCapability(cc, secret) };
}

/** Seals K_object to whichever key the member published (v3 for 65 bytes, v2 for 1216). */
export function sealObjectKeyForMember(cc, memberPublicKeyRaw, kObjectRaw) {
  return cc.sealToRecipient(memberPublicKeyRaw, kObjectRaw);
}

/**
 * Recovers K_object. memberKeys is a sealing pair { privateKey, publicKeyRaw }
 * or { classical, kem }. A v2 blob with no hybrid key is a clear error
 * (code 'pq-key-unavailable'), never a decryption failure.
 */
export async function unwrapObjectKey(cc, memberKeys, sealed) {
  const isBoth = memberKeys && ('classical' in memberKeys || 'kem' in memberKeys);
  const classical = isBoth ? memberKeys.classical : memberKeys;
  const kem = isBoth ? memberKeys.kem : null;
  let kObjectRaw;
  if (sealed[0] === cc.ECIES_VERSION_2) {
    if (!kem) throw Object.assign(new Error('this object key was sealed with a post-quantum key this device does not have'), { code: 'pq-key-unavailable' });
    kObjectRaw = await cc.openWithKemPrivateKey(kem, sealed);
  } else {
    if (!classical) throw new Error('no classical key pair supplied');
    kObjectRaw = await cc.openWithPrivateKey(classical, sealed);
  }
  return { kObjectRaw, kObjectKey: await cc.importSymmetricKey(kObjectRaw) };
}

// ---- the second tier -----------------------------------------------------

export function generateDetailKey(cc) { return cc.generateSymmetricKey(); }

/** An object-scoped pseudonym for a recipient: the label a grant sits under. The NUL separates label and hash. */
export async function detailGrantLabel(cc, kObjectRaw, recipientKeyRaw) {
  const info = cc.concatBytes(utf8.encode(cc.label(PURPOSE_DETAIL_GRANT, 1)), new Uint8Array([0]), await cc.sha256(recipientKeyRaw));
  return cc.toBase64Url(await cc.hkdfDeriveBits(kObjectRaw, new Uint8Array(0), info, 256));
}

/** label → K_detail sealed to that recipient. Recipients with no usable key are skipped. */
export async function buildDetailGrants(cc, kObjectRaw, kDetailRaw, recipientKeys) {
  const grants = {};
  for (const keyRaw of recipientKeys) {
    if (!keyRaw) continue;
    grants[await detailGrantLabel(cc, kObjectRaw, keyRaw)] = cc.toBase64Url(await cc.sealToRecipient(keyRaw, kDetailRaw));
  }
  return grants;
}

/** This account's grant, trying every key it holds (hybrid first); null when there is none yet. */
export async function openDetailGrant(cc, kObjectRaw, grants, candidates) {
  if (!grants || !Array.isArray(candidates)) return null;
  for (const c of candidates) {
    if (!c || !c.publicKeyRaw || !c.privateKey) continue;
    try {
      const sealed = grants[await detailGrantLabel(cc, kObjectRaw, c.publicKeyRaw)];
      if (!sealed) continue;
      const opened = await openWithAnyKey(cc, [c], cc.fromBase64Url(sealed));
      if (opened) return opened;
    } catch { /* the next key */ }
  }
  return null;
}

/** An example grant rule, ready to pass as `grantDue`: a named (verified) or quiet row that says "going" and has not opted out. */
export function goingGrantDue(entry) {
  if (!entry) return false;
  const c = entry.content || {};
  return (entry.verified === true || entry.quiet === true) && c.status === 'going' && !c.optedOut;
}

/**
 * The owner's sweep: every row `grantDue` says (and every admin) with no
 * grant yet, in one go. Returns the NEW grant map, or null when there is
 * nothing to do, so an owner opening the same screen ten times writes once.
 * Grants are added, never pruned: only rotation revokes.
 */
export async function planDetailGrantSweep(cc, { kObjectRaw, kDetailRaw, existingGrants, entries, grantDue, adminSigningKeys = null }) {
  if (!kDetailRaw) return null;
  const targets = [];
  for (const e of entries || []) {
    if (!e) continue;
    const isAdmin = Boolean(adminSigningKeys && e.verified && e.identitySigningKeyRaw && adminSigningKeys.has(cc.toBase64Url(e.identitySigningKeyRaw)));
    if (!grantDue(e) && !isAdmin) continue;
    const target = e.sealTargetKeyRaw;
    if (!target) continue;
    if (existingGrants && existingGrants[await detailGrantLabel(cc, kObjectRaw, target)]) continue;
    targets.push(target);
  }
  if (!targets.length) return null;
  return { ...(existingGrants || {}), ...(await buildDetailGrants(cc, kObjectRaw, kDetailRaw, targets)) };
}

/**
 * What THIS viewer sees: the preview with the second tier merged over it if
 * they hold a grant, the preview untouched otherwise. Every failure returns
 * the preview; a viewer with no grant is the ordinary case, and the app says
 * so in words. viewer: { identity?, quietRotationKey?, quietRotationKemSeed? }.
 */
export async function openForViewer(cc, { kObjectRaw, objectId, epoch, preview, encryptedDetail, viewer, merge = defaultMerge }) {
  if (!preview || !encryptedDetail || !preview.detailGrants || !viewer) return preview;
  try {
    const candidates = identityGrantKeys(viewer.identity);
    if (viewer.quietRotationKey) {
      const q = await cc.importSealingKeyPair(viewer.quietRotationKey);
      candidates.push({ publicKeyRaw: q.publicKeyRaw, privateKey: q.privateKey, kem: false });
      if (viewer.quietRotationKemSeed) {
        const k = await cc.kemKeyPairFromSeed(viewer.quietRotationKemSeed);
        if (k) candidates.unshift({ publicKeyRaw: k.publicKeyRaw, privateKey: k.privateKey, kem: true });
      }
    }
    const kDetailRaw = await openDetailGrant(cc, kObjectRaw, preview.detailGrants, candidates);
    if (!kDetailRaw) return preview;
    return merge(preview, await openDetail(cc, await cc.importSymmetricKey(kDetailRaw), objectId, epoch, encryptedDetail));
  } catch {
    return preview;
  }
}

/** Detail wins; an absent detail leaves the preview as it is. */
export function defaultMerge(preview, detail) {
  if (!detail) return preview;
  return { ...preview, ...detail };
}

// ---- creating and joining --------------------------------------------------

/**
 * createObject(cc, { identity, content, ownerRowContent, twoTier, split, pointerCodec, now })
 *
 * Mints K_object, the admin and row capabilities, the owner's row and seat,
 * the owner's pointer; with `twoTier`, also K_detail, the caller's
 * split(content) → { preview, detail } and the owner's own grant. Returns the
 * bundle the create message is built from; the coarse selector is the app's
 * to add.
 */
export async function createObject(cc, { identity, content, ownerRowContent = {}, twoTier = false, split = null, pointerCodec, now = Date.now() }) {
  if (!pointerCodec) throw new Error('createObject needs a pointerCodec');
  if (twoTier && typeof split !== 'function') throw new Error('a two-tier object needs a split function');
  const objectId = globalThis.crypto.randomUUID();
  const epoch = 1;
  const kObjectRaw = cc.generateSymmetricKey();
  const kObjectKey = await cc.importSymmetricKey(kObjectRaw);
  const admin = await newCapability(cc);
  const ownerRow = await newCapability(cc);
  const ownerRowId = globalThis.crypto.randomUUID();
  const withOwner = { ...content, ownerSigningKey: cc.toBase64Url(identity.identitySigning.publicKeyRaw) };
  const adminBlock = await newAdminBlock(cc, identity, { objectId, epoch, adminCapabilitySecret: admin.secret, selfRowId: ownerRowId });
  let preview = { ...withOwner, ...adminBlock };
  let kDetailRaw = null;
  let encryptedDetail = null;
  if (twoTier) {
    kDetailRaw = generateDetailKey(cc);
    const parts = split(withOwner);
    encryptedDetail = await sealDetail(cc, await cc.importSymmetricKey(kDetailRaw), objectId, epoch, parts.detail);
    preview = { ...parts.preview, ...adminBlock, detailGrants: await buildDetailGrants(cc, kObjectRaw, kDetailRaw, [identity.identity.publicKeyRaw]) };
  }
  const encryptedContent = await sealContent(cc, kObjectKey, objectId, epoch, preview);
  const readSecret = await readCapability(cc, kObjectRaw);
  const encryptedRow = await sealMemberRow(cc, kObjectKey, identity, objectId, ownerRowId, ownerRowContent);
  const encryptedObjectKey = await sealObjectKeyForMember(cc, identity.identity.publicKeyRaw, kObjectRaw);
  const pointer = await pointerCodec.build(identity, {
    objectId, kObject: kObjectRaw, keyEpoch: epoch, rowCapabilitySecret: ownerRow.secret, adminCapabilitySecret: admin.secret,
  });
  return {
    objectId, kObjectRaw, kDetailRaw, epoch, encryptedContent, encryptedDetail,
    adminCapabilitySecret: admin.secret, adminCapabilityHash: admin.hash,
    readCapabilitySecret: readSecret, readCapabilityHash: await hashCapability(cc, readSecret),
    ownerRow: { rowId: ownerRowId, encryptedRow, encryptedObjectKey, rowCapabilitySecret: ownerRow.secret, rowCapabilityHash: ownerRow.hash, keyEpoch: epoch },
    pointer,
    previewContent: preview,
  };
}

/** A named member row for an existing object, once K_object is held. */
export async function buildMemberRow(cc, { identity, objectId, kObjectRaw, keyEpoch, content = {} }) {
  const kObjectKey = await cc.importSymmetricKey(kObjectRaw);
  const row = await newCapability(cc);
  const rowId = globalThis.crypto.randomUUID();
  return {
    rowId,
    encryptedRow: await sealMemberRow(cc, kObjectKey, identity, objectId, rowId, content),
    encryptedObjectKey: await sealObjectKeyForMember(cc, identity.identity.publicKeyRaw, kObjectRaw),
    rowCapabilitySecret: row.secret, rowCapabilityHash: row.hash, keyEpoch,
  };
}

/** A quiet member row: the row, and the per-object keys its pointer must keep. Callers write both or neither. */
export async function buildQuietMemberRow(cc, { objectId, kObjectRaw, keyEpoch, content = {} }) {
  const kObjectKey = await cc.importSymmetricKey(kObjectRaw);
  const row = await newCapability(cc);
  const rowId = globalThis.crypto.randomUUID();
  const rotation = await generateQuietRotationKeys(cc);
  return {
    quietRotationKey: rotation.jwk,
    quietRotationKemSeed: rotation.kemSeed,
    row: {
      rowId,
      encryptedRow: await sealQuietMemberRow(cc, kObjectKey, objectId, rowId, rotation.publicKeyRaw, content, rotation.kemPublicKeyRaw),
      encryptedObjectKey: await sealObjectKeyForMember(cc, rotation.kemPublicKeyRaw || rotation.publicKeyRaw, kObjectRaw),
      rowCapabilitySecret: row.secret, rowCapabilityHash: row.hash, keyEpoch,
    },
  };
}

/** Read access and nothing else: a pointer with K_object and no row. Opening a link does not enlist anyone. */
export async function buildReadOnlyPointer(cc, { identity, objectId, kObjectRaw, keyEpoch, invitedBy = null, pointerCodec, extra = {} }) {
  return pointerCodec.build(identity, { ...extra, objectId, kObject: kObjectRaw, keyEpoch, invitedBy });
}

/**
 * The first reaction on an object this account only had read access to: the
 * row AND the replacement pointer carrying its new row secret (and, for a
 * quiet reaction, the rotation keys). The only place that secret is ever
 * persisted, so writing the row without the pointer would strand it.
 */
export async function buildFirstReaction(cc, { identity, objectId, kObjectRaw, keyEpoch, content = {}, quiet = false, existingPointer = {}, pointerCodec }) {
  if (quiet) {
    const built = await buildQuietMemberRow(cc, { objectId, kObjectRaw, keyEpoch, content });
    const pointer = await pointerCodec.build(identity, {
      ...existingPointer, objectId, kObject: kObjectRaw, keyEpoch,
      rowCapabilitySecret: built.row.rowCapabilitySecret, quietRotationKey: built.quietRotationKey, quietRotationKemSeed: built.quietRotationKemSeed,
    });
    return { row: built.row, pointer, readCapabilitySecret: await readCapability(cc, kObjectRaw) };
  }
  const row = await buildMemberRow(cc, { identity, objectId, kObjectRaw, keyEpoch, content });
  const pointer = await pointerCodec.build(identity, { ...existingPointer, objectId, kObject: kObjectRaw, keyEpoch, rowCapabilitySecret: row.rowCapabilitySecret });
  return { row, pointer, readCapabilitySecret: await readCapability(cc, kObjectRaw) };
}

/** Opens every row the server returned into roster entries; a row that will not open is skipped. */
export async function openRows(cc, { kObjectRaw, objectId, rows, now = Date.now() }) {
  const kObjectKey = await cc.importSymmetricKey(kObjectRaw);
  const out = [];
  for (const row of rows || []) {
    try {
      out.push({ rowId: row.rowId, keyEpoch: row.keyEpoch, opened: await openMemberRow(cc, kObjectKey, objectId, row.rowId, row.encryptedRow, now), encryptedRow: row.encryptedRow });
    } catch { /* undecryptable with this key: a row under another epoch, or damaged */ }
  }
  return out;
}

export { chooseMemberSealTarget };
