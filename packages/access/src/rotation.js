/**
 * Removal: a new K_object (and K_detail), a new read capability, a new admin
 * capability, every remaining row carried across, and every row named so the
 * server can check the plan is whole and refuse one built on a stale epoch:
 * buildRotationPlan, and the member's refreshPointerAfterRotation, with the
 * version-2 contexts.
 *
 * WHICH ROWS ARE CARRIED. A row that is signed and verifies, and a quiet
 * row, are sealed to. A row that cannot have come from an honest
 * client — a signature that fails for this object and row, a stripped
 * signature, a row that does not open, a row naming no key — is SET ASIDE:
 * named as removed, never sealed to, reported so the owner is told. Sealing
 * the new key to whatever the server lists would let a server hand back a
 * removed member's old row under a remaining member's id.
 *
 * WHO GETS THE SECOND TIER: the same rule as the owner's sweep. The new
 * K_detail goes to the rotator, every admin, every row `grantDue` says, and
 * every row that already held a grant: a key change is aimed at the person
 * removed and nobody else loses it.
 *
 * WHO RUNS IT, so a removed admin keeps no power. A new admin capability and
 * K_adminbox every time; seats for the admins the box still lists, less
 * anyone removed or set aside; the rotator always among them.
 */
import { openMemberRow, chooseMemberSealTarget, resealMemberRow, rosterEntry, quietRotationKeys } from './envelope.js';
import { readAdmins, adminEntryForIdentity, adminEntryFromPayload, adminSeatTarget, buildAdminSeats, sealAdminBox } from './admin.js';
import { sealContent, sealDetail, generateDetailKey, buildDetailGrants, detailGrantLabel, readCapability, hashCapability, sealObjectKeyForMember, unwrapObjectKey } from './object.js';

export const SET_ASIDE_REASONS = Object.freeze(['unreadable', 'bad-signature', 'unsigned-envelope', 'no-key']);

async function rotationViewOfRow(cc, kObjectKey, objectId, row, now) {
  let opened;
  try { opened = await openMemberRow(cc, kObjectKey, objectId, row.rowId, row.encryptedRow, now); } catch { return { setAside: 'unreadable' }; }
  if (!opened.quiet) {
    if (!opened.signed) return { setAside: 'unsigned-envelope', opened };
    if (!opened.verified) return { setAside: 'bad-signature', opened };
  }
  let target;
  try { target = chooseMemberSealTarget(cc, opened.payload, now); } catch { return { setAside: 'no-key', opened }; }
  return { opened, target };
}

/**
 * buildRotationPlan(cc, { objectId, identity, oldKObjectRaw, oldEpoch, content, rows, remove, selfRowId,
 *                         twoTier: { split, detailOpened } | null, grantDue, now })
 *   content   the object as it stands, merged with its second tier where there is one
 *   rows      every active row as the server returns them: { rowId, keyEpoch, encryptedRow }
 */
export async function buildRotationPlan(cc, { objectId, identity, oldKObjectRaw, oldEpoch, content, rows, remove = [], selfRowId = null, twoTier = null, grantDue = () => false, now = Date.now() } = {}) {
  if (typeof objectId !== 'string') throw new Error('buildRotationPlan: objectId is required');
  if (!identity || !identity.identitySigning || !identity.identity) throw new Error('buildRotationPlan: the rotating identity is required');
  if (!(oldKObjectRaw instanceof Uint8Array) || oldKObjectRaw.length !== 32) throw new Error('buildRotationPlan: oldKObjectRaw (32 bytes) is required');
  if (!Number.isInteger(oldEpoch) || oldEpoch < 1) throw new Error('buildRotationPlan: oldEpoch must be an integer >= 1');
  if (!content || typeof content !== 'object') throw new Error('buildRotationPlan: the content is required');
  if (twoTier && (typeof twoTier.split !== 'function' || twoTier.detailOpened !== true)) {
    throw Object.assign(new Error('this device does not hold the object\'s second tier, so it cannot re-key without losing it'), { code: 'rotation-needs-detail' });
  }
  const oldKObjectKey = await cc.importSymmetricKey(oldKObjectRaw);
  const removing = new Set(remove);
  const newEpoch = oldEpoch + 1;
  const selfSigningKey = cc.toBase64Url(identity.identitySigning.publicKeyRaw);

  const kept = [];
  const setAside = [];
  const leavingIds = new Set();
  const leavingKeys = new Set();
  for (const row of rows || []) {
    const view = await rotationViewOfRow(cc, oldKObjectKey, objectId, row, now);
    const signing = view.opened && view.opened.verified && view.opened.identitySigningKeyRaw ? cc.toBase64Url(view.opened.identitySigningKeyRaw) : null;
    if (removing.has(row.rowId)) { leavingIds.add(row.rowId); if (signing) leavingKeys.add(signing); continue; }
    if (view.setAside) {
      if (selfRowId && row.rowId === selfRowId) throw Object.assign(new Error('the rotator\'s own row did not check out; nothing was changed'), { code: 'rotation-self-set-aside', reason: view.setAside });
      setAside.push({ rowId: row.rowId, reason: view.setAside });
      leavingIds.add(row.rowId);
      continue;
    }
    kept.push({ row, opened: view.opened, target: view.target, signing });
  }

  // Who runs it: the admins the box still lists, less anyone leaving; new capability, new box key.
  let admins = [];
  const read = await readAdmins(cc, identity, content, objectId, oldEpoch);
  if (read) admins = read.admins;
  admins = admins.filter((a) => !(a.rowId && leavingIds.has(a.rowId)) && !leavingKeys.has(a.signingKey));
  const keptBySigning = new Map(kept.filter((k) => k.signing).map((k) => [k.signing, k]));
  admins = admins.map((a) => { const k = keptBySigning.get(a.signingKey); return (k && adminEntryFromPayload(cc, k.opened.payload, k.row.rowId)) || a; });
  if (!admins.some((a) => a.signingKey === selfSigningKey)) admins.unshift(adminEntryForIdentity(cc, identity, selfRowId));
  const adminSigningKeys = new Set(admins.map((a) => a.signingKey));
  const adminCapabilitySecret = cc.randomBytes(32);
  const kAdminboxRaw = cc.generateSymmetricKey();
  const adminBlock = {
    adminSeats: await buildAdminSeats(cc, admins, { objectId, epoch: newEpoch, adminCapabilitySecret, kAdminboxRaw }),
    adminBox: await sealAdminBox(cc, kAdminboxRaw, objectId, newEpoch, admins),
  };

  const newKObjectRaw = cc.generateSymmetricKey();
  const newKObjectKey = await cc.importSymmetricKey(newKObjectRaw);

  let newKDetailRaw = null;
  let encryptedDetail = null;
  let preview = { ...content };
  if (twoTier) {
    newKDetailRaw = generateDetailKey(cc);
    const parts = twoTier.split(content);
    encryptedDetail = await sealDetail(cc, await cc.importSymmetricKey(newKDetailRaw), objectId, newEpoch, parts.detail);
    const oldGrants = content.detailGrants || {};
    const targets = [identity.identity.publicKeyRaw];
    for (const a of admins) { try { targets.push(adminSeatTarget(cc, a)); } catch { /* no usable key: no grant */ } }
    for (const k of kept) {
      const heldBefore = Boolean(oldGrants[await detailGrantLabel(cc, oldKObjectRaw, k.target)]);
      const due = grantDue(rosterEntry(k.row.rowId, k.row.keyEpoch, k.opened));
      if (heldBefore || due || (k.signing && adminSigningKeys.has(k.signing))) targets.push(k.target);
    }
    const unique = [...new Map(targets.map((t) => [cc.toHex(t), t])).values()];
    preview = { ...parts.preview, detailGrants: await buildDetailGrants(cc, newKObjectRaw, newKDetailRaw, unique) };
  }
  preview.adminSeats = adminBlock.adminSeats;
  preview.adminBox = adminBlock.adminBox;

  const encryptedContent = await sealContent(cc, newKObjectKey, objectId, newEpoch, preview);
  const readCapabilityHash = await hashCapability(cc, await readCapability(cc, newKObjectRaw));
  const adminCapabilityHash = await hashCapability(cc, adminCapabilitySecret);

  const updates = [];
  for (const k of kept) {
    updates.push({
      rowId: k.row.rowId,
      encryptedRow: await resealMemberRow(cc, oldKObjectKey, newKObjectKey, objectId, k.row.rowId, k.row.encryptedRow),
      encryptedObjectKey: await sealObjectKeyForMember(cc, k.target, newKObjectRaw),
    });
  }

  return {
    expectedEpoch: oldEpoch, newEpoch, newKObjectRaw, newKDetailRaw,
    encryptedContent, encryptedDetail, readCapabilityHash, adminCapabilitySecret, adminCapabilityHash,
    updates, removedRowIds: [...leavingIds], setAside, admins: admins.length, previewContent: preview,
  };
}

/**
 * A remaining member's self-refresh once their pointer's epoch lags the
 * object's: the new K_object from their own row (the quiet keys tried first,
 * the identity key second — the pointer is only evidence about which the
 * row was written with) and a pointer rewritten with only the key and epoch
 * changed.
 */
export async function refreshPointerAfterRotation(cc, { identity, objectId, myRow, existingPointer, pointerCodec }) {
  let kObjectRaw = null;
  if (existingPointer && existingPointer.quietRotationKey) {
    try {
      ({ kObjectRaw } = await unwrapObjectKey(cc, await quietRotationKeys(cc, existingPointer.quietRotationKey, existingPointer.quietRotationKemSeed), myRow.encryptedObjectKey));
    } catch { kObjectRaw = null; }
  }
  if (!kObjectRaw) ({ kObjectRaw } = await unwrapObjectKey(cc, { classical: identity.identity, kem: identity.identityKem ? identity.identityKem.privateKey : null }, myRow.encryptedObjectKey));
  return { kObjectRaw, pointer: await pointerCodec.build(identity, { ...existingPointer, objectId, kObject: kObjectRaw, keyEpoch: myRow.keyEpoch }) };
}
