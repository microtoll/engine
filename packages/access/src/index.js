/**
 * @microtoll/access — public entry point.
 *
 * Layers: envelope.js (member rows), pointer.js, admin.js (seats and box),
 * object.js (keys, content, second tier, grants, builders), rotation.js,
 * links.js (share links), wire.js (the server messages). `createAccess` binds
 * them to one crypto-core instance and the app's three choices: its pointer
 * fields, its content split, and its grant rule.
 */
import * as envelope from './envelope.js';
import * as pointer from './pointer.js';
import * as admin from './admin.js';
import * as object from './object.js';
import * as rotation from './rotation.js';
import * as links from './links.js';
import * as wire from './wire.js';

export * from './envelope.js';
export * from './pointer.js';
export * from './admin.js';
export * from './object.js';
export * from './rotation.js';
export * from './links.js';
export * from './wire.js';

/**
 * createAccess({ cryptoCore, pointerFields, split, grantDue, merge })
 *   pointerFields  the app's pointer extension table { name: { wire, seal, open } }
 *   split          (content) → { preview, detail }, for two-tier objects
 *   grantDue       (rosterEntry) → boolean: who is owed the second tier (default: nobody but owners and admins)
 *   merge          (preview, detail) → content (default: detail wins)
 */
export function createAccess({ cryptoCore: cc, pointerFields = {}, split = null, grantDue = () => false, merge = object.defaultMerge } = {}) {
  if (!cc) throw new Error('createAccess needs a cryptoCore');
  const pointerCodec = pointer.createPointerCodec(cc, pointerFields);
  const bind = (fns) => Object.fromEntries(Object.entries(fns).map(([k, f]) => [k, (...a) => f(cc, ...a)]));

  return Object.freeze({
    cc, pointerCodec, split, grantDue, merge,
    // Objects and members
    createObject: (opts) => object.createObject(cc, { ...opts, pointerCodec, split: opts.split || split }),
    buildMemberRow: (opts) => object.buildMemberRow(cc, opts),
    buildQuietMemberRow: (opts) => object.buildQuietMemberRow(cc, opts),
    buildReadOnlyPointer: (opts) => object.buildReadOnlyPointer(cc, { ...opts, pointerCodec }),
    buildFirstReaction: (opts) => object.buildFirstReaction(cc, { ...opts, pointerCodec }),
    openRows: (opts) => object.openRows(cc, opts),
    roster: (rows, options) => rows.map((r) => envelope.rosterEntry(r.rowId, r.keyEpoch, r.opened, options)),
    openForViewer: (opts) => object.openForViewer(cc, { ...opts, merge: opts.merge || merge }),
    planDetailGrantSweep: (opts) => object.planDetailGrantSweep(cc, { ...opts, grantDue: opts.grantDue || grantDue }),
    buildRotationPlan: (opts) => rotation.buildRotationPlan(cc, { ...opts, grantDue: opts.grantDue || grantDue, twoTier: opts.twoTier ? { split: opts.twoTier.split || split, detailOpened: opts.twoTier.detailOpened } : null }),
    refreshPointerAfterRotation: (opts) => rotation.refreshPointerAfterRotation(cc, { ...opts, pointerCodec }),
    ...bind({
      sealContent: object.sealContent, openContent: object.openContent, sealDetail: object.sealDetail, openDetail: object.openDetail,
      readCapability: object.readCapability, hashCapability: object.hashCapability, newCapability: object.newCapability,
      sealObjectKeyForMember: object.sealObjectKeyForMember, unwrapObjectKey: object.unwrapObjectKey,
      detailGrantLabel: object.detailGrantLabel, buildDetailGrants: object.buildDetailGrants, openDetailGrant: object.openDetailGrant,
      sealMemberRow: envelope.sealMemberRow, sealQuietMemberRow: envelope.sealQuietMemberRow, openMemberRow: envelope.openMemberRow,
      updateMemberRow: envelope.updateMemberRow, resealMemberRow: envelope.resealMemberRow, chooseMemberSealTarget: envelope.chooseMemberSealTarget,
      generateQuietRotationKeys: envelope.generateQuietRotationKeys, quietRotationKeys: envelope.quietRotationKeys,
      readAdmins: admin.readAdmins, openAdminSeat: admin.openAdminSeat, addCoOwner: admin.addCoOwner, adminEntryForIdentity: admin.adminEntryForIdentity,
      createShareLink: links.createShareLink, redeemShareLink: links.redeemShareLink, hashToken: links.hashToken,
      // wire
      createObjectMessage: wire.createObjectMessage, fetchObject: wire.fetchObject, joinObject: wire.joinObject, fetchMembers: wire.fetchMembers,
      rotateObjectKey: wire.rotateObjectKey, fetchMyRow: wire.fetchMyRow, createMemberRow: wire.createMemberRow, updateMemberRowMessage: wire.updateMemberRowMessage,
      updateObject: wire.updateObject, deleteObject: wire.deleteObject, deleteMyRow: wire.deleteMyRow, fetchPointers: wire.fetchPointers, updatePointer: wire.updatePointer,
      publishShareLink: wire.publishShareLink, redeemShareLinkMessage: wire.redeemShareLinkMessage, revokeShareLink: wire.revokeShareLink, fetchShareLinkStats: wire.fetchShareLinkStats,
      queryObjects: wire.queryObjects, onLiveObject: wire.onLiveObject,
    }),
    watchObjects: wire.watchObjects, unwatchObjects: wire.unwatchObjects, watchImminent: wire.watchImminent, deletePointer: wire.deletePointer,
    rosterEntry: envelope.rosterEntry,
    goingGrantDue: object.goingGrantDue,
    tokenFromFragment: links.tokenFromFragment,
    normaliseLinkRecords: links.normaliseLinkRecords,
  });
}
