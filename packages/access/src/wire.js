/**
 * The client side of the object, member, pointer and share-link messages.
 * Message names, field names and encodings are the server protocol
 * blind-store speaks (D-27); some say "event" (`create-event`, `eventUserId`)
 * where the functions here say "object". Bytes travel as base64url;
 * capability hashes as base64url of the raw 32 bytes.
 *
 * The coarse selector (for blind-store: collection, selector, windowStart,
 * windowEnd, rosterMembersOnly) is the app's: it is spread into create-event
 * and update-event from `selector` and read back from fetch-event as `fields`.
 */
import { sendAndAwait } from '@microtoll/identity';

const hexToWire = (cc, hex) => cc.toBase64Url(cc.fromHex(hex));

function rowWire(cc, row) {
  return {
    eventUserId: row.rowId,
    encryptedParticipationDataBlob: cc.toBase64Url(row.encryptedRow),
    encryptedSharedEventKey: cc.toBase64Url(row.encryptedObjectKey),
    rowCapabilityHash: hexToWire(cc, row.rowCapabilityHash),
    keyEpoch: row.keyEpoch,
  };
}

function decodeObject(cc, e) {
  return {
    objectId: e.id,
    encryptedContent: cc.fromBase64Url(e.encryptedEventData),
    encryptedDetail: e.encryptedEventDetail ? cc.fromBase64Url(e.encryptedEventDetail) : null,
    keyEpoch: e.keyEpoch,
    adminCapabilityHash: e.adminCapabilityHash ? cc.fromBase64Url(e.adminCapabilityHash) : null,
    fields: e,
  };
}

/** create-event: the object, the owner's row and the owner's pointer in one transaction. */
export async function createObjectMessage(cc, ws, created, selector = {}) {
  const r = await sendAndAwait(ws, {
    type: 'create-event',
    eventId: created.objectId,
    encryptedEventData: cc.toBase64Url(created.encryptedContent),
    ...(created.encryptedDetail ? { encryptedEventDetail: cc.toBase64Url(created.encryptedDetail) } : {}),
    ...selector,
    adminCapabilityHash: hexToWire(cc, created.adminCapabilityHash),
    readCapabilityHash: hexToWire(cc, created.readCapabilityHash),
    creatorParticipation: rowWire(cc, created.ownerRow),
    pointer: { encryptedEventAccessBlob: cc.toBase64Url(created.pointer) },
  }, 'create-event-ok', 'create-event-failed');
  return r.eventId;
}

export async function fetchObject(cc, ws, objectId) {
  const r = await sendAndAwait(ws, { type: 'fetch-event', eventId: objectId }, 'event', 'fetch-event-failed');
  if (!r.event || r.event.id !== objectId) throw Object.assign(new Error('the server answered with a different object'), { code: 'crossed-reply' });
  return decodeObject(cc, r.event);
}

export function decodeObjectWire(cc, e) { return decodeObject(cc, e); }

/** join-event: read access only (a pointer), or with a member row proved by the read capability. */
export async function joinObject(cc, ws, { objectId, pointer, row = null, readCapabilitySecret = null }) {
  if (row && !readCapabilitySecret) throw new Error('joinObject: a member row needs the read capability');
  const r = await sendAndAwait(ws, {
    type: 'join-event',
    eventId: objectId,
    ...(row ? { participation: rowWire(cc, row), readCapabilitySecret: cc.toBase64Url(readCapabilitySecret) } : {}),
    pointer: { encryptedEventAccessBlob: cc.toBase64Url(pointer) },
  }, 'join-event-ok', 'join-event-failed');
  return r.eventId;
}

export async function fetchMembers(cc, ws, objectId, { adminCapabilitySecret = null, readCapabilitySecret = null, rowCapabilitySecret = null } = {}) {
  const r = await sendAndAwait(ws, {
    type: 'fetch-event-members',
    eventId: objectId,
    adminCapabilitySecret: adminCapabilitySecret ? cc.toBase64Url(adminCapabilitySecret) : undefined,
    readCapabilitySecret: readCapabilitySecret ? cc.toBase64Url(readCapabilitySecret) : undefined,
    rowCapabilitySecret: rowCapabilitySecret ? cc.toBase64Url(rowCapabilitySecret) : undefined,
  }, 'event-members', 'fetch-event-members-failed');
  return r.members.map((m) => ({ rowId: m.id, encryptedRow: cc.fromBase64Url(m.encryptedParticipationDataBlob), keyEpoch: m.keyEpoch }));
}

export async function rotateObjectKey(cc, ws, objectId, adminCapabilitySecret, plan) {
  const r = await sendAndAwait(ws, {
    type: 'rotate-event-key',
    eventId: objectId,
    adminCapabilitySecret: cc.toBase64Url(adminCapabilitySecret),
    expectedEpoch: plan.expectedEpoch,
    encryptedEventData: cc.toBase64Url(plan.encryptedContent),
    ...(plan.encryptedDetail ? { encryptedEventDetail: cc.toBase64Url(plan.encryptedDetail) } : {}),
    readCapabilityHash: hexToWire(cc, plan.readCapabilityHash),
    adminCapabilityHash: hexToWire(cc, plan.adminCapabilityHash),
    updates: plan.updates.map((u) => ({ eventUserId: u.rowId, encryptedParticipationDataBlob: cc.toBase64Url(u.encryptedRow), encryptedSharedEventKey: cc.toBase64Url(u.encryptedObjectKey) })),
    removedEventUserIds: plan.removedRowIds,
  }, 'rotate-event-key-ok', 'rotate-event-key-failed');
  return r.keyEpoch;
}

export async function fetchMyRow(cc, ws, objectId, rowCapabilitySecret) {
  const r = await sendAndAwait(ws, { type: 'fetch-my-participation', eventId: objectId, rowCapabilitySecret: cc.toBase64Url(rowCapabilitySecret) }, 'my-participation', 'fetch-my-participation-failed');
  return { rowId: r.member.id, encryptedRow: cc.fromBase64Url(r.member.encryptedParticipationDataBlob), encryptedObjectKey: cc.fromBase64Url(r.member.encryptedSharedEventKey), keyEpoch: r.member.keyEpoch };
}

/** create-participation: the first row on an object held read-only, with the replacement pointer. */
export async function createMemberRow(cc, ws, { objectId, row, pointerId, pointer, readCapabilitySecret }) {
  const r = await sendAndAwait(ws, {
    type: 'create-participation',
    eventId: objectId, pointerId,
    readCapabilitySecret: cc.toBase64Url(readCapabilitySecret),
    participation: rowWire(cc, row),
    pointer: { encryptedEventAccessBlob: cc.toBase64Url(pointer) },
  }, 'create-participation-ok', 'create-participation-failed');
  return r.eventUserId;
}

export async function updateMemberRowMessage(cc, ws, { objectId, rowCapabilitySecret, encryptedRow, keyEpoch, extra = {} }) {
  if (!Number.isInteger(keyEpoch) || keyEpoch < 1) throw new Error('updateMemberRow: keyEpoch is required');
  await sendAndAwait(ws, {
    type: 'update-participation', eventId: objectId, keyEpoch,
    rowCapabilitySecret: cc.toBase64Url(rowCapabilitySecret),
    encryptedParticipationDataBlob: cc.toBase64Url(encryptedRow),
    ...extra,
  }, 'update-participation-ok', 'update-participation-failed');
}

export async function updateObject(cc, ws, { objectId, adminCapabilitySecret, keyEpoch, encryptedContent, encryptedDetail = null, selector = {} }) {
  if (!Number.isInteger(keyEpoch) || keyEpoch < 1) throw new Error('updateObject: keyEpoch is required');
  await sendAndAwait(ws, {
    type: 'update-event', eventId: objectId, keyEpoch,
    adminCapabilitySecret: cc.toBase64Url(adminCapabilitySecret),
    encryptedEventData: cc.toBase64Url(encryptedContent),
    ...(encryptedDetail ? { encryptedEventDetail: cc.toBase64Url(encryptedDetail) } : {}),
    ...selector,
  }, 'update-event-ok', 'update-event-failed');
}

export async function deleteObject(cc, ws, objectId, adminCapabilitySecret) {
  await sendAndAwait(ws, { type: 'delete-event', eventId: objectId, adminCapabilitySecret: cc.toBase64Url(adminCapabilitySecret) }, 'delete-event-ok', 'delete-event-failed');
}

/** Resolves rather than throwing when no row matched: "nothing of yours here" is the desired end state. */
export async function deleteMyRow(cc, ws, objectId, rowCapabilitySecret) {
  const r = await sendAndAwait(ws, { type: 'delete-participation', eventId: objectId, rowCapabilitySecret: cc.toBase64Url(rowCapabilitySecret) }, 'delete-participation-ok', 'delete-participation-failed');
  return Boolean(r.deleted);
}

export async function fetchPointers(cc, ws) {
  const r = await sendAndAwait(ws, { type: 'fetch-pointers' }, 'pointers', 'fetch-pointers-failed');
  return r.pointers.map((p) => ({ pointerId: p.id, sealed: cc.fromBase64Url(p.encryptedEventAccessBlob) }));
}

export async function updatePointer(cc, ws, pointerId, sealed) {
  await sendAndAwait(ws, { type: 'update-pointer', pointerId, encryptedEventAccessBlob: cc.toBase64Url(sealed) }, 'update-pointer-ok', 'update-pointer-failed');
}

/** delete-pointer (blind-store, M4): discards one of the caller's own pointers -- an object gone, or left. Resolves false when it was already gone. */
export async function deletePointer(ws, pointerId) {
  const r = await sendAndAwait(ws, { type: 'delete-pointer', pointerId }, 'delete-pointer-ok', 'delete-pointer-failed');
  return Boolean(r.deleted);
}

// ---- the selector query and the live watches (blind-store, M4) ---------------

/**
 * query-events: everything active in a collection whose selector is named
 * (or all of them, where the collection allows it) and whose window
 * overlaps. The answer is not filtered by identity: decrypt what you hold
 * keys for and discard the rest -- that is the cover traffic the model relies
 * on. `extras` carries whatever the host's queryExtras added to the reply.
 *
 *   query: { collection, selectors: [...] | all: true, windowStart?, windowEnd? }
 */
export async function queryObjects(cc, ws, query) {
  const { events, type, requestId, ...extras } = await sendAndAwait(ws, { type: 'query-events', ...query }, 'events', 'query-events-failed');
  return { objects: (events || []).map((e) => decodeObject(cc, e)), extras };
}

/** watch-events: the same query shape as a standing watch; the last watch on a socket replaces the previous one. */
export async function watchObjects(ws, query) {
  await sendAndAwait(ws, { type: 'watch-events', ...query }, 'watch-events-ok', 'watch-events-failed');
}

export async function unwatchObjects(ws) {
  await sendAndAwait(ws, { type: 'unwatch-events' }, 'unwatch-events-ok', 'unwatch-events-failed');
}

/** watch-imminent carries nothing: the server's own per-collection window, every selector. */
export async function watchImminent(ws) {
  await sendAndAwait(ws, { type: 'watch-imminent' }, 'watch-imminent-ok', 'watch-imminent-failed');
}

/**
 * Live pushes: `handler({ kind, object, objectId })` for every 'event-live'
 * message -- kind 'created' or 'updated' with the decoded object, 'deleted'
 * or 'participation' with the id alone. Returns a function that stops
 * listening. Unsolicited messages never carry a request id, so nothing here
 * can satisfy a pending request.
 */
export function onLiveObject(cc, ws, handler) {
  const onMessage = (event) => {
    let msg;
    try { msg = JSON.parse(event.data); } catch { return; }
    if (msg.type !== 'event-live') return;
    if (msg.kind === 'created' || msg.kind === 'updated') handler({ kind: msg.kind, object: decodeObject(cc, msg.event), objectId: msg.event.id });
    else handler({ kind: msg.kind, object: null, objectId: msg.eventId });
  };
  ws.addEventListener('message', onMessage);
  return () => ws.removeEventListener('message', onMessage);
}

// ---- share links -----------------------------------------------------------

export async function publishShareLink(cc, ws, link) {
  await sendAndAwait(ws, {
    type: 'create-url-invite',
    hashedToken: link.hashedToken,
    encryptedPayload: cc.toBase64Url(link.encryptedPayload),
    maxUses: link.maxUses,
    expiresAt: link.expiresAt,
    manageCapabilityHash: hexToWire(cc, link.manageCapabilityHash),
  }, 'create-url-invite-ok', 'create-url-invite-failed');
}

/** Claims one use; the payload comes back sealed. Reasons: not-found, expired, exhausted. */
export async function redeemShareLinkMessage(cc, ws, hashedToken) {
  const r = await sendAndAwait(ws, { type: 'redeem-url-invite', hashedToken }, 'redeem-url-invite-ok', 'redeem-url-invite-failed');
  return cc.fromBase64Url(r.encryptedPayload);
}

export async function revokeShareLink(cc, ws, hashedToken, manageSecret) {
  const r = await sendAndAwait(ws, { type: 'revoke-url-invite', hashedToken, manageSecret: cc.toBase64Url(manageSecret) }, 'revoke-url-invite-ok', 'revoke-url-invite-failed');
  return r.revoked;
}

/** Use counts for links this account created; a pair that does not match is simply absent. */
export async function fetchShareLinkStats(cc, ws, links) {
  const r = await sendAndAwait(ws, {
    type: 'fetch-invite-token-stats',
    links: links.map((l) => ({ hashedToken: l.hashedToken, manageSecret: cc.toBase64Url(l.manageSecret) })),
  }, 'invite-token-stats', 'fetch-invite-token-stats-failed');
  return r.tokens;
}
