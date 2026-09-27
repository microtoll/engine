// The notes app, without a page: everything it does with the packages, so
// the same code runs in the browser (page.js) and in Node (test/). Read
// this file first; it is the whole model.
//
// A note is an object in the `notes` collection. Its content {title, body}
// is sealed under K_object; its owner holds the admin capability; a reader
// who opens a share link gets K_object and a read-only pointer, and becomes
// a member by "joining" (the protocol calls it a first reaction). The owner
// can remove a member: every key rotates and the removed key opens nothing
// written afterwards.
//
// THE SHELF is the coarse public selector. When a note is created the app
// picks one of 256 shelves at random and keeps it in the note's pointer
// (the access package's pointer extension). To list its notes the app asks
// the server for every note on the shelves it uses and decrypts only its
// own. What the server learns: which shelves this routing key reads. What
// it cannot learn: which notes on a shelf are this account's. Cover is only
// as deep as the crowd on a shelf -- the same honesty any coarse selector
// owes its users.
import { createAccess, asIs } from '@microtoll/access';
import * as ac from '@microtoll/access';

export const COLLECTION = 'notes';
export const SHELVES = 256;

/** One of 256 shelves, at random: two hex characters. */
export function pickShelf(cc) {
  return cc.randomBytes(1)[0].toString(16).padStart(2, '0');
}

/**
 * createNotes({ cryptoCore, session })
 *   session  an identity session (createIdentitySession) that is unlocked:
 *            its `state()` gives the identity and the open socket, and
 *            `ensureConnected()` reconnects.
 */
export function createNotes({ cryptoCore: cc, session }) {
  const access = createAccess({ cryptoCore: cc, pointerFields: { shelf: { wire: 'shelf', ...asIs } } });
  const me = () => { const s = session.state(); if (s.locked || !s.identity) throw new Error('unlock first'); return s.identity; };
  const ws = () => session.ensureConnected();
  const selectorOf = (shelf) => ({ collection: COLLECTION, selector: shelf });

  /** Every pointer this account holds, opened: objectId -> { pointerId, p }. */
  async function myPointers() {
    const identity = me();
    const out = new Map();
    for (const { pointerId, sealed } of await access.fetchPointers(await ws())) {
      try {
        const p = await access.pointerCodec.open(identity, sealed);
        out.set(p.objectId, { pointerId, p });
      } catch { /* not this app's pointer, or not this account's: skipped */ }
    }
    return out;
  }

  /** The content a note's holder can read, or null when the held key no longer opens it (removed after a rotation). */
  async function openNote(objectId, kObjectRaw, fetched) {
    try {
      const key = await cc.importSymmetricKey(kObjectRaw);
      const content = await ac.openContent(cc, key, objectId, fetched.keyEpoch, fetched.encryptedContent);
      return content;
    } catch { return null; }
  }

  /**
   * The notes this account can read: the shelves from its pointers, one
   * query for all of them, and only the rows it holds keys for opened. A
   * row that will not open with the held key is reported `stale` (the note
   * was re-keyed; heal() fetches the member's own row for the new key).
   */
  async function list() {
    const pointers = await myPointers();
    const shelves = [...new Set([...pointers.values()].map(({ p }) => p.shelf).filter(Boolean))];
    if (shelves.length === 0) return [];
    const { objects } = await access.queryObjects(await ws(), { collection: COLLECTION, selectors: shelves });
    const notes = [];
    for (const o of objects) {
      const held = pointers.get(o.objectId);
      if (!held) continue; // cover traffic: someone else's note on a shared shelf
      const content = await openNote(o.objectId, held.p.kObject, o);
      notes.push({
        id: o.objectId, shelf: o.fields.selector, keyEpoch: o.keyEpoch,
        title: content ? content.title : null, body: content ? content.body : null,
        mine: Boolean(held.p.adminCapabilitySecret), member: Boolean(held.p.rowCapabilitySecret),
        stale: !content || held.p.keyEpoch !== o.keyEpoch,
      });
    }
    // Pointers whose note no longer exists are dropped here, on the next use.
    const seen = new Set(objects.map((o) => o.objectId));
    for (const [objectId, { pointerId }] of pointers) if (!seen.has(objectId)) await access.deletePointer(await ws(), pointerId).catch(() => {});
    return notes;
  }

  async function create({ title, body }) {
    const identity = me();
    const shelf = pickShelf(cc);
    const c = await access.createObject({ identity, content: { title, body }, ownerRowContent: { role: 'owner' } });
    // The pointer carries the shelf so the app knows where to ask for this note.
    c.pointer = await access.pointerCodec.build(identity, {
      objectId: c.objectId, kObject: c.kObjectRaw, keyEpoch: 1, rowCapabilitySecret: c.ownerRow.rowCapabilitySecret, adminCapabilitySecret: c.adminCapabilitySecret, shelf,
    });
    await access.createObjectMessage(await ws(), c, selectorOf(shelf));
    return { id: c.objectId, shelf };
  }

  /** The owner edits: the content is re-sealed under the current key at the current epoch. */
  async function update(id, { title, body }) {
    const held = (await myPointers()).get(id);
    if (!held || !held.p.adminCapabilitySecret) throw new Error('not your note');
    const fetched = await access.fetchObject(await ws(), id);
    const key = await cc.importSymmetricKey(held.p.kObject);
    const current = await ac.openContent(cc, key, id, fetched.keyEpoch, fetched.encryptedContent);
    const sealed = await ac.sealContent(cc, key, id, fetched.keyEpoch, { ...current, title, body });
    await access.updateObject(await ws(), { objectId: id, adminCapabilitySecret: held.p.adminCapabilitySecret, keyEpoch: fetched.keyEpoch, encryptedContent: sealed, selector: selectorOf(held.p.shelf) });
  }

  /** A share link: the token stays in the URL fragment and never reaches the server. Returns the fragment to append to the page's address. */
  async function share(id, { maxUses = 10, days = 7 } = {}) {
    const held = (await myPointers()).get(id);
    if (!held || !held.p.adminCapabilitySecret) throw new Error('not your note');
    const link = await access.createShareLink({ objectId: id, kObjectRaw: held.p.kObject, maxUses, expiresAt: new Date(Date.now() + days * 86400000).toISOString(), creator: me(), keyEpoch: held.p.keyEpoch });
    await access.publishShareLink(await ws(), link);
    return { fragment: `#note=${link.token}`, token: link.token };
  }

  /** Opening a link: redeem it, fetch the note, keep a read-only pointer with the shelf, read it. */
  async function open(token) {
    const identity = me();
    const socket = await ws();
    const payload = await access.redeemShareLinkMessage(socket, await access.hashToken(token));
    const redeemed = await access.redeemShareLink(token, payload);
    const fetched = await access.fetchObject(socket, redeemed.objectId);
    const pointer = await access.buildReadOnlyPointer({ identity, objectId: redeemed.objectId, kObjectRaw: redeemed.kObjectRaw, keyEpoch: fetched.keyEpoch, extra: { shelf: fetched.fields.selector } });
    await access.joinObject(socket, { objectId: redeemed.objectId, pointer });
    const content = await openNote(redeemed.objectId, redeemed.kObjectRaw, fetched);
    return { id: redeemed.objectId, title: content && content.title, body: content && content.body, verifiedCreator: redeemed.verified === true };
  }

  /** Becoming a member of a note held read-only: the first reaction, which gives this account a signed row the owner can see and remove. */
  async function join(id, { name }) {
    const identity = me();
    const held = (await myPointers()).get(id);
    if (!held) throw new Error('no pointer for this note');
    const first = await access.buildFirstReaction({ identity, objectId: id, kObjectRaw: held.p.kObject, keyEpoch: held.p.keyEpoch, content: { name }, existingPointer: held.p });
    await access.createMemberRow(await ws(), { objectId: id, row: first.row, pointerId: held.pointerId, pointer: first.pointer, readCapabilitySecret: first.readCapabilitySecret });
  }

  /** Who holds a row on this note, with the display rule applied (verified rows show their name; forged ones show nothing). */
  async function members(id) {
    const held = (await myPointers()).get(id);
    if (!held) throw new Error('no pointer for this note');
    const auth = held.p.adminCapabilitySecret ? { adminCapabilitySecret: held.p.adminCapabilitySecret } : { readCapabilitySecret: await access.readCapability(held.p.kObject) };
    const rows = await access.fetchMembers(await ws(), id, auth);
    const roster = access.roster(await access.openRows({ kObjectRaw: held.p.kObject, objectId: id, rows }));
    return roster.map((e) => ({ rowId: e.id, name: e.content ? (e.content.name || e.content.role || null) : null, verified: e.verified, quiet: e.quiet }));
  }

  /** The owner removes a member: a new key for everyone else in one checked transaction; the owner's own pointer moves to the new key. */
  async function remove(id, rowId) {
    const identity = me();
    const held = (await myPointers()).get(id);
    if (!held || !held.p.adminCapabilitySecret) throw new Error('not your note');
    const socket = await ws();
    const fetched = await access.fetchObject(socket, id);
    const key = await cc.importSymmetricKey(held.p.kObject);
    const content = await ac.openContent(cc, key, id, fetched.keyEpoch, fetched.encryptedContent);
    const rows = await access.fetchMembers(socket, id, { adminCapabilitySecret: held.p.adminCapabilitySecret });
    const plan = await access.buildRotationPlan({ objectId: id, identity, oldKObjectRaw: held.p.kObject, oldEpoch: fetched.keyEpoch, content, rows, remove: [rowId], selfRowId: null });
    const newEpoch = await access.rotateObjectKey(socket, id, held.p.adminCapabilitySecret, plan);
    const pointer = await access.pointerCodec.build(identity, { ...held.p, kObject: plan.newKObjectRaw, keyEpoch: newEpoch, adminCapabilitySecret: plan.adminCapabilitySecret });
    await access.updatePointer(socket, held.pointerId, pointer);
    return newEpoch;
  }

  /** A member whose note was re-keyed (and who was kept) picks up the new key from their own row. */
  async function heal(id) {
    const identity = me();
    const held = (await myPointers()).get(id);
    if (!held || !held.p.rowCapabilitySecret) throw new Error('no member row to heal from');
    const socket = await ws();
    const myRow = await access.fetchMyRow(socket, id, held.p.rowCapabilitySecret);
    const refreshed = await access.refreshPointerAfterRotation({ identity, objectId: id, myRow, existingPointer: held.p });
    await access.updatePointer(socket, held.pointerId, refreshed.pointer);
    return refreshed.kObjectRaw !== null;
  }

  async function destroy(id) {
    const held = (await myPointers()).get(id);
    if (!held || !held.p.adminCapabilitySecret) throw new Error('not your note');
    const socket = await ws();
    await access.deleteObject(socket, id, held.p.adminCapabilitySecret);
    await access.deletePointer(socket, held.pointerId);
  }

  /** Live: re-run `onChange` when any note on this account's shelves changes. Returns a stop function. */
  async function watch(onChange) {
    const pointers = await myPointers();
    const shelves = [...new Set([...pointers.values()].map(({ p }) => p.shelf).filter(Boolean))];
    const socket = await ws();
    if (shelves.length) await access.watchObjects(socket, { collection: COLLECTION, selectors: shelves });
    return access.onLiveObject(socket, () => onChange());
  }

  /** The pointer this account holds for a note, opened: { pointerId, p } or null. (The invite example builds on it.) */
  async function held(id) { return (await myPointers()).get(id) || null; }

  return { access, list, create, update, share, open, join, members, remove, heal, destroy, watch, held, pickShelf: () => pickShelf(cc) };
}

/** The token from a page address such as https://host/#note=<token>, or null. */
export function tokenFromLocation(hash) {
  const m = /(?:^#|[#&])note=([A-Za-z0-9_-]+)/.exec(hash || '');
  return m ? m[1] : null;
}
