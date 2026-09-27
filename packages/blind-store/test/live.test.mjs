// The live watches (DESIGN.md §2.3) over a real LISTEN connection: routed
// by the selector the server already sees, re-read before sending,
// content-free for member rows, collapsed for a rotation, the imminent
// watch by the collection's own window, and the mailbox wake-up.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as id from '@microtoll/identity';
import * as ac from '@microtoll/access';
import { requireDatabase } from './tooling/db.mjs';
import { startServer, person, makeAccess, cc, daysAhead } from './tooling/harness.mjs';

let db = null;
let s = null;
const access = makeAccess();
const sel = () => Math.random().toString(36).slice(2, 7).padEnd(5, 'x');
const today = (offset) => { const d = new Date(); d.setUTCDate(d.getUTCDate() + offset); return d.toISOString().slice(0, 10); };
const events = (extra = {}) => ({ collection: 'events', selector: sel(), windowStart: '2026-10-01', windowEnd: '2026-10-02', ...extra });

before(async () => {
  db = await requireDatabase();
  if (!db) return;
  s = await startServer({ db });
  assert.equal(s.store.live.isSubscribed(), true, 'the LISTEN connection is up');
});
after(async () => { if (s) await s.close(); if (db) await db.owner.end(); });
const needsDb = (t) => { if (!db) { t.skip('no test database'); return false; } return true; };

/** Collects live pushes on a socket; `next()` resolves with the next one, `none(ms)` proves silence. */
function listener(ws) {
  const queue = []; const waiters = [];
  const stop = access.onLiveObject(ws, (m) => { if (waiters.length) waiters.shift()(m); else queue.push(m); });
  const api = {
    next: (ms = 3000) => new Promise((resolve, reject) => { if (queue.length) return resolve(queue.shift()); const t = setTimeout(() => reject(new Error('no live push')), ms); waiters.push((m) => { clearTimeout(t); resolve(m); }); }),
    // The next push of one kind: a create lands two pushes ('created' at
    // once, the owner's row as a debounced 'participation'), and the two
    // re-reads race, so a test names the kind it is waiting for.
    nextOf: async (kind, ms = 3000) => { const deadline = Date.now() + ms; for (;;) { const m = await api.next(Math.max(1, deadline - Date.now())); if (m.kind === kind) return m; } },
    none: (ms = 700) => new Promise((resolve, reject) => { if (queue.length) return reject(new Error('unexpected push: ' + JSON.stringify(queue[0]))); const t = setTimeout(() => { const i = waiters.indexOf(w); if (i >= 0) waiters.splice(i, 1); resolve(); }, ms); const w = (m) => { clearTimeout(t); reject(new Error('unexpected push: ' + JSON.stringify(m))); }; waiters.push(w); }),
    // Swallows whatever lands within the window: an object published just
    // before a watch was registered still has its owner's row pushing a
    // debounced 'participation' to the new watcher.
    drain: (ms = 700) => new Promise((resolve) => setTimeout(() => { queue.length = 0; resolve(); }, ms)),
    stop,
  };
  return api;
}
const published = async (owner, selector, content = { title: 'x' }) => {
  const c = await access.createObject({ identity: owner.identity, content, ownerRowContent: { status: 'going' } });
  await access.createObjectMessage(owner.ws, c, selector);
  return { ...c, selector };
};

test('an edit pushes a decryptable update to a watcher of that selector, and nothing to watchers of another selector or another window; an all-watcher hears it', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const here = await person(s); const there = await person(s); const later = await person(s); const all = await person(s);
  const c = await published(owner, events());
  await access.watchObjects(here.ws, { collection: 'events', selectors: [c.selector.selector], windowStart: '2026-10-01' });
  await access.watchObjects(there.ws, { collection: 'events', selectors: [sel()], windowStart: '2026-10-01' });
  await access.watchObjects(later.ws, { collection: 'events', selectors: [c.selector.selector], windowStart: '2026-11-01', windowEnd: '2026-11-30' });
  await access.watchObjects(all.ws, { collection: 'events', all: true, windowStart: '2026-10-01', windowEnd: '2026-10-31' });
  const L = { here: listener(here.ws), there: listener(there.ws), later: listener(later.ws), all: listener(all.ws) };
  await Promise.all(Object.values(L).map((l) => l.drain()));
  const key = await cc.importSymmetricKey(c.kObjectRaw);
  const content = await ac.sealContent(cc, key, c.objectId, 1, { ...c.previewContent, title: 'edited' });
  await access.updateObject(owner.ws, { objectId: c.objectId, adminCapabilitySecret: c.adminCapabilitySecret, keyEpoch: 1, encryptedContent: content, selector: c.selector });
  const m = await L.here.nextOf('updated');
  assert.equal((await ac.openContent(cc, key, c.objectId, 1, m.object.encryptedContent)).title, 'edited');
  assert.equal(m.object.adminCapabilityHash, null);
  await L.all.nextOf('updated');
  await L.there.none(); await L.later.none();
  for (const l of Object.values(L)) l.stop();
  for (const p of [owner, here, there, later, all]) p.close();
});

test('created and deleted are pushed; an object moved to another selector reaches the watchers of the selector it left; unwatch stops the selector watch', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const w = await person(s);
  const cell = sel();
  await access.watchObjects(w.ws, { collection: 'events', selectors: [cell], windowStart: '2026-10-01', windowEnd: '2026-10-31' });
  const L = listener(w.ws);
  const c = await published(owner, events({ selector: cell }));
  const created = await L.nextOf('created');
  assert.equal(created.objectId, c.objectId);
  await L.nextOf('participation'); // the owner's own row, debounced
  await access.deleteObject(owner.ws, c.objectId, c.adminCapabilitySecret);
  const deleted = await L.nextOf('deleted');
  assert.equal(deleted.objectId, c.objectId);
  // An object that moves away reaches the watcher of the cell it left, carrying where it went.
  const d = await published(owner, events({ selector: cell }));
  await L.nextOf('created'); await L.nextOf('participation');
  const key = await cc.importSymmetricKey(d.kObjectRaw);
  const content = await ac.sealContent(cc, key, d.objectId, 1, d.previewContent);
  await access.updateObject(owner.ws, { objectId: d.objectId, adminCapabilitySecret: d.adminCapabilitySecret, keyEpoch: 1, encryptedContent: content, selector: events() });
  const moved = await L.nextOf('updated');
  assert.notEqual(moved.object.fields.selector, cell, 'the watcher of the old cell learns where it went');
  // Gone from this cell: its deletion is no longer this watcher's news.
  await access.deleteObject(owner.ws, d.objectId, d.adminCapabilitySecret);
  await L.none(400);
  await access.unwatchObjects(w.ws);
  await published(owner, events({ selector: cell }));
  await L.none();
  L.stop(); owner.close(); w.close();
});

test('a member-row change pushes a content-free participation update; a rotation\'s per-member writes collapse into one', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const bob = await person(s); const w = await person(s);
  const c = await published(owner, events());
  await access.watchObjects(w.ws, { collection: 'events', selectors: [c.selector.selector], windowStart: '2026-10-01' });
  const L = listener(w.ws);
  await L.drain();
  const bobRow = await access.buildMemberRow({ identity: bob.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  await access.joinObject(bob.ws, { objectId: c.objectId, pointer: await access.buildReadOnlyPointer({ identity: bob.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1 }), row: bobRow, readCapabilitySecret: c.readCapabilitySecret });
  const m = await L.next();
  assert.deepEqual(m, { kind: 'participation', object: null, objectId: c.objectId });
  await L.none(400);
  const rows = await access.fetchMembers(owner.ws, c.objectId, { adminCapabilitySecret: c.adminCapabilitySecret });
  const plan = await access.buildRotationPlan({ objectId: c.objectId, identity: owner.identity, oldKObjectRaw: c.kObjectRaw, oldEpoch: 1, content: c.previewContent, rows, selfRowId: c.ownerRow.rowId });
  await access.rotateObjectKey(owner.ws, c.objectId, c.adminCapabilitySecret, plan);
  const kinds = [(await L.next()).kind, (await L.next()).kind].sort();
  assert.deepEqual(kinds, ['participation', 'updated'], 'one re-sealed object, one collapsed participation');
  await L.none(500);
  L.stop(); owner.close(); bob.close(); w.close();
});

test('the imminent watch carries tomorrow\'s change to somebody watching elsewhere, and stays silent about one a fortnight away; it survives unwatch', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const w = await person(s);
  await access.watchObjects(w.ws, { collection: 'events', selectors: [sel()], windowStart: today(0), windowEnd: today(30) });
  await access.watchImminent(w.ws);
  await access.unwatchObjects(w.ws);
  const L = listener(w.ws);
  const soon = await published(owner, events({ windowStart: today(1), windowEnd: today(1) }));
  const m = await L.nextOf('created');
  assert.equal(m.objectId, soon.objectId);
  await L.nextOf('participation'); // the owner's row, also inside the window
  await published(owner, events({ windowStart: today(14), windowEnd: today(15) }));
  await L.none();
  L.stop(); owner.close(); w.close();
});

test('a hidden object is pushed as deleted, and a hidden object\'s member change is not pushed', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const w = await person(s);
  const c = await published(owner, events());
  await access.watchObjects(w.ws, { collection: 'events', selectors: [c.selector.selector], windowStart: '2026-10-01' });
  const L = listener(w.ws);
  await L.drain();
  await db.owner.query("UPDATE objects SET status = 'hidden' WHERE id = $1", [c.objectId]);
  await L.nextOf('deleted'); // the owner's own row may still push a debounced 'participation' first
  await db.owner.query('UPDATE object_members SET key_epoch = key_epoch WHERE object_id = $1', [c.objectId]);
  await L.none();
  L.stop(); owner.close(); w.close();
});

test('a mailbox drop wakes the connection watching that label, and no other', async (t) => {
  if (!needsDb(t)) return;
  const sender = await person(s); const mine = await person(s); const other = await person(s);
  const label = cc.randomBytes(32);
  const watch = (ws, ids) => id.sendAndAwait(ws, { type: 'watch-invites', mailboxIds: ids.map((x) => cc.toBase64Url(x)) }, 'watch-invites-ok', 'watch-invites-failed');
  await watch(mine.ws, [label]);
  await watch(other.ws, [cc.randomBytes(32)]);
  const heard = [];
  // Armed BEFORE the drop is sent: the wake-up can reach the watcher before
  // the sender's own send-invite-ok does (the trigger fires at commit).
  let wake;
  const woke = new Promise((resolve, reject) => { const t = setTimeout(() => reject(new Error('no wake-up')), 3000); wake = () => { clearTimeout(t); resolve(); }; });
  for (const [who, ws] of [['mine', mine.ws], ['other', other.ws]]) ws.addEventListener('message', (e) => { const m = JSON.parse(e.data); if (m.type === 'invite-live') { heard.push([who, m.mailboxId]); wake(); } });
  await id.sendAndAwait(sender.ws, { type: 'send-invite', mailboxId: cc.toBase64Url(label), encryptedBundle: cc.toBase64Url(cc.randomBytes(8)), expiresAt: daysAhead(1) }, 'send-invite-ok', 'send-invite-failed');
  await woke;
  await new Promise((r) => setTimeout(r, 300));
  assert.deepEqual(heard, [['mine', cc.toHex(label)]]);
  await assert.rejects(watch(mine.ws, []), (e) => e.reason === 'invalid');
  sender.close(); mine.close(); other.close();
});

test('without live configured, the watches answer unsupported', async (t) => {
  if (!needsDb(t)) return;
  const p = await startServer({ db, live: null });
  try {
    const w = await person(p);
    await assert.rejects(access.watchObjects(w.ws, { collection: 'events', selectors: ['abcde'], windowStart: '2026-10-01' }), (e) => e.reason === 'unsupported');
    await assert.rejects(access.watchImminent(w.ws), (e) => e.reason === 'unsupported');
    w.close();
  } finally { await p.close(); }
});
