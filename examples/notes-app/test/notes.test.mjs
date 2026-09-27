// The notes example, driven from Node: notes.js against a real blind-store
// with the `notes` collection and a real database -- the integration test
// the build plan asks for (M4). Two people: the owner and a reader who
// opens a link, becomes a member, and is removed.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { createCryptoCore } from '@microtoll/crypto-core';
import { createIdentitySession, createSessionStore, createKnownAccountStore, memoryStore, memoryStorage } from '@microtoll/identity';
import { createBlindStore } from '@microtoll/blind-store';
import { requireDatabase } from '../../../packages/blind-store/test/tooling/db.mjs';
import { createNotes, tokenFromLocation, pickShelf, SHELVES } from '../notes.js';

const cc = createCryptoCore({ namespace: 'notes-example' });
const ORIGIN = 'http://localhost:8088';
let db = null, store = null, pool = null, url = null;

before(async () => {
  db = await requireDatabase();
  if (!db) return;
  pool = new pg.Pool({ ...db.appConfig, max: 5 });
  pool.on('error', () => {});
  store = createBlindStore({
    namespace: 'notes-example', allowedOrigins: [ORIGIN], pool, port: 0, host: '127.0.0.1',
    collections: { notes: { selectorLength: 2 } }, live: { connectionConfig: db.appConfig }, sweep: false, log: { info() {}, error() {} },
  });
  await new Promise((resolve) => store.httpServer.once('listening', resolve));
  url = `ws://127.0.0.1:${store.address().port}`;
});
after(async () => { if (store) await store.close(); if (pool) await pool.end(); if (db) await db.owner.end(); });

/** A person: an identity session in memory, signed up with a recovery code, and their notes app. */
async function personWithNotes() {
  const connect = () => new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.addEventListener('open', () => resolve(ws), { once: true });
    ws.addEventListener('error', () => reject(new Error('could not connect')), { once: true });
  });
  const session = createIdentitySession({
    cryptoCore: cc, origin: ORIGIN, transport: { connect },
    sessionStore: createSessionStore({ cryptoCore: cc, store: memoryStore() }),
    knownAccounts: createKnownAccountStore({ cryptoCore: cc, storage: memoryStorage() }),
    ui: { askRecoveryCode: async () => { throw new Error('not in this test'); }, confirmDeletion: async () => true },
  });
  await session.bootGuest();
  const { recoveryCode } = await session.registerCurrentIdentity({ label: 'test', passkey: 'none' });
  return { session, recoveryCode, notes: createNotes({ cryptoCore: cc, session }) };
}

test('a shelf is one of 256, two hex characters; the token comes out of a page address', () => {
  assert.equal(SHELVES, 256);
  for (let i = 0; i < 20; i++) assert.match(pickShelf(cc), /^[0-9a-f]{2}$/);
  assert.equal(tokenFromLocation('#note=abc_-9'), 'abc_-9');
  assert.equal(tokenFromLocation('#x=1&note=q'), 'q');
  assert.equal(tokenFromLocation(''), null);
});

test('the whole story: write, list by shelf, share, open, join, see members, remove, the old key fails, delete', async (t) => {
  if (!db) { t.skip('no test database'); return; }
  const owner = await personWithNotes();
  const reader = await personWithNotes();
  // Write two notes; they are filed on shelves and come back by the shelf query.
  const a = await owner.notes.create({ title: 'Shopping', body: 'milk' });
  const b = await owner.notes.create({ title: 'Ideas', body: '' });
  assert.match(a.shelf, /^[0-9a-f]{2}$/);
  let mine = await owner.notes.list();
  assert.deepEqual(mine.map((n) => n.title).sort(), ['Ideas', 'Shopping']);
  assert.ok(mine.every((n) => n.mine && n.member && !n.stale));
  await owner.notes.update(a.id, { title: 'Shopping', body: 'milk, bread' });
  assert.equal((await owner.notes.list()).find((n) => n.id === a.id).body, 'milk, bread');
  // The reader sees nothing yet: no pointers, no shelves, no query.
  assert.deepEqual(await reader.notes.list(), []);
  // A share link; the token never reaches the server.
  const { fragment, token } = await owner.notes.share(a.id, { maxUses: 2 });
  assert.equal(tokenFromLocation(fragment), token);
  const links = await db.owner.query('SELECT hashed_token FROM share_links');
  assert.ok(links.rows.every((r) => !r.hashed_token.includes(token)));
  const opened = await reader.notes.open(token);
  assert.equal(opened.title, 'Shopping');
  assert.equal(opened.body, 'milk, bread');
  assert.equal(opened.verifiedCreator, true);
  let theirs = await reader.notes.list();
  assert.equal(theirs.length, 1);
  assert.equal(theirs[0].mine, false); assert.equal(theirs[0].member, false);
  // The reader joins as a member; the owner sees a verified name.
  await reader.notes.join(a.id, { name: 'Bea' });
  theirs = await reader.notes.list();
  assert.equal(theirs[0].member, true);
  const members = await owner.notes.members(a.id);
  assert.deepEqual(members.map((m) => [m.name, m.verified]).sort(), [['Bea', true], ['owner', true]]);
  // The owner removes Bea: every key rotates; Bea's copy is stale and cannot heal; the owner still reads and writes.
  const bea = members.find((m) => m.name === 'Bea');
  assert.equal(await owner.notes.remove(a.id, bea.rowId), 2);
  await owner.notes.update(a.id, { title: 'Shopping', body: 'milk, bread, eggs' });
  const beaView = (await reader.notes.list()).find((n) => n.id === a.id);
  assert.equal(beaView.stale, true);
  assert.equal(beaView.body, null, 'the old key opens nothing written since');
  await assert.rejects(reader.notes.heal(a.id), /not-found/);
  assert.equal((await owner.notes.list()).find((n) => n.id === a.id).body, 'milk, bread, eggs');
  assert.deepEqual((await owner.notes.members(a.id)).map((m) => m.name), ['owner']);
  // The server holds ciphertext and shelves only.
  const rows = await db.owner.query('SELECT sealed_content, selector, collection FROM objects WHERE id = $1', [a.id]);
  assert.equal(rows.rows[0].collection, 'notes');
  assert.equal(rows.rows[0].selector, a.shelf);
  assert.ok(!Buffer.from(rows.rows[0].sealed_content).toString('latin1').includes('eggs'));
  // Delete: the owner's pointer goes with it; the reader's stale pointer is dropped on their next list.
  await owner.notes.destroy(a.id);
  assert.deepEqual((await owner.notes.list()).map((n) => n.id), [b.id]);
  assert.deepEqual(await reader.notes.list(), []);
  const ptr = await db.owner.query('SELECT count(*)::int AS n FROM pointers');
  assert.ok(ptr.rows[0].n >= 1);
  await owner.session.lock(); await reader.session.lock();
});

test('live: a watcher of the shelves is told when a note changes', async (t) => {
  if (!db) { t.skip('no test database'); return; }
  const owner = await personWithNotes();
  const a = await owner.notes.create({ title: 'Watch me', body: '' });
  let changes = 0;
  const stop = await owner.notes.watch(() => { changes++; });
  await owner.notes.update(a.id, { title: 'Watch me', body: 'changed' });
  await new Promise((r) => setTimeout(r, 1500));
  assert.ok(changes >= 1, `changes seen: ${changes}`);
  stop();
  await owner.notes.destroy(a.id);
  await owner.session.lock();
});
