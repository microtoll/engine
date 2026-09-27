// The invite example, driven from Node against a real blind-store and a
// real database: two people share a note by link, become contacts, and
// from then on invite each other directly -- collected live, acknowledged
// on opening, or taken back before it is collected.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { createCryptoCore } from '@microtoll/crypto-core';
import { createIdentitySession, createSessionStore, createKnownAccountStore, memoryStore, memoryStorage } from '@microtoll/identity';
import { createBlindStore } from '@microtoll/blind-store';
import { requireDatabase } from '../../../packages/blind-store/test/tooling/db.mjs';
import { tokenFromLocation } from '../../notes-app/notes.js';
import { createInvites } from '../invites.js';

const cc = createCryptoCore({ namespace: 'invite-example' });
const ORIGIN = 'http://localhost:8089';
let db = null, store = null, pool = null, url = null;

before(async () => {
  db = await requireDatabase();
  if (!db) return;
  pool = new pg.Pool({ ...db.appConfig, max: 5 });
  pool.on('error', () => {});
  store = createBlindStore({
    namespace: 'invite-example', allowedOrigins: [ORIGIN], pool, port: 0, host: '127.0.0.1',
    collections: { notes: { selectorLength: 2 } }, live: { connectionConfig: db.appConfig }, sweep: false, log: { info() {}, error() {} },
  });
  await new Promise((resolve) => store.httpServer.once('listening', resolve));
  url = `ws://127.0.0.1:${store.address().port}`;
});
after(async () => { if (store) await store.close(); if (pool) await pool.end(); if (db) await db.owner.end(); });

async function personNamed(name) {
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
  await session.registerCurrentIdentity({ label: 'test', passkey: 'none' });
  const app = createInvites({ cryptoCore: cc, session });
  return { name, session, app, signingKey: cc.toBase64Url(session.state().identity.identitySigning.publicKeyRaw) };
}

test('share a note by link, become contacts, then invite directly: collected live, acknowledged on opening; a second invitation taken back before collection opens for nobody', async (t) => {
  if (!db) { t.skip('no test database'); return; }
  const ada = await personNamed('Ada');
  const bea = await personNamed('Bea');
  // 1. Once, by link: Ada shares a note, Bea opens it and joins as a member.
  const first = await ada.app.notes.create({ title: 'How we met', body: '' });
  const { fragment } = await ada.app.notes.share(first.id);
  await bea.app.notes.open(tokenFromLocation(fragment));
  await bea.app.notes.join(first.id, { name: 'Bea' });
  assert.equal(await ada.app.rememberContacts(first.id), 1);
  assert.equal(await bea.app.rememberContacts(first.id), 1);
  assert.equal(ada.app.contacts()[0].signingKey, bea.signingKey);
  assert.equal(ada.app.contacts()[0].name, 'Bea');
  assert.equal(bea.app.contacts()[0].signingKey, ada.signingKey);
  assert.equal(bea.app.contacts()[0].name, 'owner');
  // 2. Directly, with nothing to forward: Ada invites Bea to a new note; Bea is woken and collects.
  const second = await ada.app.notes.create({ title: 'Direct', body: 'no link was made' });
  let woken = 0;
  const stop = await bea.app.watch(() => { woken++; });
  const sent = await ada.app.invite(second.id, bea.signingKey, { name: 'Ada' });
  assert.ok(sent.inviteId);
  await new Promise((r) => setTimeout(r, 1200));
  assert.ok(woken >= 1, 'the live wake-up reached Bea');
  stop();
  const got = await bea.app.collect();
  assert.deepEqual(got.newNotes.map((n) => [n.id, n.from]), [[second.id, 'Ada']]);
  const beaSees = (await bea.app.notes.list()).find((n) => n.id === second.id);
  assert.equal(beaSees.body, 'no link was made');
  assert.equal(beaSees.member, false, 'read access, as a link gives');
  // Ada sees it collected, not yet seen; Bea opens it and acknowledges; Ada sees "seen".
  let status = await ada.app.invitations(second.id);
  assert.deepEqual(status.map((s) => [s.name, s.collected, s.seen]), [['Bea', true, null]]);
  assert.equal(await bea.app.acknowledge(second.id, { name: 'Bea' }), true);
  assert.equal((await ada.app.collect()).acks, 1);
  status = await ada.app.invitations(second.id);
  assert.deepEqual(status.map((s) => [s.collected, s.seen]), [[true, 'seen']]);
  // The server saw labels and ciphertext: no name, no pairing.
  const drops = await db.owner.query('SELECT sealed_bundle, mailbox_id FROM mailbox_drops');
  assert.ok(drops.rows.length >= 2);
  for (const r of drops.rows) { assert.equal(r.mailbox_id.length, 32); assert.ok(!Buffer.from(r.sealed_bundle).toString('latin1').includes('Ada')); }
  // 3. Taken back: a third invitation withdrawn before Bea collects; Bea finds nothing new.
  const third = await ada.app.notes.create({ title: 'Changed my mind', body: '' });
  await ada.app.invite(third.id, bea.signingKey, { name: 'Ada' });
  assert.deepEqual(await ada.app.withdraw(third.id, bea.signingKey), { burned: 1, collected: false });
  const after = await bea.app.collect();
  assert.deepEqual(after.newNotes, []);
  assert.equal(after.counts.already >= 1, true, 'the withdrawn row is there, consumed, with no bundle');
  assert.equal((await bea.app.notes.list()).some((n) => n.id === third.id), false);
  await assert.rejects(ada.app.invite(third.id, 'nobody', {}), /not a contact/);
  await ada.session.lock(); await bea.session.lock();
});
