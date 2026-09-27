// The trusted-device session (record v2, D-28): save and load, expiry and
// tampering, the lock interval, and the binding cases.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '@microtoll/crypto-core';
import { createSessionStore, memoryStore, memoryStorage, sessionContext, SESSION_DAYS, LOCK_INTERVALS } from '../src/index.js';

const cc = createCryptoCore({ namespace: 'example' });
const root = cc.generateSymmetricKey();
const routing = cc.randomBytes(32);
const make = () => { const store = memoryStore(); const s = createSessionStore({ cryptoCore: cc, store, lockIntervalStorage: memoryStorage() }); return { store, s }; };

test('save then load: the root key comes back, the record holds no plaintext root key, the session key is non-extractable', async () => {
  const { store, s } = make();
  await s.saveSession(root, routing, { now: 1000, sessionGeneration: 3 });
  const rec = store._map.get('current');
  assert.equal(rec.v, 2);
  assert.equal(rec.sessionKey.extractable, false);
  assert.equal(cc.toHex(rec.wrappedRootKey).includes(cc.toHex(root)), false);
  assert.equal(rec.expiresAt, 1000 + SESSION_DAYS * 86400000);
  const got = await s.loadSession({ now: 2000 });
  assert.deepEqual(got.rootKey, root);
  assert.equal(got.routingPublicKey, cc.toBase64Url(routing));
  assert.equal(got.sessionGeneration, 3);
  await assert.rejects(globalThis.crypto.subtle.exportKey('raw', rec.sessionKey));
});

test('expired, tampered, edited-expiry, edited-generation and edited-routing records all load as null and are deleted', async () => {
  for (const edit of [
    (r) => { r.expiresAt = 1; },
    (r) => { r.wrappedRootKey[20] ^= 1; },
    (r) => { r.expiresAt += 1; },                       // pushed forward: the AAD refuses it
    (r) => { r.sessionGeneration = 99; },               // raised to defeat sign-out-everywhere
    (r) => { r.routingPublicKey = cc.toBase64Url(cc.randomBytes(32)); },
    (r) => { r.v = 1; },
  ]) {
    const { store, s } = make();
    await s.saveSession(root, routing, { now: 1000, sessionGeneration: 3 });
    edit(store._map.get('current'));
    assert.equal(await s.loadSession({ now: 2000 }), null);
    assert.equal(store._map.has('current'), false, 'deleted');
  }
});

test('ttlMs wins over days; zero is refused; clear is idempotent', async () => {
  const { store, s } = make();
  await s.saveSession(root, routing, { now: 0, ttlMs: LOCK_INTERVALS['30-min'] });
  assert.equal(store._map.get('current').expiresAt, 30 * 60 * 1000);
  await assert.rejects(s.saveSession(root, routing, { ttlMs: 0 }), /longer than zero/);
  await s.clearSession(); await s.clearSession();
  assert.equal(await s.loadSession(), null);
});

test('isSessionStale truth table: unknown on either side is never stale', () => {
  const { s } = make();
  assert.equal(s.isSessionStale({ sessionGeneration: 1 }, 2), true);
  assert.equal(s.isSessionStale({ sessionGeneration: 2 }, 2), false);
  assert.equal(s.isSessionStale({ sessionGeneration: null }, 2), false);
  assert.equal(s.isSessionStale({ sessionGeneration: 1 }, null), false);
  assert.equal(s.isSessionStale(null, 2), false);
});

test('the lock interval is per device, namespaced, and defaults to 30 days', () => {
  const storage = memoryStorage();
  const s = createSessionStore({ cryptoCore: cc, store: memoryStore(), lockIntervalStorage: storage });
  assert.equal(s.loadLockInterval(), '30-days');
  s.saveLockInterval('30-min');
  assert.equal(storage.getItem('example:lockInterval'), '30-min');
  assert.equal(s.loadLockInterval(), '30-min');
  assert.throws(() => s.saveLockInterval('never'), /unknown lock interval/);
  storage.setItem('example:lockInterval', 'garbage');
  assert.equal(s.loadLockInterval(), '30-days');
});

test('the session context is frozen: label ‖ 0x00 ‖ routing ‖ u64be(expiresAt) ‖ u32be(generation)', () => {
  const ctx = sessionContext(cc, routing, 1758758400000, 7);
  const expected = cc.concatBytes(new TextEncoder().encode('example/aad/session/v2'), new Uint8Array([0]), routing, cc.u64be(1758758400000), cc.u32be(7));
  assert.equal(cc.toHex(ctx), cc.toHex(expected));
  assert.equal(cc.toHex(sessionContext(cc, routing, 1, null)).slice(-8), '00000000', 'an unknown generation binds as 0');
});
