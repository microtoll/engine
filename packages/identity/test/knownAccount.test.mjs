import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '@microtoll/crypto-core';
import { createKnownAccountStore, memoryStorage } from '../src/index.js';

const cc = createCryptoCore({ namespace: 'example' });

test('records are namespaced, round trip, and a recovery record never overwrites a passkey record', () => {
  const storage = memoryStorage();
  const k = createKnownAccountStore({ cryptoCore: cc, storage });
  const routing = cc.randomBytes(32), cred = cc.randomBytes(16);
  assert.equal(k.loadKnownAccount(), null);
  k.rememberDeviceRecoveryAccount('phone', routing);
  assert.equal(k.loadKnownAccount().credentialId, null);
  k.rememberDevicePasskey(cred, 'phone', routing, ['internal', 7]);
  const rec = k.loadKnownAccount();
  assert.deepEqual(rec.credentialId, cred);
  assert.deepEqual(rec.routingPublicKey, routing);
  assert.deepEqual(rec.transports, ['internal']);
  k.rememberDeviceRecoveryAccount('x', cc.randomBytes(32));
  assert.deepEqual(k.loadKnownAccount().credentialId, cred, 'not overwritten');
  assert.ok(storage.getItem('example:knownAccount'));
  k.markDevicePasskeyBlocked('prf-unsupported');
  assert.equal(k.isDevicePasskeyBlocked(), true);
  k.rememberDevicePasskey(cred, 'phone', routing);
  assert.equal(k.isDevicePasskeyBlocked(), false, 'a working passkey clears the block');
  k.clearKnownAccount();
  assert.equal(k.loadKnownAccount(), null);
  storage.setItem('example:knownAccount', '{not json');
  assert.equal(k.loadKnownAccount(), null);
});

test('blob revisions are remembered per account and only ever climb', () => {
  const k = createKnownAccountStore({ cryptoCore: cc, storage: memoryStorage() });
  const a = cc.randomBytes(32), b = cc.randomBytes(32);
  assert.equal(k.knownBlobRevision(a), 0);
  k.rememberBlobRevision(a, 5);
  k.rememberBlobRevision(a, 3);
  assert.equal(k.knownBlobRevision(a), 5);
  assert.equal(k.knownBlobRevision(b), 0);
  k.forgetBlobRevision(a);
  assert.equal(k.knownBlobRevision(a), 0);
});

test('a storage that throws is tolerated', () => {
  const k = createKnownAccountStore({ cryptoCore: cc, storage: { getItem() { throw new Error('private'); }, setItem() { throw new Error('private'); }, removeItem() { throw new Error('private'); } } });
  assert.equal(k.loadKnownAccount(), null);
  assert.doesNotThrow(() => k.rememberDevicePasskey(cc.randomBytes(4), 'x', cc.randomBytes(32)));
});
