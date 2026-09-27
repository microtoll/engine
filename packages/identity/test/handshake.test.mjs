// The bound handshake (v2, D-29) and the account messages against the fake
// server, which verifies exactly as blind-store will.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '../src/index.js';
import { createFakeServer, socketPair } from './tooling/fakeServer.mjs';

const cc = createCryptoCore({ namespace: 'example' });
const ORIGIN = 'https://example.test';

test('the signed message is frozen: "<ns>/auth/v2" ‖ 0x00 ‖ SHA-256(origin) ‖ nonce', async () => {
  const nonce = cc.randomBytes(32);
  const m = await id.authMessage(cc, ORIGIN, nonce);
  const expected = cc.concatBytes(new TextEncoder().encode('example/auth/v2'), new Uint8Array([0]), await cc.sha256(new TextEncoder().encode(ORIGIN)), nonce);
  assert.equal(cc.toHex(m), cc.toHex(expected));
  await assert.rejects(id.authMessage(cc, '', nonce), /origin/);
  await assert.rejects(id.authMessage(cc, ORIGIN, new Uint8Array(31)), /32 bytes/);
});

test('a signature verifies for its origin and nonce only, never for another origin, nonce, key or the bare nonce', async () => {
  const me = await id.createEphemeralIdentity(cc);
  const nonce = cc.randomBytes(32);
  const sig = await cc.signBytes(me.routing.privateKey, await id.authMessage(cc, ORIGIN, nonce));
  assert.equal(await id.verifyAuthSignature(cc, me.routing.publicKeyRaw, ORIGIN, nonce, sig), true);
  assert.equal(await id.verifyAuthSignature(cc, me.routing.publicKeyRaw, 'https://evil.test', nonce, sig), false);
  assert.equal(await id.verifyAuthSignature(cc, me.routing.publicKeyRaw, ORIGIN, cc.randomBytes(32), sig), false);
  assert.equal(await id.verifyAuthSignature(cc, cc.randomBytes(32), ORIGIN, nonce, sig), false);
  assert.equal(await cc.verifyBytes(me.routing.publicKeyRaw, nonce, sig), false, 'not a signature over the bare nonce');
  const other = createCryptoCore({ namespace: 'other' });
  assert.equal(await id.verifyAuthSignature(other, me.routing.publicKeyRaw, ORIGIN, nonce, sig), false, 'the namespace is in the label');
});

test('handshake against the fake server: auth-ok without an account; a wrong origin is refused and closes the socket', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const me = await id.createEphemeralIdentity(cc);
  const ws = await server.connect();
  const r = await id.authenticateConnection(cc, ws, me.routing, ORIGIN);
  assert.equal(r.hasAccount, false);
  assert.equal(r.encryptedIdentityBlob, null);
  ws.close();
  const ws2 = await server.connect();
  await assert.rejects(id.authenticateConnection(cc, ws2, me.routing, 'https://evil.test'), (e) => e.code === 'auth-failed');
});

test('receiveChallenge and sendAndAwait time out, and reject on close, as transport errors', async () => {
  const [client] = socketPair(); // no server attached: nothing ever answers
  await assert.rejects(id.receiveChallenge(cc, client, { timeoutMs: 20 }), (e) => id.isTransportError(e) && e.kind === 'timeout');
  const p = id.sendAndAwait(client, { type: 'x' }, 'x-ok', 'x-failed', { timeoutMs: 1000 });
  client.close();
  await assert.rejects(p, (e) => id.isTransportError(e) && e.kind === 'closed');
});

test('sendAndAwait accepts only its own answer: another request\'s reply with the same type is ignored', async () => {
  const [client, server] = socketPair();
  server.addEventListener('message', (e) => {
    const m = JSON.parse(e.data);
    // Answer first with a foreign request id, then with the right one.
    server.send(JSON.stringify({ type: 'thing-ok', requestId: 'r0.foreign', value: 'wrong' }));
    server.send(JSON.stringify({ type: 'thing-ok', requestId: m.requestId, value: 'right' }));
  });
  const r = await id.sendAndAwait(client, { type: 'thing' }, 'thing-ok', 'thing-failed');
  assert.equal(r.value, 'right');
});

test('register with two methods, then look each up before authentication; a foreign lookup is not-found', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const me = await id.createIdentity(cc);
  const prf = cc.randomBytes(32), credentialId = cc.randomBytes(16), salt = cc.randomBytes(32);
  const a = await id.wrapRootKeyWithPrf(cc, me.rootKey, prf, credentialId, salt, 'phone');
  const { method: b, displayString } = await id.wrapRootKeyWithNewRecoveryCode(cc, me.rootKey, 'code');
  const sealLabel = (l, method) => id.sealMethodLabel(cc, me.masterSymmKey, method, l);
  const openLabel = (s, method) => id.openMethodLabel(cc, me.masterSymmKey, method, s);
  const ws = await server.connect();
  await id.authenticateConnection(cc, ws, me.routing, ORIGIN);
  const blob = await id.sealIdentityBlob(cc, me, id.buildIdentityBlobPlaintext(cc, me, {}));
  const { identityBlobToken } = await id.registerAccount(cc, ws, me, blob, [a, b], { sealLabel, policyFields: { termsVersion: 'v1', ageDeclared18Plus: true } });
  assert.equal(typeof identityBlobToken, 'string');
  await assert.rejects(id.registerAccount(cc, ws, me, blob, [a], { sealLabel }), (e) => e.reason === 'already-registered');
  const methods = await id.listUnlockMethods(cc, ws, { openLabel });
  assert.deepEqual(methods.map((m) => [m.type, m.label]), [['passkey-prf', 'phone'], ['recovery-code', 'code']]);
  ws.close();

  const ws2 = await server.connect();
  await id.receiveChallenge(cc, ws2);
  const found = await id.lookupUnlockMethod(cc, ws2, { credentialId });
  assert.deepEqual(await id.unwrapRootKeyWithPrf(cc, found, prf), me.rootKey);
  const found2 = await id.lookupUnlockMethod(cc, ws2, { recoveryLookupHash: b.lookupHash });
  assert.deepEqual(await id.unwrapRootKeyWithRecoveryCode(cc, found2, displayString), me.rootKey);
  await assert.rejects(id.lookupUnlockMethod(cc, ws2, { credentialId: cc.randomBytes(16) }), (e) => e.reason === 'not-found');
  ws2.close();
});

test('the identity blob compare-and-swap: a stale token conflicts and hands back the winner', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const me = await id.createIdentity(cc);
  const { method } = await id.wrapRootKeyWithNewRecoveryCode(cc, me.rootKey);
  const sealLabel = async () => new Uint8Array(0);
  const ws = await server.connect();
  await id.authenticateConnection(cc, ws, me.routing, ORIGIN);
  const p1 = id.buildIdentityBlobPlaintext(cc, me, {});
  const { identityBlobToken: t1 } = await id.registerAccount(cc, ws, me, await id.sealIdentityBlob(cc, me, p1), [method], { sealLabel });
  const p2 = id.buildIdentityBlobPlaintext(cc, me, { ...p1, a: 1 });
  const { identityBlobToken: t2 } = await id.updateIdentityBlob(cc, ws, await id.sealIdentityBlob(cc, me, p2), t1);
  assert.notEqual(t2, t1);
  const p3 = id.buildIdentityBlobPlaintext(cc, me, { ...p1, b: 2 });
  const conflict = await id.updateIdentityBlob(cc, ws, await id.sealIdentityBlob(cc, me, p3), t1).then(() => null, (e) => e);
  assert.ok(conflict, 'the stale token must be refused');
  assert.equal(conflict.conflict, true);
  assert.equal(conflict.identityBlobToken, t2);
  assert.deepEqual(await id.openIdentityBlob(cc, me, conflict.encryptedIdentityBlob), p2);
  ws.close();
});
