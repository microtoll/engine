// The handshake's server half (DESIGN.md §3.1; D-29, D-34): the
// cross-implementation test. The message is framed here with Node's Buffer
// and verified with node:crypto; the client frames it with crypto-core's
// frameContext and signs with Web Crypto. Both halves must agree, byte for
// byte, or nobody can sign in.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '@microtoll/crypto-core';
import { authMessage as clientAuthMessage, createIdentity } from '@microtoll/identity';
import { authMessage, authLabel, verifyAuthSignature, verifyAgainstOrigins, generateNonce, importEd25519PublicKeyRaw, assertNamespace, NONCE_BYTES } from '../src/index.js';

const NS = 'testapp';
const cc = createCryptoCore({ namespace: NS });
const ORIGIN = 'https://app.example';

test('the label is crypto-core\'s own: <ns>/auth/v2', () => {
  assert.equal(authLabel(NS), cc.label('auth', 2));
  assert.equal(authLabel('example'), 'example/auth/v2');
});

test('the server frames exactly the bytes the identity package signs', async () => {
  const nonce = generateNonce();
  assert.equal(nonce.length, NONCE_BYTES);
  const server = authMessage(NS, ORIGIN, nonce);
  const client = await clientAuthMessage(cc, ORIGIN, nonce);
  assert.equal(Buffer.from(server).toString('hex'), Buffer.from(client).toString('hex'));
  // The layout, spelled out: label, a NUL, SHA-256 of the origin, the nonce.
  const label = Buffer.from(`${NS}/auth/v2`, 'utf8');
  assert.equal(server.length, label.length + 1 + 32 + 32);
  assert.equal(server.subarray(0, label.length).toString('utf8'), `${NS}/auth/v2`);
  assert.equal(server[label.length], 0);
  assert.equal(server.subarray(label.length + 1, label.length + 33).toString('hex'), Buffer.from(await cc.sha256(new TextEncoder().encode(ORIGIN))).toString('hex'));
  assert.equal(server.subarray(label.length + 33).toString('hex'), nonce.toString('hex'));
});

test('a signature made with Web Crypto verifies under Node, and only for its origin, namespace and nonce', async () => {
  const identity = await createIdentity(cc);
  const nonce = generateNonce();
  const signature = await cc.signBytes(identity.routing.privateKey, await clientAuthMessage(cc, ORIGIN, nonce));
  const pub = identity.routing.publicKeyRaw;
  assert.equal(verifyAuthSignature(NS, pub, ORIGIN, nonce, signature), true);
  assert.equal(verifyAuthSignature(NS, pub, 'https://evil.example', nonce, signature), false, 'another origin');
  assert.equal(verifyAuthSignature('other', pub, ORIGIN, nonce, signature), false, 'another namespace');
  assert.equal(verifyAuthSignature(NS, pub, ORIGIN, generateNonce(), signature), false, 'another nonce');
  const other = await createIdentity(cc);
  assert.equal(verifyAuthSignature(NS, other.routing.publicKeyRaw, ORIGIN, nonce, signature), false, 'another key');
  const flipped = Buffer.from(signature); flipped[10] ^= 1;
  assert.equal(verifyAuthSignature(NS, pub, ORIGIN, nonce, flipped), false, 'a flipped bit');
  assert.equal(verifyAuthSignature(NS, pub, ORIGIN, nonce, signature.subarray(0, 63)), false, 'a short signature is false, not thrown');
  // A version-1 signature over the bare nonce is refused, by design.
  const bare = await cc.signBytes(identity.routing.privateKey, nonce);
  assert.equal(verifyAuthSignature(NS, pub, ORIGIN, nonce, bare), false);
});

test('verifyAgainstOrigins finds the origin the client signed for among the allowed ones', async () => {
  const identity = await createIdentity(cc);
  const nonce = generateNonce();
  const signature = await cc.signBytes(identity.routing.privateKey, await clientAuthMessage(cc, 'http://localhost:8088', nonce));
  assert.equal(verifyAgainstOrigins(NS, identity.routing.publicKeyRaw, ['https://app.example', 'http://localhost:8088'], nonce, signature), 'http://localhost:8088');
  assert.equal(verifyAgainstOrigins(NS, identity.routing.publicKeyRaw, ['https://app.example'], nonce, signature), null);
});

test('a malformed key throws (structural), never returns "unverified"', () => {
  assert.throws(() => importEd25519PublicKeyRaw(new Uint8Array(31)), /32 bytes/);
  assert.throws(() => verifyAuthSignature(NS, new Uint8Array(33), ORIGIN, generateNonce(), new Uint8Array(64)), /32 bytes/);
  assert.throws(() => authMessage(NS, '', generateNonce()), /origin/);
  assert.throws(() => authMessage(NS, ORIGIN, new Uint8Array(31)), /32 bytes/);
});

test('the namespace rule is crypto-core\'s', () => {
  assert.equal(assertNamespace('example'), 'example');
  assert.equal(assertNamespace('a-1'), 'a-1');
  for (const bad of ['', 'Example', '-x', 'a b', 'a/b', 'x'.repeat(65), undefined, 42]) assert.throws(() => assertNamespace(bad), /namespace/);
  assert.throws(() => cc.label('auth', 1) && createCryptoCore({ namespace: 'Example' }), /namespace/);
});
