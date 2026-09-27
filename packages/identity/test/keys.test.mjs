// The key hierarchy: the derivations pinned by the crypto-core frozen
// fixtures, with non-extractable working keys and a stored sealing key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCryptoCore } from '@microtoll/crypto-core';
import { createIdentity, identityFromRootKey, createEphemeralIdentity, adoptSealingKey, encodeRoutingHandle } from '../src/index.js';

const fx = JSON.parse(readFileSync(new URL('../../crypto-core/test/fixtures/frozen-v1.json', import.meta.url), 'utf8'));
const cc = createCryptoCore({ namespace: fx.namespace });
const H = cc.fromHex;

test('a root key derives the frozen routing and signing keys exactly, and signs identically', async () => {
  const id = await identityFromRootKey(cc, H(fx.derivations.root));
  assert.equal(cc.toHex(id.routing.publicKeyRaw), fx.derivations.routingPublicKey);
  assert.equal(cc.toHex(id.identitySigning.publicKeyRaw), fx.derivations.identitySigningPublicKey);
  assert.equal(encodeRoutingHandle(cc, id.routing.publicKeyRaw), fx.derivations.routingHandle);
  assert.equal(cc.toHex(await cc.signBytes(id.routing.privateKey, H(fx.derivations.nonce))), fx.derivations.nonceSignature);
  assert.equal(cc.toHex(await cc.openSymmetric(id.masterSymmKey, H(fx.derivations.masterSymmSealed))), fx.derivations.masterSymmPlaintext);
});

test('the working Ed25519 keys and K_master_symm are non-extractable; the sealing key is stored, not derived', async () => {
  const id = await createIdentity(cc);
  assert.equal(id.routing.privateKey.extractable, false);
  assert.equal(id.identitySigning.privateKey.extractable, false);
  assert.equal(id.masterSymmKey.extractable, false);
  assert.equal(id.identity.privateKey.extractable, false);
  assert.equal(id.identity.stored, false);
  assert.equal(id.identityKem, null, 'hybrid sealing is off by default');
  await assert.rejects(globalThis.crypto.subtle.exportKey('jwk', id.routing.privateKey));
  const again = await identityFromRootKey(cc, id.rootKey);
  assert.equal(cc.toHex(again.routing.publicKeyRaw), cc.toHex(id.routing.publicKeyRaw), 'derived keys are deterministic');
  assert.notEqual(cc.toHex(again.identity.publicKeyRaw), cc.toHex(id.identity.publicKeyRaw), 'the sealing key is generated, not derived');
});

test('adoptSealingKey replaces the fresh key with the blob\'s, and throws on a corrupt one', async () => {
  const id = await createIdentity(cc);
  const stored = await cc.generateSealingKeyPair();
  assert.equal(await adoptSealingKey(cc, id, {}), false);
  assert.equal(await adoptSealingKey(cc, id, { sealingKey: stored.jwk }), true);
  assert.equal(cc.toHex(id.identity.publicKeyRaw), cc.toHex(stored.publicKeyRaw));
  assert.equal(id.identity.stored, true);
  await assert.rejects(adoptSealingKey(cc, id, { sealingKey: { ...stored.jwk, crv: 'P-384' } }));
});

test('an ephemeral identity has only a routing key and signs the handshake', async () => {
  const e = await createEphemeralIdentity(cc);
  assert.equal(e.ephemeral, true);
  assert.equal(e.routing.publicKeyRaw.length, 32);
  assert.equal(e.routing.privateKey.extractable, false);
  assert.equal(await cc.verifyBytes(e.routing.publicKeyRaw, new Uint8Array([1]), await cc.signBytes(e.routing.privateKey, new Uint8Array([1]))), true);
});

test('a root key must be 32 bytes', async () => {
  await assert.rejects(identityFromRootKey(cc, new Uint8Array(31)), /32 bytes/);
});
