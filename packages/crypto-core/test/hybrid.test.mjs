// The hybrid post-quantum seal (ECIES v2) and the master switch. Runs through the test-only
// shim over the X-Wing composition (test/tooling), so a green run proves the
// framing, labels, version bytes and dispatch — not that a browser agrees
// (DECISIONS.md D-07: the browser cross-check is a release gate).
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '../src/index.js';
import { installPqShim } from './tooling/pq-test-shim.mjs';
import * as xw from './tooling/xwing.mjs';

const utf8 = (s) => new TextEncoder().encode(s);
const text = (b) => new TextDecoder().decode(b);
const SEED = Uint8Array.from({ length: 32 }, (_, i) => i + 1);

// --- Without the algorithm: the path every browser without it is on -------
// These run FIRST, before the shim is installed, so they cannot be contaminated.
test('without the algorithm: pqSealAvailable is false even with the switch on, and a KEM key is null', async () => {
  const cc = createCryptoCore({ namespace: 'example', hybridSealing: true });
  assert.equal(await cc.pqSealAvailable(), false, 'this Node claims native support — the shim leaked, or Node now ships it');
  assert.equal(await cc.kemKeyPairFromSeed(SEED), null);
});

test('without the algorithm: classical sealing is unaffected', async () => {
  const cc = createCryptoCore({ namespace: 'example', hybridSealing: true });
  const id = await cc.generateSealingKeyPair();
  const sealed = await cc.sealToRecipient(id.publicKeyRaw, utf8('classical still works'));
  assert.equal(sealed[0], cc.ECIES_VERSION_3);
  assert.equal(text(await cc.openWithPrivateKey(id, sealed)), 'classical still works');
});

// --- With the platform able -----------------------------------------------
// Scoped to this block, so the shim is installed only after the tests above
// have proved the fallback path on a bare runtime.
describe('with the platform able (test shim installed)', () => {
let uninstall;
before(async () => {
  const a = await xw.available();
  if (!a.ok) throw new Error('this Node cannot run the X-Wing composition: ' + a.reason);
  uninstall = installPqShim();
});
after(() => uninstall && uninstall());

test('SWITCH OFF on a capable platform: no post-quantum key is made and everything seals classically', async () => {
  const cc = createCryptoCore({ namespace: 'example' }); // default: off
  assert.equal(await cc.pqSealAvailable(), false);
  assert.equal(await cc.kemKeyPairFromSeed(SEED), null);
  const id = await cc.generateSealingKeyPair();
  assert.equal((await cc.sealToRecipient(id.publicKeyRaw, utf8('x')))[0], cc.ECIES_VERSION_3);
});

test('SWITCH ON: a KEM key pair from a seed is deterministic, 1216 bytes, and seals v2', async () => {
  const cc = createCryptoCore({ namespace: 'example', hybridSealing: true });
  assert.equal(await cc.pqSealAvailable(), true);
  const a = await cc.kemKeyPairFromSeed(SEED);
  const b = await cc.kemKeyPairFromSeed(SEED);
  assert.equal(a.publicKeyRaw.length, cc.PQ_KEM_PUBLIC_KEY_BYTES);
  assert.equal(cc.toHex(a.publicKeyRaw), cc.toHex(b.publicKeyRaw), 'deterministic from the seed');
  const sealed = await cc.sealToRecipient(a.publicKeyRaw, utf8('post-quantum hello \u{1F680}'));
  assert.equal(sealed[0], cc.ECIES_VERSION_2);
  assert.equal(sealed.length, 1 + cc.PQ_KEM_CIPHERTEXT_BYTES + 1 + 12 + utf8('post-quantum hello \u{1F680}').length + 16);
  assert.equal(text(await cc.openWithKemPrivateKey(a.privateKey, sealed)), 'post-quantum hello \u{1F680}');
});

test('SWITCH OFF afterwards: an existing v2 blob is still readable (the switch stops new writes, never reads)', async () => {
  const on = createCryptoCore({ namespace: 'example', hybridSealing: true });
  const kem = await on.kemKeyPairFromSeed(SEED);
  const sealed = await on.sealToKemPublicKey(kem.publicKeyRaw, utf8('written while on'));
  on._setHybridSealing(false);
  assert.equal(await on.pqSealAvailable(), false);
  assert.equal(text(await on.openWithKemPrivateKey(kem.privateKey, sealed)), 'written while on');
});

test('v2 authenticates its version byte and binds the recipient', async () => {
  const cc = createCryptoCore({ namespace: 'example', hybridSealing: true });
  const alice = await cc.kemKeyPairFromSeed(SEED);
  const bob = await cc.kemKeyPairFromSeed(new Uint8Array(32).fill(9));
  const sealed = await cc.sealToKemPublicKey(alice.publicKeyRaw, utf8('bound'));
  const relabelled = sealed.slice(); relabelled[0] = cc.ECIES_VERSION_1;
  await assert.rejects(cc.openWithKemPrivateKey(alice.privateKey, relabelled), /unsupported ECIES version: 1/);
  await assert.rejects(cc.openWithKemPrivateKey(bob.privateKey, sealed), 'wrong recipient');
});

test('v2 refuses a flipped bit in the KEM ciphertext or the AEAD part, and truncation', async () => {
  const cc = createCryptoCore({ namespace: 'example', hybridSealing: true });
  const alice = await cc.kemKeyPairFromSeed(SEED);
  const sealed = await cc.sealToKemPublicKey(alice.publicKeyRaw, utf8('intact'));
  for (const i of [5, 1100, 1 + cc.PQ_KEM_CIPHERTEXT_BYTES + 3, sealed.length - 1]) {
    const t = sealed.slice(); t[i] ^= 0x01;
    await assert.rejects(cc.openWithKemPrivateKey(alice.privateKey, t), `flipped byte ${i}`);
  }
  for (const n of [0, 1, cc.PQ_KEM_CIPHERTEXT_BYTES]) {
    await assert.rejects(cc.openWithKemPrivateKey(alice.privateKey, sealed.slice(0, n)), /too short|version/);
  }
});

test('v2 and v3 openers reject each other\'s blobs by version, and wrong key lengths are refused', async () => {
  const cc = createCryptoCore({ namespace: 'example', hybridSealing: true });
  const kem = await cc.kemKeyPairFromSeed(SEED);
  const p256 = await cc.generateSealingKeyPair();
  const v2 = await cc.sealToRecipient(kem.publicKeyRaw, utf8('v2'));
  const v3 = await cc.sealToRecipient(p256.publicKeyRaw, utf8('v3'));
  await assert.rejects(cc.openWithPrivateKey(p256, v2), /unsupported ECIES version: 2/);
  // A v3 blob is shorter than any v2 blob, so the length check fires first.
  await assert.rejects(cc.openWithKemPrivateKey(kem.privateKey, v3), /too short/);
  const padded = cc.concatBytes(v3, new Uint8Array(cc.PQ_KEM_CIPHERTEXT_BYTES));
  await assert.rejects(cc.openWithKemPrivateKey(kem.privateKey, padded), /unsupported ECIES version: 3/);
  await assert.rejects(cc.sealToKemPublicKey(new Uint8Array(1215), utf8('x')), /1216 bytes/);
  await assert.rejects(cc.kemKeyPairFromSeed(new Uint8Array(31)), /32 bytes/);
});

test('the label is bound into v2 too: another namespace cannot open the blob', async () => {
  const cc = createCryptoCore({ namespace: 'example', hybridSealing: true });
  const other = createCryptoCore({ namespace: 'other', hybridSealing: true });
  const kem = await cc.kemKeyPairFromSeed(SEED);
  const sealed = await cc.sealToKemPublicKey(kem.publicKeyRaw, utf8('example only'));
  await assert.rejects(other.openWithKemPrivateKey(kem.privateKey, sealed));
});

});
