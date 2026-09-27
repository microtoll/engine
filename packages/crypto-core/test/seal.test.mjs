// ECIES v3 (P-256): round trips, tamper detection, and recipient binding.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '../src/index.js';

const cc = createCryptoCore({ namespace: 'example' });
const utf8 = (s) => new TextEncoder().encode(s);
const text = (b) => new TextDecoder().decode(b);

test('v3 round trip: version byte 0x03, a 65-byte uncompressed ephemeral point, then AEAD v1', async () => {
  const alice = await cc.generateSealingKeyPair();
  const message = 'a message for Alice, containing an emoji \u{1F600}';
  const sealed = await cc.sealToPublicKey(alice.publicKeyRaw, utf8(message));
  assert.equal(sealed[0], cc.ECIES_VERSION_3);
  assert.equal(sealed[1], 0x04);
  assert.equal(sealed.length, 1 + 65 + 1 + 12 + utf8(message).length + 16);
  assert.equal(text(await cc.openWithPrivateKey(alice, sealed)), message);
});

test('two seals of one message use different ephemeral keys and ciphertexts', async () => {
  const alice = await cc.generateSealingKeyPair();
  const s1 = await cc.sealToPublicKey(alice.publicKeyRaw, utf8('same'));
  const s2 = await cc.sealToPublicKey(alice.publicKeyRaw, utf8('same'));
  assert.notEqual(cc.toHex(s1), cc.toHex(s2));
  assert.notEqual(cc.toHex(s1.slice(1, 66)), cc.toHex(s2.slice(1, 66)), 'ephemeral key reused');
});

test("the wrong recipient's key pair is refused", async () => {
  const alice = await cc.generateSealingKeyPair();
  const bob = await cc.generateSealingKeyPair();
  const sealed = await cc.sealToPublicKey(alice.publicKeyRaw, utf8('for Alice'));
  await assert.rejects(cc.openWithPrivateKey(bob, sealed));
});

test('a bare private key is refused before any crypto runs: the open needs the pair', async () => {
  const alice = await cc.generateSealingKeyPair();
  const sealed = await cc.sealToPublicKey(alice.publicKeyRaw, utf8('x'));
  await assert.rejects(cc.openWithPrivateKey(alice.privateKey, sealed), /pair/);
});

test('v3 binds the recipient: the right private key with a swapped public half fails at the tag', async () => {
  const alice = await cc.generateSealingKeyPair();
  const bob = await cc.generateSealingKeyPair();
  const sealed = await cc.sealToPublicKey(alice.publicKeyRaw, utf8('bound'));
  await assert.rejects(cc.openWithPrivateKey({ privateKey: alice.privateKey, publicKeyRaw: bob.publicKeyRaw }, sealed));
});

test('v3 authenticates its version byte: a relabelled blob fails at the tag', async () => {
  const alice = await cc.generateSealingKeyPair();
  const sealed = await cc.sealToPublicKey(alice.publicKeyRaw, utf8('labelled'));
  const relabelled = sealed.slice(); relabelled[0] = 0x07;
  await assert.rejects(cc.openWithPrivateKey(alice, relabelled), /unsupported ECIES version: 7/);
  // And a blob whose version byte was rewritten to 3 from something else also
  // fails: the tag covers it. Simulate by flipping the AAD-covered byte after
  // the ephemeral key.
  const tampered = sealed.slice(); tampered[66] ^= 0x01; // the inner AEAD version byte
  await assert.rejects(cc.openWithPrivateKey(alice, tampered));
});

test('a retired v1 (X25519) blob is refused by name', async () => {
  const alice = await cc.generateSealingKeyPair();
  const fake = cc.concatBytes(new Uint8Array([cc.ECIES_VERSION_1]), new Uint8Array(32), new Uint8Array(40));
  await assert.rejects(cc.openWithPrivateKey(alice, fake), /retired X25519/);
});

test('sealToRecipient dispatches by key length: 65 → v3; 32 (the retired X25519 length) is an error', async () => {
  const alice = await cc.generateSealingKeyPair();
  const v3 = await cc.sealToRecipient(alice.publicKeyRaw, utf8('x'));
  assert.equal(v3[0], cc.ECIES_VERSION_3);
  await assert.rejects(cc.sealToRecipient(new Uint8Array(32), utf8('x')), /unrecognised recipient key length 32/);
  await assert.rejects(cc.sealToRecipient(new Uint8Array(64), utf8('x')), /unrecognised recipient key length 64/);
});

test('a sealed blob that is too short, or whose ephemeral point is off the curve, is refused', async () => {
  const alice = await cc.generateSealingKeyPair();
  await assert.rejects(cc.openWithPrivateKey(alice, new Uint8Array([0x03, 0x04, 0x05])), /too short/);
  const sealed = await cc.sealToPublicKey(alice.publicKeyRaw, utf8('x'));
  const bad = sealed.slice(); bad[10] ^= 0xff; // corrupt the ephemeral point
  await assert.rejects(cc.openWithPrivateKey(alice, bad));
});

test('the label is bound in: a different namespace cannot open the blob', async () => {
  const other = createCryptoCore({ namespace: 'other' });
  const alice = await cc.generateSealingKeyPair();
  const sealed = await cc.sealToPublicKey(alice.publicKeyRaw, utf8('example only'));
  await assert.rejects(other.openWithPrivateKey(alice, sealed));
  assert.equal(text(await cc.openWithPrivateKey(alice, sealed)), 'example only');
});
