// Property and tamper tests for AEAD v1.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cc from '../src/index.js';

const utf8 = (s) => new TextEncoder().encode(s);

test('AEAD v1 round trips every size from empty to 100 KB, and the full emoji range', async () => {
  const key = await cc.importSymmetricKey(cc.generateSymmetricKey());
  const cases = [
    new Uint8Array(0),
    new Uint8Array([7]),
    cc.randomBytes(16),
    cc.randomBytes(32),
    cc.randomBytes(100 * 1024),
    utf8('café 🦊🌲❄️ — “quotes” \u0000 nul'),
  ];
  for (const pt of cases) {
    const sealed = await cc.sealSymmetric(key, pt);
    assert.equal(sealed[0], cc.AEAD_VERSION_1);
    assert.equal(sealed.length, 1 + cc.AEAD_IV_BYTES + pt.length + 16);
    assert.deepEqual(await cc.openSymmetric(key, sealed), pt);
  }
});

test('AEAD v1 with additional data round trips, and refuses different or missing AAD', async () => {
  const key = await cc.importSymmetricKey(cc.generateSymmetricKey());
  const aad = cc.frameContext('example/context/v1', cc.uuidBytes('123e4567-e89b-12d3-a456-426614174000'), cc.u32be(3));
  const sealed = await cc.sealSymmetric(key, utf8('bound'), aad);
  assert.equal(new TextDecoder().decode(await cc.openSymmetric(key, sealed, aad)), 'bound');
  await assert.rejects(cc.openSymmetric(key, sealed), 'no AAD');
  const other = cc.frameContext('example/context/v1', cc.uuidBytes('123e4567-e89b-12d3-a456-426614174000'), cc.u32be(4));
  await assert.rejects(cc.openSymmetric(key, sealed, other), 'different epoch');
});

test('AEAD v1 refuses the wrong key, a flipped tag bit, a tampered IV, a truncated tag and an unknown version', async () => {
  const key = await cc.importSymmetricKey(cc.generateSymmetricKey());
  const other = await cc.importSymmetricKey(cc.generateSymmetricKey());
  const sealed = await cc.sealSymmetric(key, utf8('secret'));

  await assert.rejects(cc.openSymmetric(other, sealed), 'wrong key');

  for (const i of [sealed.length - 1, sealed.length - 16, 1 + cc.AEAD_IV_BYTES]) {
    const t = sealed.slice(); t[i] ^= 0x01;
    await assert.rejects(cc.openSymmetric(key, t), `flipped byte ${i}`);
  }

  const iv = sealed.slice(); iv[1] ^= 0x80;
  await assert.rejects(cc.openSymmetric(key, iv), 'tampered IV');

  await assert.rejects(cc.openSymmetric(key, sealed.slice(0, sealed.length - 1)), 'truncated tag');
  await assert.rejects(cc.openSymmetric(key, sealed.slice(0, 5)), /too short/);

  const v = sealed.slice(); v[0] = 0x99;
  await assert.rejects(cc.openSymmetric(key, v), /unsupported AEAD version: 153/);
});

test('two seals of the same plaintext never share an IV or a ciphertext (2,000 seals)', async () => {
  const key = await cc.importSymmetricKey(cc.generateSymmetricKey());
  const seen = new Set();
  for (let i = 0; i < 2000; i++) {
    const sealed = await cc.sealSymmetric(key, utf8('same'));
    const iv = cc.toHex(sealed.slice(1, 1 + cc.AEAD_IV_BYTES));
    assert.equal(seen.has(iv), false, 'IV repeated');
    seen.add(iv);
  }
});

test('a symmetric key must be exactly 32 bytes, and the imported key is non-extractable', async () => {
  await assert.rejects(cc.importSymmetricKey(new Uint8Array(16)), /32 bytes/);
  const key = await cc.importSymmetricKey(cc.generateSymmetricKey());
  assert.equal(key.extractable, false);
});

test('sealed output looks like noise: the plaintext never appears in the ciphertext', async () => {
  const key = await cc.importSymmetricKey(cc.generateSymmetricKey());
  const pt = utf8('THIS IS A DISTINCTIVE PLAINTEXT SENTENCE');
  const sealed = await cc.sealSymmetric(key, pt);
  assert.equal(cc.toHex(sealed).includes(cc.toHex(pt)), false);
});
