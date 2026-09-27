// Encoding helpers and the fixed-length frame. The frozen byte layouts here
// are change-detectors: a change silently invalidates every existing seal or
// signature bound to a frame.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as cc from '../src/index.js';

test('hex round trips and rejects odd lengths or non-hex characters', () => {
  const bytes = cc.randomBytes(33);
  assert.deepEqual(cc.fromHex(cc.toHex(bytes)), bytes);
  assert.throws(() => cc.fromHex('abc'), /even length/);
  assert.throws(() => cc.fromHex('zz'), /hex digits/);
  assert.deepEqual(cc.fromHex(''), new Uint8Array(0));
});

test('base64url round trips without padding, for every length mod 3', () => {
  for (const n of [0, 1, 2, 3, 4, 31, 32, 33, 65]) {
    const bytes = cc.randomBytes(n);
    const s = cc.toBase64Url(bytes);
    assert.equal(/[+/=]/.test(s), false, 'no +, / or = in base64url');
    assert.deepEqual(cc.fromBase64Url(s), bytes);
  }
});

test('Crockford base32 round trips, uses no I, L, O or U, and rejects other characters', () => {
  for (const n of [1, 5, 16, 20, 32]) {
    const bytes = cc.randomBytes(n);
    const s = cc.bytesToBase32Crockford(bytes);
    assert.equal(/[ILOU]/.test(s), false);
    assert.deepEqual(cc.base32CrockfordToBytes(s).slice(0, n), bytes);
  }
  assert.equal(cc.bytesToBase32Crockford(new Uint8Array(16)).length, 26, '16 bytes → 26 characters');
  assert.throws(() => cc.base32CrockfordToBytes('ABCU'), /invalid base32 character/);
});

test('uuidBytes gives the 16 raw bytes and refuses anything that is not a UUID', () => {
  assert.equal(cc.toHex(cc.uuidBytes('123e4567-e89b-12d3-a456-426614174000')), '123e4567e89b12d3a456426614174000');
  assert.equal(cc.toHex(cc.uuidBytes('123E4567E89B12D3A456426614174000')), '123e4567e89b12d3a456426614174000', 'case and dashes do not matter');
  assert.throws(() => cc.uuidBytes('not-a-uuid'), /not a uuid/);
  assert.throws(() => cc.uuidBytes('123e4567-e89b-12d3-a456-42661417400'), /not a uuid/);
});

test('u32be is 4 big-endian bytes and refuses out-of-range values', () => {
  assert.equal(cc.toHex(cc.u32be(0)), '00000000');
  assert.equal(cc.toHex(cc.u32be(1)), '00000001');
  assert.equal(cc.toHex(cc.u32be(0x01020304)), '01020304');
  assert.equal(cc.toHex(cc.u32be(0xffffffff)), 'ffffffff');
  for (const bad of [-1, 0x100000000, 1.5, NaN]) assert.throws(() => cc.u32be(bad), /out of range/);
});

test('u64be is 8 big-endian bytes and refuses out-of-range values', () => {
  assert.equal(cc.toHex(cc.u64be(0)), '0000000000000000');
  assert.equal(cc.toHex(cc.u64be(1)), '0000000000000001');
  assert.equal(cc.toHex(cc.u64be(0x01020304)), '0000000001020304');
  assert.equal(cc.toHex(cc.u64be(1758758400000)), '000001997e2b7000', 'a millisecond timestamp (2026-09-25T00:00:00Z)');
  assert.equal(cc.toHex(cc.u64be(Number.MAX_SAFE_INTEGER)), '001fffffffffffff');
  for (const bad of [-1, 1.5, NaN, 2 ** 53]) assert.throws(() => cc.u64be(bad), /out of range/);
});

test('frameContext layout is frozen: context ‖ 0x00 ‖ parts', () => {
  const frame = cc.frameContext('x/y/v1', cc.uuidBytes('00000000-0000-0000-0000-000000000001'), cc.u32be(7));
  assert.equal(cc.toHex(frame), '782f792f763100' + '00000000000000000000000000000001' + '00000007');
  assert.equal(cc.frameContext('').length, 1, 'an empty context is just the NUL');
});

test('randomBytes returns the requested length and refuses silly ones', () => {
  assert.equal(cc.randomBytes(0).length, 0);
  assert.equal(cc.randomBytes(32).length, 32);
  assert.equal(cc.generateSymmetricKey().length, 32);
  assert.notDeepEqual(cc.generateSymmetricKey(), cc.generateSymmetricKey());
  assert.equal(cc.randomBytes(70000).length, 70000, 'longer than one getRandomValues call');
  assert.throws(() => cc.randomBytes(-1), /out of range/);
  assert.throws(() => cc.randomBytes(1.5), /out of range/);
});

test('sha256 matches the FIPS 180-4 "abc" answer', async () => {
  const d = await cc.sha256(new TextEncoder().encode('abc'));
  assert.equal(cc.toHex(d), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
