// The recovery-code format: version 3 (D-46), 128 bits in Crockford base32
// with a weighted check over GF(32); version 2 (D-26) read only on request.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as cc from '../src/index.js';

const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const flat = (s) => s.replace(/-/g, '');
const errorCode = (s, options) => cc.parseRecoveryCode(s, options).then(() => null, (e) => e.code);
const H = (hex) => Uint8Array.from(hex.match(/../g), (b) => parseInt(b, 16));

test('generate, format, parse round trip: version 3, 16 bytes, 27 characters in seven groups', async () => {
  const { secretBytes, displayString } = await cc.generateRecoveryCode();
  assert.equal(secretBytes.length, 16);
  assert.match(displayString, /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){5}-[0-9A-HJKMNP-TV-Z]{3}$/);
  assert.deepEqual(await cc.parseRecoveryCode(displayString), secretBytes);
  assert.equal(cc.RECOVERY_CODE_VERSION, 3);
  assert.deepEqual(cc.RECOVERY_CODE_VERSIONS, [2, 3]);
});

test('version 3 vectors, computed by hand in GF(32) = GF(2)[x]/(x⁵ + x² + 1), a = x (D-46)', async () => {
  // Each check is Σ aⁱ⁺¹·sᵢ. The powers of x used: x¹ = 2, x² = 4, x⁸ = 13,
  // x¹³ = 28, x¹⁵ = 31, x¹⁹ = 6, x²⁶ = 23, x²⁸ = 22; Σ x¹…x²⁵ = x⁴ = 16.
  const vectors = [
    // All zero: every term is zero, so the check is 0.
    ['00000000000000000000000000000000', '0000-0000-0000-0000-0000-0000-000'],
    // s₀ = 1 (the first five bits 00001): a¹·1 = 2.
    ['08000000000000000000000000000000', '1000-0000-0000-0000-0000-0000-002'],
    // s₁ = 1 (bit 9 set): a²·1 = 4.
    ['00400000000000000000000000000000', '0100-0000-0000-0000-0000-0000-004'],
    // s₂₅ = 4 (the last bit of the last byte, then two zero padding bits): a²⁶·x² = x²⁸ = 22 = P.
    ['00000000000000000000000000000001', '0000-0000-0000-0000-0000-0000-04P'],
    // All ones: s₀…s₂₄ = 31 = x¹⁵ and s₂₅ = 28 = x¹³: x⁴·x¹⁵ ⊕ x²⁶·x¹³ = x¹⁹ ⊕ x⁸ = 6 ⊕ 13 = 11 = B.
    ['ffffffffffffffffffffffffffffffff', 'ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZZZZ-ZWB'],
  ];
  for (const [hex, code] of vectors) {
    assert.equal(await cc.formatRecoveryCode(H(hex)), code, hex);
    assert.deepEqual(await cc.parseRecoveryCode(code), H(hex), code);
  }
});

test('version 3 catches EVERY single wrong character, at every one of the 27 positions', async () => {
  for (const hex of ['00000000000000000000000000000000', 'ffffffffffffffffffffffffffffffff', null]) {
    const bytes = hex ? H(hex) : cc.randomBytes(16);
    const chars = flat(await cc.formatRecoveryCode(bytes)).split('');
    for (let i = 0; i < 27; i++) {
      for (const replacement of A) {
        if (replacement === chars[i]) continue;
        const typo = chars.slice(); typo[i] = replacement;
        assert.equal(await errorCode(typo.join('')), 'recovery-code-checksum', `position ${i} as ${replacement}`);
      }
    }
  }
});

test('version 3 catches EVERY swap of two different characters, adjacent or not, the check character included', async () => {
  for (let t = 0; t < 5; t++) {
    const chars = flat((await cc.generateRecoveryCode()).displayString).split('');
    for (let i = 0; i < 27; i++) {
      for (let j = i + 1; j < 27; j++) {
        if (chars[i] === chars[j]) continue;
        const swapped = chars.slice(); [swapped[i], swapped[j]] = [swapped[j], swapped[i]];
        assert.equal(await errorCode(swapped.join('')), 'recovery-code-checksum', `swap ${i} and ${j}`);
      }
    }
  }
});

test('version 3: one string names one secret — the unused bits must be zero, and there are exactly 26 data characters', async () => {
  const bytes = cc.randomBytes(16);
  const chars = flat(await cc.formatRecoveryCode(bytes)).split('');
  // The same 16 bytes with a non-zero padding bit, whatever the check character says.
  const last = A.indexOf(chars[25]);
  for (const padding of [1, 2, 3]) {
    const variant = chars.slice(0, 25).concat(A[last | padding]);
    assert.deepEqual(cc.base32CrockfordToBytes(variant.join('')), bytes, 'decodes to the same bytes');
    for (const check of A) assert.equal(await errorCode(variant.join('') + check), 'recovery-code-checksum');
  }
  // A 27th data character also decodes to 16 bytes; it is refused.
  for (const extra of A) assert.equal(await errorCode(chars.slice(0, 26).join('') + extra + chars[26]), 'recovery-code-length');
});

test('lower case, spaces, missing dashes and the O/I/L confusions still parse', async () => {
  const { secretBytes, displayString } = await cc.generateRecoveryCode();
  const messy = '  ' + displayString.toLowerCase().replace(/-/g, ' ') + '  ';
  assert.deepEqual(await cc.parseRecoveryCode(messy), secretBytes);
  const confused = displayString.replace(/0/g, 'O').replace(/1/g, 'I');
  assert.deepEqual(await cc.parseRecoveryCode(confused), secretBytes);
});

test('errors carry a code: too short, wrong length, invalid character, bad check', async () => {
  assert.equal(await errorCode(''), 'recovery-code-short');
  assert.equal(await errorCode('ABCD-EFGH'), 'recovery-code-length');
  assert.equal(await errorCode('ABCU-EFGH-JKMN-PQRS-TVWX-YZ01-234'), 'recovery-code-char');
  assert.equal(await errorCode('0000-0000-0000-0000-0000-0000-00U'), 'recovery-code-char', 'U is not a check character');
  const { displayString } = await cc.generateRecoveryCode();
  const wrongCheck = displayString.slice(0, -1) + A[(A.indexOf(displayString.slice(-1)) + 1) % 32];
  assert.equal(await errorCode(wrongCheck), 'recovery-code-checksum');
  await assert.rejects(cc.formatRecoveryCode(new Uint8Array(15)), /16 bytes/);
  await assert.rejects(cc.formatRecoveryCode(new Uint8Array(16), { version: 1 }), /unknown recovery-code version: 1/);
  await assert.rejects(cc.parseRecoveryCode(displayString, { version: 4 }), /unknown recovery-code version: 4/);
});

test('version 2 is read and written only when asked for by name: the check is the low five bits of SHA-256(secret)[0]', async () => {
  const bytes = Uint8Array.from({ length: 16 }, (_, i) => (i * 37) & 0xff);
  const v2 = await cc.formatRecoveryCode(bytes, { version: 2 });
  assert.equal(flat(v2).slice(0, 26), cc.bytesToBase32Crockford(bytes));
  assert.equal(flat(v2).slice(26), A[createHash('sha256').update(bytes).digest()[0] & 0x1f]);
  assert.deepEqual(await cc.parseRecoveryCode(v2, { version: 2 }), bytes);
  // The same bytes in version 3 differ only in the check character.
  const v3 = await cc.formatRecoveryCode(bytes);
  assert.equal(flat(v3).slice(0, 26), flat(v2).slice(0, 26));
  if (v3 !== v2) {
    // Never silently accepted as the other version: that would give up version 3's guarantees.
    assert.equal(await errorCode(v2), 'recovery-code-checksum');
    assert.equal(await errorCode(v3, { version: 2 }), 'recovery-code-checksum');
  }
});
