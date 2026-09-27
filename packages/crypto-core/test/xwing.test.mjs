// Known-answer tests for the X-Wing composition in test/tooling/xwing.mjs
// (draft-connolly-cfrg-xwing-kem test vectors). This is the
// test tooling's own gate: nothing may be sealed through the shim until these
// are green. A red one means the composition is wrong or the draft moved,
// never that a number needs regenerating.
//
// What can be checked against a vector: key generation (seed → public key)
// and decapsulation ((ciphertext, seed) → shared secret), both deterministic.
// Encapsulation cannot be: the draft's vectors use a derandomised
// encapsulation and Node exposes no way to inject that randomness, so it is
// covered by round trips. ML-KEM's implicit rejection means a corrupted
// ciphertext gives a DIFFERENT secret, never an exception.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import * as xw from './tooling/xwing.mjs';

const H = (h) => Uint8Array.from(Buffer.from(h, 'hex'));
const hex = (b) => Buffer.from(b).toString('hex');
const vectors = JSON.parse(readFileSync(new URL('./vectors/xwing-vectors-draft10.json', import.meta.url), 'utf8'));
const wg = JSON.parse(readFileSync(new URL('./vectors/xwing-vectors-wg04.json', import.meta.url), 'utf8'))[0];

before(async () => {
  const a = await xw.available();
  if (!a.ok) throw new Error(`this Node cannot do ML-KEM-768, SHA3-256 and SHAKE256: ${a.reason}`);
});

test('the vector file is the draft it claims and is not empty', () => {
  assert.equal(vectors.length, 3);
  for (const v of vectors) {
    assert.equal(H(v.seed).length, xw.SK_BYTES);
    assert.equal(H(v.pk).length, xw.PK_BYTES);
    assert.equal(H(v.ct).length, xw.CT_BYTES);
    assert.equal(H(v.ss).length, xw.SS_BYTES);
  }
  assert.equal(xw.XWING_DRAFT, 'draft-connolly-cfrg-xwing-kem-10');
});

for (const [i, v] of vectors.entries()) {
  test(`draft-10 Appendix C vector ${i}: seed → public key, and (ciphertext, seed) → shared secret`, async () => {
    assert.equal(hex(await xw.publicKeyFromSeed(H(v.seed))), v.pk);
    assert.equal(hex(await xw.decapsulate(H(v.ct), H(v.seed))), v.ss);
  });
}

test('working-group draft (concrete-hybrid-kems-04, MLKEM768-X25519): the same construction under the WebCrypto name', async () => {
  assert.equal(hex(await xw.publicKeyFromSeed(H(wg.seed))), wg.pk);
  assert.equal(hex(await xw.decapsulate(H(wg.ct), H(wg.seed))), wg.ss);
  assert.equal(xw.WEBCRYPTO_ALGORITHM_NAME, 'MLKEM768-X25519');
});

test('round trip: encapsulate to a vector public key, decapsulate with its seed', async () => {
  const { sharedSecret, ciphertext } = await xw.encapsulate(H(vectors[0].pk));
  assert.equal(ciphertext.length, xw.CT_BYTES);
  assert.equal(hex(await xw.decapsulate(ciphertext, H(vectors[0].seed))), hex(sharedSecret));
});

test('implicit rejection: a wrong seed or a flipped ciphertext byte gives a different secret, with no exception', async () => {
  const { sharedSecret, ciphertext } = await xw.encapsulate(H(vectors[1].pk));
  const wrongSeed = hex(await xw.decapsulate(ciphertext, H(vectors[2].seed)));
  assert.notEqual(wrongSeed, hex(sharedSecret));
  for (const i of [5, 1100]) {
    const c = ciphertext.slice(); c[i] ^= 0x01;
    assert.notEqual(hex(await xw.decapsulate(c, H(vectors[1].seed))), hex(sharedSecret), `byte ${i}`);
  }
});

test('malformed lengths are refused', async () => {
  await assert.rejects(xw.publicKeyFromSeed(new Uint8Array(31)), /32 bytes/);
  await assert.rejects(xw.encapsulate(new Uint8Array(1215)), /1216 bytes/);
  await assert.rejects(xw.decapsulate(new Uint8Array(1119), H(vectors[0].seed)), /1120 bytes/);
});

test('the tooling is never imported by src/', () => {
  const dir = new URL('../src/', import.meta.url);
  for (const f of readdirSync(dir)) {
    const text = readFileSync(new URL(f, dir), 'utf8');
    assert.equal(/tooling|xwing|pq-test-shim/.test(text.replace(/^\s*\/\/.*$/gm, '').replace(/\/\*[\s\S]*?\*\//g, '')), false, `${f} imports test tooling`);
  }
});
