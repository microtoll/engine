/**
 * X-Wing (X25519 + ML-KEM-768 hybrid KEM), composed from Node's own
 * primitives. TEST TOOLING ONLY.
 *
 * SECURITY-CRITICAL. Never change a byte layout to make a test pass: the
 * known-answer tests in `test/xwing.test.mjs` are pinned to the draft's own
 * vectors, and a red one means the code is wrong or the spec moved, never
 * that the number needs updating.
 *
 * WHY THIS FILE EXISTS AT ALL, since "no third-party crypto, SubtleCrypto
 * only" is a standing rule and this looks like an exception. It is not one:
 *
 *  - Every primitive below is Node's own — ML-KEM-768 and SHA3-256 through
 *    WebCrypto, SHAKE256 through `node:crypto`, X25519 through a PKCS#8
 *    import (kept here because no browser path in the engine uses X25519:
 *    Safari has never had it, and the classical seal is P-256). Nothing is
 *    hand-rolled, no bignum is written here, and no dependency is added.
 *    What this file contributes is the *composition* the X-Wing draft
 *    specifies: three slices, two key agreements and one hash.
 *  - It never runs in a browser. The client calls native `MLKEM768-X25519`
 *    in SubtleCrypto where the browser ships it (Chrome 154), and until a
 *    person's browser has it they stay on the classical path (D-07). So this
 *    composition is not a polyfill and must never become one.
 *  - Its only consumer is the test suite, through the platform shim
 *    (`pq-test-shim.mjs`). When Node ships X-Wing natively, delete the
 *    composition and keep the tests.
 *
 * Spec: draft-connolly-cfrg-xwing-kem-10 (2 March 2026). Not yet an RFC, and
 * that draft expired on 3 September 2026 — so the vectors are pinned to that
 * exact revision and the suite says which one it checked. If a later
 * revision changes the construction, the KATs go red and that is the whole
 * point of having them.
 *
 *   sk  32 bytes   (the seed IS the private key)
 *   pk  1216 = ML-KEM-768 public 1184 || X25519 public 32
 *   ct  1120 = ML-KEM-768 ciphertext 1088 || X25519 ephemeral public 32
 *   ss  32 bytes
 */
import { createHash } from 'node:crypto';
// TEST TOOLING for @microtoll/crypto-core. It lives under test/ and is never
// imported by src/: a self-check asserts that. The import below reads the
// public half of an X25519 key through the package's own JWK reader.
import * as cs from '../../src/primitives.js';

const subtle = globalThis.crypto.subtle;

export const XWING_DRAFT = 'draft-connolly-cfrg-xwing-kem-10';
export const SK_BYTES = 32;
export const PK_BYTES = 1216;
export const CT_BYTES = 1120;
export const SS_BYTES = 32;
const MLKEM_PK_BYTES = 1184;
const MLKEM_CT_BYTES = 1088;
const X25519_BYTES = 32;

/**
 * The 6-byte label the combiner ends with. Written as the draft writes it —
 * the ASCII art "\./" over "/^\" — and immediately checked against the
 * hexadecimal the draft also publishes, because a label that silently
 * differs by one byte produces shared secrets that are wrong everywhere and
 * wrong consistently, which is the hardest kind of bug to see.
 */
const XWING_LABEL = new Uint8Array([0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
if (Buffer.from(XWING_LABEL).toString('hex') !== '5c2e2f2f5e5c') {
  throw new Error('X-Wing label does not match the draft');
}
if (Buffer.from(XWING_LABEL).toString('latin1') !== '\\./' + '/^\\') {
  throw new Error('X-Wing label bytes are not the draft\'s ASCII string');
}

const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
};

/** SHAKE256 with a 96-byte output. Not in WebCrypto; `node:crypto` has it. */
function shake256_96(seed32) {
  const h = createHash('shake256', { outputLength: 96 });
  h.update(Buffer.from(seed32));
  return new Uint8Array(h.digest());
}

/**
 * seed -> the four key parts. Deterministic, and this determinism is what
 * makes X-Wing fit the engine at all: a 32-byte HKDF output from the Account
 * Root Key becomes an X-Wing key with nothing stored.
 */
// X25519 import, Node-side only. No browser path in the engine uses X25519
// (Safari's Web Crypto has none), but X-Wing is X25519 by definition and this
// file runs only under Node, which has it.
// PKCS#8 header for a 32-byte X25519 private key (RFC 8410, OID 1.3.101.110).
const X25519_PKCS8_HEADER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
]);
async function importX25519PrivateKeyFromSeed(seed32) {
  if (seed32.length !== 32) throw new Error(`X25519 seed must be 32 bytes, got ${seed32.length}`);
  return subtle.importKey('pkcs8', concat(X25519_PKCS8_HEADER, seed32), { name: 'X25519' }, true, ['deriveBits']);
}
async function importX25519PublicKey(raw32) {
  if (raw32.length !== 32) throw new Error(`X25519 public key must be 32 bytes, got ${raw32.length}`);
  return subtle.importKey('raw', raw32, { name: 'X25519' }, true, []);
}

export async function expandDecapsulationKey(seed32) {
  if (seed32.length !== SK_BYTES) throw new Error(`seed must be ${SK_BYTES} bytes, got ${seed32.length}`);
  const expanded = shake256_96(seed32);
  // expanded[0:64] is ML-KEM-768's own (d || z) keygen seed; [64:96] is the
  // X25519 scalar. Slicing the wrong way round still produces valid-looking
  // keys, so the vectors are the only real check.
  const skM = await subtle.importKey('raw-seed', expanded.slice(0, 64), { name: 'ML-KEM-768' }, true, ['decapsulateBits']);
  const pkMKey = await subtle.getPublicKey(skM, []);
  const pkM = new Uint8Array(await subtle.exportKey('raw-public', pkMKey));
  const skXRaw = expanded.slice(64, 96);
  const skX = await importX25519PrivateKeyFromSeed(skXRaw);
  const pkX = await cs.exportPublicKeyRawFromPrivate(skX);
  return { skM, skX, pkM, pkX };
}

/** The public key a counterparty needs: ML-KEM public || X25519 public. */
export async function publicKeyFromSeed(seed32) {
  const { pkM, pkX } = await expandDecapsulationKey(seed32);
  return concat(pkM, pkX);
}

/** SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel) — draft §5.3. */
async function combiner(ssM, ssX, ctX, pkX) {
  const digest = await subtle.digest('SHA3-256', concat(ssM, ssX, ctX, pkX, XWING_LABEL));
  return new Uint8Array(digest);
}

/**
 * Encapsulate to a 1216-byte X-Wing public key.
 *
 * The ML-KEM half uses Node's own randomness (there is no derandomised
 * encapsulation exposed), so this cannot reproduce a test vector's
 * ciphertext — which is why the vectors are checked through key generation
 * and DEcapsulation, the two halves that are deterministic. Correctness of
 * this direction is covered by round-trips against them.
 */
export async function encapsulate(pk1216) {
  if (pk1216.length !== PK_BYTES) throw new Error(`public key must be ${PK_BYTES} bytes, got ${pk1216.length}`);
  const pkM = pk1216.slice(0, MLKEM_PK_BYTES);
  const pkX = pk1216.slice(MLKEM_PK_BYTES, PK_BYTES);

  const pkMKey = await subtle.importKey('raw-public', pkM, { name: 'ML-KEM-768' }, true, ['encapsulateBits']);
  const { sharedKey, ciphertext } = await subtle.encapsulateBits({ name: 'ML-KEM-768' }, pkMKey);
  const ssM = new Uint8Array(sharedKey);
  const ctM = new Uint8Array(ciphertext);

  const ephemeral = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
  const ctX = new Uint8Array(await subtle.exportKey('raw', ephemeral.publicKey));
  const peer = await importX25519PublicKey(pkX);
  const ssX = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: peer }, ephemeral.privateKey, 256));

  return { sharedSecret: await combiner(ssM, ssX, ctX, pkX), ciphertext: concat(ctM, ctX) };
}

/** Decapsulate a 1120-byte ciphertext with the 32-byte seed. Deterministic. */
export async function decapsulate(ct1120, seed32) {
  if (ct1120.length !== CT_BYTES) throw new Error(`ciphertext must be ${CT_BYTES} bytes, got ${ct1120.length}`);
  const ctM = ct1120.slice(0, MLKEM_CT_BYTES);
  const ctX = ct1120.slice(MLKEM_CT_BYTES, CT_BYTES);
  const { skM, skX, pkX } = await expandDecapsulationKey(seed32);

  const ssM = new Uint8Array(await subtle.decapsulateBits({ name: 'ML-KEM-768' }, skM, ctM));
  const peer = await importX25519PublicKey(ctX);
  const ssX = new Uint8Array(await subtle.deriveBits({ name: 'X25519', public: peer }, skX, 256));

  return combiner(ssM, ssX, ctX, pkX);
}

/**
 * Whether this Node can do the above at all. Reported by the tests and by
 * the opener, so "it did not run" never looks like "it passed".
 */
export async function available() {
  try {
    await subtle.digest('SHA3-256', new Uint8Array(1));
    createHash('shake256', { outputLength: 96 });
    await subtle.generateKey({ name: 'ML-KEM-768' }, true, ['encapsulateBits', 'decapsulateBits']);
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

/**
 * The name WebCrypto exposes this construction under — and it is NOT
 * "X-Wing", which is the name of the paper and of the individual draft.
 *
 * Found on 2026-09-06, before any client code was written, by reading the
 * spec rather than assuming: `wicg.github.io/webcrypto-modern-algos` never
 * says "X-Wing" at all. It names three hybrid KEMs — `MLKEM768-P256`,
 * `MLKEM768-X25519`, `MLKEM1024-P384` — and cites
 * draft-irtf-cfrg-concrete-hybrid-kems, the working-group document that
 * took the individual X-Wing draft over. That draft says in so many words
 * that `MLKEM768-X25519` "is identical to the X-Wing" construction, carries
 * the same 5c2e2f2f5e5c label, and **its own test vector passes through the
 * composition in this file** (checked, and pinned in
 * `xwing-vectors-wg04.json`).
 *
 * So the construction is the same and our vectors were right; only the name
 * differed. `{ name: 'X-Wing' }` in client code would have failed in Chrome
 * with "Unrecognized algorithm name" — the cheapest possible version of that
 * bug, but only because it was looked up instead of guessed.
 */
export const WEBCRYPTO_ALGORITHM_NAME = 'MLKEM768-X25519';

/**
 * True where this runtime has the hybrid KEM natively, so the composition
 * can retire. Probes the real WebCrypto name, and the paper's name too, in
 * case some engine ships it under that.
 */
export async function nativeXWingAvailable() {
  for (const name of [WEBCRYPTO_ALGORITHM_NAME, 'X-Wing']) {
    try {
      await subtle.generateKey({ name }, true, ['encapsulateBits', 'decapsulateBits']);
      return true;
    } catch { /* next */ }
  }
  return false;
}
