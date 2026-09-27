/**
 * Format-independent primitives.
 *
 * A change to any output of this file is a format change: it is recorded in
 * CHANGELOG.md and DECISIONS.md, and the frozen fixtures
 * (test/fixtures/frozen-v1.json) fail until it is.
 *
 * Rules of this file: pure functions only; no DOM, no network, no storage; the
 * only cryptography is `globalThis.crypto` (Web Crypto). Every non-obvious
 * choice names the standard or the test vector it answers to.
 */

const subtle = globalThis.crypto.subtle;

// #####################################################################
// # Byte and encoding helpers
// #####################################################################

export function toHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('hex string must have even length and only hex digits');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

export function toBase64Url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function fromBase64Url(str) {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/')
    .padEnd(str.length + (4 - str.length % 4) % 4, '=');
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrs) { out.set(a, offset); offset += a.length; }
  return out;
}

/**
 * A UUID's 16 raw bytes: how an id goes into additional authenticated data or
 * a signed frame, where its text form would be a second encoding of the same
 * value. Refuses anything that is not a UUID.
 */
export function uuidBytes(id) {
  const hex = String(id).replace(/-/g, '');
  if (!/^[0-9a-f]{32}$/i.test(hex)) throw new Error('not a uuid');
  return fromHex(hex.toLowerCase());
}

/** A 32-bit unsigned integer (an epoch) as 4 big-endian bytes. */
export function u32be(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error('epoch out of range');
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** A non-negative integer below 2^53 (a millisecond timestamp) as 8 big-endian bytes. */
export function u64be(n) {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('value out of range');
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 7; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; }
  return out;
}

/**
 * The frame a context-bound seal or signature is keyed to:
 * context ‖ 0x00 ‖ parts. The NUL ends the context so no label can run into
 * what follows, and every part is fixed-length (a UUID as 16 bytes, an epoch
 * as u32be), so one frame can never be read as another.
 */
export function frameContext(context, ...parts) {
  return concatBytes(new TextEncoder().encode(context), new Uint8Array([0]), ...parts);
}

// Crockford base32: no I, L, O or U, so a handwritten code cannot be confused
// with 1/1/0/V. Used for recovery codes; the checksum that follows the data
// part belongs to the recovery-code format, not to this codec.
const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function bytesToBase32Crockford(bytes) {
  let bitBuffer = 0, bitCount = 0, output = '';
  for (const byte of bytes) {
    bitBuffer = (bitBuffer << 8) | byte;
    bitCount += 8;
    while (bitCount >= 5) {
      bitCount -= 5;
      output += CROCKFORD_ALPHABET[(bitBuffer >>> bitCount) & 0x1f];
    }
    bitBuffer &= (1 << bitCount) - 1;
  }
  if (bitCount > 0) output += CROCKFORD_ALPHABET[(bitBuffer << (5 - bitCount)) & 0x1f];
  return output;
}

export function base32CrockfordToBytes(str) {
  let bitBuffer = 0, bitCount = 0;
  const out = [];
  for (const ch of str) {
    const idx = CROCKFORD_ALPHABET.indexOf(ch);
    if (idx === -1) throw Object.assign(new Error('invalid base32 character'), { code: 'base32-char' });
    bitBuffer = (bitBuffer << 5) | idx;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      out.push((bitBuffer >>> bitCount) & 0xff);
    }
    bitBuffer &= (1 << bitCount) - 1;
  }
  return new Uint8Array(out);
}

// #####################################################################
// # Random and hashing
// #####################################################################

export function randomBytes(length) {
  if (!Number.isInteger(length) || length < 0) throw new Error('length out of range');
  const out = new Uint8Array(length);
  // getRandomValues fills at most 65,536 bytes per call (Web Crypto §10.1.1).
  for (let offset = 0; offset < length; offset += 65536) {
    globalThis.crypto.getRandomValues(out.subarray(offset, Math.min(offset + 65536, length)));
  }
  return out;
}

/** 32 random bytes: a root key, an object key, a capability secret. */
export function generateSymmetricKey() {
  return randomBytes(32);
}

export async function sha256(bytes) {
  return new Uint8Array(await subtle.digest('SHA-256', bytes));
}

// #####################################################################
// # HKDF (RFC 5869), SHA-256
// #####################################################################

export const HKDF_HASH = 'SHA-256';

/**
 * Extract-and-expand to raw bits, with any salt and info. Exported so the
 * RFC 5869 known-answer tests drive this exact function.
 */
export async function hkdfDeriveBits(ikmBytes, saltBytes, infoBytes, lengthBits) {
  const baseKey = await subtle.importKey('raw', ikmBytes, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'HKDF', hash: HKDF_HASH, salt: saltBytes, info: infoBytes },
    baseKey, lengthBits,
  );
  return new Uint8Array(bits);
}

/** The labelled derivation shape: empty salt, a UTF-8 text label as info (RFC 5869 §3.1 allows the empty salt). */
export async function hkdfDeriveSeedBits(ikm, label, lengthBits = 256) {
  return hkdfDeriveBits(ikm, new Uint8Array(0), new TextEncoder().encode(label), lengthBits);
}

/** The same shape, straight to a non-extractable AES-256-GCM key. */
export async function hkdfDeriveAesGcmKey(ikm, label) {
  const baseKey = await subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: HKDF_HASH, salt: new Uint8Array(0), info: new TextEncoder().encode(label) },
    baseKey,
    { name: 'AES-GCM', length: AEAD_KEY_LENGTH_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

// #####################################################################
// # Ed25519 from a 32-byte seed
// #####################################################################

// RFC 8410 PKCS#8 DER header for a raw 32-byte Ed25519 CurvePrivateKey seed:
// SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING { OCTET STRING seed } }.
const ED25519_PKCS8_HEADER = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

/**
 * Imports a seed as a signing key. Extractable, because Web Crypto offers no
 * other way to read the public half (below). A caller that keeps the key
 * reads the public half once and re-imports the seed non-extractable for use
 * (the identity package's ed25519PairFromSeed, its FORMATS.md §2.6).
 */
export async function importEd25519PrivateKeyFromSeed(seed32) {
  if (!seed32 || seed32.length !== 32) throw new Error('seed must be 32 bytes, got ' + (seed32 ? seed32.length : 'none'));
  return subtle.importKey('pkcs8', concatBytes(ED25519_PKCS8_HEADER, seed32), { name: 'Ed25519' }, true, ['sign']);
}

/** The public key is the JWK "x" field of the private key (RFC 8037). */
export async function exportPublicKeyRawFromPrivate(privateKey) {
  const jwk = await subtle.exportKey('jwk', privateKey);
  if (!jwk.x) throw new Error('exported JWK has no public "x" component');
  return fromBase64Url(jwk.x);
}

export async function importEd25519PublicKey(rawBytes32) {
  return subtle.importKey('raw', rawBytes32, { name: 'Ed25519' }, false, ['verify']);
}

export async function signBytes(signingPrivateKey, messageBytes) {
  return new Uint8Array(await subtle.sign('Ed25519', signingPrivateKey, messageBytes));
}

/** False rather than a throw on a malformed key or signature: unverifiable is an ordinary state to render. */
export async function verifyBytes(signingPublicKeyRaw, messageBytes, signatureBytes) {
  try {
    const pubKey = await importEd25519PublicKey(signingPublicKeyRaw);
    return await subtle.verify('Ed25519', pubKey, signatureBytes, messageBytes);
  } catch {
    return false;
  }
}

// #####################################################################
// # The stored P-256 sealing key
// #####################################################################
// Generated once, kept as a private JWK inside an authenticated ciphertext,
// never derived: Safari has no X25519 and Firefox cannot import a P-256
// private key from a bare scalar, while every engine imports a JWK {d, x, y}
// This is measured browser behaviour, not a preference.

export const SEALING_CURVE = 'P-256';
export const P256_PUBLIC_KEY_BYTES = 65; // 0x04 ‖ x ‖ y, uncompressed

function assertSealingJwk(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== SEALING_CURVE || typeof jwk.d !== 'string'
      || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new Error(`not a ${SEALING_CURVE} private JWK (needs kty EC, crv ${SEALING_CURVE}, d, x, y)`);
  }
}

/** The raw public point read straight off a JWK; no crypto call. */
export function sealingPublicKeyFromJwk(jwk) {
  assertSealingJwk(jwk);
  const x = fromBase64Url(jwk.x);
  const y = fromBase64Url(jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new Error(`JWK coordinates are ${x.length}/${y.length} bytes, expected 32/32`);
  return concatBytes(new Uint8Array([0x04]), x, y);
}

/** Importing is what validates the point lies on the curve. */
export async function importSealingPublicKey(rawBytes65) {
  if (!rawBytes65 || rawBytes65.length !== P256_PUBLIC_KEY_BYTES) {
    throw new Error(`a ${SEALING_CURVE} public key is ${P256_PUBLIC_KEY_BYTES} bytes, got ${rawBytes65 ? rawBytes65.length : 'none'}`);
  }
  return subtle.importKey('raw', rawBytes65, { name: 'ECDH', namedCurve: SEALING_CURVE }, false, []);
}

/**
 * A stored key back into use: { privateKey (non-extractable), publicKeyRaw, jwk }.
 * The public half is re-imported only so the point is checked; a JWK whose d
 * and (x, y) disagree cannot be detected without scalar multiplication, which
 * is why the JWK is minted by SubtleCrypto itself (generateSealingKeyPair) and
 * travels only inside an authenticated ciphertext.
 */
/**
 * The agreement two long-term P-256 sealing keys share: 256 bits of ECDH
 * between this private key and the other party's public key, the same
 * non-interactive agreement (a.B == b.A) the mailbox package feeds to HKDF
 * for a pairwise mailbox label. Exposed for the mailbox
 * package (M3b); the ECIES seal above does the same step with an ephemeral
 * key. Never used as a key directly -- always through HKDF with a label.
 */
export async function deriveSealingSharedBits(privateKey, otherPublicKeyRaw65) {
  const otherPublicKey = await importSealingPublicKey(otherPublicKeyRaw65);
  return new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: otherPublicKey }, privateKey, 256));
}

export async function importSealingKeyPair(jwk) {
  assertSealingJwk(jwk);
  const clean = { kty: jwk.kty, crv: jwk.crv, d: jwk.d, x: jwk.x, y: jwk.y };
  const privateKey = await subtle.importKey('jwk', clean, { name: 'ECDH', namedCurve: SEALING_CURVE }, false, ['deriveBits']);
  const publicKeyRaw = sealingPublicKeyFromJwk(clean);
  await importSealingPublicKey(publicKeyRaw);
  return { privateKey, publicKeyRaw, jwk: clean };
}

/** A new pair, extractable only for the one export that produces the JWK. */
export async function generateSealingKeyPair() {
  const generated = await subtle.generateKey({ name: 'ECDH', namedCurve: SEALING_CURVE }, true, ['deriveBits']);
  const full = await subtle.exportKey('jwk', generated.privateKey);
  return importSealingKeyPair({ kty: full.kty, crv: full.crv, d: full.d, x: full.x, y: full.y });
}

// #####################################################################
// # AEAD v1 — the canonical symmetric ciphertext
// #####################################################################
// [version byte 0x01][12-byte random IV][AES-256-GCM ciphertext ‖ 16-byte tag]
// SubtleCrypto appends the tag; nothing that stores this gets a tag column.
// `additionalData` is authenticated, not encrypted; a caller that omits it
// gets byte-for-byte the format without it.

export const AEAD_VERSION_1 = 0x01;
export const AEAD_IV_BYTES = 12;
export const AEAD_KEY_LENGTH_BITS = 256;

/** Raw 32 bytes as a non-extractable AES-256-GCM key. */
export async function importSymmetricKey(rawBytes32) {
  if (!rawBytes32 || rawBytes32.length !== 32) throw new Error('a symmetric key is 32 bytes, got ' + (rawBytes32 ? rawBytes32.length : 'none'));
  return subtle.importKey('raw', rawBytes32, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/**
 * A fresh AES-256-GCM key that never exists as bytes in JavaScript
 * (non-extractable), for a record a device keeps for itself, such as a
 * trusted-device session.
 */
export async function generateNonExtractableSymmetricKey() {
  return subtle.generateKey({ name: 'AES-GCM', length: AEAD_KEY_LENGTH_BITS }, false, ['encrypt', 'decrypt']);
}

export async function sealSymmetric(key, plaintextBytes, additionalData = null) {
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(AEAD_IV_BYTES));
  const params = additionalData ? { name: 'AES-GCM', iv, additionalData } : { name: 'AES-GCM', iv };
  const ciphertext = await subtle.encrypt(params, key, plaintextBytes);
  return concatBytes(new Uint8Array([AEAD_VERSION_1]), iv, new Uint8Array(ciphertext));
}

export async function openSymmetric(key, sealedBytes, additionalData = null) {
  if (sealedBytes.length < 1 + AEAD_IV_BYTES) throw new Error('sealed blob too short');
  if (sealedBytes[0] !== AEAD_VERSION_1) throw new Error('unsupported AEAD version: ' + sealedBytes[0]);
  const iv = sealedBytes.slice(1, 1 + AEAD_IV_BYTES);
  const ciphertext = sealedBytes.slice(1 + AEAD_IV_BYTES);
  const params = additionalData ? { name: 'AES-GCM', iv, additionalData } : { name: 'AES-GCM', iv };
  const plaintext = await subtle.decrypt(params, key, ciphertext);
  return new Uint8Array(plaintext);
}

// #####################################################################
// # PBKDF2-SHA-256
// #####################################################################
// Stretches and salt-binds a secret that already carries its own entropy
// (a recovery code: 128 bits). Web Crypto has no memory-hard KDF, so
// the entropy, not the iteration count, carries the security.

/** Raw bits, for the RFC 7914 §11 known-answer tests and for callers that need bytes. */
export async function pbkdf2DeriveBits(passwordBytes, saltBytes, iterations, lengthBits) {
  if (!Number.isInteger(iterations) || iterations < 1) throw new Error('iterations must be a positive integer');
  const baseKey = await subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: HKDF_HASH },
    baseKey, lengthBits,
  );
  return new Uint8Array(bits);
}

/** Straight to a non-extractable AES-256-GCM key (the recovery-code unwrap key). */
export async function deriveAesGcmKeyFromPbkdf2(passwordBytes, saltBytes, iterations) {
  if (!Number.isInteger(iterations) || iterations < 1) throw new Error('iterations must be a positive integer');
  const baseKey = await subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBytes, iterations, hash: HKDF_HASH },
    baseKey,
    { name: 'AES-GCM', length: AEAD_KEY_LENGTH_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}
