/**
 * The recovery-code format, version 3 (DECISIONS.md D-46), with version 2
 * (D-26) still readable when asked for by name.
 *
 * 16 random bytes (128 bits) in Crockford base32 (26 characters), then one
 * check character, in groups of four: `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX`,
 * 27 characters. The alphabet has no I, L, O or U, so a handwritten code
 * cannot be confused with 1/1/0/V; the parser folds those confusions back.
 *
 * Version 3's check character is Σ aⁱ⁺¹·sᵢ over the 26 data characters'
 * values sᵢ, in GF(32) with a = x under x⁵ + x² + 1. That polynomial is
 * irreducible, so x has order 31 and the weights a¹…a²⁶ (and the check
 * character's own implicit weight a⁰) are distinct and non-zero: EVERY
 * single wrong character and EVERY swap of two different characters,
 * adjacent or not, is caught; a random error is caught 31 times in 32. The
 * parser also refuses a code whose two unused final bits are not zero (26
 * characters carry 130 bits for 128), so one string names one secret.
 *
 * Version 2's check character is the Crockford digit of the low five bits of
 * the first byte of SHA-256(secret bytes). A version-2 and a version-3 code
 * have the same shape, so a parser cannot tell them apart; falling back from
 * one to the other would give up both of version 3's guarantees. Version 3 is
 * therefore the only one read by default, and version 2 is read only when the
 * caller passes `{ version: 2 }`. Version 1 (a byte sum) is not read.
 *
 * Errors carry a `code` so the app can word them: 'recovery-code-short',
 * 'recovery-code-length', 'recovery-code-char', 'recovery-code-checksum'.
 */
import { randomBytes, sha256, bytesToBase32Crockford, base32CrockfordToBytes } from './primitives.js';

export const RECOVERY_CODE_VERSION = 3;
export const RECOVERY_CODE_VERSIONS = Object.freeze([2, 3]);
export const RECOVERY_CODE_ENTROPY_BYTES = 16;
export const RECOVERY_CODE_GROUP_SIZE = 4;
const RECOVERY_CODE_DATA_CHARS = 26; // ceil(128 / 5)
const CROCKFORD_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
// x⁵ + x² + 1 (D-46): GF(32) = GF(2)[x] / (x⁵ + x² + 1).
const GF32_MODULUS = 0b100101;

function groupWithDashes(str, groupSize) {
  const groups = [];
  for (let i = 0; i < str.length; i += groupSize) groups.push(str.slice(i, i + groupSize));
  return groups.join('-');
}

function versionOf(options) {
  const version = options && options.version !== undefined ? options.version : RECOVERY_CODE_VERSION;
  if (!RECOVERY_CODE_VERSIONS.includes(version)) throw new Error(`unknown recovery-code version: ${version}`);
  return version;
}

/** Multiplication in GF(32): carry-less, reduced by the modulus. */
function gf32Multiply(a, b) {
  let product = 0;
  while (b) {
    if (b & 1) product ^= a;
    b >>= 1;
    a <<= 1;
    if (a & 0b100000) a ^= GF32_MODULUS;
  }
  return product;
}

/** Version 3 (D-46): Σ aⁱ⁺¹·sᵢ over the data characters' values, a = x. */
function checkCharV3(dataChars) {
  let sum = 0, weight = 1;
  for (const ch of dataChars) {
    weight = gf32Multiply(weight, 0b10); // a^(i+1)
    sum ^= gf32Multiply(weight, CROCKFORD_ALPHABET.indexOf(ch));
  }
  return CROCKFORD_ALPHABET[sum];
}

/** Version 2 (D-26): the low five bits of SHA-256(secret)[0]. */
async function checkCharV2(secretBytes) {
  const digest = await sha256(secretBytes);
  return CROCKFORD_ALPHABET[digest[0] & 0x1f];
}

/** Returns { secretBytes, displayString }, version 3. Persist nothing; the code is shown once. */
export async function generateRecoveryCode() {
  const secretBytes = randomBytes(RECOVERY_CODE_ENTROPY_BYTES);
  return { secretBytes, displayString: await formatRecoveryCode(secretBytes) };
}

/**
 * The display string for 16 bytes: version 3 unless `{ version: 2 }` is
 * given. Asynchronous because version 2's check needs SHA-256.
 */
export async function formatRecoveryCode(secretBytes, options = {}) {
  const version = versionOf(options);
  if (!secretBytes || secretBytes.length !== RECOVERY_CODE_ENTROPY_BYTES) {
    throw new Error(`a recovery code is ${RECOVERY_CODE_ENTROPY_BYTES} bytes, got ${secretBytes ? secretBytes.length : 'none'}`);
  }
  const data = bytesToBase32Crockford(secretBytes);
  const check = version === 3 ? checkCharV3(data) : await checkCharV2(secretBytes);
  return groupWithDashes(data + check, RECOVERY_CODE_GROUP_SIZE);
}

/**
 * Tolerant of case, spaces, dashes and the usual confusions (O→0, I/L→1).
 * Rejects with a `code` when the length, a character or the check is wrong:
 * a mistyped code, not corrupted data. Version 3 unless `{ version: 2 }` is
 * given (see the header: the two cannot be told apart).
 */
export async function parseRecoveryCode(displayString, options = {}) {
  const version = versionOf(options);
  const cleaned = String(displayString).toUpperCase().replace(/[^0-9A-Z]/g, '')
    .replace(/O/g, '0').replace(/[IL]/g, '1');
  if (cleaned.length < 2) {
    throw Object.assign(new Error('recovery code too short'), { code: 'recovery-code-short', usable: cleaned.length });
  }
  const dataChars = cleaned.slice(0, -1);
  const given = cleaned.slice(-1);
  let secretBytes;
  try {
    secretBytes = base32CrockfordToBytes(dataChars);
    if (!CROCKFORD_ALPHABET.includes(given)) throw new Error('check character');
  } catch {
    throw Object.assign(new Error('recovery code has an invalid character'), { code: 'recovery-code-char' });
  }
  // Version 3 also requires exactly 26 data characters: a longer string can
  // decode to 16 bytes too, and one string must name one secret (D-46).
  if (secretBytes.length !== RECOVERY_CODE_ENTROPY_BYTES || (version === 3 && dataChars.length !== RECOVERY_CODE_DATA_CHARS)) {
    throw Object.assign(new Error('recovery code is not complete'), { code: 'recovery-code-length', decodedBytes: secretBytes.length });
  }
  const expected = version === 3 ? checkCharV3(dataChars) : await checkCharV2(secretBytes);
  // The last data character's two low bits are padding and must be zero
  // (D-46: otherwise four strings would name the same secret).
  const unusedBitsSet = version === 3 && (CROCKFORD_ALPHABET.indexOf(dataChars[RECOVERY_CODE_DATA_CHARS - 1]) & 0b11) !== 0;
  if (given !== expected || unusedBitsSet) {
    throw Object.assign(new Error('recovery code check character does not match'), { code: 'recovery-code-checksum' });
  }
  return secretBytes;
}
