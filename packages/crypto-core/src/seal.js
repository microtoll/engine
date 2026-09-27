/**
 * Sealing to a recipient's public key.
 *
 * The labels come from a profile. Two formats, both authenticating their
 * version byte and binding the recipient's key into the key derivation (the
 * same binding RFC 9180 HPKE performs, against key-substitution attacks):
 *
 *   v3  [0x03][65-byte ephemeral P-256 point][AEAD v1, AAD = [0x03]]
 *       key = HKDF(ECDH secret, info = "<ns>/ecies/v3" ‖ SHA-256(ephemeral ‖ recipient))
 *   v2  [0x02][1120-byte X-Wing ciphertext][AEAD v1, AAD = [0x02]]
 *       key = HKDF(KEM secret,  info = "<ns>/ecies/v2" ‖ SHA-256(ciphertext ‖ recipient))
 *   v1  retired (X25519); refused by name.
 *
 * The context is hashed before it goes into HKDF because Web Crypto caps
 * `info` at 1024 bytes and a hybrid key plus ciphertext is 2,336: the
 * concatenate-and-hash context of ETSI TS 103 744 clause 7.2.3. Both inputs
 * are fixed-length and checked, so the plain concatenation inside the hash is
 * unambiguous (SP 800-227 §4.6.2 does not apply). If either ever becomes
 * variable, length-prefix them.
 */
import {
  concatBytes, importSealingPublicKey, sealSymmetric, openSymmetric,
  HKDF_HASH, AEAD_KEY_LENGTH_BITS, SEALING_CURVE, P256_PUBLIC_KEY_BYTES,
} from './primitives.js';

const subtle = globalThis.crypto.subtle;

export const ECIES_VERSION_1 = 0x01; // retired X25519 format; refused
export const ECIES_VERSION_2 = 0x02; // hybrid post-quantum
export const ECIES_VERSION_3 = 0x03; // classical, P-256

// The hybrid KEM as Web Crypto names it. `{ name: 'X-Wing' }` fails in Chrome:
// the WebCrypto draft cites draft-irtf-cfrg-concrete-hybrid-kems, which calls
// the identical construction MLKEM768-X25519.
export const PQ_KEM_ALGORITHM = 'MLKEM768-X25519';
export const PQ_KEM_PUBLIC_KEY_BYTES = 1216;  // ML-KEM-768 public 1184 ‖ X25519 public 32
export const PQ_KEM_CIPHERTEXT_BYTES = 1120;  // ML-KEM-768 ciphertext 1088 ‖ X25519 public 32
export const PQ_KEM_SEED_BYTES = 32;          // the private key IS the seed

async function deriveSealKey(label, contextParts, sharedSecret) {
  const contextHash = new Uint8Array(await subtle.digest('SHA-256', concatBytes(...contextParts)));
  const info = concatBytes(new TextEncoder().encode(label), contextHash);
  const baseKey = await subtle.importKey('raw', sharedSecret, { name: 'HKDF' }, false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'HKDF', hash: HKDF_HASH, salt: new Uint8Array(0), info },
    baseKey,
    { name: 'AES-GCM', length: AEAD_KEY_LENGTH_BITS },
    false,
    ['encrypt', 'decrypt'],
  );
}

/**
 * Builds the sealing functions for one profile.
 *
 * `hybridSealing` is the master switch. It
 * beats the browser, always: a capable browser with the switch off behaves
 * exactly like an incapable one, so what activates the post-quantum path is a
 * decision taken by the app, never a browser updating itself overnight.
 * Off by default (DECISIONS.md D-07): the hybrid seal has not yet been
 * cross-checked against a real browser.
 */
export function createSealer(profile, { hybridSealing = false } = {}) {
  let hybridEnabled = !!hybridSealing;
  let hybridSupport = null; // cached probe; the answer cannot change within a page load

  /** Can this runtime do post-quantum sealing? A real attempt, not a feature string. */
  async function pqSealAvailable() {
    if (!hybridEnabled) return false;
    if (hybridSupport === null) {
      hybridSupport = (async () => {
        try {
          await subtle.importKey('raw-seed', new Uint8Array(PQ_KEM_SEED_BYTES), { name: PQ_KEM_ALGORITHM }, true, ['decapsulateBits']);
          return true;
        } catch { return false; }
      })();
    }
    return hybridSupport;
  }

  /** Test seam: flip the switch and forget the cached probe. */
  function _setHybridSealing(enabled) { hybridEnabled = !!enabled; hybridSupport = null; }
  /** Test seam: forget the cached probe. */
  function _resetHybridSupport() { hybridSupport = null; }

  /**
   * A hybrid KEM key pair from an arbitrary 32-byte seed, or null where the
   * runtime cannot (or the switch is off). Never throws for "unavailable":
   * that is an ordinary state the app has to render.
   */
  async function kemKeyPairFromSeed(seed32) {
    if (!seed32 || seed32.length !== PQ_KEM_SEED_BYTES) {
      throw new Error(`KEM seed must be ${PQ_KEM_SEED_BYTES} bytes, got ${seed32 ? seed32.length : 'none'}`);
    }
    if (!(await pqSealAvailable())) return null;
    const privateKey = await subtle.importKey('raw-seed', seed32, { name: PQ_KEM_ALGORITHM }, true, ['decapsulateBits']);
    const publicKey = await subtle.getPublicKey(privateKey, ['encapsulateBits']);
    const publicKeyRaw = new Uint8Array(await subtle.exportKey('raw-public', publicKey));
    if (publicKeyRaw.length !== PQ_KEM_PUBLIC_KEY_BYTES) {
      throw new Error(`KEM public key is ${publicKeyRaw.length} bytes, expected ${PQ_KEM_PUBLIC_KEY_BYTES}`);
    }
    return { privateKey, publicKeyRaw };
  }

  /**
   * Seal to whichever kind of key the recipient published. Dispatch is on
   * length, and the two are unmistakable: 65 is P-256 (v3), 1216 is the
   * hybrid KEM (v2). Exactly one seal per recipient, never both (a classical
   * copy beside a hybrid one protects nothing). What stops a downgrade is the
   * caller, not this function: it obeys the key it is handed.
   */
  async function sealToRecipient(recipientPublicKeyRaw, plaintextBytes) {
    if (recipientPublicKeyRaw.length === PQ_KEM_PUBLIC_KEY_BYTES) return sealToKemPublicKey(recipientPublicKeyRaw, plaintextBytes);
    if (recipientPublicKeyRaw.length === P256_PUBLIC_KEY_BYTES) return sealToPublicKey(recipientPublicKeyRaw, plaintextBytes);
    throw new Error(
      `unrecognised recipient key length ${recipientPublicKeyRaw.length}: `
      + `expected ${P256_PUBLIC_KEY_BYTES} (${SEALING_CURVE}) or ${PQ_KEM_PUBLIC_KEY_BYTES} (${PQ_KEM_ALGORITHM})`,
    );
  }

  // ---- v3, classical --------------------------------------------------

  async function sealToPublicKey(recipientPublicKeyRaw, plaintextBytes) {
    const recipientPubKey = await importSealingPublicKey(recipientPublicKeyRaw);
    const ephemeral = await subtle.generateKey({ name: 'ECDH', namedCurve: SEALING_CURVE }, true, ['deriveBits']);
    const ephemeralPubRaw = new Uint8Array(await subtle.exportKey('raw', ephemeral.publicKey));
    const sharedBits = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: recipientPubKey }, ephemeral.privateKey, 256));
    const aesKey = await deriveSealKey(profile.eciesV3, [ephemeralPubRaw, recipientPublicKeyRaw], sharedBits);
    const sealed = await sealSymmetric(aesKey, plaintextBytes, new Uint8Array([ECIES_VERSION_3]));
    return concatBytes(new Uint8Array([ECIES_VERSION_3]), ephemeralPubRaw, sealed);
  }

  /**
   * Takes the recipient's key PAIR ({ privateKey, publicKeyRaw }), not a bare
   * private key: the public half is bound into the derivation and a
   * non-extractable private key cannot produce it. A wrong pair fails at the
   * authentication tag, never with a wrong plaintext.
   */
  async function openWithPrivateKey(recipientKeyPair, blob) {
    if (!recipientKeyPair || !recipientKeyPair.privateKey || !recipientKeyPair.publicKeyRaw) {
      throw new Error('openWithPrivateKey needs the recipient key pair ({ privateKey, publicKeyRaw }): the public half is bound into the key');
    }
    if (blob.length < 1 + P256_PUBLIC_KEY_BYTES) throw new Error('sealed blob too short');
    if (blob[0] === ECIES_VERSION_1) {
      throw new Error('sealed under the retired X25519 format (v1) -- no current build can open it');
    }
    if (blob[0] !== ECIES_VERSION_3) throw new Error('unsupported ECIES version: ' + blob[0]);
    const ephemeralPubRaw = blob.slice(1, 1 + P256_PUBLIC_KEY_BYTES);
    const sealed = blob.slice(1 + P256_PUBLIC_KEY_BYTES);
    if (recipientKeyPair.publicKeyRaw.length !== P256_PUBLIC_KEY_BYTES) throw new Error('v3 key derivation got a wrong-sized public key');
    const ephemeralPubKey = await importSealingPublicKey(ephemeralPubRaw);
    const sharedBits = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: ephemeralPubKey }, recipientKeyPair.privateKey, 256));
    const aesKey = await deriveSealKey(profile.eciesV3, [ephemeralPubRaw, recipientKeyPair.publicKeyRaw], sharedBits);
    return openSymmetric(aesKey, sealed, new Uint8Array([ECIES_VERSION_3]));
  }

  // ---- v2, hybrid post-quantum ------------------------------------------

  async function sealToKemPublicKey(recipientPublicKeyRaw, plaintextBytes) {
    if (recipientPublicKeyRaw.length !== PQ_KEM_PUBLIC_KEY_BYTES) {
      throw new Error(`KEM public key must be ${PQ_KEM_PUBLIC_KEY_BYTES} bytes, got ${recipientPublicKeyRaw.length}`);
    }
    const publicKey = await subtle.importKey('raw-public', recipientPublicKeyRaw, { name: PQ_KEM_ALGORITHM }, true, ['encapsulateBits']);
    const { sharedKey, ciphertext } = await subtle.encapsulateBits({ name: PQ_KEM_ALGORITHM }, publicKey);
    const ct = new Uint8Array(ciphertext);
    if (ct.length !== PQ_KEM_CIPHERTEXT_BYTES) throw new Error(`KEM ciphertext is ${ct.length} bytes, expected ${PQ_KEM_CIPHERTEXT_BYTES}`);
    const aesKey = await deriveSealKey(profile.eciesV2, [ct, recipientPublicKeyRaw], new Uint8Array(sharedKey));
    const sealed = await sealSymmetric(aesKey, plaintextBytes, new Uint8Array([ECIES_VERSION_2]));
    return concatBytes(new Uint8Array([ECIES_VERSION_2]), ct, sealed);
  }

  /**
   * The recipient's public key is re-derived from the private key rather
   * than passed in, so a caller cannot supply the wrong one and get a silent
   * failure that looks like a corrupt blob.
   */
  async function openWithKemPrivateKey(kemPrivateKey, blob) {
    if (blob.length < 1 + PQ_KEM_CIPHERTEXT_BYTES) throw new Error('sealed blob too short');
    if (blob[0] !== ECIES_VERSION_2) throw new Error('unsupported ECIES version: ' + blob[0]);
    const ct = blob.slice(1, 1 + PQ_KEM_CIPHERTEXT_BYTES);
    const sealed = blob.slice(1 + PQ_KEM_CIPHERTEXT_BYTES);
    const sharedBits = await subtle.decapsulateBits({ name: PQ_KEM_ALGORITHM }, kemPrivateKey, ct);
    const publicKey = await subtle.getPublicKey(kemPrivateKey, ['encapsulateBits']);
    const recipientPublicKeyRaw = new Uint8Array(await subtle.exportKey('raw-public', publicKey));
    if (recipientPublicKeyRaw.length !== PQ_KEM_PUBLIC_KEY_BYTES) throw new Error('v2 key derivation got a wrong-sized public key');
    const aesKey = await deriveSealKey(profile.eciesV2, [ct, recipientPublicKeyRaw], new Uint8Array(sharedBits));
    return openSymmetric(aesKey, sealed, new Uint8Array([ECIES_VERSION_2]));
  }

  return {
    pqSealAvailable, _setHybridSealing, _resetHybridSupport, kemKeyPairFromSeed,
    sealToRecipient, sealToPublicKey, openWithPrivateKey, sealToKemPublicKey, openWithKemPrivateKey,
  };
}
