/**
 * @microtoll/crypto-core — public entry point.
 *
 * Two layers:
 *  - stateless primitives and formats, exported directly (`sealSymmetric`,
 *    `hkdfDeriveBits`, the recovery-code codec, …);
 *  - everything derived under a label, on an instance made with
 *    `createCryptoCore({ namespace })`, so no app can share another app's
 *    labels by accident (DECISIONS.md D-05), for example
 *    `createCryptoCore({ namespace: 'myapp' })`.
 */
import * as primitives from './primitives.js';
import { createProfile, DEFAULT_PBKDF2_ITERATIONS } from './profile.js';
import {
  createSealer,
  ECIES_VERSION_1, ECIES_VERSION_2, ECIES_VERSION_3,
  PQ_KEM_ALGORITHM, PQ_KEM_PUBLIC_KEY_BYTES, PQ_KEM_CIPHERTEXT_BYTES, PQ_KEM_SEED_BYTES,
} from './seal.js';
import * as recovery from './recovery.js';

export * from './primitives.js';
export * from './recovery.js';
export { createProfile, DEFAULT_PBKDF2_ITERATIONS };
export {
  ECIES_VERSION_1, ECIES_VERSION_2, ECIES_VERSION_3,
  PQ_KEM_ALGORITHM, PQ_KEM_PUBLIC_KEY_BYTES, PQ_KEM_CIPHERTEXT_BYTES, PQ_KEM_SEED_BYTES,
};

/**
 * An instance bound to one namespace. Options:
 *  - `namespace` (required): the label prefix, e.g. 'myapp'.
 *  - `hybridSealing` (default false): the post-quantum master switch (D-07).
 *  - `pbkdf2Iterations` (default 310,000): the recovery-code stretch.
 */
export function createCryptoCore(options = {}) {
  const profile = createProfile(options);
  const sealer = createSealer(profile, { hybridSealing: options.hybridSealing });

  /** HKDF under `<namespace>/<purpose>/v<version>`: empty salt, the label as info. */
  function deriveBits(ikm, purpose, { version = 1, bits = 256 } = {}) {
    return primitives.hkdfDeriveSeedBits(ikm, profile.label(purpose, version), bits);
  }

  /** The same derivation straight to a non-extractable AES-256-GCM key. */
  function deriveAesKey(ikm, purpose, { version = 1 } = {}) {
    return primitives.hkdfDeriveAesGcmKey(ikm, profile.label(purpose, version));
  }

  /** PBKDF2-SHA-256 with the profile's iteration count, to a non-extractable AES-256-GCM key. */
  function deriveAesKeyFromSecret(secretBytes, saltBytes) {
    return primitives.deriveAesGcmKeyFromPbkdf2(secretBytes, saltBytes, profile.pbkdf2Iterations);
  }

  return Object.freeze({
    ...primitives,
    ...recovery,
    ...sealer,
    ECIES_VERSION_1, ECIES_VERSION_2, ECIES_VERSION_3,
    PQ_KEM_ALGORITHM, PQ_KEM_PUBLIC_KEY_BYTES, PQ_KEM_CIPHERTEXT_BYTES, PQ_KEM_SEED_BYTES,
    profile,
    label: profile.label,
    deriveBits,
    deriveAesKey,
    deriveAesKeyFromSecret,
  });
}
