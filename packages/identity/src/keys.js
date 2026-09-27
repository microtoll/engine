/**
 * The key hierarchy: everything that hangs off the Account Root Key.
 *
 *   Account Root Key — 32 random bytes; never stored in plaintext
 *   ├─ HKDF "<ns>/routing/v1"       → Ed25519 routing key (login; public half is the plaintext handle)
 *   ├─ HKDF "<ns>/identity-sign/v1" → Ed25519 identity signing key (the recognition anchor)
 *   ├─ HKDF "<ns>/symm/v1"          → K_master_symm (AES-256-GCM; seals the account's own data)
 *   ├─ HKDF "<ns>/identity-kem/v1"  → hybrid KEM key, or null where the runtime cannot
 *   └─ (no label) P-256 sealing key — GENERATED once, stored as a private JWK in the identity blob
 *
 * The two Ed25519 working keys are NON-EXTRACTABLE (FORMATS.md §2.6): the
 * seed is imported once extractable only to read the public half from the
 * JWK, then imported again non-extractable for use. The derivations are
 * frozen: the crypto-core fixtures pin every output byte.
 */

const PURPOSE_ROUTING = 'routing';
const PURPOSE_IDENTITY_SIGN = 'identity-sign';
const PURPOSE_SYMM = 'symm';
const PURPOSE_IDENTITY_KEM = 'identity-kem';

/** An Ed25519 pair from a 32-byte seed: { privateKey (non-extractable), publicKeyRaw }. */
export async function ed25519PairFromSeed(cc, seed32) {
  const extractable = await cc.importEd25519PrivateKeyFromSeed(seed32);
  const publicKeyRaw = await cc.exportPublicKeyRawFromPrivate(extractable);
  const privateKey = await importNonExtractable(cc, seed32);
  return { privateKey, publicKeyRaw };
}

async function importNonExtractable(cc, seed32) {
  // The same PKCS#8 wrapper crypto-core uses, imported with extractable=false.
  // Kept here rather than in crypto-core so crypto-core's own function stays
  // unchanged (its known-answer tests drive it); this is the identity
  // package's lifetime decision (FORMATS.md §2.6).
  const header = new Uint8Array([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
  return globalThis.crypto.subtle.importKey('pkcs8', cc.concatBytes(header, seed32), { name: 'Ed25519' }, false, ['sign']);
}

/** The plaintext locker number: base64url of the routing public key. */
export function encodeRoutingHandle(cc, routingPublicKeyRaw) {
  return cc.toBase64Url(routingPublicKeyRaw);
}

/**
 * Everything derived from a root key, plus a fresh (not yet stored) sealing
 * key that `adoptSealingKey` replaces the moment the account's blob is
 * opened. `identityKem` is null where the runtime has no hybrid KEM or the
 * switch is off: an ordinary identity, not a broken one.
 */
export async function deriveIdentityKeys(cc, rootKey) {
  if (!(rootKey instanceof Uint8Array) || rootKey.length !== 32) throw new Error('a root key is 32 bytes');
  const routingSeed = await cc.deriveBits(rootKey, PURPOSE_ROUTING);
  const signingSeed = await cc.deriveBits(rootKey, PURPOSE_IDENTITY_SIGN);
  const routing = await ed25519PairFromSeed(cc, routingSeed);
  const identitySigning = await ed25519PairFromSeed(cc, signingSeed);
  routingSeed.fill(0); signingSeed.fill(0); // best effort; JavaScript gives no stronger guarantee
  const masterSymmKey = await cc.deriveAesKey(rootKey, PURPOSE_SYMM);
  let identityKem = null;
  if (await cc.pqSealAvailable()) {
    identityKem = await cc.kemKeyPairFromSeed(await cc.deriveBits(rootKey, PURPOSE_IDENTITY_KEM));
  }
  const identity = { ...(await cc.generateSealingKeyPair()), stored: false };
  return { rootKey, routing, identity, identitySigning, identityKem, masterSymmKey };
}

/** A brand-new identity: a random root key and everything derived from it. No unlock method yet. */
export async function createIdentity(cc) {
  return deriveIdentityKeys(cc, cc.generateSymmetricKey());
}

/** The identity for a root key already known (a restored session, an unwrap). Nothing new is minted. */
export async function identityFromRootKey(cc, rootKey) {
  return deriveIdentityKeys(cc, rootKey);
}

/**
 * A throwaway identity for a connection that must not say who is looking:
 * only a routing key, made for this page load and discarded with it. Cheaper
 * than a full identity (no P-256 or KEM key) and holds no account.
 */
export async function createEphemeralIdentity(cc) {
  const rootKey = cc.generateSymmetricKey();
  const routingSeed = await cc.deriveBits(rootKey, PURPOSE_ROUTING);
  const routing = await ed25519PairFromSeed(cc, routingSeed);
  routingSeed.fill(0); rootKey.fill(0);
  return { routing, ephemeral: true };
}

/**
 * Adopts the account's stored sealing key from an opened identity blob.
 * True when the blob carried one (identity.identity now IS that key, on this
 * device as on every other); false when it did not, in which case the caller
 * must persist the in-memory key so every device converges on one. A blob
 * whose key will not import throws: the blob is under an authenticated
 * cipher, so an unreadable key here is corruption, never chance.
 */
export async function adoptSealingKey(cc, identity, blob) {
  const jwk = blob && blob.sealingKey;
  if (!jwk) return false;
  identity.identity = { ...(await cc.importSealingKeyPair(jwk)), stored: true };
  return true;
}
