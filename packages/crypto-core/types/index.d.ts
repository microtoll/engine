// Hand-written declarations for @microtoll/crypto-core (source stays JavaScript;
// DECISIONS.md D-08). Checked with `tsc --noEmit` in CI.

/** A P-256 private key in JSON Web Key form, as stored inside the identity blob. */
export interface SealingJwk {
  kty: 'EC';
  crv: 'P-256';
  d: string;
  x: string;
  y: string;
}

/** A sealing key in use: the non-extractable private key, its 65-byte public point, and the JWK it came from. */
export interface SealingKeyPair {
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array;
  jwk: SealingJwk;
}

/** A hybrid (MLKEM768-X25519) key pair: the private key object and the 1216-byte public key. */
export interface KemKeyPair {
  privateKey: CryptoKey;
  publicKeyRaw: Uint8Array;
}

// ---------------------------------------------------------------------------
// Stateless primitives
// ---------------------------------------------------------------------------

// Byte and encoding helpers
export function toHex(bytes: Uint8Array): string;
export function fromHex(hex: string): Uint8Array;
export function toBase64Url(bytes: Uint8Array): string;
export function fromBase64Url(str: string): Uint8Array;
export function concatBytes(...arrs: Uint8Array[]): Uint8Array;
export function uuidBytes(id: string): Uint8Array;
export function u32be(n: number): Uint8Array;
export function u64be(n: number): Uint8Array;
/** context ‖ 0x00 ‖ parts — the frame a context-bound seal or signature is keyed to. */
export function frameContext(context: string, ...parts: Uint8Array[]): Uint8Array;
export function bytesToBase32Crockford(bytes: Uint8Array): string;
export function base32CrockfordToBytes(str: string): Uint8Array;

// Random and hashing
export function randomBytes(length: number): Uint8Array;
export function generateSymmetricKey(): Uint8Array;
export function sha256(bytes: Uint8Array): Promise<Uint8Array>;

// HKDF-SHA-256 (RFC 5869)
export const HKDF_HASH: 'SHA-256';
export function hkdfDeriveBits(ikm: Uint8Array, salt: Uint8Array, info: Uint8Array, lengthBits: number): Promise<Uint8Array>;
export function hkdfDeriveSeedBits(ikm: Uint8Array, label: string, lengthBits?: number): Promise<Uint8Array>;
export function hkdfDeriveAesGcmKey(ikm: Uint8Array, label: string): Promise<CryptoKey>;

// Ed25519
export function importEd25519PrivateKeyFromSeed(seed32: Uint8Array): Promise<CryptoKey>;
export function exportPublicKeyRawFromPrivate(privateKey: CryptoKey): Promise<Uint8Array>;
export function importEd25519PublicKey(rawBytes32: Uint8Array): Promise<CryptoKey>;
export function signBytes(signingPrivateKey: CryptoKey, message: Uint8Array): Promise<Uint8Array>;
/** Resolves false, never throws, on a malformed key or signature. */
export function verifyBytes(signingPublicKeyRaw: Uint8Array, message: Uint8Array, signature: Uint8Array): Promise<boolean>;

// The stored P-256 sealing key
export const SEALING_CURVE: 'P-256';
export const P256_PUBLIC_KEY_BYTES: 65;
export function sealingPublicKeyFromJwk(jwk: SealingJwk): Uint8Array;
export function importSealingPublicKey(rawBytes65: Uint8Array): Promise<CryptoKey>;
/** 256 bits of P-256 ECDH between this sealing private key and another party's public key (the mailbox label's secret); always fed to HKDF, never used as a key. */
export function deriveSealingSharedBits(privateKey: CryptoKey, otherPublicKeyRaw65: Uint8Array): Promise<Uint8Array>;
export function importSealingKeyPair(jwk: SealingJwk): Promise<SealingKeyPair>;
export function generateSealingKeyPair(): Promise<SealingKeyPair>;

// AEAD v1: [0x01][12-byte IV][AES-256-GCM ciphertext ‖ tag]
export const AEAD_VERSION_1: 0x01;
export const AEAD_IV_BYTES: 12;
export const AEAD_KEY_LENGTH_BITS: 256;
export function importSymmetricKey(rawBytes32: Uint8Array): Promise<CryptoKey>;
export function generateNonExtractableSymmetricKey(): Promise<CryptoKey>;
export function sealSymmetric(key: CryptoKey, plaintext: Uint8Array, additionalData?: Uint8Array | null): Promise<Uint8Array>;
export function openSymmetric(key: CryptoKey, sealed: Uint8Array, additionalData?: Uint8Array | null): Promise<Uint8Array>;

// PBKDF2-SHA-256
export function pbkdf2DeriveBits(password: Uint8Array, salt: Uint8Array, iterations: number, lengthBits: number): Promise<Uint8Array>;
export function deriveAesGcmKeyFromPbkdf2(password: Uint8Array, salt: Uint8Array, iterations: number): Promise<CryptoKey>;

// Recovery code: 16 bytes → Crockford base32 + check character, `XXXX-…-XXX`.
// Version 3 (D-46) by default; version 2 (D-26) only when named.
export const RECOVERY_CODE_ENTROPY_BYTES: 16;
export const RECOVERY_CODE_GROUP_SIZE: 4;
export const RECOVERY_CODE_VERSION: 3;
export const RECOVERY_CODE_VERSIONS: readonly [2, 3];
export interface RecoveryCodeOptions { version?: 2 | 3; }
export function generateRecoveryCode(): Promise<{ secretBytes: Uint8Array; displayString: string }>;
export function formatRecoveryCode(secretBytes: Uint8Array, options?: RecoveryCodeOptions): Promise<string>;
/** Throws an Error with `code` 'recovery-code-short' | 'recovery-code-length' | 'recovery-code-char' | 'recovery-code-checksum'. */
export function parseRecoveryCode(displayString: string, options?: RecoveryCodeOptions): Promise<Uint8Array>;

// Seal format constants
export const ECIES_VERSION_1: 0x01;
export const ECIES_VERSION_2: 0x02;
export const ECIES_VERSION_3: 0x03;
export const PQ_KEM_ALGORITHM: 'MLKEM768-X25519';
export const PQ_KEM_PUBLIC_KEY_BYTES: 1216;
export const PQ_KEM_CIPHERTEXT_BYTES: 1120;
export const PQ_KEM_SEED_BYTES: 32;

// ---------------------------------------------------------------------------
// The label profile (D-05) and the instance
// ---------------------------------------------------------------------------

export interface ProfileOptions {
  /** The label prefix, 1–64 characters of a–z, 0–9 and "-". Required. */
  namespace: string;
  /** PBKDF2 iterations for the recovery-code stretch; default 310,000. */
  pbkdf2Iterations?: number;
}

export interface Profile {
  readonly namespace: string;
  readonly pbkdf2Iterations: number;
  /** `<namespace>/<purpose>/v<version>`; retired labels are refused. */
  label(purpose: string, version?: number): string;
  readonly eciesV3: string;
  readonly eciesV2: string;
}

/** The default PBKDF2-SHA-256 iteration count; part of the recovery-code format. */
export const DEFAULT_PBKDF2_ITERATIONS: 310000;
export function createProfile(options: ProfileOptions): Profile;

export interface CryptoCoreOptions extends ProfileOptions {
  /** The post-quantum master switch (D-07). Default false. */
  hybridSealing?: boolean;
}

/** Everything the module exports, plus the label-bound functions. */
export interface CryptoCore {
  readonly profile: Profile;
  label(purpose: string, version?: number): string;
  /** HKDF-SHA-256 under the profile label: empty salt, the label as info. */
  deriveBits(ikm: Uint8Array, purpose: string, options?: { version?: number; bits?: number }): Promise<Uint8Array>;
  deriveAesKey(ikm: Uint8Array, purpose: string, options?: { version?: number }): Promise<CryptoKey>;
  /** PBKDF2-SHA-256 with the profile's iteration count. */
  deriveAesKeyFromSecret(secret: Uint8Array, salt: Uint8Array): Promise<CryptoKey>;

  // Sealing
  pqSealAvailable(): Promise<boolean>;
  _setHybridSealing(enabled: boolean): void;
  _resetHybridSupport(): void;
  kemKeyPairFromSeed(seed32: Uint8Array): Promise<KemKeyPair | null>;
  /** Dispatches on key length: 65 → ECIES v3, 1216 → ECIES v2. */
  sealToRecipient(recipientPublicKeyRaw: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  sealToPublicKey(recipientPublicKeyRaw: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  openWithPrivateKey(recipient: Pick<SealingKeyPair, 'privateKey' | 'publicKeyRaw'>, blob: Uint8Array): Promise<Uint8Array>;
  sealToKemPublicKey(recipientPublicKeyRaw: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array>;
  openWithKemPrivateKey(kemPrivateKey: CryptoKey, blob: Uint8Array): Promise<Uint8Array>;

  // Primitives, re-exposed on the instance
  toHex: typeof toHex; fromHex: typeof fromHex; toBase64Url: typeof toBase64Url; fromBase64Url: typeof fromBase64Url;
  concatBytes: typeof concatBytes; uuidBytes: typeof uuidBytes; u32be: typeof u32be; u64be: typeof u64be; frameContext: typeof frameContext;
  bytesToBase32Crockford: typeof bytesToBase32Crockford; base32CrockfordToBytes: typeof base32CrockfordToBytes;
  randomBytes: typeof randomBytes; generateSymmetricKey: typeof generateSymmetricKey; sha256: typeof sha256;
  hkdfDeriveBits: typeof hkdfDeriveBits; hkdfDeriveSeedBits: typeof hkdfDeriveSeedBits; hkdfDeriveAesGcmKey: typeof hkdfDeriveAesGcmKey;
  importEd25519PrivateKeyFromSeed: typeof importEd25519PrivateKeyFromSeed; exportPublicKeyRawFromPrivate: typeof exportPublicKeyRawFromPrivate;
  importEd25519PublicKey: typeof importEd25519PublicKey; signBytes: typeof signBytes; verifyBytes: typeof verifyBytes;
  sealingPublicKeyFromJwk: typeof sealingPublicKeyFromJwk; importSealingPublicKey: typeof importSealingPublicKey; deriveSealingSharedBits: typeof deriveSealingSharedBits;
  importSealingKeyPair: typeof importSealingKeyPair; generateSealingKeyPair: typeof generateSealingKeyPair;
  importSymmetricKey: typeof importSymmetricKey; generateNonExtractableSymmetricKey: typeof generateNonExtractableSymmetricKey;
  sealSymmetric: typeof sealSymmetric; openSymmetric: typeof openSymmetric;
  pbkdf2DeriveBits: typeof pbkdf2DeriveBits; deriveAesGcmKeyFromPbkdf2: typeof deriveAesGcmKeyFromPbkdf2;
  generateRecoveryCode: typeof generateRecoveryCode; formatRecoveryCode: typeof formatRecoveryCode; parseRecoveryCode: typeof parseRecoveryCode;
  readonly HKDF_HASH: typeof HKDF_HASH; readonly SEALING_CURVE: typeof SEALING_CURVE; readonly P256_PUBLIC_KEY_BYTES: typeof P256_PUBLIC_KEY_BYTES;
  readonly AEAD_VERSION_1: typeof AEAD_VERSION_1; readonly AEAD_IV_BYTES: typeof AEAD_IV_BYTES; readonly AEAD_KEY_LENGTH_BITS: typeof AEAD_KEY_LENGTH_BITS;
  readonly RECOVERY_CODE_VERSION: typeof RECOVERY_CODE_VERSION; readonly RECOVERY_CODE_VERSIONS: typeof RECOVERY_CODE_VERSIONS; readonly RECOVERY_CODE_ENTROPY_BYTES: typeof RECOVERY_CODE_ENTROPY_BYTES; readonly RECOVERY_CODE_GROUP_SIZE: typeof RECOVERY_CODE_GROUP_SIZE;
  readonly ECIES_VERSION_1: typeof ECIES_VERSION_1; readonly ECIES_VERSION_2: typeof ECIES_VERSION_2; readonly ECIES_VERSION_3: typeof ECIES_VERSION_3;
  readonly PQ_KEM_ALGORITHM: typeof PQ_KEM_ALGORITHM; readonly PQ_KEM_PUBLIC_KEY_BYTES: typeof PQ_KEM_PUBLIC_KEY_BYTES;
  readonly PQ_KEM_CIPHERTEXT_BYTES: typeof PQ_KEM_CIPHERTEXT_BYTES; readonly PQ_KEM_SEED_BYTES: typeof PQ_KEM_SEED_BYTES;
}

export function createCryptoCore(options: CryptoCoreOptions): CryptoCore;
