// Hand-written declarations for @microtoll/identity (source stays JavaScript; D-08).
import type { CryptoCore, SealingKeyPair, KemKeyPair } from '@microtoll/crypto-core';

export interface Ed25519Pair { privateKey: CryptoKey; publicKeyRaw: Uint8Array; }

/** Everything derived from a root key, plus the stored (or not-yet-stored) sealing key. */
export interface Identity {
  rootKey: Uint8Array;
  routing: Ed25519Pair;
  identitySigning: Ed25519Pair;
  identity: SealingKeyPair & { stored: boolean };
  identityKem: KemKeyPair | null;
  masterSymmKey: CryptoKey;
}
export interface EphemeralIdentity { routing: Ed25519Pair; ephemeral: true; }

// keys.js
export function ed25519PairFromSeed(cc: CryptoCore, seed32: Uint8Array): Promise<Ed25519Pair>;
export function encodeRoutingHandle(cc: CryptoCore, routingPublicKeyRaw: Uint8Array): string;
export function deriveIdentityKeys(cc: CryptoCore, rootKey: Uint8Array): Promise<Identity>;
export function createIdentity(cc: CryptoCore): Promise<Identity>;
export function identityFromRootKey(cc: CryptoCore, rootKey: Uint8Array): Promise<Identity>;
export function createEphemeralIdentity(cc: CryptoCore): Promise<EphemeralIdentity>;
export function adoptSealingKey(cc: CryptoCore, identity: Identity, blob: IdentityBlob | null | undefined): Promise<boolean>;

// envelope.js
export const METHOD_PASSKEY: 'passkey-prf';
export const METHOD_RECOVERY: 'recovery-code';
export interface PasskeyMethod { type: 'passkey-prf'; label: string | null; wrappedRootKey: Uint8Array; credentialId: Uint8Array; prfSalt: Uint8Array; }
export interface RecoveryMethod { type: 'recovery-code'; label: string | null; wrappedRootKey: Uint8Array; salt: Uint8Array; lookupHash: string; }
export type UnlockMethod = PasskeyMethod | RecoveryMethod;
export function unlockMethodContext(cc: CryptoCore, type: 'passkey-prf' | 'recovery-code', methodId: Uint8Array): Promise<Uint8Array>;
export function deriveUnwrapKeyFromPrf(cc: CryptoCore, prfOutput32: Uint8Array): Promise<CryptoKey>;
export function deriveUnwrapKeyFromRecoveryCode(cc: CryptoCore, secretBytes16: Uint8Array, salt: Uint8Array): Promise<CryptoKey>;
export function deriveRecoveryLookupHash(cc: CryptoCore, secretBytes16: Uint8Array): Promise<string>;
export function wrapRootKeyWithPrf(cc: CryptoCore, rootKey: Uint8Array, prfOutput32: Uint8Array, credentialId: Uint8Array, prfSalt: Uint8Array, label?: string | null): Promise<PasskeyMethod>;
export function wrapRootKeyWithNewRecoveryCode(cc: CryptoCore, rootKey: Uint8Array, label?: string | null): Promise<{ method: RecoveryMethod; displayString: string }>;
/** `recoveryCodeVersion: 2` reads a code written before D-46; the default is crypto-core's current version. */
export interface RecoveryCodeReadOptions { recoveryCodeVersion?: 2 | 3; }
export function lookupHashForEnteredCode(cc: CryptoCore, enteredCode: string, options?: RecoveryCodeReadOptions): Promise<string>;
export function unwrapRootKeyWithPrf(cc: CryptoCore, method: PasskeyMethod, prfOutput32: Uint8Array): Promise<Uint8Array>;
export function unwrapRootKeyWithRecoveryCode(cc: CryptoCore, method: RecoveryMethod, enteredCode: string, options?: RecoveryCodeReadOptions): Promise<Uint8Array>;
/** The method a label is bound to (version 3, D-47): a passkey by its credential id, a recovery code by its type. */
export interface LabelledMethod { type: 'passkey-prf' | 'recovery-code' | string; credentialId?: Uint8Array | null; }
export function labelContext(cc: CryptoCore, method: LabelledMethod): Promise<Uint8Array>;
export function sealMethodLabel(cc: CryptoCore, masterSymmKey: CryptoKey, method: LabelledMethod, label: string): Promise<Uint8Array>;
export function openMethodLabel(cc: CryptoCore, masterSymmKey: CryptoKey, method: LabelledMethod, sealed: Uint8Array): Promise<string | null>;
/** Version 2 (D-28), bound to the account only: read, never written. */
export function labelContextV2(cc: CryptoCore, routingPublicKeyRaw: Uint8Array): Uint8Array;
export function openMethodLabelV2(cc: CryptoCore, masterSymmKey: CryptoKey, routingPublicKeyRaw: Uint8Array, sealed: Uint8Array): Promise<string | null>;
export type SealLabel = (label: string, method: LabelledMethod) => Promise<Uint8Array>;
export type OpenLabel = (sealed: Uint8Array, method: LabelledMethod) => Promise<string | null>;
export function assertSafeToRemove(methods: unknown[], indexToRemove: number): void;

// blob.js
export interface IdentityBlob {
  identityPublicKey?: string; identitySigningKey?: string; sealingKey?: object; revision?: number;
  [key: string]: unknown;
}
export const IDENTITY_BLOB_UNREADABLE: 'identity-blob-unreadable';
export const IDENTITY_BLOB_ROLLED_BACK: 'identity-blob-rolled-back';
export function blobContext(cc: CryptoCore, routingPublicKeyRaw: Uint8Array): Uint8Array;
export function buildIdentityBlobPlaintext(cc: CryptoCore, identity: Identity, extra?: IdentityBlob): IdentityBlob;
export function sealIdentityBlob(cc: CryptoCore, identity: Identity, plaintext: IdentityBlob): Promise<Uint8Array>;
export function openIdentityBlob(cc: CryptoCore, identity: Identity, sealed: Uint8Array | null, options?: { minRevision?: number }): Promise<IdentityBlob>;

// session.js
export const SESSION_DAYS: 30;
export const SESSION_RECORD_VERSION: 2;
export const LOCK_INTERVALS: Readonly<{ 'every-open': 0; '30-min': number; '30-days': number }>;
export const DEFAULT_LOCK_INTERVAL: '30-days';
export type LockInterval = keyof typeof LOCK_INTERVALS;
export interface KeyValueStore { get(key: string): Promise<unknown>; put(key: string, value: unknown): Promise<void>; delete(key: string): Promise<void>; }
export interface StringStorage { getItem(key: string): string | null; setItem(key: string, value: string): void; removeItem(key: string): void; }
export interface RestoredSession { rootKey: Uint8Array; routingPublicKey: string; routingPublicKeyRaw: Uint8Array; unlockedAt: number; expiresAt: number; sessionGeneration: number | null; }
export interface SessionStore {
  saveSession(rootKey: Uint8Array, routingPublicKeyRaw: Uint8Array, options?: { now?: number; days?: number; ttlMs?: number | null; sessionGeneration?: number | null }): Promise<void>;
  loadSession(options?: { now?: number }): Promise<RestoredSession | null>;
  clearSession(): Promise<void>;
  isSessionStale(session: { sessionGeneration: number | null } | null, serverGeneration: number | null): boolean;
  loadLockInterval(): LockInterval;
  saveLockInterval(interval: LockInterval): void;
  readonly LOCK_INTERVALS: typeof LOCK_INTERVALS; readonly DEFAULT_LOCK_INTERVAL: typeof DEFAULT_LOCK_INTERVAL; readonly SESSION_DAYS: typeof SESSION_DAYS;
}
export function sessionContext(cc: CryptoCore, routingPublicKeyRaw: Uint8Array, expiresAt: number, sessionGeneration: number | null): Uint8Array;
export function indexedDbStore(options: { dbName: string; storeName?: string }): KeyValueStore;
export function memoryStore(): KeyValueStore & { _map: Map<string, unknown> };
export function createSessionStore(options: { cryptoCore: CryptoCore; store?: KeyValueStore | null; lockIntervalStorage?: StringStorage | null }): SessionStore;

// handshake.js
export const REQUEST_TIMEOUT_MS: 20000;
export interface WebSocketLike {
  readyState: number;
  send(data: string): void;
  close(): void;
  addEventListener(type: 'message' | 'close' | 'open' | 'error', listener: (event: any) => void, options?: unknown): void;
  removeEventListener(type: 'message' | 'close' | 'open' | 'error', listener: (event: any) => void): void;
}
export interface AuthOk { hasAccount: boolean; encryptedIdentityBlob: Uint8Array | null; sessionGeneration: number | null; identityBlobToken: string | null; fields: Record<string, unknown>; }
export function isTransportError(e: unknown): boolean;
export function authMessage(cc: CryptoCore, origin: string, nonce: Uint8Array): Promise<Uint8Array>;
export function verifyAuthSignature(cc: CryptoCore, routingPublicKeyRaw: Uint8Array, origin: string, nonce: Uint8Array, signature: Uint8Array): Promise<boolean>;
export function receiveChallenge(cc: CryptoCore, ws: WebSocketLike, options?: { timeoutMs?: number }): Promise<Uint8Array>;
export function respondToChallenge(cc: CryptoCore, ws: WebSocketLike, nonce: Uint8Array, routing: Ed25519Pair, origin: string, options?: { timeoutMs?: number }): Promise<AuthOk>;
export function authenticateConnection(cc: CryptoCore, ws: WebSocketLike, routing: Ed25519Pair, origin: string, options?: { timeoutMs?: number }): Promise<AuthOk>;
export function sendAndAwait(ws: WebSocketLike, request: object, okType: string, failType: string, options?: { timeoutMs?: number }): Promise<any>;
export interface LookedUpMethod { type: string; wrappedRootKey: Uint8Array; credentialId: Uint8Array | null; prfSalt: Uint8Array | null; salt: Uint8Array | null; lookupHash: string | null; }
export function lookupUnlockMethod(cc: CryptoCore, ws: WebSocketLike, query: { credentialId?: Uint8Array; recoveryLookupHash?: string }): Promise<LookedUpMethod>;
export function registerAccount(cc: CryptoCore, ws: WebSocketLike, identity: Identity, encryptedIdentityBlob: Uint8Array, methods: UnlockMethod | UnlockMethod[], options: { sealLabel: SealLabel; policyFields?: Record<string, unknown> }): Promise<{ identityBlobToken: string }>;
export function addUnlockMethod(cc: CryptoCore, ws: WebSocketLike, identity: Identity, method: UnlockMethod, options: { sealLabel: SealLabel }): Promise<void>;
export interface ListedMethod { id: string; type: string; credentialId: Uint8Array | null; label: string | null; }
export function listUnlockMethods(cc: CryptoCore, ws: WebSocketLike, options: { openLabel: OpenLabel }): Promise<ListedMethod[]>;
export function removeUnlockMethod(ws: WebSocketLike, methodId: string): Promise<number>;
export function rotateRecoveryCode(cc: CryptoCore, ws: WebSocketLike, identity: Identity, method: RecoveryMethod, cancelMethodIds: string[], options: { sealLabel: SealLabel }): Promise<{ methodId: string; sessionGeneration: number }>;
export function bumpSessionGeneration(ws: WebSocketLike): Promise<number>;
export function updateIdentityBlob(cc: CryptoCore, ws: WebSocketLike, sealedBlob: Uint8Array, baseToken: string | null): Promise<{ identityBlobToken: string }>;
export function deleteAccount(ws: WebSocketLike): Promise<boolean>;

// webauthn.js
export interface CreatedPasskey { credentialId: Uint8Array; prfSalt: Uint8Array; prfOutput32: Uint8Array; transports: string[]; backedUp: boolean | null; }
export interface WebAuthn {
  probePasskeySupport(): Promise<{ webauthn: boolean; platform: boolean; prf: boolean | null; hybrid: boolean | null }>;
  createPasskeyWithPrf(userName: string, options?: { attachment?: 'platform' | 'cross-platform' }): Promise<CreatedPasskey>;
  evaluatePrf(credentialId: Uint8Array, prfSalt: Uint8Array, transports?: string[], options?: { afterCreate?: boolean }): Promise<{ prfOutput32: Uint8Array }>;
  assertAnyCredential(): Promise<{ credentialId: Uint8Array; transports: string[]; userHandle: Uint8Array | null }>;
  backupStateFromAuthData(authData: ArrayBuffer | Uint8Array | null): boolean | null;
  hintsForTransports(transports: string[]): string[];
  present(): boolean;
}
export function createWebAuthn(options: { credentials?: CredentialsContainer | null; rpName: string; rpId?: string; randomBytes?: (n: number) => Uint8Array }): WebAuthn;
export function backupStateFromAuthData(authData: ArrayBuffer | Uint8Array | null): boolean | null;
export function hintsForTransports(transports: string[]): string[];

// knownAccount.js
export interface KnownAccount { credentialId: Uint8Array | null; label: string | null; routingPublicKey: Uint8Array | null; transports: string[]; }
export interface KnownAccountStore {
  rememberDevicePasskey(credentialId: Uint8Array, label: string | null, routingPublicKeyRaw: Uint8Array | null, transports?: string[]): void;
  rememberDeviceRecoveryAccount(label: string | null, routingPublicKeyRaw: Uint8Array | null): void;
  loadKnownAccount(): KnownAccount | null;
  clearKnownAccount(): void;
  markDevicePasskeyBlocked(reason?: string): void;
  isDevicePasskeyBlocked(): boolean;
  clearDevicePasskeyBlocked(): void;
  knownBlobRevision(routingPublicKeyRaw: Uint8Array): number;
  rememberBlobRevision(routingPublicKeyRaw: Uint8Array, revision: number): void;
  forgetBlobRevision(routingPublicKeyRaw: Uint8Array): void;
}
export function memoryStorage(): StringStorage;
export function createKnownAccountStore(options: { cryptoCore: CryptoCore; storage?: StringStorage | null }): KnownAccountStore;

// flows.js
export const STEP_UP_GRACE_MS: number;
export interface SessionState {
  identity: Identity | null; ws: WebSocketLike | null; hasAccount: boolean; blob: IdentityBlob; blobToken: string | null;
  serverGeneration: number | null; authFields: Record<string, unknown> | null; locked: boolean;
}
export interface IdentitySessionOptions {
  cryptoCore: CryptoCore;
  origin: string;
  transport: { connect(): Promise<WebSocketLike> };
  sessionStore: SessionStore;
  knownAccounts: KnownAccountStore;
  webauthn?: WebAuthn | null;
  ui?: {
    askRecoveryCode?(reason: string, hint: string): Promise<string | null>;
    confirmDeletion?(): Promise<boolean>;
    passkeyName?(identity: Identity): Promise<string> | string;
    status?(stage: string, detail?: unknown): void;
  };
  hooks?: {
    registrationFields?(): Promise<Record<string, unknown>> | Record<string, unknown>;
    afterUnlock?(state: SessionState): Promise<void> | void;
    onLocked?(): Promise<void> | void;
    beforeDeleteAccount?(ctx: { ws: WebSocketLike; identity: Identity; blob: IdentityBlob }): Promise<void> | void;
  };
  stepUpGraceMs?: number;
  now?: () => number;
}
export type BootResult =
  | { restored: true; state: SessionState }
  | { restored: false; reason: 'none' | 'stale' | 'no-account' | 'mismatch' }
  | { restored: false; reason: 'unreadable'; error: Error }
  | { restored: false; reason: 'offline'; identity: Identity; session: RestoredSession };
export interface IdentitySession {
  state(): SessionState;
  bootGuest(): Promise<SessionState>;
  registerCurrentIdentity(options?: { label?: string; passkey?: 'platform' | 'cross-platform' | 'none' }): Promise<{ recoveryCode: string; passkey: boolean; passkeyBackedUp: boolean }>;
  unlockWithPasskey(): Promise<SessionState>;
  unlockWithDiscoverablePasskey(options?: { label?: string }): Promise<SessionState>;
  unlockWithRecoveryCode(code: string): Promise<SessionState>;
  bootFromTrustedSession(): Promise<BootResult>;
  switchTo(identity: Identity, options?: { freshProof?: boolean }): Promise<SessionState>;
  ensureConnected(): Promise<WebSocketLike>;
  requireFreshUnlock(reason: string): Promise<void>;
  saveIdentityBlob(mutation: (blob: IdentityBlob) => IdentityBlob, options?: { attempts?: number }): Promise<IdentityBlob>;
  rememberUnlockedSession(): Promise<void>;
  lock(): Promise<void>;
  listUnlockMethods(): Promise<ListedMethod[]>;
  addPasskey(options?: { label?: string; attachment?: 'platform' | 'cross-platform' }): Promise<{ credentialId: Uint8Array }>;
  removeUnlockMethod(methodId: string): Promise<void>;
  rotateRecoveryCode(options?: { label?: string }): Promise<{ recoveryCode: string }>;
  signOutEverywhere(): Promise<number>;
  checkDeviceAccountMatch(): Promise<{ status: 'in-sync' | 'diverged' | 'stale-device-passkey' | 'no-device-passkey'; known: KnownAccount | null }>;
  deleteAccount(): Promise<boolean>;
}
export function createIdentitySession(options: IdentitySessionOptions): IdentitySession;
