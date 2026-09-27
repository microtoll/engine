// Hand-written declarations for @microtoll/blind-store (M4). Checked by the
// repository's `npm run typecheck` without @types/node or @types/ws (the
// check has no dependencies): Node's and ws's own types are described by
// the small structural interfaces below, which is all the package relies on.
// The source is plain JavaScript.

/** Anything with pg's `query(text, values)`: a Pool or a Client. */
export interface Queryable { query(text: string, values?: unknown[]): Promise<{ rows: any[]; rowCount: number | null }>; }
export interface PoolLike extends Queryable { connect(): Promise<Queryable & { release(): void }>; }

/** A ws socket: what the handlers use of it. */
export interface ServerSocket { send(data: string): void; close(code?: number, reason?: string): void; terminate(): void; readyState: number; on(event: string, listener: (...args: any[]) => void): unknown; }
export interface SocketServerLike { clients: Set<ServerSocket>; close(cb?: () => void): void; on(event: string, listener: (...args: any[]) => void): unknown; }
export interface HttpServerLike { listen(port?: number, host?: string): unknown; close(cb?: () => void): unknown; once(event: string, listener: (...args: any[]) => void): unknown; address(): { port: number; address: string } | string | null; }
export interface HttpRequestLike { url?: string; method?: string; headers: Record<string, string | string[] | undefined>; }
export interface HttpResponseLike { writeHead(status: number, headers?: Record<string, string>): unknown; end(body?: string): void; }
export interface RequestStore { getStore(): { ws: ServerSocket; requestId: string | null } | undefined; run<T>(store: { ws: ServerSocket; requestId: string | null }, fn: () => T): T; }

export interface ConnectionState {
  authenticated: boolean;
  routingPublicKey: Uint8Array | null;
  hasAccount: boolean;
  /** The origin the handshake was verified against. */
  origin: string | null;
  lookups: number;
}

export interface HandlerContext {
  pool: PoolLike | null;
  ws: ServerSocket;
  msg: any;
  state: ConnectionState;
  routingPublicKey: Uint8Array | null;
}
export type Handler = (ctx: HandlerContext) => void | Promise<void>;
export type AuthMode = 'required' | 'none' | 'any';

export interface CollectionConfig {
  /** The exact length of every selector in this collection, 1-64. */
  selectorLength: number;
  /** Whether objects carry a date window (default false). */
  window?: boolean;
  /** Whether a query may name every selector at once (default false). */
  allowAll?: boolean;
  /** The server-owned window for watch-imminent, in days; needs `window`. */
  imminentDays?: number | null;
  /** Fields merged into the query reply (a host's piggy-backed data). */
  queryExtras?: ((pool: PoolLike, query: ParsedQuery) => Promise<Record<string, unknown>> | Record<string, unknown>) | null;
}
export interface NormalisedCollection {
  name: string; selectorLength: number; window: boolean; allowAll: boolean; imminentDays: number | null;
  queryExtras: CollectionConfig['queryExtras'];
}
export interface ParsedQuery { collection: NormalisedCollection; all: boolean; selectors: string[] | null; windowStart: string | null; windowEnd: string | null; }

export interface RegistrationPolicy {
  /** Extra `users` columns the host declared in its own init file. */
  columns?: string[];
  /** Their values from the register message, or throws with the reason the client is told. */
  onRegister?: (msg: any) => Record<string, unknown> | void;
  /** Fields added to auth-ok from those columns; row is null when there is no account. */
  authOkFields?: (row: Record<string, unknown> | null) => Record<string, unknown>;
}

export interface TransportLimits {
  preAuthTimeoutMs: number;
  bucket: { capacity: number; refillPerSec: number };
  maxSockets: number;
  maxLookupsPerSocket: number;
  allowedOrigins: readonly string[];
}
export interface QueryLimits { maxSelectors: number; maxQueryRows: number; }
export interface Logger { info(message: string): void; error(message: string): void; }
export type BlobLimitKey = 'encryptedIdentityBlob' | 'encryptedEventData' | 'encryptedEventDetail' | 'encryptedParticipationDataBlob'
  | 'encryptedEventAccessBlob' | 'encryptedPayload' | 'encryptedBundle' | 'encryptedSharedEventKey' | 'wrappedRootKey' | 'encryptedLabel' | 'credentialId' | 'prfSalt' | 'pbkdf2Salt';

export interface BlindStoreOptions {
  /** REQUIRED: the crypto-core namespace the handshake label is built from. */
  namespace: string;
  /** REQUIRED: the web origins browsers may connect from. */
  allowedOrigins: string[];
  pool?: PoolLike | null;
  port?: number;
  host?: string;
  collections?: Record<string, CollectionConfig>;
  transport?: Partial<Omit<TransportLimits, 'allowedOrigins'>>;
  /** Overrides for the per-field ciphertext caps, by wire field name. */
  limits?: Partial<Record<BlobLimitKey, number>>;
  query?: Partial<QueryLimits>;
  rateLimits?: Record<string, number>;
  registration?: RegistrationPolicy | null;
  live?: { connectionConfig?: object | null; extraChannels?: Record<string, (payload: string) => void> } | null;
  sweep?: false | { intervalMs?: number };
  httpRoutes?: Record<string, (req: HttpRequestLike, res: HttpResponseLike) => void | Promise<void>>;
  onAuthenticated?: ((routingPublicKey: Uint8Array, ws: ServerSocket) => void) | null;
  onSocketClose?: ((ws: ServerSocket) => void) | null;
  onDeleteAccount?: ((pool: PoolLike, routingPublicKey: Uint8Array) => void | Promise<void>) | null;
  log?: Logger;
}

export interface RateLimiter {
  consume(pool: PoolLike, routingPublicKey: Uint8Array | null, action: string): Promise<{ allowed: boolean; count: number; limit: number; degraded?: boolean }>;
  clearFor(queryable: Queryable, routingPublicKey: Uint8Array): Promise<void>;
  defineLimits(extra: Record<string, number>): void;
  limits: Record<string, number>;
}

export interface Live {
  setWatch(ws: ServerSocket, query: ParsedQuery): void;
  dropWatch(ws: ServerSocket): void;
  setImminentWatch(ws: ServerSocket): void;
  setMailboxWatch(ws: ServerSocket, mailboxIdsHex: string[]): void;
  removeWatcher(ws: ServerSocket): void;
  counts(): { watchers: number; imminent: number; mailbox: number };
  handleObjectNotification(raw: string | object): Promise<void>;
  handleMailboxNotification(raw: string): void;
  start(): Promise<void>;
  stop(): Promise<void>;
  isSubscribed(): boolean;
}

export interface BlindStore {
  wss: SocketServerLike;
  httpServer: HttpServerLike;
  handle(type: string, handler: Handler, options?: { auth?: AuthMode; needsPool?: boolean }): void;
  setFallback(fn: (ctx: HandlerContext) => Promise<boolean> | boolean): void;
  close(cb?: (err?: unknown) => void): Promise<void>;
  limits: TransportLimits;
  blobLimits: Record<string, number>;
  queryLimits: QueryLimits;
  rateLimit: RateLimiter;
  live: Live | null;
  liveStart: Promise<void>;
  collections: Map<string, NormalisedCollection>;
  namespace: string;
  runSweep: (() => Promise<void>) | null;
  address(): ReturnType<HttpServerLike['address']>;
}

export function createBlindStore(options: BlindStoreOptions): BlindStore;
/** Another name for createBlindStore (D-36). */
export const createCore: typeof createBlindStore;

// ---- the wire helpers a host's handlers share ----
export function send(ws: ServerSocket, obj: object): void;
export const requestContext: RequestStore;
export function fromB64u(str: string): Uint8Array;
export function toB64u(bytes: Uint8Array): string;
export const UUID_RE: RegExp;
export const DATE_RE: RegExp;
export function blobValue(value: unknown, limitKey: string, name?: string, options?: { required?: boolean; limits?: Record<string, number> }): Uint8Array | null;
export function blobField(msg: any, key: string, options?: { required?: boolean; limits?: Record<string, number> }): Uint8Array | null;
export function hashField(value: unknown, name: string, options?: { required?: boolean }): Uint8Array | null;
export function hashSecret(secretBytes: Uint8Array): Uint8Array;
export function expiryField(value: unknown, name: string, options?: { maxDays?: number; now?: number }): string;
export const CLOSE_PROTOCOL_ERROR: 1002;
export const CLOSE_AUTH_FAILED: 1008;
export const IDENTITY_BLOB_TOKEN_BYTES: 16;

// ---- the limits ----
export const MAX_FRAME_BYTES: number;
export const BLOB_LIMITS: Readonly<Record<BlobLimitKey, number>>;
export const URL_INVITE_MAX_USES: 200;
export const INVITE_MAX_DAYS: 400;
export const QUERY_DEFAULTS: Readonly<QueryLimits>;
export const TRANSPORT_DEFAULTS: Readonly<Omit<TransportLimits, 'allowedOrigins'>>;
export const RATE_LIMIT_DEFAULTS: Readonly<Record<string, number>>;

// ---- the handshake's server half ----
export const NONCE_BYTES: 32;
export function generateNonce(): Uint8Array;
export function assertNamespace(namespace: unknown): string;
export function authLabel(namespace: string): string;
export function authMessage(namespace: string, origin: string, nonce: Uint8Array): Uint8Array;
/** A Node KeyObject for the raw Ed25519 public key. */
export function importEd25519PublicKeyRaw(rawBytes32: Uint8Array): object;
export function verifyAuthSignature(namespace: string, routingPublicKeyRaw32: Uint8Array, origin: string, nonce: Uint8Array, signature: Uint8Array): boolean;
export function verifyAgainstOrigins(namespace: string, routingPublicKeyRaw32: Uint8Array, origins: readonly string[], nonce: Uint8Array, signature: Uint8Array): string | null;

// ---- the counters, pointers, mailbox, collections, live ----
export function createRateLimiter(options?: { limits?: Record<string, number>; log?: Logger }): RateLimiter;
export function insertPointer(client: Queryable, routingPublicKey: Uint8Array, pointer: { sealed: Uint8Array }): Promise<void>;
export function parsePointerField(pointer: unknown, limits?: Record<string, number>): { sealed: Uint8Array };
export const MAILBOX_ID_BYTES: 32;
export function parseMailboxIds(value: unknown): Uint8Array[];
export function normaliseCollections(collections?: Record<string, CollectionConfig>): Map<string, NormalisedCollection>;
export function parseQueryMessage(config: Map<string, NormalisedCollection>, msg: any, queryLimits: QueryLimits): ParsedQuery;
export const OBJECT_COLUMNS: string;
export const OBJECT_SELECT_ACTIVE: string;
export function rowToObjectWire(row: any): {
  id: string; collection: string; selector: string; windowStart: string | null; windowEnd: string | null;
  encryptedEventData: string; encryptedEventDetail: string | null; keyEpoch: number; rosterMembersOnly: boolean;
};
export function verifyAdminCapability(pool: Queryable, objectId: string, adminCapabilitySecretB64u: unknown): Promise<boolean>;
export function verifyReadCapability(pool: Queryable, objectId: string, readCapabilitySecretB64u: unknown): Promise<boolean>;
export function verifyRowCapabilityForObject(pool: Queryable, objectId: string, rowCapabilitySecretB64u: unknown): Promise<boolean>;
export function rosterIsMembersOnly(pool: Queryable, objectId: string): Promise<boolean>;
export function createLive(options: { pool: PoolLike; collections: Map<string, NormalisedCollection>; connectionConfig?: object | null; extraChannels?: Record<string, (payload: string) => void>; debounceMs?: number; log?: Logger }): Live;
export const OBJECT_CHANNEL: 'blind_store_object_live';
export const MAILBOX_CHANNEL: 'blind_store_mailbox_live';
