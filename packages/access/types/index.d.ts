// Hand-written declarations for @microtoll/access (source stays JavaScript; D-08).
import type { CryptoCore, SealingKeyPair, KemKeyPair, SealingJwk } from '@microtoll/crypto-core';
import type { Identity, WebSocketLike } from '@microtoll/identity';

export type UUID = string;
/** A key a member can be sealed to: 65-byte P-256 or 1216-byte hybrid. */
export type RecipientKey = Uint8Array;
export type JSONObject = Record<string, unknown>;

// ---------------------------------------------------------------------------
// envelope.js — member rows
// ---------------------------------------------------------------------------
export const ENVELOPE_QUIET: 2;
export const ENVELOPE_SIGNED: 3;
export const PQ_KEM_ADVERT_MAX_AGE_MS: number;

export interface OpenedRow {
  verified: boolean;
  signed: boolean;
  quiet: boolean;
  payload: JSONObject;
  identityPublicKeyRaw: Uint8Array | null;
  identitySigningKeyRaw: Uint8Array | null;
  rotationPublicKeyRaw: Uint8Array | null;
  identityKemKeyRaw: Uint8Array | null;
  sealTargetKeyRaw: RecipientKey | null;
}
export interface RosterEntry {
  id: UUID;
  keyEpoch: number;
  verified: boolean;
  quiet: boolean;
  /** The row's content; null for an unverified row, which shows nothing. */
  content: JSONObject | null;
  identitySigningKeyRaw: Uint8Array | null;
  identityPublicKeyRaw: Uint8Array | null;
  sealTargetKeyRaw: RecipientKey | null;
}
export interface QuietRotationKeys {
  jwk: SealingJwk; privateKey: CryptoKey; publicKeyRaw: Uint8Array;
  kemSeed: Uint8Array | null; kemPrivateKey: CryptoKey | null; kemPublicKeyRaw: Uint8Array | null;
}
export interface MemberKeys { classical: SealingKeyPair | Pick<SealingKeyPair, 'privateKey' | 'publicKeyRaw'> | null; kem: CryptoKey | null; }

export function rowContext(cc: CryptoCore, objectId: UUID, rowId: UUID): Uint8Array;
export function rowSigningMessage(cc: CryptoCore, objectId: UUID, rowId: UUID, payloadJson: string): Uint8Array;
export function isKemAdvertStale(isoDate: unknown, now?: number): boolean;
export function chooseMemberSealTarget(cc: CryptoCore, payload: JSONObject, now?: number): RecipientKey;
export function sealMemberRow(cc: CryptoCore, kObjectKey: CryptoKey, author: Identity, objectId: UUID, rowId: UUID, content: JSONObject): Promise<Uint8Array>;
export function sealQuietMemberRow(cc: CryptoCore, kObjectKey: CryptoKey, objectId: UUID, rowId: UUID, rotationPublicKeyRaw: Uint8Array, content: JSONObject, rotationKemPublicKeyRaw?: Uint8Array | null): Promise<Uint8Array>;
export function generateQuietRotationKeys(cc: CryptoCore): Promise<QuietRotationKeys>;
export function quietRotationKeys(cc: CryptoCore, jwk: SealingJwk, kemSeed?: Uint8Array | null): Promise<MemberKeys>;
export function openMemberRow(cc: CryptoCore, kObjectKey: CryptoKey, objectId: UUID, rowId: UUID, sealed: Uint8Array, now?: number): Promise<OpenedRow>;
export function resealMemberRow(cc: CryptoCore, oldKey: CryptoKey, newKey: CryptoKey, objectId: UUID, rowId: UUID, sealed: Uint8Array): Promise<Uint8Array>;
export function updateMemberRow(cc: CryptoCore, kObjectKey: CryptoKey, author: Identity, objectId: UUID, rowId: UUID, changes: JSONObject, previousPayload?: JSONObject | null, options?: { becomeNamed?: boolean }): Promise<Uint8Array>;
export function rosterEntry(rowId: UUID, keyEpoch: number, opened: OpenedRow, options?: { pick?: (payload: JSONObject) => JSONObject }): RosterEntry;

// ---------------------------------------------------------------------------
// pointer.js
// ---------------------------------------------------------------------------
export interface FieldCodec<T = unknown> { seal(value: unknown): unknown; open(value: unknown): T; }
export interface PointerFieldSpec<T = unknown> extends FieldCodec<T> { wire: string; }
export type PointerExtension = Record<string, PointerFieldSpec>;
export interface Pointer {
  objectId: UUID;
  kObject: Uint8Array;
  keyEpoch: number;
  rowCapabilitySecret: Uint8Array | null;
  adminCapabilitySecret: Uint8Array | null;
  quietRotationKey: SealingJwk | null;
  quietRotationKemSeed: Uint8Array | null;
  sharedLinks: unknown[];
  invitedBy: JSONObject | null;
  [extension: string]: unknown;
}
export interface PointerCodec {
  readonly fields: Readonly<Record<string, PointerFieldSpec>>;
  /** Seals a pointer for the account (its masterSymmKey and routing key; D-37). */
  build(identity: Pick<Identity, 'masterSymmKey' | 'routing'>, values: Partial<Pointer> & { objectId: UUID; kObject: Uint8Array; keyEpoch: number }): Promise<Uint8Array>;
  /** Opens one of the account's pointers as the server returns them (no id); the object it names is `objectId` inside. */
  open(identity: Pick<Identity, 'masterSymmKey' | 'routing'>, sealed: Uint8Array): Promise<Pointer>;
}
export const asIs: FieldCodec;
export const flag: FieldCodec<boolean>;
export const list: FieldCodec<unknown[]>;
export const objectOrNull: FieldCodec<JSONObject | null>;
export const instantOrNull: FieldCodec<string | null>;
export function oneOf<T extends string>(values: readonly T[]): FieldCodec<T | null>;
export function pointerContext(cc: CryptoCore, routingPublicKeyRaw: Uint8Array): Uint8Array;
export function coreFields(cc: CryptoCore): Readonly<Record<string, PointerFieldSpec>>;
export function createPointerCodec(cc: CryptoCore, extension?: PointerExtension): PointerCodec;

// ---------------------------------------------------------------------------
// admin.js — seats and the box
// ---------------------------------------------------------------------------
export const ADMIN_SEAT_BUCKET: 4;
export const ADMIN_SEAT_PLAINTEXT_BYTES: 256;
export const ADMIN_BOX_BUCKET_BYTES: 1024;
export interface AdminEntry { signingKey: string; identityPublicKey: string; rowId: UUID | null; identityKemKey?: string; identityKemKeyAt?: string | null; }
export interface AdminBlock { adminSeats: string[]; adminBox: string; }
export interface AdminSeat { adminCapabilitySecret: Uint8Array; kAdminboxRaw: Uint8Array; }
export interface GrantKey { publicKeyRaw: Uint8Array; privateKey: CryptoKey; kem: boolean; }
export function adminBoxContext(cc: CryptoCore, objectId: UUID, epoch: number): Uint8Array;
export function checkAdminEntry(cc: CryptoCore, entry: unknown): AdminEntry;
export function adminEntryForIdentity(cc: CryptoCore, identity: Identity, rowId?: UUID | null): AdminEntry;
export function adminEntryFromPayload(cc: CryptoCore, payload: JSONObject, rowId: UUID | null): AdminEntry | null;
export function sealAdminBox(cc: CryptoCore, kAdminboxRaw: Uint8Array, objectId: UUID, epoch: number, admins: AdminEntry[]): Promise<string>;
export function openAdminBox(cc: CryptoCore, kAdminboxRaw: Uint8Array, objectId: UUID, epoch: number, sealedB64u: string): Promise<AdminEntry[]>;
export function adminSeatTarget(cc: CryptoCore, entry: AdminEntry): RecipientKey;
export function buildAdminSeats(cc: CryptoCore, admins: AdminEntry[], material: { objectId: UUID; epoch: number; adminCapabilitySecret: Uint8Array; kAdminboxRaw: Uint8Array }): Promise<string[]>;
export function identityGrantKeys(identity: Identity | null | undefined): GrantKey[];
export function openWithAnyKey(cc: CryptoCore, candidates: GrantKey[], blob: Uint8Array): Promise<Uint8Array | null>;
export function openAdminSeat(cc: CryptoCore, identity: Identity, content: Partial<AdminBlock> | null, objectId: UUID, epoch: number): Promise<AdminSeat | null>;
export function readAdmins(cc: CryptoCore, identity: Identity, content: Partial<AdminBlock>, objectId: UUID, epoch: number): Promise<{ seat: AdminSeat; admins: AdminEntry[] } | null>;
export function newAdminBlock(cc: CryptoCore, identity: Identity, material: { objectId: UUID; epoch: number; adminCapabilitySecret: Uint8Array; selfRowId?: UUID | null }): Promise<AdminBlock>;
export function addCoOwner(cc: CryptoCore, identity: Identity, content: Partial<AdminBlock>, options: { objectId: UUID; epoch: number; adminCapabilitySecret: Uint8Array; grantee: AdminEntry; selfRowId?: UUID | null }): Promise<AdminBlock & { added: boolean }>;

// ---------------------------------------------------------------------------
// object.js — keys, content, second tier, builders
// ---------------------------------------------------------------------------
export interface BuiltRow {
  rowId: UUID; encryptedRow: Uint8Array; encryptedObjectKey: Uint8Array;
  rowCapabilitySecret: Uint8Array; rowCapabilityHash: string; keyEpoch: number;
}
export interface CreatedObject {
  objectId: UUID; kObjectRaw: Uint8Array; kDetailRaw: Uint8Array | null; epoch: 1;
  encryptedContent: Uint8Array; encryptedDetail: Uint8Array | null;
  adminCapabilitySecret: Uint8Array; adminCapabilityHash: string;
  readCapabilitySecret: Uint8Array; readCapabilityHash: string;
  ownerRow: BuiltRow; pointer: Uint8Array; previewContent: JSONObject;
}
export interface ServerRow { rowId: UUID; keyEpoch: number; encryptedRow: Uint8Array; }
export interface OpenedServerRow extends ServerRow { opened: OpenedRow; }
export type Split = (content: JSONObject) => { preview: JSONObject; detail: JSONObject };
export type Merge = (preview: JSONObject, detail: JSONObject | null) => JSONObject;
export type GrantDue = (entry: RosterEntry) => boolean;
export interface Viewer { identity?: Identity | null; quietRotationKey?: SealingJwk | null; quietRotationKemSeed?: Uint8Array | null; }

export function contentContext(cc: CryptoCore, objectId: UUID, epoch: number): Uint8Array;
export function detailContext(cc: CryptoCore, objectId: UUID, epoch: number): Uint8Array;
export function sealContent(cc: CryptoCore, kObjectKey: CryptoKey, objectId: UUID, epoch: number, content: JSONObject): Promise<Uint8Array>;
export function openContent(cc: CryptoCore, kObjectKey: CryptoKey, objectId: UUID, epoch: number, sealed: Uint8Array): Promise<JSONObject>;
export function sealDetail(cc: CryptoCore, kDetailKey: CryptoKey, objectId: UUID, epoch: number, detail: JSONObject): Promise<Uint8Array>;
export function openDetail(cc: CryptoCore, kDetailKey: CryptoKey, objectId: UUID, epoch: number, sealed: Uint8Array): Promise<JSONObject>;
export function readCapability(cc: CryptoCore, kObjectRaw: Uint8Array): Promise<Uint8Array>;
export function hashCapability(cc: CryptoCore, secret: Uint8Array): Promise<string>;
export function newCapability(cc: CryptoCore): Promise<{ secret: Uint8Array; hash: string }>;
export function sealObjectKeyForMember(cc: CryptoCore, memberPublicKeyRaw: RecipientKey, kObjectRaw: Uint8Array): Promise<Uint8Array>;
export function unwrapObjectKey(cc: CryptoCore, memberKeys: MemberKeys | SealingKeyPair | Pick<SealingKeyPair, 'privateKey' | 'publicKeyRaw'>, sealed: Uint8Array): Promise<{ kObjectRaw: Uint8Array; kObjectKey: CryptoKey }>;
export function generateDetailKey(cc: CryptoCore): Uint8Array;
export function detailGrantLabel(cc: CryptoCore, kObjectRaw: Uint8Array, recipientKeyRaw: RecipientKey): Promise<string>;
export function buildDetailGrants(cc: CryptoCore, kObjectRaw: Uint8Array, kDetailRaw: Uint8Array, recipientKeys: Array<RecipientKey | null>): Promise<Record<string, string>>;
export function openDetailGrant(cc: CryptoCore, kObjectRaw: Uint8Array, grants: Record<string, string> | null | undefined, candidates: GrantKey[]): Promise<Uint8Array | null>;
export function goingGrantDue(entry: RosterEntry): boolean;
export function planDetailGrantSweep(cc: CryptoCore, options: { kObjectRaw: Uint8Array; kDetailRaw: Uint8Array | null; existingGrants: Record<string, string> | null | undefined; entries: RosterEntry[]; grantDue: GrantDue; adminSigningKeys?: Set<string> | null }): Promise<Record<string, string> | null>;
export function openForViewer(cc: CryptoCore, options: { kObjectRaw: Uint8Array; objectId: UUID; epoch: number; preview: JSONObject; encryptedDetail: Uint8Array | null; viewer: Viewer | null; merge?: Merge }): Promise<JSONObject>;
export function defaultMerge(preview: JSONObject, detail: JSONObject | null): JSONObject;
export function createObject(cc: CryptoCore, options: { identity: Identity; content: JSONObject; ownerRowContent?: JSONObject; twoTier?: boolean; split?: Split | null; pointerCodec: PointerCodec; now?: number }): Promise<CreatedObject>;
export function buildMemberRow(cc: CryptoCore, options: { identity: Identity; objectId: UUID; kObjectRaw: Uint8Array; keyEpoch: number; content?: JSONObject }): Promise<BuiltRow>;
export function buildQuietMemberRow(cc: CryptoCore, options: { objectId: UUID; kObjectRaw: Uint8Array; keyEpoch: number; content?: JSONObject }): Promise<{ quietRotationKey: SealingJwk; quietRotationKemSeed: Uint8Array | null; row: BuiltRow }>;
export function buildReadOnlyPointer(cc: CryptoCore, options: { identity: Identity; objectId: UUID; kObjectRaw: Uint8Array; keyEpoch: number; invitedBy?: JSONObject | null; pointerCodec: PointerCodec; extra?: Partial<Pointer> }): Promise<Uint8Array>;
export function buildFirstReaction(cc: CryptoCore, options: { identity: Identity; objectId: UUID; kObjectRaw: Uint8Array; keyEpoch: number; content?: JSONObject; quiet?: boolean; existingPointer?: Partial<Pointer>; pointerCodec: PointerCodec }): Promise<{ row: BuiltRow; pointer: Uint8Array; readCapabilitySecret: Uint8Array }>;
export function openRows(cc: CryptoCore, options: { kObjectRaw: Uint8Array; objectId: UUID; rows: ServerRow[]; now?: number }): Promise<OpenedServerRow[]>;

// ---------------------------------------------------------------------------
// rotation.js
// ---------------------------------------------------------------------------
export const SET_ASIDE_REASONS: readonly ['unreadable', 'bad-signature', 'unsigned-envelope', 'no-key'];
export interface RotationPlan {
  expectedEpoch: number; newEpoch: number; newKObjectRaw: Uint8Array; newKDetailRaw: Uint8Array | null;
  encryptedContent: Uint8Array; encryptedDetail: Uint8Array | null;
  readCapabilityHash: string; adminCapabilitySecret: Uint8Array; adminCapabilityHash: string;
  updates: Array<{ rowId: UUID; encryptedRow: Uint8Array; encryptedObjectKey: Uint8Array }>;
  removedRowIds: UUID[];
  setAside: Array<{ rowId: UUID; reason: (typeof SET_ASIDE_REASONS)[number] }>;
  admins: number;
  previewContent: JSONObject;
}
export function buildRotationPlan(cc: CryptoCore, options: {
  objectId: UUID; identity: Identity; oldKObjectRaw: Uint8Array; oldEpoch: number; content: JSONObject; rows: ServerRow[];
  remove?: UUID[]; selfRowId?: UUID | null; twoTier?: { split: Split; detailOpened: boolean } | null; grantDue?: GrantDue; now?: number;
}): Promise<RotationPlan>;
export function refreshPointerAfterRotation(cc: CryptoCore, options: { identity: Identity; objectId: UUID; myRow: { encryptedObjectKey: Uint8Array; keyEpoch: number }; existingPointer: Partial<Pointer> | null; pointerCodec: PointerCodec }): Promise<{ kObjectRaw: Uint8Array; pointer: Uint8Array }>;

// ---------------------------------------------------------------------------
// links.js — share links
// ---------------------------------------------------------------------------
export interface ShareLinkRecord { hashedToken: string; token: string | null; manageSecret: string | null; label: string | null; createdAt: string | null; maxUses: number | null; expiresAt: string | null; keyEpoch: number | null; }
export interface ShareLink {
  token: string; hashedToken: string; encryptedPayload: Uint8Array; maxUses: number; expiresAt: string;
  manageSecret: Uint8Array; manageCapabilityHash: string; record: ShareLinkRecord;
}
export interface RedeemedLink { objectId: UUID; kObjectRaw: Uint8Array; verified: boolean; creatorName: string | null; creatorSigningKeyRaw: Uint8Array | null; }
export function randomToken(cc: CryptoCore): string;
export function hashToken(cc: CryptoCore, token: string): Promise<string>;
export function linkSigningMessage(cc: CryptoCore, hashedTokenHex: string, payloadJson: string): Uint8Array;
export function linkContext(cc: CryptoCore, hashedTokenHex: string): Uint8Array;
export function createShareLink(cc: CryptoCore, options: { objectId: UUID; kObjectRaw: Uint8Array; maxUses?: number; expiresAt: string; creator?: Identity | null; creatorName?: string | null; keyEpoch?: number | null; label?: string | null }): Promise<ShareLink>;
export function redeemShareLink(cc: CryptoCore, token: string, encryptedPayload: Uint8Array): Promise<RedeemedLink>;
export function tokenFromFragment(hash: string | null | undefined): string | null;
export function normaliseLinkRecords(records?: Array<string | ShareLinkRecord>): Array<ShareLinkRecord & { manageable: boolean; shareable: boolean }>;

// ---------------------------------------------------------------------------
// wire.js — the server messages (D-27)
// ---------------------------------------------------------------------------
export interface FetchedObject { objectId: UUID; encryptedContent: Uint8Array; encryptedDetail: Uint8Array | null; keyEpoch: number; adminCapabilityHash: Uint8Array | null; fields: Record<string, unknown>; }
export interface MyRow { rowId: UUID; encryptedRow: Uint8Array; encryptedObjectKey: Uint8Array; keyEpoch: number; }
export interface LinkStats { hashedToken: string; useCount: number; maxUses: number; expiresAt: string | null; }
export function createObjectMessage(cc: CryptoCore, ws: WebSocketLike, created: CreatedObject, selector?: Record<string, unknown>): Promise<UUID>;
export function fetchObject(cc: CryptoCore, ws: WebSocketLike, objectId: UUID): Promise<FetchedObject>;
export function decodeObjectWire(cc: CryptoCore, e: Record<string, any>): FetchedObject;
export function joinObject(cc: CryptoCore, ws: WebSocketLike, options: { objectId: UUID; pointer: Uint8Array; row?: BuiltRow | null; readCapabilitySecret?: Uint8Array | null }): Promise<UUID>;
export function fetchMembers(cc: CryptoCore, ws: WebSocketLike, objectId: UUID, secrets?: { adminCapabilitySecret?: Uint8Array | null; readCapabilitySecret?: Uint8Array | null; rowCapabilitySecret?: Uint8Array | null }): Promise<ServerRow[]>;
export function rotateObjectKey(cc: CryptoCore, ws: WebSocketLike, objectId: UUID, adminCapabilitySecret: Uint8Array, plan: RotationPlan): Promise<number>;
export function fetchMyRow(cc: CryptoCore, ws: WebSocketLike, objectId: UUID, rowCapabilitySecret: Uint8Array): Promise<MyRow>;
export function createMemberRow(cc: CryptoCore, ws: WebSocketLike, options: { objectId: UUID; row: BuiltRow; pointerId: string; pointer: Uint8Array; readCapabilitySecret: Uint8Array }): Promise<UUID>;
export function updateMemberRowMessage(cc: CryptoCore, ws: WebSocketLike, options: { objectId: UUID; rowCapabilitySecret: Uint8Array; encryptedRow: Uint8Array; keyEpoch: number; extra?: Record<string, unknown> }): Promise<void>;
export function updateObject(cc: CryptoCore, ws: WebSocketLike, options: { objectId: UUID; adminCapabilitySecret: Uint8Array; keyEpoch: number; encryptedContent: Uint8Array; encryptedDetail?: Uint8Array | null; selector?: Record<string, unknown> }): Promise<void>;
export function deleteObject(cc: CryptoCore, ws: WebSocketLike, objectId: UUID, adminCapabilitySecret: Uint8Array): Promise<void>;
export function deleteMyRow(cc: CryptoCore, ws: WebSocketLike, objectId: UUID, rowCapabilitySecret: Uint8Array): Promise<boolean>;
export function fetchPointers(cc: CryptoCore, ws: WebSocketLike): Promise<Array<{ pointerId: string; sealed: Uint8Array }>>;
export function updatePointer(cc: CryptoCore, ws: WebSocketLike, pointerId: string, sealed: Uint8Array): Promise<void>;
/** delete-pointer (blind-store, M4): discards one of the caller's own pointers; false when it was already gone. */
export function deletePointer(ws: WebSocketLike, pointerId: string): Promise<boolean>;

// ---- the selector query and the live watches (blind-store, M4) ----
export interface ObjectQuery { collection: string; selectors?: string[]; all?: true; windowStart?: string; windowEnd?: string; }
/** query-events: everything active that matches, unfiltered by identity; `extras` is whatever the host added to the reply. */
export function queryObjects(cc: CryptoCore, ws: WebSocketLike, query: ObjectQuery): Promise<{ objects: FetchedObject[]; extras: Record<string, unknown> }>;
export function watchObjects(ws: WebSocketLike, query: ObjectQuery): Promise<void>;
export function unwatchObjects(ws: WebSocketLike): Promise<void>;
export function watchImminent(ws: WebSocketLike): Promise<void>;
export interface LiveObjectEvent { kind: 'created' | 'updated' | 'deleted' | 'participation'; object: FetchedObject | null; objectId: string; }
/** Live pushes on a socket; returns the function that stops listening. */
export function onLiveObject(cc: CryptoCore, ws: WebSocketLike, handler: (event: LiveObjectEvent) => void): () => void;
export function publishShareLink(cc: CryptoCore, ws: WebSocketLike, link: ShareLink): Promise<void>;
export function redeemShareLinkMessage(cc: CryptoCore, ws: WebSocketLike, hashedToken: string): Promise<Uint8Array>;
export function revokeShareLink(cc: CryptoCore, ws: WebSocketLike, hashedToken: string, manageSecret: Uint8Array): Promise<number>;
export function fetchShareLinkStats(cc: CryptoCore, ws: WebSocketLike, links: Array<{ hashedToken: string; manageSecret: Uint8Array }>): Promise<LinkStats[]>;

// ---------------------------------------------------------------------------
// The instance
// ---------------------------------------------------------------------------
type Bound<F> = F extends (cc: CryptoCore, ...args: infer A) => infer R ? (...args: A) => R : never;

export interface AccessOptions {
  cryptoCore: CryptoCore;
  pointerFields?: PointerExtension;
  split?: Split | null;
  grantDue?: GrantDue;
  merge?: Merge;
}
export interface Access {
  readonly cc: CryptoCore;
  readonly pointerCodec: PointerCodec;
  readonly split: Split | null;
  readonly grantDue: GrantDue;
  readonly merge: Merge;
  createObject(options: Omit<Parameters<typeof createObject>[1], 'pointerCodec' | 'split'> & { split?: Split }): Promise<CreatedObject>;
  buildMemberRow: Bound<typeof buildMemberRow>;
  buildQuietMemberRow: Bound<typeof buildQuietMemberRow>;
  buildReadOnlyPointer(options: Omit<Parameters<typeof buildReadOnlyPointer>[1], 'pointerCodec'>): Promise<Uint8Array>;
  buildFirstReaction(options: Omit<Parameters<typeof buildFirstReaction>[1], 'pointerCodec'>): Promise<{ row: BuiltRow; pointer: Uint8Array; readCapabilitySecret: Uint8Array }>;
  openRows: Bound<typeof openRows>;
  roster(rows: OpenedServerRow[], options?: { pick?: (payload: JSONObject) => JSONObject }): RosterEntry[];
  openForViewer(options: Omit<Parameters<typeof openForViewer>[1], 'merge'> & { merge?: Merge }): Promise<JSONObject>;
  planDetailGrantSweep(options: Omit<Parameters<typeof planDetailGrantSweep>[1], 'grantDue'> & { grantDue?: GrantDue }): Promise<Record<string, string> | null>;
  buildRotationPlan(options: Omit<Parameters<typeof buildRotationPlan>[1], 'twoTier' | 'grantDue'> & { twoTier?: { split?: Split; detailOpened: boolean } | null; grantDue?: GrantDue }): Promise<RotationPlan>;
  refreshPointerAfterRotation(options: Omit<Parameters<typeof refreshPointerAfterRotation>[1], 'pointerCodec'>): Promise<{ kObjectRaw: Uint8Array; pointer: Uint8Array }>;
  sealContent: Bound<typeof sealContent>; openContent: Bound<typeof openContent>; sealDetail: Bound<typeof sealDetail>; openDetail: Bound<typeof openDetail>;
  readCapability: Bound<typeof readCapability>; hashCapability: Bound<typeof hashCapability>; newCapability: Bound<typeof newCapability>;
  sealObjectKeyForMember: Bound<typeof sealObjectKeyForMember>; unwrapObjectKey: Bound<typeof unwrapObjectKey>;
  detailGrantLabel: Bound<typeof detailGrantLabel>; buildDetailGrants: Bound<typeof buildDetailGrants>; openDetailGrant: Bound<typeof openDetailGrant>;
  sealMemberRow: Bound<typeof sealMemberRow>; sealQuietMemberRow: Bound<typeof sealQuietMemberRow>; openMemberRow: Bound<typeof openMemberRow>;
  updateMemberRow: Bound<typeof updateMemberRow>; resealMemberRow: Bound<typeof resealMemberRow>; chooseMemberSealTarget: Bound<typeof chooseMemberSealTarget>;
  generateQuietRotationKeys: Bound<typeof generateQuietRotationKeys>; quietRotationKeys: Bound<typeof quietRotationKeys>;
  readAdmins: Bound<typeof readAdmins>; openAdminSeat: Bound<typeof openAdminSeat>; addCoOwner: Bound<typeof addCoOwner>; adminEntryForIdentity: Bound<typeof adminEntryForIdentity>;
  createShareLink: Bound<typeof createShareLink>; redeemShareLink: Bound<typeof redeemShareLink>; hashToken: Bound<typeof hashToken>;
  createObjectMessage: Bound<typeof createObjectMessage>; fetchObject: Bound<typeof fetchObject>; joinObject: Bound<typeof joinObject>; fetchMembers: Bound<typeof fetchMembers>;
  rotateObjectKey: Bound<typeof rotateObjectKey>; fetchMyRow: Bound<typeof fetchMyRow>; createMemberRow: Bound<typeof createMemberRow>; updateMemberRowMessage: Bound<typeof updateMemberRowMessage>;
  updateObject: Bound<typeof updateObject>; deleteObject: Bound<typeof deleteObject>; deleteMyRow: Bound<typeof deleteMyRow>; fetchPointers: Bound<typeof fetchPointers>; updatePointer: Bound<typeof updatePointer>;
  queryObjects: Bound<typeof queryObjects>; onLiveObject: Bound<typeof onLiveObject>;
  watchObjects: typeof watchObjects; unwatchObjects: typeof unwatchObjects; watchImminent: typeof watchImminent; deletePointer: typeof deletePointer;
  publishShareLink: Bound<typeof publishShareLink>; redeemShareLinkMessage: Bound<typeof redeemShareLinkMessage>; revokeShareLink: Bound<typeof revokeShareLink>; fetchShareLinkStats: Bound<typeof fetchShareLinkStats>;
  rosterEntry: typeof rosterEntry;
  goingGrantDue: typeof goingGrantDue;
  tokenFromFragment: typeof tokenFromFragment;
  normaliseLinkRecords: typeof normaliseLinkRecords;
}
export function createAccess(options: AccessOptions): Access;
