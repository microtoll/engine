// Hand-written declarations for @microtoll/mailbox (M3b). Checked by the
// repository's `npm run typecheck`; the source is plain JavaScript.
import type { CryptoCore } from '@microtoll/crypto-core';
import type { Identity, WebSocketLike } from '@microtoll/identity';

export type Base64Url = string;
/** A person this account knows, as the app keeps them: keys as base64url. `sealToKey` is a hybrid KEM key they advertised, when the app has seen one. */
export interface Contact { signingKey: Base64Url; identityKey: Base64Url; sealToKey?: Base64Url | null; [extra: string]: unknown; }

export const BUNDLE_VERSION: 2;

// ---- labels ----
export function epoch(date?: Date): string;
export function pollEpochs(date?: Date): [string, string];
export function pushEpochs(date?: Date): [string, string];
export function mailboxId(cc: CryptoCore, myPrivateKey: CryptoKey, otherPublicKeyRaw: Uint8Array, senderPublicKeyRaw: Uint8Array, recipientPublicKeyRaw: Uint8Array, epoch: string): Promise<Uint8Array>;
export function mailboxForSending(cc: CryptoCore, sender: Identity, recipientPublicKeyRaw: Uint8Array, epoch?: string): Promise<Uint8Array>;
export function mailboxForReceiving(cc: CryptoCore, recipient: Identity, senderPublicKeyRaw: Uint8Array, epoch?: string): Promise<Uint8Array>;

// ---- bundles ----
export interface OpenedBundle {
  verified: boolean;
  kind: string;
  objectId: string | null;
  kObjectRaw: Uint8Array | null;
  keyEpoch: number | null;
  /** Shown only when verified. */
  senderName: string | null;
  senderIdentityKeyRaw: Uint8Array | null;
  senderSigningKeyRaw: Uint8Array | null;
  hashedToken: string | null;
  stage: string | null;
  /** The app's claims inside the signed payload; empty unless verified. */
  claims: Record<string, unknown>;
}
export function inviteSigningMessage(cc: CryptoCore, mailboxId: Uint8Array, recipientKeyRaw: Uint8Array, payloadJson: string): Promise<Uint8Array>;
export function buildInvite(cc: CryptoCore, sender: Identity, recipientKeyRaw: Uint8Array, options: { mailboxId: Uint8Array; objectId: string; kObjectRaw: Uint8Array; keyEpoch: number; senderName?: string | null; claims?: Record<string, unknown> }): Promise<Uint8Array>;
export function buildAck(cc: CryptoCore, sender: Identity, recipientKeyRaw: Uint8Array, options: { mailboxId: Uint8Array; objectId: string; senderName?: string | null; hashedToken?: string | null; stage?: string | null; claims?: Record<string, unknown> }): Promise<Uint8Array>;
export function openBundle(cc: CryptoCore, recipient: Identity, mailboxId: Uint8Array, sealed: Uint8Array): Promise<OpenedBundle>;

// ---- the wire ----
export interface PolledRow { id: string; mailboxId: Uint8Array; encryptedBundle: Uint8Array | null; consumed: boolean; }
export function sendInvite(cc: CryptoCore, ws: WebSocketLike, mailboxId: Uint8Array, sealedBundle: Uint8Array, expiresAt?: string | null): Promise<string>;
export function pollInvites(cc: CryptoCore, ws: WebSocketLike, mailboxIds: Uint8Array[]): Promise<PolledRow[]>;
export function consumeInvite(ws: WebSocketLike, inviteId: string): Promise<void>;
export function watchInvites(cc: CryptoCore, ws: WebSocketLike, mailboxIds: Uint8Array[]): Promise<void>;
export function onLiveInvite(ws: WebSocketLike, handler: (event: { mailboxId: string }) => void): () => void;

// ---- send, collect, withdraw, status ----
export interface SentResult { signingKey: Base64Url | null; epoch: string; mailboxId: Uint8Array | null; inviteId: string | null; ok: boolean; error: string | null; }
export interface CollectedBase { rowId: string; mailboxId: Base64Url; epoch: string | null; viaContact: Contact | null; objectId: string | null; }
export interface CollectedInvite extends CollectedBase { kObjectRaw: Uint8Array | null; keyEpoch: number | null; verified: true; senderName: string | null; senderSigningKey: Base64Url; senderIdentityKeyRaw: Uint8Array | null; claims: Record<string, unknown>; }
export interface CollectedAck extends CollectedBase { verified: boolean; senderName: string | null; senderSigningKey: Base64Url | null; hashedToken: string | null; stage: string | null; claims: Record<string, unknown>; }
export interface CollectedUnsigned extends CollectedBase { kObjectRaw: Uint8Array | null; keyEpoch: number | null; }
export interface Collected { invites: CollectedInvite[]; acks: CollectedAck[]; unsigned: CollectedUnsigned[]; counts: { labels: number; rows: number; already: number; unreadable: number; other: number }; }
export function receivingLabels(cc: CryptoCore, identity: Identity, contacts: Contact[], epochs?: string[]): Promise<Map<Base64Url, { contact: Contact; epoch: string; mailboxId: Uint8Array }>>;
export function send(cc: CryptoCore, ws: WebSocketLike, sender: Identity, recipients: Contact[], options: { objectId: string; kObjectRaw: Uint8Array; keyEpoch: number; senderName?: string | null; claims?: Record<string, unknown>; expiresAt?: string | null; epoch?: string }): Promise<SentResult[]>;
export function collect(cc: CryptoCore, ws: WebSocketLike, identity: Identity, contacts: Contact[], options?: { epochs?: string[]; consumeAcks?: boolean }): Promise<Collected>;
export function withdraw(cc: CryptoCore, ws: WebSocketLike, sender: Identity, recipientIdentityKeyRaw: Uint8Array, epoch: string, inviteId?: string | null): Promise<{ burned: number; collected: boolean }>;
export interface InvitedRecord { identityKey: Base64Url; epoch: string; inviteId?: string | null; [extra: string]: unknown; }
export function status(cc: CryptoCore, ws: WebSocketLike, sender: Identity, invited: InvitedRecord[]): Promise<Array<InvitedRecord & { collected: boolean | null }>>;

// ---- the bound instance ----
type Bound<F> = F extends (cc: CryptoCore, ...args: infer A) => infer R ? (...args: A) => R : never;
export interface Mailbox {
  readonly cc: CryptoCore;
  epoch: typeof epoch; pollEpochs: typeof pollEpochs; pushEpochs: typeof pushEpochs;
  mailboxId: Bound<typeof mailboxId>; mailboxForSending: Bound<typeof mailboxForSending>; mailboxForReceiving: Bound<typeof mailboxForReceiving>;
  inviteSigningMessage: Bound<typeof inviteSigningMessage>; buildInvite: Bound<typeof buildInvite>; buildAck: Bound<typeof buildAck>; openBundle: Bound<typeof openBundle>;
  sendInvite: Bound<typeof sendInvite>; pollInvites: Bound<typeof pollInvites>; watchInvites: Bound<typeof watchInvites>;
  receivingLabels: Bound<typeof receivingLabels>; send: Bound<typeof send>; collect: Bound<typeof collect>; withdraw: Bound<typeof withdraw>; status: Bound<typeof status>;
  consumeInvite: typeof consumeInvite; onLiveInvite: typeof onLiveInvite;
}
export function createMailbox(options: { cryptoCore: CryptoCore }): Mailbox;
