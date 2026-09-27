/**
 * @microtoll/blind-store — public entry point.
 *
 * The library (DESIGN.md §5.1): createBlindStore mounts the engine's
 * handlers on one WebSocket listener; a host registers its own beside them
 * with `handle`. The wire helpers a host's handlers share with the engine's
 * are exported as they are, and so are the limits, the collection parsers
 * and the capability checks.
 */
export { createBlindStore, createCore } from './server.js';
export {
  send, requestContext, fromB64u, toB64u, UUID_RE, DATE_RE,
  blobValue, blobField, hashField, hashSecret, expiryField,
  CLOSE_PROTOCOL_ERROR, CLOSE_AUTH_FAILED, IDENTITY_BLOB_TOKEN_BYTES,
} from './wire.js';
export {
  MAX_FRAME_BYTES, BLOB_LIMITS, URL_INVITE_MAX_USES, INVITE_MAX_DAYS,
  QUERY_DEFAULTS, TRANSPORT_DEFAULTS, RATE_LIMIT_DEFAULTS,
} from './limits.js';
export { NONCE_BYTES, generateNonce, authLabel, authMessage, verifyAuthSignature, verifyAgainstOrigins, importEd25519PublicKeyRaw, assertNamespace } from './auth.js';
export { createRateLimiter } from './rateLimit.js';
export { insertPointer, parsePointerField } from './pointers.js';
export { MAILBOX_ID_BYTES, parseMailboxIds } from './mailbox.js';
export {
  normaliseCollections, parseQueryMessage, OBJECT_COLUMNS, OBJECT_SELECT_ACTIVE, rowToObjectWire,
  verifyAdminCapability, verifyReadCapability, verifyRowCapabilityForObject, rosterIsMembersOnly,
} from './objects.js';
export { createLive, OBJECT_CHANNEL, MAILBOX_CHANNEL } from './live.js';
