/**
 * The wire helpers: `send` with the request-id correlation, the base64url
 * codecs, the field parsers that enforce the size caps, the capability-hash
 * digest and the expiry parser. Shared by the engine's handlers and a
 * host's alike.
 */
import { AsyncLocalStorage } from 'node:async_hooks';
import { createHash } from 'node:crypto';
import { BLOB_LIMITS, INVITE_MAX_DAYS } from './limits.js';

export const CLOSE_PROTOCOL_ERROR = 1002;
export const CLOSE_AUTH_FAILED = 1008;

// Length of users.identity_blob_token. Mirrored in the identity package's
// registerAccount and updateIdentityBlob (16 random bytes) and in the CHECK
// constraint in the schema -- all three change together.
export const IDENTITY_BLOB_TOKEN_BYTES = 16;

/**
 * WHICH REQUEST AN ANSWER BELONGS TO.
 *
 * Every request carries a `requestId`, and every reply to it carries the
 * same one; the client resolves only its own answer. Without it two requests
 * of one kind in flight take each other's answers.
 *
 * AsyncLocalStorage rather than a parameter, because `send` is called from
 * handlers several frames deep and several awaits in; the store is entered
 * once, at the dispatcher, and read once, here.
 *
 * TWO GUARDS, both load-bearing:
 *  - `ctx.ws === ws`: a handler may write to a DIFFERENT socket inside its
 *    own async tree, and that message is not an answer to this request.
 *  - `ctx.requestId`: absent when the client did not ask for correlation.
 * The live-update broadcasts do not pass through here at all (live.js owns
 * its own send), so no unsolicited message ever carries a request id.
 */
export const requestContext = new AsyncLocalStorage();

export function send(ws, obj) {
  const ctx = requestContext.getStore();
  ws.send(JSON.stringify(ctx && ctx.ws === ws && ctx.requestId ? { ...obj, requestId: ctx.requestId } : obj));
}

export function fromB64u(str) {
  return Buffer.from(str, 'base64url');
}

export function toB64u(buf) {
  return Buffer.from(buf).toString('base64url');
}

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * Decodes a base64url ciphertext value and enforces the ceiling registered
 * for `limitKey`. For a field that sits inside another message; blobField
 * below is the same for a top-level one. `name` is what an error says.
 *
 * The length is checked on the DECODED bytes, not the string: base64url is
 * 4/3 the size of what it carries, and a limit expressed in the wrong unit
 * is a limit somebody will quietly get wrong later. `required: false` is for
 * the fields that are legitimately absent (an object with no second tier,
 * a method with no label).
 */
export function blobValue(value, limitKey, name = limitKey, { required = true, limits = BLOB_LIMITS } = {}) {
  if (value === undefined || value === null) {
    if (required) throw new Error(`missing ${name}`);
    return null;
  }
  if (typeof value !== 'string') throw new Error(`missing ${name}`);
  const max = limits[limitKey];
  if (max === undefined) throw new Error(`no size limit registered for ${limitKey}`);
  const bytes = fromB64u(value);
  if (bytes.length > max) throw new Error(`${name} is too large (${bytes.length} bytes, limit ${max})`);
  return bytes;
}

export function blobField(msg, key, { required = true, limits = BLOB_LIMITS } = {}) {
  return blobValue(msg[key], key, key, { required, limits });
}

/**
 * A capability hash, or any other SHA-256 off the wire: exactly 32 bytes.
 * Checked here and by the tables' own CHECK constraints, so a hash of any
 * other length can neither be stored nor matched against.
 */
export function hashField(value, name, { required = true } = {}) {
  if (value === undefined || value === null) {
    if (required) throw new Error(`missing ${name}`);
    return null;
  }
  if (typeof value !== 'string') throw new Error(`missing ${name}`);
  const bytes = fromB64u(value);
  if (bytes.length !== 32) throw new Error(`${name} must be 32 bytes`);
  return bytes;
}

/**
 * SHA-256 of raw secret bytes, as a Buffer -- matches the BYTEA columns and
 * the client's hashCapability (the same digest, hex-encoded there).
 */
export function hashSecret(secretBytes) {
  return createHash('sha256').update(secretBytes).digest();
}

/** An expiry off the wire: required, a real instant, in the future, and within INVITE_MAX_DAYS. */
export function expiryField(value, name, { maxDays = INVITE_MAX_DAYS, now = Date.now() } = {}) {
  if (typeof value !== 'string') throw new Error(`missing ${name}`);
  const t = Date.parse(value);
  if (Number.isNaN(t)) throw new Error(`malformed ${name}`);
  if (t <= now) throw new Error(`${name} is already past`);
  if (t > now + maxDays * 24 * 60 * 60 * 1000) throw new Error(`${name} is more than ${maxDays} days away`);
  return new Date(t).toISOString();
}
