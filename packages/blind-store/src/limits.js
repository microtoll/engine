/**
 * The limits: the frame cap, the per-field ciphertext caps, the link and
 * mailbox limits, the transport limits and the query limits. Numbers only;
 * the checks that apply them are in wire.js, objects.js and server.js.
 * Every field, nested ones included, is capped, and so is the socket
 * itself; the query-rows backstop is D-33's. Every number is a DoS
 * backstop, not a product rule: a cap that a real person can hit is a bug
 * report.
 */

/**
 * The largest frame the server accepts. Without it, `ws` applies its own
 * default of 100 MiB and the process parses whatever arrives. Sized as a
 * backstop against a process falling over -- roughly twice the largest
 * legitimate message (an identity blob at its cap, base64'd, plus envelope).
 *
 * FAILURE DIRECTION: closed. `ws` answers an oversize frame with close code
 * 1009 and drops that one connection; no other client notices. Refusing is
 * safe because no legitimate client can produce a frame this size, so a
 * false positive costs nobody anything.
 */
export const MAX_FRAME_BYTES = 4 * 1024 * 1024;

/**
 * Per-field byte ceilings for every variable-length ciphertext a client can
 * ask the server to store, keyed by the wire field name (the protocol's
 * names are kept as they are, D-27). Registering costs nothing -- identity is a locally
 * generated keypair -- so "an authenticated client" is not a barrier, and
 * every field is capped, nested ones included. Justified against the
 * largest thing the design says can be there:
 *
 *   encryptedIdentityBlob            contacts, favourites, per-object records:
 *                                    grows with a life's use. The most generous.
 *   encryptedEventData               the content, including the second-tier
 *                                    grants map (~100 bytes per grantee).
 *   encryptedEventDetail             the second tier. Small.
 *   encryptedParticipationDataBlob   a member row: a name, a status, flags.
 *   encryptedEventAccessBlob         a pointer: keys, flags, link records.
 *   encryptedPayload                 a share link's sealed bundle.
 *   encryptedBundle                  a mailbox drop's sealed bundle.
 *   encryptedSharedEventKey          a sealed 32-byte key: 127 bytes classical,
 *                                    1,182 in hybrid mode.
 *   wrappedRootKey                   a sealed 32-byte root key: 61 bytes.
 *   encryptedLabel                   a device's own name for a method, sealed.
 *   credentialId                     WebAuthn's own ceiling is 1,023 bytes.
 *   prfSalt, pbkdf2Salt              32 and 16 bytes in practice.
 *
 * FAILURE DIRECTION: closed, with the same reasoning as the frame cap. This
 * is deliberately NOT the fail-open rule that governs the rate counters,
 * where refusing would deny somebody a real action because a counter table
 * was down.
 */
export const BLOB_LIMITS = Object.freeze({
  encryptedIdentityBlob: 2 * 1024 * 1024,
  encryptedEventData: 512 * 1024,
  encryptedEventDetail: 256 * 1024,
  encryptedParticipationDataBlob: 64 * 1024,
  encryptedEventAccessBlob: 256 * 1024,
  encryptedPayload: 256 * 1024,
  encryptedBundle: 256 * 1024,
  encryptedSharedEventKey: 4 * 1024,
  wrappedRootKey: 1024,
  encryptedLabel: 4 * 1024,
  credentialId: 1023,
  prfSalt: 256,
  pbkdf2Salt: 256,
});

/**
 * The limits on a share link and a mailbox drop, held here as well as in
 * the client: a limit only the honest client keeps is a limit on the honest
 * client.
 *   URL_INVITE_MAX_USES  the largest group a link can be made for (the
 *                        schema's CHECK says the same number; change both)
 *   INVITE_MAX_DAYS      how far ahead a link or a drop may expire
 */
export const URL_INVITE_MAX_USES = 200;
export const INVITE_MAX_DAYS = 400;

/**
 * The query limits (DESIGN.md §2.2).
 *   maxSelectors  how many selectors one query or watch may name: the honest
 *                 client covers what it shows and never approaches this, so
 *                 it only ever rejects a hand-crafted message -- the list
 *                 goes straight into an ANY($1) query and, for a watch, is
 *                 held in memory for the connection's lifetime.
 *   maxQueryRows  a query whose answer would exceed this is refused with
 *                 'too-many' and the client narrows its selector. A server-side
 *                 backstop for a client that does not keep its own queries
 *                 small; fails closed for that one request.
 */
export const QUERY_DEFAULTS = Object.freeze({
  maxSelectors: 10000,
  maxQueryRows: 5000,
});

/**
 * TRANSPORT LIMITS (the appsec panel's figures, 2026-09-25). The socket is
 * reachable by anyone who can reach the host, and a guest login costs one
 * page load, so the socket itself is bounded. Each
 * limit fails CLOSED for the one connection that crosses it and changes
 * nothing for any other:
 *
 *   preAuthTimeoutMs   a socket that has not signed its nonce by then is
 *                      closed. Two minutes, not seconds: the unlock flow
 *                      holds its socket open across the lookup, a passkey
 *                      prompt and PBKDF2 before it signs.
 *   bucket             each socket's messages draw on an allowance that
 *                      tops up at `refillPerSec` to at most `capacity`; one
 *                      that empties it is closed (1008). A real client
 *                      paces its requests on round trips.
 *   maxSockets         the most connections open at once; past it a new one
 *                      is refused (503).
 *   maxLookupsPerSocket  lookup-unlock-method answers before sign-in with a
 *                      wrapped root key; every real flow asks once per
 *                      connection (D-20). Per visitor address the limit is
 *                      the reverse proxy's, on new connections: the address
 *                      never reaches this process.
 *
 * allowedOrigins has no default: a BROWSER naming a page elsewhere is
 * refused (403). No Origin at all is allowed -- a non-browser client can
 * claim any, so requiring one would buy nothing -- and the handshake is
 * then verified against each allowed origin in turn (auth.js).
 */
export const TRANSPORT_DEFAULTS = Object.freeze({
  preAuthTimeoutMs: 120 * 1000,
  bucket: Object.freeze({ capacity: 300, refillPerSec: 60 }),
  maxSockets: 2000,
  maxLookupsPerSocket: 3,
});

/** The daily counters (rateLimit.js): hygiene against a flood or a runaway retry loop, fail open. */
export const RATE_LIMIT_DEFAULTS = Object.freeze({
  'create-event': 20,
  'create-url-invite': 20,
  'send-invite': 50,
});
