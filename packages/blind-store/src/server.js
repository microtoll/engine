/**
 * The server: the WebSocket listener, the challenge-response handshake, the
 * pre-authentication allow-list, the dispatcher and its registry, the
 * request-id correlation, the transport limits, /healthz, the sweep timer
 * and the live hub -- with the engine's own handlers (account.js,
 * pointers.js, objects.js, links.js, mailbox.js) mounted like any host's:
 * a library first, with a thin reference server (D-23, D-34).
 *
 * Single-use nonce, replay protection is structural: each connection gets
 * one freshly random nonce and exactly one chance to sign it correctly -- a
 * wrong signature closes the connection immediately, no cache or retry path
 * to reason about. Once authenticated, one connection = one identity for
 * its whole lifetime. Proving key ownership never requires an account to
 * already exist: auth-ok always succeeds for a valid signature, and says
 * whether an account is there.
 *
 * Plain JSON with readable field names on the wire; every reply carries the
 * request id of the message it answers (wire.js `send`).
 */
import http from 'node:http';
import { WebSocketServer } from 'ws';
import { generateNonce, assertNamespace, verifyAgainstOrigins } from './auth.js';
import { send, fromB64u, requestContext, CLOSE_PROTOCOL_ERROR, CLOSE_AUTH_FAILED } from './wire.js';
import { MAX_FRAME_BYTES, BLOB_LIMITS, TRANSPORT_DEFAULTS, QUERY_DEFAULTS } from './limits.js';
import { createRateLimiter } from './rateLimit.js';
import * as account from './account.js';
import * as pointers from './pointers.js';
import * as links from './links.js';
import * as mailbox from './mailbox.js';
import * as objects from './objects.js';
import { createLive } from './live.js';

const SWEEP_INTERVAL_MS = 60 * 60 * 1000;
const ORIGIN_RE = /^https?:\/\/[^/\s]+$/;

/**
 * /healthz. The load balancer's question is not "is the process up" -- a
 * process with no database is up and useless -- so this runs a real
 * `SELECT 1` through the same pool every handler uses. It answers 200 or
 * 503 and NOTHING ELSE: no version, no uptime, no row counts. A health
 * endpoint is the one route that is deliberately unauthenticated, so it
 * must not become a place to learn anything.
 */
function createHttpHandler(pool, routes = {}) {
  return async (req, res) => {
    const path = String(req.url || '').split('?')[0];
    // The host's own plain-HTTP routes share this port, matched on the path
    // before anything else, for any method.
    if (Object.prototype.hasOwnProperty.call(routes, path)) { await routes[path](req, res); return; }
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { 'content-type': 'text/plain' });
      res.end('method not allowed');
      return;
    }
    if (path !== '/healthz') {
      // A browser pointed at the WebSocket port, usually. Answer, so it does not hang.
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
      return;
    }
    if (!pool) {
      res.writeHead(503, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      res.end('no database');
      return;
    }
    try {
      await pool.query('SELECT 1');
      res.writeHead(200, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      res.end('ok');
    } catch {
      // No detail: a health endpoint that reports why it is unhealthy tells
      // an unauthenticated caller about the inside of the system.
      res.writeHead(503, { 'content-type': 'text/plain', 'cache-control': 'no-store' });
      res.end('unhealthy');
    }
  };
}

function positiveIntegers(table, what) {
  for (const [k, v] of Object.entries(table)) {
    if (!Number.isInteger(v) || v < 1) throw new Error(`${what}.${k} must be a positive integer`);
  }
  return table;
}

/**
 * createBlindStore(options) -> { wss, handle, setFallback, close, limits, blobLimits, queryLimits, rateLimit, live, collections }
 *
 *   namespace        REQUIRED. The label prefix the handshake verifies ("<ns>/auth/v2"),
 *                    the same one the app gives createCryptoCore.
 *   allowedOrigins   REQUIRED. The web origins browsers may connect from; a browser
 *                    naming another is refused at upgrade (403). No Origin header is
 *                    allowed (a non-browser client), and the handshake is then verified
 *                    against each of these in turn.
 *   pool             the pg Pool, connected as blind_store_app. null runs the handshake
 *                    alone: every type that needs the database is refused as unknown.
 *   port             what the HTTP server, and so the WebSocket server, listens on.
 *                    Omit it to attach the listener yourself (`wss`, `httpServer`).
 *   host             the address to bind (default: every interface).
 *   collections      { name: { selectorLength, window, allowAll, imminentDays, queryExtras } }
 *   transport        overrides for TRANSPORT_DEFAULTS (limits.js).
 *   limits           overrides for the per-field ciphertext caps (BLOB_LIMITS).
 *   query            overrides for QUERY_DEFAULTS (maxSelectors, maxQueryRows).
 *   rateLimits       overrides for the daily counters (RATE_LIMIT_DEFAULTS).
 *   registration     the host's registration policy, or nothing:
 *                      columns           the extra `users` columns the host declared in
 *                                        its own init file and reads back;
 *                      onRegister(msg)   returns their values, or throws -- the message
 *                                        is refused as 'invalid' with the thrown message
 *                                        as `detail`;
 *                      authOkFields(row) the fields added to auth-ok from those columns;
 *                                        row is null when there is no account.
 *   live             { connectionConfig, extraChannels } to run the live watches;
 *                    without it the watches answer 'unsupported'. connectionConfig
 *                    is a pg connection config for the dedicated LISTEN client.
 *   sweep            false to leave blind_store_sweep() to the host; otherwise
 *                    { intervalMs } (default hourly), run at start too.
 *   httpRoutes       { '/path': async (req, res) => {} }, served beside /healthz.
 *   onAuthenticated  (routingPublicKeyBuffer, ws) after auth-ok.
 *   onSocketClose    (ws) when a connection closes: the host drops its own state.
 *   onDeleteAccount  (pool, routingPublicKey), inside delete-account once the users
 *                    row and its counters are gone: the host's clean-up of anything of
 *                    its own that names the key and does not cascade.
 *   log              { info, error }; default console. Counts and reasons only --
 *                    never a message body, never a routing key.
 *
 *   handle(type, handler, { auth, needsPool }) registers a message type.
 *     handler({ pool, ws, msg, state, routingPublicKey }) answers through
 *     `send`. auth is 'required' (after sign-in; the default), 'none'
 *     (before sign-in only) or 'any' (either, and checked before everything
 *     else: public reference data). needsPool (default true) means the type
 *     is refused as unknown when there is no pool. A type registered twice
 *     throws: the pre-authentication surface is widened on purpose, once, by name.
 *   setFallback(async (ctx) => boolean) is consulted after sign-in for a
 *     type no handler claims, before the unknown-type refusal.
 *   close() terminates every client, closes the listener, the LISTEN client
 *     and the timers; returns a promise (and calls a callback if given).
 */
export function createBlindStore({
  namespace, allowedOrigins, pool = null, port = undefined, host = undefined, collections = {},
  transport = {}, limits: blobLimitOverrides = {}, query = {}, rateLimits = {},
  registration = null, live = null, sweep = undefined, httpRoutes = {},
  onAuthenticated = null, onSocketClose = null, onDeleteAccount = null, log = console,
} = {}) {
  assertNamespace(namespace);
  if (!Array.isArray(allowedOrigins) || allowedOrigins.length === 0 || !allowedOrigins.every((o) => typeof o === 'string' && ORIGIN_RE.test(o))) {
    throw new Error('allowedOrigins is required: a non-empty list of web origins such as "https://app.example"');
  }
  const policy = { columns: [], onRegister: () => ({}), authOkFields: () => ({}), ...(registration || {}) };
  for (const column of policy.columns) {
    if (!/^[a-z_][a-z0-9_]*$/.test(column)) throw new Error(`registration.columns: ${column} is not a plain column name`);
  }
  const blobLimits = Object.freeze(positiveIntegers({ ...BLOB_LIMITS, ...blobLimitOverrides }, 'limits'));
  const queryLimits = Object.freeze(positiveIntegers({ ...QUERY_DEFAULTS, ...query }, 'query'));
  const limits = Object.freeze({ ...TRANSPORT_DEFAULTS, ...transport, allowedOrigins: Object.freeze([...allowedOrigins]) });
  const allowed = new Set(limits.allowedOrigins);
  const rateLimit = createRateLimiter({ limits: rateLimits, log });
  const config = objects.normaliseCollections(collections);
  const liveHub = live ? createLive({ pool, collections: config, connectionConfig: live.connectionConfig || null, extraChannels: live.extraChannels || {}, log }) : null;
  const deps = { config, limits: blobLimits, queryLimits, rateLimit, live: liveHub, policy, onDeleteAccount };

  // The registry: one map per authentication requirement, and one optional
  // fallback. A message type lives in exactly one map, so the order handlers
  // were registered in can never decide which one answers.
  const registry = { any: new Map(), none: new Map(), required: new Map() };
  let fallback = null;
  function handle(type, handler, { auth = 'required', needsPool = true } = {}) {
    if (typeof type !== 'string' || !type) throw new Error('handle: a message type is required');
    if (typeof handler !== 'function') throw new Error(`handle: ${type} needs a handler function`);
    if (!registry[auth]) throw new Error(`handle: ${type}: auth must be 'required', 'none' or 'any'`);
    for (const map of Object.values(registry)) if (map.has(type)) throw new Error(`handle: ${type} is already registered`);
    registry[auth].set(type, { handler, needsPool: needsPool !== false });
  }
  function setFallback(fn) {
    if (typeof fn !== 'function') throw new Error('setFallback needs a function');
    if (fallback) throw new Error('setFallback: a fallback is already set');
    fallback = fn;
  }
  // A registered handler that may answer now: the type is known, and either
  // it needs no pool or there is one. Without a pool the type falls through
  // exactly as an unknown one does.
  const claimed = (map, type) => {
    const entry = type === null ? undefined : map.get(type);
    return entry && (!entry.needsPool || pool) ? entry : null;
  };

  // ------------------------------------------------------------------
  // The engine's own handlers, registered like any host's.
  // ------------------------------------------------------------------
  handle('lookup-unlock-method', async (c) => {
    // A few per connection (D-20): every real sign-in asks once, and the
    // answer is a wrapped root key.
    if (++c.state.lookups > limits.maxLookupsPerSocket) {
      send(c.ws, { type: 'lookup-unlock-method-failed', reason: 'rate-limited' });
      return;
    }
    await account.handleLookupUnlockMethod(c.pool, c.ws, c.msg, blobLimits);
  }, { auth: 'none' });
  handle('register', (c) => account.handleRegister(c.pool, c.ws, c.routingPublicKey, c.msg, c.state, policy, blobLimits));
  handle('update-identity-blob', (c) => account.handleUpdateIdentityBlob(c.pool, c.ws, c.routingPublicKey, c.msg, blobLimits));
  handle('add-unlock-method', (c) => account.handleAddUnlockMethod(c.pool, c.ws, c.routingPublicKey, c.msg, c.state, blobLimits));
  handle('list-unlock-methods', (c) => account.handleListUnlockMethods(c.pool, c.ws, c.routingPublicKey));
  handle('remove-unlock-method', (c) => account.handleRemoveUnlockMethod(c.pool, c.ws, c.routingPublicKey, c.msg, c.state));
  handle('rotate-recovery-code', (c) => account.handleRotateRecoveryCode(c.pool, c.ws, c.routingPublicKey, c.msg, c.state, blobLimits));
  handle('bump-session-generation', (c) => account.handleBumpSessionGeneration(c.pool, c.ws, c.routingPublicKey, c.state));
  handle('delete-account', (c) => account.handleDeleteAccount(c.pool, c.ws, c.routingPublicKey, deps));
  handle('fetch-pointers', (c) => pointers.handleFetchPointers(c.pool, c.ws, c.routingPublicKey));
  handle('update-pointer', (c) => pointers.handleUpdatePointer(c.pool, c.ws, c.routingPublicKey, c.msg, blobLimits));
  handle('delete-pointer', (c) => pointers.handleDeletePointer(c.pool, c.ws, c.routingPublicKey, c.msg));
  // Objects and members (the protocol's message names, D-27).
  handle('create-event', (c) => objects.handleCreate(c.pool, c.ws, c.routingPublicKey, c.msg, c.state, deps));
  handle('query-events', (c) => objects.handleQuery(c.pool, c.ws, c.msg, deps));
  handle('fetch-event', (c) => objects.handleFetch(c.pool, c.ws, c.msg));
  handle('join-event', (c) => objects.handleJoin(c.pool, c.ws, c.routingPublicKey, c.msg, c.state, deps));
  handle('fetch-event-members', (c) => objects.handleFetchMembers(c.pool, c.ws, c.msg));
  handle('rotate-event-key', (c) => objects.handleRotate(c.pool, c.ws, c.msg, deps));
  handle('fetch-my-participation', (c) => objects.handleFetchMyRow(c.pool, c.ws, c.msg));
  handle('create-participation', (c) => objects.handleCreateMemberRow(c.pool, c.ws, c.routingPublicKey, c.msg, c.state, deps));
  handle('update-participation', (c) => objects.handleUpdateMemberRow(c.pool, c.ws, c.msg, deps));
  handle('update-event', (c) => objects.handleUpdate(c.pool, c.ws, c.msg, deps));
  handle('delete-event', (c) => objects.handleDelete(c.pool, c.ws, c.msg));
  handle('delete-participation', (c) => objects.handleDeleteMemberRow(c.pool, c.ws, c.msg));
  handle('watch-events', (c) => objects.handleWatch(liveHub, c.ws, c.msg, deps), { needsPool: false });
  handle('watch-imminent', (c) => objects.handleWatchImminent(liveHub, c.ws), { needsPool: false });
  handle('unwatch-events', (c) => objects.handleUnwatch(liveHub, c.ws), { needsPool: false });
  // Share links.
  handle('create-url-invite', (c) => links.handleCreateUrlInvite(c.pool, c.ws, c.routingPublicKey, c.msg, deps));
  handle('redeem-url-invite', (c) => links.handleRedeemUrlInvite(c.pool, c.ws, c.msg));
  handle('revoke-url-invite', (c) => links.handleRevokeUrlInvite(c.pool, c.ws, c.msg));
  handle('fetch-invite-token-stats', (c) => links.handleFetchInviteTokenStats(c.pool, c.ws, c.msg));
  // The mailbox's server half.
  handle('send-invite', (c) => mailbox.handleSendInvite(c.pool, c.ws, c.routingPublicKey, c.msg, deps));
  handle('poll-invites', (c) => mailbox.handlePollInvites(c.pool, c.ws, c.msg));
  handle('consume-invite', (c) => mailbox.handleConsumeInvite(c.pool, c.ws, c.msg));
  handle('watch-invites', (c) => mailbox.handleWatchInvites(liveHub, c.ws, c.msg), { needsPool: false });
  // The heartbeat: answered so a half-open socket is noticed, and carrying nothing back.
  handle('ping', (c) => { send(c.ws, { type: 'pong' }); }, { needsPool: false });

  // ------------------------------------------------------------------
  // The listener. An explicit HTTP server, so /healthz can share the
  // WebSocket port. maxPayload, or `ws` uses its 100 MiB default and this
  // process parses whatever arrives: an oversize frame gets close code 1009
  // and takes only its own connection with it.
  // ------------------------------------------------------------------
  const httpServer = http.createServer(createHttpHandler(pool, httpRoutes));
  const wss = new WebSocketServer({
    server: httpServer,
    maxPayload: MAX_FRAME_BYTES,
    // Checked before the upgrade completes, so a refused connection never
    // becomes a socket at all.
    verifyClient: (info, done) => {
      if (wss.clients.size >= limits.maxSockets) { done(false, 503, 'too many connections'); return; }
      const origin = info.origin;
      if (origin && !allowed.has(origin)) { done(false, 403, 'origin not allowed'); return; }
      done(true);
    },
  });
  if (port !== undefined) httpServer.listen(port, host);

  // Socket errors must not be thrown. Node's EventEmitter RETHROWS an 'error'
  // event that has no listener, and `ws` emits 'error' on any protocol
  // violation -- an invalid opcode, an unmasked client frame, a payload that
  // is not valid UTF-8, a frame past maxPayload. Without these two listeners
  // a single malformed frame from an unauthenticated sender takes the
  // whole process down. FAILURE DIRECTION: closed for that ONE socket, open
  // for everybody else. Logged without the message body -- a malformed frame
  // is attacker-controlled bytes and has no place in a log kept thin.
  wss.on('error', (err) => log.error(`websocket server error: ${err.code || err.message}`));

  wss.on('connection', (ws, req) => {
    ws.on('error', (err) => log.error(`websocket connection error: ${err.code || err.message}`));
    const nonce = generateNonce();
    // The browser's Origin, already allow-listed above; a non-browser client
    // sends none and is verified against each allowed origin (auth.js).
    const originHeader = typeof req.headers.origin === 'string' && allowed.has(req.headers.origin) ? req.headers.origin : null;
    // `ready` resolves once auth-ok has been sent, with hasAccount set: a
    // frame that arrives while the account lookup is in flight waits for it,
    // rather than being handled as if there were no account.
    let markReady;
    const state = {
      authenticated: false, routingPublicKey: null, hasAccount: false, origin: null,
      ready: new Promise((resolve) => { markReady = resolve; }), isReady: false,
      lookups: 0,
    };
    state.markReady = () => { state.isReady = true; markReady(); };

    // Sign in within the limit, or the socket is closed. Cleared the moment
    // the nonce is signed, and with the socket.
    const preAuthTimer = setTimeout(() => {
      if (!state.authenticated) { try { ws.close(CLOSE_AUTH_FAILED, 'sign-in took too long'); } catch { /* already gone */ } }
    }, limits.preAuthTimeoutMs);
    if (typeof preAuthTimer.unref === 'function') preAuthTimer.unref();
    ws.on('close', () => {
      clearTimeout(preAuthTimer);
      state.markReady();
      // A watch outlives nothing: the registries hold the socket itself as
      // their key, so a dropped connection that is never unregistered would
      // keep the socket object alive for the process's lifetime.
      if (liveHub) liveHub.removeWatcher(ws);
      if (typeof onSocketClose === 'function') onSocketClose(ws);
    });

    // The message allowance: a token bucket, topped up by elapsed time.
    let tokens = limits.bucket.capacity;
    let toppedUpAt = Date.now();
    const drawToken = () => {
      const now = Date.now();
      tokens = Math.min(limits.bucket.capacity, tokens + ((now - toppedUpAt) / 1000) * limits.bucket.refillPerSec);
      toppedUpAt = now;
      if (tokens < 1) return false;
      tokens -= 1;
      return true;
    };

    send(ws, { type: 'challenge', nonce: nonce.toString('base64url') });

    const context = (msg) => ({ pool, ws, msg, state, routingPublicKey: state.routingPublicKey });
    const dispatchMessage = async (text) => {
      let msg = null;
      let parsed = false;
      try { msg = JSON.parse(text); parsed = true; } catch { msg = null; }
      // A type is a string on an object, or nothing: the JSON text `null`,
      // a number or a string has no type, and neither has a broken frame.
      const type = parsed && msg && typeof msg === 'object' && typeof msg.type === 'string' ? msg.type : null;

      // Answered whatever the state, auth or no auth: public reference data only.
      const any = claimed(registry.any, type);
      if (any) { await any.handler(context(msg)); return; }

      if (!state.authenticated) {
        if (!parsed) {
          ws.close(CLOSE_PROTOCOL_ERROR, 'malformed JSON');
          return;
        }
        // Allowed before authentication: lookup-unlock-method, and whatever
        // the host registered with auth 'none'. None of these consume the
        // nonce or touch state.authenticated.
        const pre = claimed(registry.none, type);
        if (pre) { await pre.handler(context(msg)); return; }

        // Anything else before sign-in must be the auth message. That
        // includes valid JSON that is not an object: it closes this one
        // socket, and nobody else notices.
        if (type !== 'auth' || typeof msg.routingPublicKey !== 'string' || typeof msg.signature !== 'string') {
          ws.close(CLOSE_PROTOCOL_ERROR, 'expected an auth message');
          return;
        }

        let candidateKey, matchedOrigin = null;
        try {
          candidateKey = fromB64u(msg.routingPublicKey);
          const signature = fromB64u(msg.signature);
          matchedOrigin = verifyAgainstOrigins(namespace, candidateKey, originHeader ? [originHeader] : limits.allowedOrigins, nonce, signature);
        } catch {
          matchedOrigin = null; // malformed key or signature bytes -- exactly like a failed verification
        }
        if (!matchedOrigin) {
          send(ws, { type: 'auth-failed' });
          ws.close(CLOSE_AUTH_FAILED, 'authentication failed');
          return;
        }

        state.authenticated = true;
        state.routingPublicKey = candidateKey;
        state.origin = matchedOrigin;

        let found = { hasAccount: false, encryptedIdentityBlob: null, sessionGeneration: null, identityBlobToken: null, extra: null };
        if (pool) {
          try {
            found = await account.findUser(pool, candidateKey, policy.columns);
            state.hasAccount = found.hasAccount;
          } catch {
            // A lookup failure must not strand the connection: fail closed on
            // the account question, not on the connection.
            state.hasAccount = false;
          }
        }
        // The host's fields sit between the blob and the session generation
        // (for example a terms version), where its client expects them.
        send(ws, {
          type: 'auth-ok',
          hasAccount: state.hasAccount,
          encryptedIdentityBlob: found.encryptedIdentityBlob,
          ...policy.authOkFields(found.hasAccount ? found.extra : null),
          sessionGeneration: found.sessionGeneration,
          identityBlobToken: found.identityBlobToken,
        });
        state.markReady();
        if (typeof onAuthenticated === 'function') onAuthenticated(candidateKey, ws);
        return;
      }

      // Authenticated. A replayed 'auth' message is not registered anywhere,
      // so it is refused as an unknown type: post-auth, this connection has
      // one identity for its whole lifetime.
      const post = claimed(registry.required, type);
      if (post) { await post.handler(context(msg)); return; }
      if (type !== null && fallback && await fallback(context(msg))) return;
      // Anything else is refused by name and NEVER reflected: echoing an
      // unknown message hands its bytes straight back to the sender.
      send(ws, { type: 'error', reason: 'unknown-type' });
    };

    ws.on('message', async (raw) => {
      if (!drawToken()) {
        // Out of allowance: this connection is done; nobody else notices.
        try { ws.close(CLOSE_AUTH_FAILED, 'too many messages'); } catch { /* already gone */ }
        return;
      }
      // Signed in, but the account lookup has not answered yet: wait for it.
      if (state.authenticated && !state.isReady) await state.ready;
      const text = raw.toString();
      let peeked = null;
      try { peeked = JSON.parse(text); } catch { peeked = null; }
      // A string, and short: it comes straight back out on the wire, and the
      // client compares it to its own. Anything else is treated as absent.
      const requestId = peeked && typeof peeked === 'object' && typeof peeked.requestId === 'string'
        && peeked.requestId.length > 0 && peeked.requestId.length <= 64
        ? peeked.requestId : null;
      await requestContext.run({ ws, requestId }, async () => {
        try {
          await dispatchMessage(text);
        } catch (e) {
          // A handler that threw past its own catch: the connection stays,
          // the request is refused (inside the request's context, so the
          // refusal carries its id), and the log carries the reason and
          // never the message.
          log.error(`handler failed (${e.code || e.message})`);
          try { send(ws, { type: 'error', reason: 'server-error' }); } catch { /* gone */ }
        }
      });
    });
  });

  // ------------------------------------------------------------------
  // The sweep (D-35): at start and hourly, a count only in the log.
  // ------------------------------------------------------------------
  let sweepTimer = null;
  const runSweep = () => pool.query('SELECT blind_store_sweep() AS n')
    .then((r) => { if (r.rows[0].n > 0) log.info(`sweep: tidied ${r.rows[0].n} link, drop or counter row(s) past their date`); })
    .catch((e) => log.error(`sweep failed (${e.code || e.message})`));
  if (pool && sweep !== false) {
    const intervalMs = (sweep && Number.isInteger(sweep.intervalMs) && sweep.intervalMs > 0) ? sweep.intervalMs : SWEEP_INTERVAL_MS;
    runSweep();
    sweepTimer = setInterval(runSweep, intervalMs);
    if (typeof sweepTimer.unref === 'function') sweepTimer.unref();
  }

  // The live hub's LISTEN connection: after the server is accepting
  // connections and non-fatal on failure -- a database that will not take a
  // LISTEN connection should cost live updates, not the whole service. It
  // says so loudly (live.js) and keeps retrying.
  let liveStart = Promise.resolve();
  if (liveHub) liveStart = liveHub.start().catch((e) => log.error(`live: could not subscribe (${e.code || e.message}); live updates are OFF, retrying`));

  let closed = null;
  function close(cb) {
    if (!closed) {
      closed = (async () => {
        if (sweepTimer) clearInterval(sweepTimer);
        if (liveHub) await liveHub.stop();
        for (const client of wss.clients) client.terminate();
        await new Promise((resolve) => wss.close(() => httpServer.close(() => resolve())));
      })();
    }
    if (typeof cb === 'function') closed.then(() => cb(), (e) => cb(e));
    return closed;
  }

  return {
    wss, httpServer, handle, setFallback, close,
    limits, blobLimits, queryLimits, rateLimit, live: liveHub, liveStart, collections: config, namespace,
    runSweep: pool ? runSweep : null,
    address: () => httpServer.address(),
  };
}

/** Another name for createBlindStore (D-36), for a host whose code already calls createCore: moving to it is an import change plus the required options. */
export const createCore = createBlindStore;
