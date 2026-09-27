// A server under test, with real sockets on localhost, and clients built
// from the real client packages: the identity package's handshake and
// account messages, the access package's object messages. What the fake
// servers of the identity and access suites promised, proved here against
// the real thing.
import pg from 'pg';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '@microtoll/identity';
import { createAccess, goingGrantDue, flag, oneOf, asIs } from '@microtoll/access';
import { createBlindStore } from '../../src/index.js';

export const NAMESPACE = 'testapp';
export const cc = createCryptoCore({ namespace: NAMESPACE });
export const ORIGIN = 'http://localhost:9';
export const utf8 = (s) => new TextEncoder().encode(s);
export const text = (b) => new TextDecoder().decode(b);
const quiet = { info() {}, error() {} };

/** Example collections: `events` with a 5-character selector and a window; `notes` with a 2-character selector and none. */
export const COLLECTIONS = {
  events: { selectorLength: 5, window: true, allowAll: true, imminentDays: 2 },
  notes: { selectorLength: 2 },
};

/**
 * startServer({ db, ...options }) -> { store, port, url, pool, close }
 * `db` from tooling/db.mjs (null runs the handshake alone, no pool).
 */
export async function startServer({ db = null, log = quiet, live = undefined, ...options } = {}) {
  const pool = db ? new pg.Pool({ ...db.appConfig, max: 5 }) : null;
  if (pool) pool.on('error', () => {});
  const store = createBlindStore({
    namespace: NAMESPACE, allowedOrigins: [ORIGIN], pool, port: 0, host: '127.0.0.1',
    collections: COLLECTIONS, log,
    live: live === undefined ? (db ? { connectionConfig: db.appConfig } : null) : live,
    sweep: false,
    ...options,
  });
  await new Promise((resolve) => store.httpServer.once('listening', resolve));
  const port = store.address().port;
  if (store.live) await store.liveStart;
  return {
    store, port, url: `ws://127.0.0.1:${port}`, pool,
    async close() { await store.close(); if (pool) await pool.end(); },
  };
}

/**
 * A raw socket, open, with `ws.challenge` resolving to the server's opening
 * challenge. Captured before the socket opens: a browser-style WebSocket
 * drops a message that arrives while nobody is listening, and the server
 * sends the challenge the moment the connection exists.
 */
export async function connect(server) {
  const ws = new WebSocket(server.url);
  ws.challenge = new Promise((resolve) => {
    ws.addEventListener('message', function on(e) {
      let m; try { m = JSON.parse(e.data); } catch { return; }
      if (m.type === 'challenge') { ws.removeEventListener('message', on); resolve(m); }
    });
  });
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve, { once: true });
    ws.addEventListener('error', () => reject(new Error('could not connect')), { once: true });
  });
  return ws;
}

/** Signs in on a socket whose challenge may already have arrived, with the real client code. */
export async function signIn(ws, identity, origin = ORIGIN) {
  const nonce = cc.fromBase64Url((await ws.challenge).nonce);
  return id.respondToChallenge(cc, ws, nonce, identity.routing, origin);
}

/** The next message of a type, raw off the wire. */
export function nextMessage(ws, type, { timeoutMs = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { ws.removeEventListener('message', onMessage); reject(new Error(`no ${type || 'message'} within ${timeoutMs} ms`)); }, timeoutMs);
    const onMessage = (e) => {
      let m;
      try { m = JSON.parse(e.data); } catch { return; }
      if (type && m.type !== type) return;
      clearTimeout(timer);
      ws.removeEventListener('message', onMessage);
      resolve(m);
    };
    ws.addEventListener('message', onMessage);
  });
}

export const closedWith = (ws, { timeoutMs = 5000 } = {}) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error('the socket did not close')), timeoutMs);
  ws.addEventListener('close', (e) => { clearTimeout(timer); resolve(e.code); }, { once: true });
});

/** An access instance with example app choices (the access suite's own). */
export function makeAccess(extra = {}) {
  return createAccess({
    cryptoCore: cc,
    pointerFields: {
      myStatus: { wire: 'myStatus', ...oneOf(['going', 'interested', 'not going']) },
      pushSubscribed: { wire: 'pushSubscribed', ...flag },
      shelf: { wire: 'shelf', ...asIs },
    },
    split: (content) => { const { address, ...preview } = content; return { preview: { ...preview, locationIsApproximate: true }, detail: { address } }; },
    merge: (preview, detail) => { if (!detail) return preview; const m = { ...preview, ...detail }; delete m.locationIsApproximate; return m; },
    grantDue: goingGrantDue,
    ...extra,
  });
}

/** An identity, signed in on a fresh socket; with an account (a recovery code) unless told otherwise. */
export async function person(server, { account = true, identity = null } = {}) {
  identity = identity || await id.createIdentity(cc);
  const ws = await connect(server);
  const ok = await id.authenticateConnection(cc, ws, identity.routing, ORIGIN);
  let method = null, code = null, identityBlobToken = null;
  if (account && !ok.hasAccount) {
    const wrapped = await id.wrapRootKeyWithNewRecoveryCode(cc, identity.rootKey);
    method = wrapped.method; code = wrapped.displayString;
    const blob = await id.sealIdentityBlob(cc, identity, id.buildIdentityBlobPlaintext(cc, identity, {}));
    ({ identityBlobToken } = await id.registerAccount(cc, ws, identity, blob, [method], { sealLabel: async () => new Uint8Array(0) }));
  }
  return { identity, ws, ok, method, code, identityBlobToken, close: () => ws.close() };
}

export const selector = (extra = {}) => ({ collection: 'events', selector: 'gcpvj', windowStart: '2026-10-01', windowEnd: '2026-10-01', ...extra });
export const daysAhead = (n) => new Date(Date.now() + n * 24 * 60 * 60 * 1000).toISOString();
