// The listener alone, no database (pool: null): the handshake over a real
// socket, the pre-authentication surface, the registry, malformed and
// oversize frames, the token bucket, the pre-authentication timeout, the
// origin and socket-count refusals, request-id correlation, /healthz.
// Every limit fails closed for the one connection that crosses it and
// changes nothing for any other.
import test from 'node:test';
import assert from 'node:assert/strict';
import WsClient from 'ws';
import * as id from '@microtoll/identity';
import { createBlindStore, send, MAX_FRAME_BYTES } from '../src/index.js';
import { startServer, connect, signIn, nextMessage, closedWith, cc, ORIGIN, NAMESPACE } from './tooling/harness.mjs';

const identityFor = () => id.createIdentity(cc);

test('the handshake: a challenge on connect, auth-ok for a valid signature, hasAccount false without a database', async () => {
  const s = await startServer();
  try {
    const me = await identityFor();
    const ws = await connect(s);
    const ok = await id.authenticateConnection(cc, ws, me.routing, ORIGIN);
    assert.equal(ok.hasAccount, false);
    assert.equal(ok.encryptedIdentityBlob, null);
    assert.equal(ok.sessionGeneration, null);
    ws.close();
  } finally { await s.close(); }
});

test('a wrong key, a wrong origin and a bare-nonce (version 1) signature are all refused: auth-failed, then 1008', async () => {
  const s = await startServer();
  try {
    const attempts = [
      async (ws, nonce) => { const other = await identityFor(); const me = await identityFor(); return { key: me.routing.publicKeyRaw, sig: await cc.signBytes(other.routing.privateKey, await id.authMessage(cc, ORIGIN, nonce)) }; },
      async (ws, nonce) => { const me = await identityFor(); return { key: me.routing.publicKeyRaw, sig: await cc.signBytes(me.routing.privateKey, await id.authMessage(cc, 'https://evil.example', nonce)) }; },
      async (ws, nonce) => { const me = await identityFor(); return { key: me.routing.publicKeyRaw, sig: await cc.signBytes(me.routing.privateKey, nonce) }; },
    ];
    for (const make of attempts) {
      const ws = await connect(s);
      const nonce = cc.fromBase64Url((await ws.challenge).nonce);
      const { key, sig } = await make(ws, nonce);
      const failed = nextMessage(ws, 'auth-failed');
      const code = closedWith(ws);
      ws.send(JSON.stringify({ type: 'auth', routingPublicKey: cc.toBase64Url(key), signature: cc.toBase64Url(sig) }));
      assert.equal((await failed).type, 'auth-failed');
      assert.equal(await code, 1008);
    }
  } finally { await s.close(); }
});

test('before sign-in: malformed JSON, the JSON text null, and any non-auth type close that socket (1002) and the next connection is served', async () => {
  const s = await startServer();
  try {
    for (const frame of ['{not json', 'null', '42', '"auth"', JSON.stringify({ type: 'fetch-pointers' }), JSON.stringify({ type: 'auth' })]) {
      const ws = await connect(s);
      await ws.challenge;
      const code = closedWith(ws);
      ws.send(frame);
      assert.equal(await code, 1002, `frame ${frame}`);
    }
    const ws = await connect(s);
    assert.equal((await ws.challenge).type, 'challenge');
    ws.close();
  } finally { await s.close(); }
});

test('after sign-in: an unknown type is refused by name and never reflected; a second auth is unknown; ping gets a pong; a bad frame is refused, not fatal', async () => {
  const s = await startServer();
  try {
    const me = await identityFor();
    const ws = await connect(s);
    await id.authenticateConnection(cc, ws, me.routing, ORIGIN);
    const secret = 'do-not-echo-' + Math.random();
    let reply = nextMessage(ws, 'error');
    ws.send(JSON.stringify({ type: 'nonsense', secret }));
    let m = await reply;
    assert.equal(m.reason, 'unknown-type');
    assert.equal(JSON.stringify(m).includes(secret), false, 'reflected');
    reply = nextMessage(ws, 'error');
    ws.send(JSON.stringify({ type: 'auth', routingPublicKey: 'x', signature: 'y' }));
    assert.equal((await reply).reason, 'unknown-type');
    reply = nextMessage(ws, 'pong');
    ws.send(JSON.stringify({ type: 'ping' }));
    assert.equal((await reply).type, 'pong');
    reply = nextMessage(ws, 'error');
    ws.send('{broken');
    assert.equal((await reply).reason, 'unknown-type');
    // A type that needs the database, with none: refused as unknown, as documented.
    reply = nextMessage(ws, 'error');
    ws.send(JSON.stringify({ type: 'fetch-pointers' }));
    assert.equal((await reply).reason, 'unknown-type');
    ws.close();
  } finally { await s.close(); }
});

test('the request id: echoed on the answer when the request carried one (1-64 characters), absent otherwise, and only to the asker', async () => {
  const s = await startServer();
  try {
    const me = await identityFor();
    const ws = await connect(s);
    await id.authenticateConnection(cc, ws, me.routing, ORIGIN);
    const ask = async (extra) => { const p = nextMessage(ws, 'pong'); ws.send(JSON.stringify({ type: 'ping', ...extra })); return p; };
    assert.equal((await ask({ requestId: 'r1' })).requestId, 'r1');
    assert.equal('requestId' in (await ask({})), false);
    assert.equal('requestId' in (await ask({ requestId: '' })), false);
    assert.equal('requestId' in (await ask({ requestId: 'x'.repeat(65) })), false);
    assert.equal('requestId' in (await ask({ requestId: 7 })), false);
    // Ten at once, each answered with its own id.
    const ids = Array.from({ length: 10 }, (_, i) => `q${i}`);
    const answers = new Set();
    const done = new Promise((resolve) => {
      ws.addEventListener('message', function on(e) { const m = JSON.parse(e.data); if (m.type === 'pong' && m.requestId) { answers.add(m.requestId); if (answers.size === 10) { ws.removeEventListener('message', on); resolve(); } } });
    });
    for (const r of ids) ws.send(JSON.stringify({ type: 'ping', requestId: r }));
    await done;
    assert.deepEqual([...answers].sort(), ids.sort());
    ws.close();
  } finally { await s.close(); }
});

test('the registry: any-handlers answer before sign-in; none-handlers only before; duplicates, the engine\'s own types and bad modes are refused; a throwing handler costs one request, not the connection', async () => {
  const s = await startServer();
  try {
    s.store.handle('hello', (c) => { send(c.ws, { type: 'hello-ok', signedIn: c.state.authenticated }); }, { auth: 'any', needsPool: false });
    s.store.handle('pre-only', (c) => { send(c.ws, { type: 'pre-only-ok' }); }, { auth: 'none', needsPool: false });
    s.store.handle('boom', () => { throw new Error('handler bug'); }, { needsPool: false });
    assert.throws(() => s.store.handle('hello', () => {}), /already registered/);
    assert.throws(() => s.store.handle('register', () => {}), /already registered/);
    assert.throws(() => s.store.handle('other', () => {}, { auth: 'sometimes' }), /auth must be/);
    assert.throws(() => s.store.handle('', () => {}), /type is required/);
    s.store.setFallback(async (c) => { if (c.msg.type !== 'fallback-me') return false; send(c.ws, { type: 'fallback-ok' }); return true; });
    assert.throws(() => s.store.setFallback(async () => false), /already set/);

    const ws = await connect(s);
    await ws.challenge;
    let reply = nextMessage(ws, 'hello-ok');
    ws.send(JSON.stringify({ type: 'hello' }));
    assert.equal((await reply).signedIn, false);
    reply = nextMessage(ws, 'pre-only-ok');
    ws.send(JSON.stringify({ type: 'pre-only' }));
    assert.equal((await reply).type, 'pre-only-ok');
    const me = await identityFor();
    await signIn(ws, me);
    reply = nextMessage(ws, 'hello-ok');
    ws.send(JSON.stringify({ type: 'hello' }));
    assert.equal((await reply).signedIn, true);
    reply = nextMessage(ws, 'error');
    ws.send(JSON.stringify({ type: 'pre-only' }));
    assert.equal((await reply).reason, 'unknown-type', 'a none-handler after sign-in');
    reply = nextMessage(ws, 'fallback-ok');
    ws.send(JSON.stringify({ type: 'fallback-me' }));
    assert.equal((await reply).type, 'fallback-ok');
    reply = nextMessage(ws, 'error');
    ws.send(JSON.stringify({ type: 'boom', requestId: 'b' }));
    const err = await reply;
    assert.equal(err.reason, 'server-error');
    assert.equal(err.requestId, 'b');
    reply = nextMessage(ws, 'pong');
    ws.send(JSON.stringify({ type: 'ping' }));
    assert.equal((await reply).type, 'pong', 'the connection survived the throwing handler');
    ws.close();
  } finally { await s.close(); }
});

test('the token bucket: a socket that empties its allowance is closed (1008); another socket is unaffected', async () => {
  const s = await startServer({ transport: { bucket: { capacity: 5, refillPerSec: 0 } } });
  try {
    const me = await identityFor();
    const you = await identityFor();
    const ws = await connect(s);
    const other = await connect(s);
    const code = closedWith(ws);
    await signIn(ws, me); // one message
    for (let i = 0; i < 5; i++) ws.send(JSON.stringify({ type: 'ping' }));
    assert.equal(await code, 1008);
    await signIn(other, you);
    const pong = nextMessage(other, 'pong');
    other.send(JSON.stringify({ type: 'ping' }));
    assert.equal((await pong).type, 'pong');
    other.close();
  } finally { await s.close(); }
});

test('the pre-authentication timeout closes a socket that never signs in (1008), and spares one that did', async () => {
  const s = await startServer({ transport: { preAuthTimeoutMs: 1000 } });
  try {
    const me = await identityFor();
    const idle = await connect(s);
    const quick = await connect(s);
    const code = closedWith(idle, { timeoutMs: 4000 });
    await signIn(quick, me);
    assert.equal(await code, 1008);
    const pong = nextMessage(quick, 'pong');
    quick.send(JSON.stringify({ type: 'ping' }));
    assert.equal((await pong).type, 'pong');
    quick.close();
  } finally { await s.close(); }
});

test('an oversize frame is refused by maxPayload (1009), and the server is still there', async () => {
  const s = await startServer();
  try {
    const ws = await connect(s);
    await ws.challenge;
    const code = closedWith(ws, { timeoutMs: 20000 });
    ws.send('x'.repeat(MAX_FRAME_BYTES + 1));
    assert.equal(await code, 1009);
    const again = await connect(s);
    assert.equal((await again.challenge).type, 'challenge');
    again.close();
  } finally { await s.close(); }
});

test('the origin allow-list: a browser Origin elsewhere is refused at upgrade (403); an allowed one and none at all connect', async () => {
  const s = await startServer();
  try {
    const attempt = (headers) => new Promise((resolve) => {
      const c = new WsClient(s.url, { headers });
      c.on('unexpected-response', (req, res) => { resolve({ status: res.statusCode }); c.terminate(); });
      c.on('open', () => { resolve({ status: 101, ws: c }); });
      c.on('error', (e) => resolve({ status: 0, error: e.message }));
    });
    const refused = await attempt({ Origin: 'https://evil.example' });
    assert.equal(refused.status, 403);
    const allowed = await attempt({ Origin: ORIGIN });
    assert.equal(allowed.status, 101);
    allowed.ws.terminate();
    const none = await attempt({});
    assert.equal(none.status, 101);
    none.ws.terminate();
  } finally { await s.close(); }
});

test('the socket cap: past maxSockets a new connection is refused (503)', async () => {
  const s = await startServer({ transport: { maxSockets: 2 } });
  try {
    const a = await connect(s);
    const b = await connect(s);
    await a.challenge; await b.challenge;
    const status = await new Promise((resolve) => {
      const c = new WsClient(s.url);
      c.on('unexpected-response', (req, res) => { resolve(res.statusCode); c.terminate(); });
      c.on('open', () => { resolve(101); c.terminate(); });
      c.on('error', () => resolve(0));
    });
    assert.equal(status, 503);
    a.close(); b.close();
  } finally { await s.close(); }
});

test('/healthz answers 503 with no database, 404 elsewhere, 405 for other methods, and nothing else', async () => {
  const s = await startServer();
  try {
    const base = `http://127.0.0.1:${s.port}`;
    const h = await fetch(`${base}/healthz`);
    assert.equal(h.status, 503);
    assert.equal(await h.text(), 'no database');
    assert.equal(h.headers.get('cache-control'), 'no-store');
    assert.equal((await fetch(`${base}/`)).status, 404);
    assert.equal((await fetch(`${base}/healthz`, { method: 'POST' })).status, 405);
  } finally { await s.close(); }
});

test('createBlindStore refuses a missing namespace, an empty or malformed origin list, a bad collection and a bad column name', () => {
  const base = { namespace: NAMESPACE, allowedOrigins: [ORIGIN] };
  assert.throws(() => createBlindStore({ ...base, namespace: undefined }), /namespace/);
  assert.throws(() => createBlindStore({ ...base, allowedOrigins: [] }), /allowedOrigins/);
  assert.throws(() => createBlindStore({ ...base, allowedOrigins: ['app.example'] }), /allowedOrigins/);
  assert.throws(() => createBlindStore({ ...base, collections: { Bad: { selectorLength: 2 } } }), /collection name/);
  assert.throws(() => createBlindStore({ ...base, collections: { notes: { selectorLength: 0 } } }), /selectorLength/);
  assert.throws(() => createBlindStore({ ...base, collections: { notes: { selectorLength: 2, imminentDays: 2 } } }), /imminentDays needs a window/);
  assert.throws(() => createBlindStore({ ...base, registration: { columns: ['drop table'] } }), /plain column name/);
  assert.throws(() => createBlindStore({ ...base, limits: { encryptedEventData: -1 } }), /positive integer/);
});
