// An in-process stand-in for the server's account protocol, behaving as the
// server does on the wire, including the version-2 handshake verification of
// FORMATS.md §2.5. It exists so the identity package's flows can be tested
// end to end without a network or a database. blind-store (M4) is the real
// thing; the message shapes here are the contract both sides keep.
//
// Also provides a WebSocket-like pair: `send` on one side dispatches a
// 'message' event on the other as a separate task (setTimeout 0), as a
// browser does — so a listener attached a few microtasks after the socket
// opened still receives the server's opening challenge, exactly as in a
// browser, while one attached after a macrotask boundary does not.
import { verifyAuthSignature } from '../../src/handshake.js';

class FakeSocket extends EventTarget {
  constructor() { super(); this.readyState = 0; this.peer = null; this.sent = []; }
  send(text) {
    if (this.readyState !== 1) throw new Error('socket is not open');
    this.sent.push(text);
    const peer = this.peer;
    setTimeout(() => { if (peer && peer.readyState === 1) peer.dispatchEvent(Object.assign(new Event('message'), { data: text })); }, 0);
  }
  close() {
    if (this.readyState === 3) return;
    this.readyState = 3;
    const peer = this.peer;
    setTimeout(() => {
      this.dispatchEvent(new Event('close'));
      if (peer && peer.readyState !== 3) peer.close();
    }, 0);
  }
}

export function socketPair() {
  const a = new FakeSocket(), b = new FakeSocket();
  a.peer = b; b.peer = a; a.readyState = 1; b.readyState = 1;
  return [a, b];
}

// Browser-safe encoders (the demo page runs this file in a browser).
const b64u = (bytes) => { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const fromB64u = (s) => { const p = s.replace(/-/g, '+').replace(/_/g, '/'); const bin = atob(p + '='.repeat((4 - p.length % 4) % 4)); return Uint8Array.from(bin, (c) => c.charCodeAt(0)); };

/**
 * createFakeServer({ cryptoCore, allowedOrigins, policy })
 *   policy: { onRegister(msg) → extra fields to store, or throws; authOkFields(row) → fields }
 * Returns { connect(): Promise<ws>, users, failNext(type, reason), log }.
 */
export function createFakeServer({ cryptoCore: cc, allowedOrigins = ['https://example.test'], policy = null, extensions = [] } = {}) {
  const users = new Map();          // routing b64u → { blob, token, generation, methods: [], extra }
  const byCredential = new Map();   // credential b64u → { user, method }
  const byLookup = new Map();       // lookup hash b64u → { user, method }
  const failures = [];
  const log = [];
  const hooks = { onRegister: () => ({}), authOkFields: () => ({}), ...(policy || {}) };
  let nextId = 1;
  // Extensions (the object and link protocol, for the access package): each is
  // async ({ msg, rid, state, send, users, db }) => true when it answered.
  const db = { objects: new Map(), rows: new Map(), pointers: new Map(), links: new Map(), pointerSeq: 1 };
  const handlers = extensions.map((make) => make({ cryptoCore: cc, db, users, b64u, fromB64u }));

  function failNext(type, reason, extra = {}) { failures.push({ type, reason, extra }); }
  function injected(type) {
    const i = failures.findIndex((f) => f.type === type);
    if (i < 0) return null;
    return failures.splice(i, 1)[0];
  }

  function attach(server) {
    const state = { routing: null, user: null, lookups: 0 };
    const nonce = cc.randomBytes(32);
    const send = (msg, requestId) => server.send(JSON.stringify(requestId ? { ...msg, requestId } : msg));
    send({ type: 'challenge', nonce: b64u(nonce) }); // the moment the connection opens, as the real server does

    server.addEventListener('message', async (event) => {
      let msg;
      try { msg = JSON.parse(event.data); } catch { server.close(); return; }
      const rid = typeof msg.requestId === 'string' ? msg.requestId : undefined;
      log.push(msg.type);
      const inj = injected(msg.type);
      if (inj) { send({ type: `${msg.type}-failed`, reason: inj.reason, ...inj.extra }, rid); return; }

      if (!state.routing) {
        if (msg.type === 'lookup-unlock-method') {
          if (++state.lookups > 5) { send({ type: 'lookup-unlock-method-failed', reason: 'rate-limited' }, rid); return; }
          const hit = msg.credentialId ? byCredential.get(msg.credentialId) : msg.recoveryLookupHash ? byLookup.get(msg.recoveryLookupHash) : null;
          if (!hit) { send({ type: 'lookup-unlock-method-failed', reason: 'not-found' }, rid); return; }
          const m = hit.method;
          send({ type: 'unlock-method', method: { methodType: m.methodType, wrappedRootKey: m.wrappedRootKey, prfSalt: m.prfSalt || null, pbkdf2Salt: m.pbkdf2Salt || null } }, rid);
          return;
        }
        if (msg.type === 'auth') {
          const pub = fromB64u(msg.routingPublicKey);
          const sig = fromB64u(msg.signature);
          let ok = false;
          for (const o of allowedOrigins) if (await verifyAuthSignature(cc, pub, o, nonce, sig)) { ok = true; break; }
          if (!ok) { send({ type: 'auth-failed' }); server.close(); return; }
          state.routing = msg.routingPublicKey;
          state.user = users.get(state.routing) || null;
          send({
            type: 'auth-ok', hasAccount: Boolean(state.user),
            encryptedIdentityBlob: state.user ? state.user.blob : null,
            identityBlobToken: state.user ? state.user.token : null,
            sessionGeneration: state.user ? state.user.generation : null,
            ...hooks.authOkFields(state.user),
          });
          return;
        }
        server.close(); // anything else before sign-in
        return;
      }

      const user = state.user;
      const needAccount = () => { if (!user) { send({ type: `${msg.type}-failed`, reason: 'no-account' }, rid); return false; } return true; };
      const storeMethod = (u, m) => {
        const row = { id: `m${nextId++}`, ...m };
        if (m.methodType === 'passkey-prf') {
          if (byCredential.has(m.credentialId)) throw Object.assign(new Error('already-used'), { reason: 'already-used' });
          byCredential.set(m.credentialId, { user: u, method: row });
        } else if (m.methodType === 'recovery-code') {
          if (byLookup.has(m.recoveryLookupHash)) throw Object.assign(new Error('already-used'), { reason: 'already-used' });
          byLookup.set(m.recoveryLookupHash, { user: u, method: row });
        } else throw Object.assign(new Error('invalid'), { reason: 'invalid' });
        u.methods.push(row);
        return row;
      };
      const dropMethod = (u, row) => {
        u.methods = u.methods.filter((m) => m.id !== row.id);
        if (row.credentialId) byCredential.delete(row.credentialId);
        if (row.recoveryLookupHash) byLookup.delete(row.recoveryLookupHash);
      };

      try {
        for (const h of handlers) if (await h({ msg, rid, state, send, user, routing: state.routing })) return;
        switch (msg.type) {
          case 'register': {
            if (user) { send({ type: 'register-failed', reason: 'already-registered' }, rid); return; }
            if (!Array.isArray(msg.unlockMethods) || !msg.unlockMethods.length || typeof msg.encryptedIdentityBlob !== 'string') { send({ type: 'register-failed', reason: 'invalid' }, rid); return; }
            let extra;
            try { extra = hooks.onRegister(msg); } catch (e) { send({ type: 'register-failed', reason: 'invalid', detail: e.message }, rid); return; }
            const u = { blob: msg.encryptedIdentityBlob, token: msg.identityBlobToken || null, generation: 1, methods: [], extra };
            for (const m of msg.unlockMethods) storeMethod(u, m);
            users.set(state.routing, u); state.user = u;
            send({ type: 'register-ok' }, rid); return;
          }
          case 'add-unlock-method': {
            if (!needAccount()) return;
            storeMethod(user, msg.unlockMethod);
            send({ type: 'add-unlock-method-ok' }, rid); return;
          }
          case 'list-unlock-methods': {
            if (!needAccount()) return;
            send({ type: 'unlock-methods', methods: user.methods.map((m) => ({ id: m.id, methodType: m.methodType, credentialId: m.credentialId || null, encryptedLabel: m.encryptedLabel || null })) }, rid); return;
          }
          case 'remove-unlock-method': {
            if (!needAccount()) return;
            const row = user.methods.find((m) => m.id === msg.methodId);
            if (!row) { send({ type: 'remove-unlock-method-failed', reason: 'not-found' }, rid); return; }
            if (user.methods.length <= 1) { send({ type: 'remove-unlock-method-failed', reason: 'last-method' }, rid); return; }
            dropMethod(user, row); user.generation += 1;
            send({ type: 'remove-unlock-method-ok', sessionGeneration: user.generation }, rid); return;
          }
          case 'rotate-recovery-code': {
            if (!needAccount()) return;
            if (msg.unlockMethod.methodType !== 'recovery-code') { send({ type: 'rotate-recovery-code-failed', reason: 'invalid' }, rid); return; }
            for (const id of msg.cancelMethodIds || []) {
              const row = user.methods.find((m) => m.id === id);
              if (!row) { send({ type: 'rotate-recovery-code-failed', reason: 'not-found' }, rid); return; }
              if (row.methodType !== 'recovery-code') { send({ type: 'rotate-recovery-code-failed', reason: 'not-a-recovery-code' }, rid); return; }
            }
            const row = storeMethod(user, msg.unlockMethod);
            for (const id of msg.cancelMethodIds || []) dropMethod(user, user.methods.find((m) => m.id === id));
            user.generation += 1;
            send({ type: 'rotate-recovery-code-ok', methodId: row.id, sessionGeneration: user.generation }, rid); return;
          }
          case 'bump-session-generation': {
            if (!needAccount()) return;
            user.generation += 1;
            send({ type: 'bump-session-generation-ok', sessionGeneration: user.generation }, rid); return;
          }
          case 'update-identity-blob': {
            if (!needAccount()) return;
            if (typeof msg.encryptedIdentityBlob !== 'string') { send({ type: 'update-identity-blob-failed', reason: 'invalid' }, rid); return; }
            if (msg.baseToken !== undefined && msg.baseToken !== user.token) {
              send({ type: 'update-identity-blob-failed', reason: 'conflict', encryptedIdentityBlob: user.blob, identityBlobToken: user.token }, rid); return;
            }
            user.blob = msg.encryptedIdentityBlob;
            user.token = msg.nextToken || user.token;
            send({ type: 'update-identity-blob-ok', identityBlobToken: user.token }, rid); return;
          }
          case 'delete-account': {
            if (!user) { send({ type: 'delete-account-ok', deleted: false }, rid); return; }
            for (const m of [...user.methods]) dropMethod(user, m);
            for (const [id, p] of [...db.pointers]) if (p.owner === state.routing) db.pointers.delete(id); // the cascade
            users.delete(state.routing); state.user = null;
            send({ type: 'delete-account-ok', deleted: true }, rid); return;
          }
          default:
            send({ type: 'error', reason: 'unknown-type' }, rid);
        }
      } catch (e) {
        send({ type: `${msg.type}-failed`, reason: e.reason || 'server-error' }, rid);
      }
    });
  }

  async function connect() {
    const [client, server] = socketPair();
    attach(server);
    return client;
  }

  return { connect, users, byCredential, byLookup, failNext, log, allowedOrigins, db };
}

/**
 * A WebAuthn stand-in: deterministic PRF from (credential id, salt), a
 * credential store per "device". `create` mints a credential; `get` finds it.
 */
export function createFakeWebAuthn({ cryptoCore: cc, prfAtCreate = true, backedUp = false } = {}) {
  const credentials = new Map(); // id b64u → { id, prfKey }
  let calls = 0;
  const prf = async (id, salt) => cc.hkdfDeriveBits(cc.concatBytes(id, salt), new Uint8Array(0), new TextEncoder().encode('fake-prf'), 256);
  const record = (id) => credentials.get(b64u(id));
  const fake = {
    calls: () => calls,
    credentials,
    async probePasskeySupport() { return { webauthn: true, platform: true, prf: true, hybrid: true }; },
    present() { return true; },
    async createPasskeyWithPrf() {
      calls++;
      const id = cc.randomBytes(16);
      credentials.set(b64u(id), { id });
      const prfSalt = cc.randomBytes(32);
      const prfOutput32 = prfAtCreate ? await prf(id, prfSalt) : null;
      if (!prfOutput32) return { credentialId: id, prfSalt, prfOutput32: await prf(id, prfSalt), transports: ['internal'], backedUp };
      return { credentialId: id, prfSalt, prfOutput32, transports: ['internal'], backedUp };
    },
    async evaluatePrf(credentialId, prfSalt) {
      calls++;
      if (!record(credentialId)) throw Object.assign(new Error('no such credential on this device'), { code: 'not-allowed' });
      return { prfOutput32: await prf(credentialId, prfSalt) };
    },
    async assertAnyCredential() {
      calls++;
      const first = credentials.values().next().value;
      if (!first) throw Object.assign(new Error('no passkeys here'), { code: 'not-allowed' });
      return { credentialId: first.id, transports: ['internal'], userHandle: null };
    },
  };
  return fake;
}
