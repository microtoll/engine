/**
 * The client half of the server protocol: the challenge-response handshake,
 * request correlation, and the account messages (the account half only; any
 * other calls are the app's), with the version-2 handshake binding of
 * FORMATS.md §2.5 (D-29).
 *
 * Written against the standard WebSocket API (addEventListener, event.data,
 * send), so it runs unchanged in a browser and in Node, and against any
 * object with that shape in tests.
 *
 * Wire: plain JSON, readable field names, bytes as base64url. Every request
 * carries a `requestId` and accepts only its own answer. Message names are
 * fixed (D-27).
 */

export const REQUEST_TIMEOUT_MS = 20000;
const PURPOSE_AUTH = 'auth';

export function isTransportError(e) { return Boolean(e && e.transport); }

function transportError(message, kind) {
  return Object.assign(new Error(message), { transport: true, kind, code: `transport-${kind}` });
}

/** The bytes the routing key signs: frameContext("<ns>/auth/v2", SHA-256(origin), nonce). */
export async function authMessage(cc, origin, nonce) {
  if (typeof origin !== 'string' || !origin) throw new Error('the handshake needs the origin it is talking to');
  if (!(nonce instanceof Uint8Array) || nonce.length !== 32) throw new Error('a nonce is 32 bytes');
  const originHash = await cc.sha256(new TextEncoder().encode(origin));
  return cc.frameContext(cc.label(PURPOSE_AUTH, 2), originHash, nonce);
}

/** The server's verification of that signature, for tests and for blind-store's mirror. */
export async function verifyAuthSignature(cc, routingPublicKeyRaw, origin, nonce, signature) {
  const message = await authMessage(cc, origin, nonce);
  return cc.verifyBytes(routingPublicKeyRaw, message, signature);
}

/** Resolves with the nonce bytes once the server's opening 'challenge' arrives. */
export function receiveChallenge(cc, ws, { timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.removeEventListener('message', onMessage);
      ws.removeEventListener('close', onClose);
    };
    function onMessage(event) {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }
      if (msg.type === 'challenge') { cleanup(); resolve(cc.fromBase64Url(msg.nonce)); }
    }
    function onClose() { cleanup(); reject(transportError('Lost the connection before signing in.', 'closed')); }
    const timer = setTimeout(() => { cleanup(); reject(transportError('The server did not answer in time.', 'timeout')); }, timeoutMs);
    ws.addEventListener('message', onMessage);
    ws.addEventListener('close', onClose);
  });
}

/**
 * Signs the nonce and completes authentication. Resolves with the auth-ok
 * fields; rejects with code 'auth-failed' if the server refuses, or a
 * transport error if the connection closes first.
 */
export async function respondToChallenge(cc, ws, nonce, routing, origin, { timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  const signature = await cc.signBytes(routing.privateKey, await authMessage(cc, origin, nonce));
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.removeEventListener('message', onMessage);
      ws.removeEventListener('close', onClose);
    };
    const timer = setTimeout(() => { cleanup(); reject(transportError('The server did not answer in time.', 'timeout')); }, timeoutMs);
    function onMessage(event) {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }
      if (msg.type === 'auth-ok') {
        cleanup();
        resolve({
          hasAccount: Boolean(msg.hasAccount),
          encryptedIdentityBlob: msg.encryptedIdentityBlob ? cc.fromBase64Url(msg.encryptedIdentityBlob) : null,
          sessionGeneration: Number.isInteger(msg.sessionGeneration) ? msg.sessionGeneration : null,
          identityBlobToken: typeof msg.identityBlobToken === 'string' ? msg.identityBlobToken : null,
          // Anything the host's registration policy adds to auth-ok (for example, termsVersionAccepted).
          fields: msg,
        });
      } else if (msg.type === 'auth-failed') {
        cleanup();
        reject(Object.assign(new Error('the server rejected authentication'), { code: 'auth-failed' }));
      }
    }
    function onClose() { cleanup(); reject(transportError('Lost the connection before signing in.', 'closed')); }
    ws.addEventListener('message', onMessage);
    ws.addEventListener('close', onClose);
    ws.send(JSON.stringify({ type: 'auth', routingPublicKey: cc.toBase64Url(routing.publicKeyRaw), signature: cc.toBase64Url(signature) }));
  });
}

/** The full handshake over an open socket: challenge, sign, authenticate. */
export async function authenticateConnection(cc, ws, routing, origin, options) {
  const nonce = await receiveChallenge(cc, ws, options);
  return respondToChallenge(cc, ws, nonce, routing, origin, options);
}

let requestCounter = 0;
function nextRequestId() { return `r${++requestCounter}.${Math.random().toString(36).slice(2, 8)}`; }

/**
 * Sends a request and resolves on ITS answer only: every request carries an
 * id, and a reply without the matching id is left for whoever is waiting for
 * it. A refusal rejects with `reason`, `detail` and the whole `serverMessage`.
 */
export function sendAndAwait(ws, request, okType, failType, { timeoutMs = REQUEST_TIMEOUT_MS } = {}) {
  const requestId = nextRequestId();
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      ws.removeEventListener('message', onMessage);
      ws.removeEventListener('close', onClose);
    };
    function onMessage(event) {
      let msg;
      try { msg = JSON.parse(event.data); } catch { return; }
      if (msg.requestId !== requestId) return;
      if (msg.type === okType) { cleanup(); resolve(msg); return; }
      if (msg.type === failType) {
        cleanup();
        reject(Object.assign(new Error(msg.reason + (msg.detail ? `: ${msg.detail}` : '')), {
          code: msg.reason, reason: msg.reason, detail: msg.detail, serverMessage: msg,
        }));
      }
    }
    function onClose() { cleanup(); reject(transportError('Lost the connection before that finished.', 'closed')); }
    const timer = setTimeout(() => { cleanup(); reject(transportError('The server did not answer in time.', 'timeout')); }, timeoutMs);
    ws.addEventListener('message', onMessage);
    ws.addEventListener('close', onClose);
    ws.send(JSON.stringify({ ...request, requestId }));
  });
}

// ---------------------------------------------------------------------
// Account messages
// ---------------------------------------------------------------------

/**
 * Pre-authentication lookup of a device's own wrapped root key, before it
 * can authenticate (the routing key comes from the root key). Exactly one of
 * credentialId (bytes) or recoveryLookupHash (hex). Returns a method record
 * the envelope functions take directly.
 */
export async function lookupUnlockMethod(cc, ws, { credentialId, recoveryLookupHash } = {}) {
  if ((credentialId != null) === (recoveryLookupHash != null)) throw new Error('lookupUnlockMethod: provide exactly one of credentialId or recoveryLookupHash');
  const request = { type: 'lookup-unlock-method' };
  if (credentialId != null) request.credentialId = cc.toBase64Url(credentialId);
  if (recoveryLookupHash != null) request.recoveryLookupHash = cc.toBase64Url(cc.fromHex(recoveryLookupHash));
  const { method: m } = await sendAndAwait(ws, request, 'unlock-method', 'lookup-unlock-method-failed');
  return {
    type: m.methodType,
    wrappedRootKey: cc.fromBase64Url(m.wrappedRootKey),
    credentialId: credentialId != null ? credentialId : null,
    prfSalt: m.prfSalt ? cc.fromBase64Url(m.prfSalt) : null,
    salt: m.pbkdf2Salt ? cc.fromBase64Url(m.pbkdf2Salt) : null,
    lookupHash: recoveryLookupHash != null ? recoveryLookupHash : null,
  };
}

async function encodeUnlockMethodForWire(cc, identity, method, sealLabel) {
  const wire = {
    methodType: method.type,
    wrappedRootKey: cc.toBase64Url(method.wrappedRootKey),
    // The label is sealed to this method (version 3, D-47), so sealLabel gets the method too.
    encryptedLabel: method.label ? cc.toBase64Url(await sealLabel(method.label, method)) : null,
  };
  if (method.type === 'passkey-prf') {
    wire.credentialId = cc.toBase64Url(method.credentialId);
    wire.prfSalt = cc.toBase64Url(method.prfSalt);
  } else if (method.type === 'recovery-code') {
    wire.pbkdf2Salt = cc.toBase64Url(method.salt);
    wire.recoveryLookupHash = cc.toBase64Url(cc.fromHex(method.lookupHash));
  } else {
    throw new Error(`unknown unlock method type: ${method.type}`);
  }
  return wire;
}

/**
 * Creates the account with every unlock method in one transaction, or not
 * at all. `policyFields` are whatever the host's registration policy
 * requires on the wire (for example, termsVersion and ageDeclared18Plus);
 * the package adds nothing of its own. Returns the blob's first
 * compare-and-swap token.
 */
export async function registerAccount(cc, ws, identity, encryptedIdentityBlob, methods, { sealLabel, policyFields = {} }) {
  const list = Array.isArray(methods) ? methods : [methods];
  if (list.length === 0) throw new Error('registerAccount needs at least one unlock method');
  const unlockMethods = [];
  for (const m of list) unlockMethods.push(await encodeUnlockMethodForWire(cc, identity, m, sealLabel));
  const identityBlobToken = cc.toBase64Url(cc.randomBytes(16));
  await sendAndAwait(ws, {
    type: 'register',
    encryptedIdentityBlob: cc.toBase64Url(encryptedIdentityBlob),
    unlockMethods,
    identityBlobToken,
    ...policyFields,
  }, 'register-ok', 'register-failed');
  return { identityBlobToken };
}

export async function addUnlockMethod(cc, ws, identity, method, { sealLabel }) {
  await sendAndAwait(ws, { type: 'add-unlock-method', unlockMethod: await encodeUnlockMethodForWire(cc, identity, method, sealLabel) }, 'add-unlock-method-ok', 'add-unlock-method-failed');
}

/**
 * The caller's own methods: ids, types, credential ids and labels (never
 * wrapped keys). Each label is opened against the method it is listed with
 * (version 3, D-47): a label the server moved to another method reads as null.
 */
export async function listUnlockMethods(cc, ws, { openLabel }) {
  const response = await sendAndAwait(ws, { type: 'list-unlock-methods' }, 'unlock-methods', 'list-unlock-methods-failed');
  return Promise.all((response.methods || []).map(async (m) => {
    const method = { type: m.methodType, credentialId: m.credentialId ? cc.fromBase64Url(m.credentialId) : null };
    let label = null;
    if (m.encryptedLabel) {
      try { label = await openLabel(cc.fromBase64Url(m.encryptedLabel), method); } catch { label = null; } // e.g. an unknown method type
    }
    return { id: m.id, type: method.type, credentialId: method.credentialId, label };
  }));
}

/** Resolves with the new session generation (every OTHER device's session is now stale). */
export async function removeUnlockMethod(ws, methodId) {
  const r = await sendAndAwait(ws, { type: 'remove-unlock-method', methodId }, 'remove-unlock-method-ok', 'remove-unlock-method-failed');
  return r.sessionGeneration;
}

export async function rotateRecoveryCode(cc, ws, identity, method, cancelMethodIds, { sealLabel }) {
  const r = await sendAndAwait(ws, {
    type: 'rotate-recovery-code',
    unlockMethod: await encodeUnlockMethodForWire(cc, identity, method, sealLabel),
    cancelMethodIds,
  }, 'rotate-recovery-code-ok', 'rotate-recovery-code-failed');
  return { methodId: r.methodId, sessionGeneration: r.sessionGeneration };
}

export async function bumpSessionGeneration(ws) {
  const r = await sendAndAwait(ws, { type: 'bump-session-generation' }, 'bump-session-generation-ok', 'bump-session-generation-failed');
  return r.sessionGeneration;
}

/**
 * Overwrites the whole blob under a compare-and-swap. On a losing swap the
 * error carries `conflict: true` plus the server's current blob and token,
 * so the caller can re-apply its change and try again.
 */
export async function updateIdentityBlob(cc, ws, sealedBlob, baseToken) {
  const nextToken = cc.toBase64Url(cc.randomBytes(16));
  try {
    const r = await sendAndAwait(ws, {
      type: 'update-identity-blob',
      encryptedIdentityBlob: cc.toBase64Url(sealedBlob),
      ...(baseToken ? { baseToken, nextToken } : {}),
    }, 'update-identity-blob-ok', 'update-identity-blob-failed');
    return { identityBlobToken: typeof r.identityBlobToken === 'string' ? r.identityBlobToken : nextToken };
  } catch (e) {
    const m = e && e.serverMessage;
    if (m && m.reason === 'conflict') {
      throw Object.assign(e, {
        conflict: true,
        encryptedIdentityBlob: m.encryptedIdentityBlob ? cc.fromBase64Url(m.encryptedIdentityBlob) : null,
        identityBlobToken: typeof m.identityBlobToken === 'string' ? m.identityBlobToken : null,
      });
    }
    throw e;
  }
}

/** Erasure. MUST be called last: the pointers it cascades away hold the only capability secrets. */
export async function deleteAccount(ws) {
  const r = await sendAndAwait(ws, { type: 'delete-account' }, 'delete-account-ok', 'delete-account-failed');
  return Boolean(r.deleted);
}
