/**
 * The identity flows, with the app's screens supplied as callbacks (D-25):
 * registration, the three unlock paths, the trusted-device boot, the
 * step-up, the identity-blob save-and-retry, lock, deletion order and
 * unlock-method management. No DOM, no page globals, no product code.
 *
 * The session ends at "an authenticated connection, the auth-ok fields, the
 * opened identity blob, the adopted sealing key" (D-11); the app takes over
 * from `hooks.afterUnlock`.
 *
 * createIdentitySession({
 *   cryptoCore,       a crypto-core instance (the namespace)
 *   origin,           the web origin the app talks to (the handshake binding, D-29)
 *   transport,        { connect(): Promise<WebSocket-like> } — the app opens sockets
 *   sessionStore,     from createSessionStore
 *   knownAccounts,    from createKnownAccountStore
 *   webauthn,         from createWebAuthn (or a stand-in)
 *   ui: {             each optional; a missing one means "cannot ask", which fails the step
 *     askRecoveryCode(reason, hint) → string | null,
 *     confirmDeletion() → boolean,
 *     passkeyName(identity) → string,     what the passkey provider shows
 *     status(stage, detail) },
 *   hooks: {          each optional
 *     registrationFields() → object,      the host's policy fields on `register`
 *     afterUnlock(state),                 the app's boot tail
 *     onLocked(),
 *     beforeDeleteAccount({ ws, identity, blob }) },   the app's sweep of its own rows
 *   stepUpGraceMs,    default 5 minutes
 *   now,              a clock, for tests
 * })
 */
import { createIdentity, identityFromRootKey, adoptSealingKey } from './keys.js';
import {
  METHOD_PASSKEY, METHOD_RECOVERY, wrapRootKeyWithPrf, wrapRootKeyWithNewRecoveryCode, lookupHashForEnteredCode,
  unwrapRootKeyWithPrf, unwrapRootKeyWithRecoveryCode, assertSafeToRemove, sealMethodLabel, openMethodLabel,
} from './envelope.js';
import { buildIdentityBlobPlaintext, sealIdentityBlob, openIdentityBlob, IDENTITY_BLOB_UNREADABLE, IDENTITY_BLOB_ROLLED_BACK } from './blob.js';
import * as wire from './handshake.js';

export const STEP_UP_GRACE_MS = 5 * 60 * 1000;

const fail = (code, message, extra = {}) => Object.assign(new Error(message), { code, ...extra });

export function createIdentitySession({
  cryptoCore: cc, origin, transport, sessionStore, knownAccounts, webauthn = null,
  ui = {}, hooks = {}, stepUpGraceMs = STEP_UP_GRACE_MS, now = Date.now,
} = {}) {
  for (const [name, v] of Object.entries({ cryptoCore: cc, origin, transport, sessionStore, knownAccounts })) {
    if (!v) throw new Error(`createIdentitySession needs ${name}`);
  }

  const state = {
    identity: null, ws: null, hasAccount: false, blob: {}, blobToken: null,
    serverGeneration: null, authFields: null, locked: true,
  };
  let lastFreshProof = { at: 0, account: null };
  const keyOf = (identity) => cc.toBase64Url(identity.routing.publicKeyRaw);
  const status = (stage, detail) => { try { ui.status && ui.status(stage, detail); } catch { /* never fatal */ } };

  // ---- connections -----------------------------------------------------

  async function openSocket() {
    const ws = await transport.connect();
    ws.addEventListener('close', () => { if (state.ws === ws) state.ws = null; });
    return ws;
  }

  /** A short-lived, authenticated connection for a proof or a check; closed by the caller. */
  async function connectAs(identity) {
    const ws = await openSocket();
    try {
      const response = await wire.authenticateConnection(cc, ws, identity.routing, origin);
      return { ws, response };
    } catch (e) {
      try { ws.close(); } catch { /* already gone */ }
      throw e;
    }
  }

  /**
   * The moment an account is open on this device: the generation check (a
   * restored session saved under an older number is refused before it is
   * renewed), the blob opened BEFORE anything is written, the sealing key
   * adopted or persisted, the session remembered.
   */
  async function openAccount(ws, identity, response, { freshProof = false, restoringSession = null } = {}) {
    if (restoringSession && sessionStore.isSessionStale(restoringSession, response.sessionGeneration)) {
      throw fail('stale-session', 'signed out everywhere', { staleSession: true });
    }
    let blob = {};
    if (response.hasAccount) {
      blob = await openIdentityBlob(cc, identity, response.encryptedIdentityBlob, {
        minRevision: knownAccounts.knownBlobRevision(identity.routing.publicKeyRaw),
      });
    }
    state.ws = ws;
    state.identity = identity;
    state.hasAccount = response.hasAccount;
    state.blob = blob;
    state.blobToken = response.identityBlobToken;
    state.serverGeneration = response.sessionGeneration;
    state.authFields = response.fields;
    state.locked = false;
    if (freshProof) noteFreshProof(identity);
    if (response.hasAccount) {
      await adoptOrPersistSealingKey();
      knownAccounts.rememberBlobRevision(identity.routing.publicKeyRaw, state.blob.revision || 0);
    }
    await rememberUnlockedSession();
    if (hooks.afterUnlock) await hooks.afterUnlock(snapshot());
    return snapshot();
  }

  function snapshot() {
    return {
      identity: state.identity, ws: state.ws, hasAccount: state.hasAccount, blob: state.blob,
      blobToken: state.blobToken, serverGeneration: state.serverGeneration, authFields: state.authFields, locked: state.locked,
    };
  }

  /** Reconnects and re-authenticates the current identity when the socket is gone; honours a generation bump, so "sign out everywhere" also locks a device that was merely disconnected. */
  async function ensureConnected() {
    if (state.locked || !state.identity) throw fail('locked', 'no account is open');
    if (state.ws && state.ws.readyState === 1) return state.ws;
    const { ws, response } = await connectAs(state.identity);
    if (state.hasAccount && Number.isInteger(response.sessionGeneration) && Number.isInteger(state.serverGeneration)
        && response.sessionGeneration > state.serverGeneration) {
      try { ws.close(); } catch { /* gone */ }
      await lock();
      throw fail('stale-session', 'signed out everywhere', { staleSession: true });
    }
    state.ws = ws;
    state.serverGeneration = response.sessionGeneration;
    state.authFields = response.fields;
    return ws;
  }

  // ---- the sealing key and the blob -------------------------------------

  // Labels are sealed to their own method (version 3, D-47).
  const sealLabel = (label, method) => sealMethodLabel(cc, state.identity.masterSymmKey, method, label);
  const openLabel = (sealed, method) => openMethodLabel(cc, state.identity.masterSymmKey, method, sealed);

  async function writeBlob(plaintext) {
    const sealed = await sealIdentityBlob(cc, state.identity, plaintext);
    const { identityBlobToken } = await wire.updateIdentityBlob(cc, state.ws, sealed, state.blobToken);
    state.blob = plaintext;
    state.blobToken = identityBlobToken;
    knownAccounts.rememberBlobRevision(state.identity.routing.publicKeyRaw, plaintext.revision || 0);
  }

  /** Adopt the blob's sealing key, or persist this device's; on a lost race adopt the winner's. */
  async function adoptOrPersistSealingKey() {
    if (await adoptSealingKey(cc, state.identity, state.blob)) return;
    if (!state.hasAccount) return;
    try {
      await writeBlob(buildIdentityBlobPlaintext(cc, state.identity, state.blob));
      state.identity.identity.stored = true;
    } catch (e) {
      if (e && e.conflict && e.encryptedIdentityBlob) {
        state.blob = await openIdentityBlob(cc, state.identity, e.encryptedIdentityBlob, { minRevision: knownAccounts.knownBlobRevision(state.identity.routing.publicKeyRaw) });
        state.blobToken = e.identityBlobToken;
        if (await adoptSealingKey(cc, state.identity, state.blob)) return;
      }
      throw e;
    }
  }

  /**
   * Read-modify-write of the blob under the compare-and-swap. `mutation`
   * takes the current plaintext and returns the next; on a losing swap the
   * winner's blob is adopted as the base and the mutation re-applied. An
   * unreadable or rolled-back winner stops the write; nothing is written
   * over it.
   */
  async function saveIdentityBlob(mutation, { attempts = 3 } = {}) {
    if (typeof mutation !== 'function') throw new Error('saveIdentityBlob takes a mutation function');
    await ensureConnected();
    for (let attempt = 1; ; attempt++) {
      const next = buildIdentityBlobPlaintext(cc, state.identity, mutation(structuredClone(state.blob)));
      try {
        await writeBlob(next);
        return state.blob;
      } catch (e) {
        if (!e || !e.conflict || attempt >= attempts) throw e;
        state.blob = await openIdentityBlob(cc, state.identity, e.encryptedIdentityBlob, { minRevision: knownAccounts.knownBlobRevision(state.identity.routing.publicKeyRaw) });
        state.blobToken = e.identityBlobToken;
        await adoptSealingKey(cc, state.identity, state.blob);
      }
    }
  }

  // ---- sessions and step-up ---------------------------------------------

  async function rememberUnlockedSession() {
    if (!state.identity || !state.hasAccount) { await sessionStore.clearSession(); return; }
    const interval = sessionStore.loadLockInterval();
    if (interval === 'every-open') { await sessionStore.clearSession(); return; }
    try {
      await sessionStore.saveSession(state.identity.rootKey, state.identity.routing.publicKeyRaw, {
        now: now(), ttlMs: sessionStore.LOCK_INTERVALS[interval], sessionGeneration: state.serverGeneration,
      });
    } catch (e) {
      status('session-not-saved', e && e.message); // storage refused: the app still works, it asks next time
    }
  }

  function noteFreshProof(identity) { lastFreshProof = { at: now(), account: keyOf(identity) }; }
  function withinStepUpGrace() {
    return Boolean(state.identity && lastFreshProof.account === keyOf(state.identity) && now() - lastFreshProof.at < stepUpGraceMs);
  }

  /** Proves an identity on its own short connection and closes it. */
  async function proveWithPasskey(known) {
    const ws = await openSocket();
    try {
      const nonce = await wire.receiveChallenge(cc, ws);
      const method = await wire.lookupUnlockMethod(cc, ws, { credentialId: known.credentialId });
      if (method.type !== METHOD_PASSKEY || !method.prfSalt) throw fail('not-a-passkey', 'that credential does not unlock by passkey');
      const { prfOutput32 } = await webauthn.evaluatePrf(known.credentialId, method.prfSalt, known.transports);
      const identity = await identityFromRootKey(cc, await unwrapRootKeyWithPrf(cc, method, prfOutput32));
      const response = await wire.respondToChallenge(cc, ws, nonce, identity.routing, origin);
      return { identity, response, ws };
    } catch (e) { try { ws.close(); } catch { /* gone */ } throw e; }
  }

  async function proveWithRecoveryCode(code) {
    const recoveryLookupHash = await lookupHashForEnteredCode(cc, code);
    const ws = await openSocket();
    try {
      const nonce = await wire.receiveChallenge(cc, ws);
      const method = await wire.lookupUnlockMethod(cc, ws, { recoveryLookupHash });
      if (method.type !== METHOD_RECOVERY) throw fail('not-a-recovery-code', 'that code does not unlock by recovery code');
      const identity = await identityFromRootKey(cc, await unwrapRootKeyWithRecoveryCode(cc, method, code));
      const response = await wire.respondToChallenge(cc, ws, nonce, identity.routing, origin);
      return { identity, response, ws };
    } catch (e) { try { ws.close(); } catch { /* gone */ } throw e; }
  }

  /**
   * Step-up for actions that change what can open the account or erase it:
   * a trusted-device session proves the device; these need the person. Uses
   * this device's passkey when it belongs to the open account, the recovery
   * code otherwise, and refuses a proof that opens something else. The grace
   * is bound to the account it proved, so a fresh proof for one account never
   * waves through a sensitive action on another.
   */
  async function requireFreshUnlock(reason) {
    if (state.locked || !state.identity) throw fail('locked', 'no account is open');
    if (withinStepUpGrace()) return;
    const mine = keyOf(state.identity);
    const known = knownAccounts.loadKnownAccount();
    let proved;
    if (webauthn && known && known.credentialId && known.routingPublicKey && cc.toBase64Url(known.routingPublicKey) === mine) {
      try {
        proved = await proveWithPasskey(known);
      } catch (e) {
        if (!e || (e.code !== 'not-allowed' && e.code !== 'prf-unsupported')) throw e;
        proved = await proveByAskedCode(reason, 'passkey-failed');
      }
    } else {
      proved = await proveByAskedCode(reason, 'no-device-passkey');
    }
    try { proved.ws.close(); } catch { /* gone */ }
    if (keyOf(proved.identity) !== mine) throw fail('different-account', 'that opens a different account, so nothing was changed');
    noteFreshProof(state.identity);
  }

  async function proveByAskedCode(reason, hint) {
    if (!ui.askRecoveryCode) throw fail('cannot-ask', 'no way to ask for the recovery code');
    const code = await ui.askRecoveryCode(reason, hint);
    if (code === null || code === undefined) throw fail('cancelled', 'cancelled');
    return proveWithRecoveryCode(code);
  }

  // ---- registration and unlock ------------------------------------------

  /** A fresh identity, connected as a guest: no account, nothing persisted. */
  async function bootGuest() {
    const identity = await createIdentity(cc);
    const { ws, response } = await connectAs(identity);
    return openAccount(ws, identity, response);
  }

  /**
   * Registers the identity currently open (a guest's, so what it made stays
   * its own). passkey: 'platform' | 'cross-platform' | 'none'. The recovery
   * code is minted first and returned exactly once; the passkey ceremony runs
   * BEFORE anything reaches the server; both methods go in one message.
   */
  async function registerCurrentIdentity({ label = 'this device', passkey = 'platform' } = {}) {
    if (state.locked || !state.identity) throw fail('locked', 'no identity is open');
    if (state.hasAccount) throw fail('already-registered', 'this identity already has an account');
    const identity = state.identity;
    const ws = await ensureConnected();
    const { method: recoveryMethod, displayString: recoveryCode } = await wrapRootKeyWithNewRecoveryCode(cc, identity.rootKey, 'recovery code');
    const policyFields = hooks.registrationFields ? await hooks.registrationFields() : {};
    const plaintext = buildIdentityBlobPlaintext(cc, identity, {});
    const sealed = await sealIdentityBlob(cc, identity, plaintext);

    let passkeyResult = null;
    if (passkey !== 'none') {
      if (!webauthn) throw fail('webauthn-unavailable', 'no passkey support was supplied');
      const name = ui.passkeyName ? await ui.passkeyName(identity) : keyOf(identity).slice(0, 8);
      passkeyResult = await webauthn.createPasskeyWithPrf(name, { attachment: passkey });
    }
    const methods = [];
    if (passkeyResult) methods.push(await wrapRootKeyWithPrf(cc, identity.rootKey, passkeyResult.prfOutput32, passkeyResult.credentialId, passkeyResult.prfSalt, label));
    methods.push(recoveryMethod);

    const { identityBlobToken } = await wire.registerAccount(cc, ws, identity, sealed, methods, { sealLabel, policyFields });
    state.hasAccount = true;
    state.blob = plaintext;
    state.blobToken = identityBlobToken;
    state.serverGeneration = 1;
    identity.identity.stored = true;
    knownAccounts.rememberBlobRevision(identity.routing.publicKeyRaw, plaintext.revision);
    if (passkeyResult) knownAccounts.rememberDevicePasskey(passkeyResult.credentialId, label, identity.routing.publicKeyRaw, passkeyResult.transports);
    else knownAccounts.rememberDeviceRecoveryAccount(label, identity.routing.publicKeyRaw);
    noteFreshProof(identity);
    await rememberUnlockedSession();
    return { recoveryCode, passkey: Boolean(passkeyResult), passkeyBackedUp: Boolean(passkeyResult && passkeyResult.backedUp === true) };
  }

  /** Unlocks with this device's known passkey. */
  async function unlockWithPasskey() {
    const known = knownAccounts.loadKnownAccount();
    if (!known || !known.credentialId) throw fail('no-device-passkey', 'no known passkey on this device');
    if (!webauthn) throw fail('webauthn-unavailable', 'no passkey support was supplied');
    const { identity, response, ws } = await proveWithPasskey(known);
    return openAccount(ws, identity, response, { freshProof: true });
  }

  /** Unlocks on a browser that has never seen the account: two ceremonies, the record written only after the proof. */
  async function unlockWithDiscoverablePasskey({ label = 'this device' } = {}) {
    if (!webauthn) throw fail('webauthn-unavailable', 'no passkey support was supplied');
    const { credentialId, transports } = await webauthn.assertAnyCredential();
    const { identity, response, ws } = await proveWithPasskey({ credentialId, transports });
    knownAccounts.rememberDevicePasskey(credentialId, label, identity.routing.publicKeyRaw, transports);
    return openAccount(ws, identity, response, { freshProof: true });
  }

  /** Unlocks by recovery code: works on a brand-new browser with no local state. */
  async function unlockWithRecoveryCode(code) {
    const { identity, response, ws } = await proveWithRecoveryCode(code);
    return openAccount(ws, identity, response, { freshProof: true });
  }

  /**
   * Restores the trusted-device session at boot. Returns { restored: true,
   * state } or { restored: false, reason } where reason is 'none', 'stale',
   * 'no-account', 'mismatch', 'unreadable' or 'offline'. 'offline' keeps the
   * session (the network is not a reason to sign anybody out) and hands back
   * the identity so the app can open an offline copy if it has one.
   */
  async function bootFromTrustedSession() {
    const session = await sessionStore.loadSession({ now: now() });
    if (!session) return { restored: false, reason: 'none' };
    const identity = await identityFromRootKey(cc, session.rootKey);
    if (cc.toBase64Url(identity.routing.publicKeyRaw) !== session.routingPublicKey) {
      await sessionStore.clearSession();
      return { restored: false, reason: 'mismatch' };
    }
    let ws;
    let response;
    try {
      ({ ws, response } = await connectAs(identity));
    } catch (e) {
      if (wire.isTransportError(e)) return { restored: false, reason: 'offline', identity, session };
      await sessionStore.clearSession();
      throw e;
    }
    try {
      if (!response.hasAccount) { try { ws.close(); } catch { /* gone */ } await sessionStore.clearSession(); return { restored: false, reason: 'no-account' }; }
      const snap = await openAccount(ws, identity, response, { restoringSession: session });
      return { restored: true, state: snap };
    } catch (e) {
      try { ws.close(); } catch { /* gone */ }
      if (e && e.staleSession) { await sessionStore.clearSession(); return { restored: false, reason: 'stale' }; }
      if (e && (e.code === IDENTITY_BLOB_UNREADABLE || e.code === IDENTITY_BLOB_ROLLED_BACK)) {
        // Said loudly, with nothing written and the session kept: the offline copy may be the last readable one.
        return { restored: false, reason: 'unreadable', error: e };
      }
      await sessionStore.clearSession();
      throw e;
    }
  }

  /** Opens an identity the app already holds (a switch between accounts in one tab). */
  async function switchTo(identity, { freshProof = false } = {}) {
    await closeSocket();
    const { ws, response } = await connectAs(identity);
    try {
      return await openAccount(ws, identity, response, { freshProof });
    } catch (e) { try { ws.close(); } catch { /* gone */ } throw e; }
  }

  async function closeSocket() {
    if (state.ws) { try { state.ws.close(); } catch { /* gone */ } }
    state.ws = null;
  }

  /** Locks: forgets the session and everything readable in this object. The app clears its own caches in onLocked. */
  async function lock() {
    await sessionStore.clearSession();
    await closeSocket();
    if (state.identity && state.identity.rootKey) state.identity.rootKey.fill(0);
    Object.assign(state, { identity: null, hasAccount: false, blob: {}, blobToken: null, serverGeneration: null, authFields: null, locked: true });
    lastFreshProof = { at: 0, account: null };
    if (hooks.onLocked) await hooks.onLocked();
  }

  // ---- unlock-method management -----------------------------------------

  async function listUnlockMethods() {
    const ws = await ensureConnected();
    return wire.listUnlockMethods(cc, ws, { openLabel });
  }

  /** Adds a passkey on this device (or a phone/security key) after a fresh proof; the device then knows this account. */
  async function addPasskey({ label = 'this device', attachment = 'platform' } = {}) {
    if (!webauthn) throw fail('webauthn-unavailable', 'no passkey support was supplied');
    await requireFreshUnlock('add a passkey');
    const ws = await ensureConnected();
    const name = ui.passkeyName ? await ui.passkeyName(state.identity) : keyOf(state.identity).slice(0, 8);
    const { credentialId, prfSalt, prfOutput32, transports } = await webauthn.createPasskeyWithPrf(name, { attachment });
    const method = await wrapRootKeyWithPrf(cc, state.identity.rootKey, prfOutput32, credentialId, prfSalt, label);
    await wire.addUnlockMethod(cc, ws, state.identity, method, { sealLabel });
    knownAccounts.rememberDevicePasskey(credentialId, label, state.identity.routing.publicKeyRaw, transports);
    return { credentialId };
  }

  /** Removes one method after a fresh proof; never the last. Re-saves this device's session under the new generation. */
  async function removeUnlockMethod(methodId) {
    await requireFreshUnlock('remove an unlock method');
    const methods = await listUnlockMethods();
    const index = methods.findIndex((m) => m.id === methodId);
    if (index < 0) throw fail('not-found', 'no such unlock method');
    assertSafeToRemove(methods, index);
    const ws = await ensureConnected();
    state.serverGeneration = await wire.removeUnlockMethod(ws, methodId);
    const removed = methods[index];
    const known = knownAccounts.loadKnownAccount();
    if (removed.credentialId && known && known.credentialId && cc.toBase64Url(known.credentialId) === cc.toBase64Url(removed.credentialId)) {
      // This device's passkey no longer opens anything: it signs in by code from now on.
      knownAccounts.clearKnownAccount();
      knownAccounts.rememberDeviceRecoveryAccount(known.label, state.identity.routing.publicKeyRaw);
    }
    await rememberUnlockedSession();
  }

  /** A new recovery code, cancelling every old one, in one server transaction. Returns the code, shown once. */
  async function rotateRecoveryCode({ label = 'recovery code' } = {}) {
    await requireFreshUnlock('make a new recovery code');
    const methods = await listUnlockMethods();
    const cancel = methods.filter((m) => m.type === METHOD_RECOVERY).map((m) => m.id);
    const { method, displayString } = await wrapRootKeyWithNewRecoveryCode(cc, state.identity.rootKey, label);
    const ws = await ensureConnected();
    const { sessionGeneration } = await wire.rotateRecoveryCode(cc, ws, state.identity, method, cancel, { sealLabel });
    state.serverGeneration = sessionGeneration;
    await rememberUnlockedSession();
    return { recoveryCode: displayString };
  }

  /** "Sign out everywhere": every other device's session becomes stale; this one is re-saved. */
  async function signOutEverywhere() {
    const ws = await ensureConnected();
    state.serverGeneration = await wire.bumpSessionGeneration(ws);
    await rememberUnlockedSession();
    return state.serverGeneration;
  }

  /** Does this device's stored passkey open the account that is open now? */
  async function checkDeviceAccountMatch() {
    const known = knownAccounts.loadKnownAccount();
    if (!known || !known.credentialId) return { status: 'no-device-passkey', known };
    const methods = await listUnlockMethods();
    const stored = cc.toBase64Url(known.credentialId);
    if (methods.some((m) => m.credentialId && cc.toBase64Url(m.credentialId) === stored)) {
      if (!known.routingPublicKey) knownAccounts.rememberDevicePasskey(known.credentialId, known.label, state.identity.routing.publicKeyRaw, known.transports);
      return { status: 'in-sync', known };
    }
    let stillExists = false;
    let ws = null;
    try {
      ws = await openSocket();
      await wire.receiveChallenge(cc, ws);
      await wire.lookupUnlockMethod(cc, ws, { credentialId: known.credentialId });
      stillExists = true;
    } catch { stillExists = false; } finally { if (ws) { try { ws.close(); } catch { /* gone */ } } }
    return { status: stillExists ? 'diverged' : 'stale-device-passkey', known };
  }

  // ---- deletion ----------------------------------------------------------

  /**
   * Erasure, in this order: the person confirms; a fresh proof; the session is
   * forgotten; the app sweeps its own rows through `beforeDeleteAccount`
   * while the pointers still exist; then delete-account; then the device's
   * records. Each app step is the app's to make best-effort.
   */
  async function deleteAccount() {
    if (state.locked || !state.identity || !state.hasAccount) throw fail('locked', 'no account is open');
    if (ui.confirmDeletion && !(await ui.confirmDeletion())) return false;
    await requireFreshUnlock('delete this account');
    await sessionStore.clearSession();
    const ws = await ensureConnected();
    if (hooks.beforeDeleteAccount) await hooks.beforeDeleteAccount({ ws, identity: state.identity, blob: state.blob });
    const deleted = await wire.deleteAccount(ws);
    knownAccounts.clearKnownAccount();
    knownAccounts.forgetBlobRevision(state.identity.routing.publicKeyRaw);
    await lock();
    return deleted;
  }

  return Object.freeze({
    state: snapshot,
    bootGuest, registerCurrentIdentity,
    unlockWithPasskey, unlockWithDiscoverablePasskey, unlockWithRecoveryCode, bootFromTrustedSession, switchTo,
    ensureConnected, requireFreshUnlock, saveIdentityBlob, rememberUnlockedSession, lock,
    listUnlockMethods, addPasskey, removeUnlockMethod, rotateRecoveryCode, signOutEverywhere, checkDeviceAccountMatch,
    deleteAccount,
  });
}
