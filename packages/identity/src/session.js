/**
 * The trusted-device session: keeps an unlocked account unlocked across
 * reloads and relaunches for up to SESSION_DAYS, so the passkey is asked for
 * about once a month per device. Record version 2 (FORMATS.md §2.4, D-28).
 *
 * Stored, through an adapter (IndexedDB by default):
 *   { v: 2, sessionKey (non-extractable AES-256-GCM CryptoKey),
 *     wrappedRootKey: sealSymmetric(sessionKey, rootKey, context),
 *     routingPublicKey (b64url), unlockedAt, expiresAt, sessionGeneration }
 *   context = frameContext("<ns>/aad/session/v2", routingPublicKey, u64be(expiresAt), u32be(sessionGeneration ?? 0))
 *
 * So the three plaintext fields that decide whether the record may open are
 * authenticated by the wrapped key: an edited expiry or generation fails the
 * open, and the record is deleted. On restore the caller also compares the
 * stored routing key with the one derived from the recovered root key.
 *
 * Honest limit: this defends against page script exporting the key and
 * against anyone without the unlocked device. It does NOT defend against
 * someone holding the unlocked device or a copy of the browser profile, which
 * is why it expires and why sensitive actions still demand a fresh proof.
 * Never stored for a guest.
 */

export const SESSION_DAYS = 30;
export const SESSION_RECORD_VERSION = 2;
export const LOCK_INTERVALS = Object.freeze({
  'every-open': 0,
  '30-min': 30 * 60 * 1000,
  '30-days': SESSION_DAYS * 24 * 60 * 60 * 1000,
});
export const DEFAULT_LOCK_INTERVAL = '30-days';
const AAD_SESSION = 'aad/session';
const RECORD_KEY = 'current';

export function sessionContext(cc, routingPublicKeyRaw, expiresAt, sessionGeneration) {
  return cc.frameContext(
    cc.label(AAD_SESSION, 2),
    routingPublicKeyRaw,
    cc.u64be(expiresAt),
    cc.u32be(Number.isInteger(sessionGeneration) && sessionGeneration >= 0 ? sessionGeneration : 0),
  );
}

/** An IndexedDB adapter: get/put/delete under one key, in one store. */
export function indexedDbStore({ dbName, storeName = 'kv' }) {
  function openDb() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(dbName, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(storeName);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  }
  function tx(mode, run) {
    return openDb().then((db) => new Promise((resolve, reject) => {
      const t = db.transaction(storeName, mode);
      const req = run(t.objectStore(storeName));
      t.oncomplete = () => { db.close(); resolve(req ? req.result : undefined); };
      t.onerror = () => { db.close(); reject(t.error); };
      t.onabort = () => { db.close(); reject(t.error); };
    }));
  }
  return {
    get: (k) => tx('readonly', (s) => s.get(k)),
    put: (k, v) => tx('readwrite', (s) => s.put(v, k)),
    delete: (k) => tx('readwrite', (s) => s.delete(k)),
  };
}

/** An in-memory adapter for tests and for runtimes without IndexedDB. */
export function memoryStore() {
  const m = new Map();
  return {
    get: async (k) => m.get(k),
    put: async (k, v) => { m.set(k, v); },
    delete: async (k) => { m.delete(k); },
    _map: m,
  };
}

/**
 * createSessionStore({ cryptoCore, store, lockIntervalStorage }):
 *   store               the record adapter; default IndexedDB "<ns>-session"
 *   lockIntervalStorage a localStorage-like object for the person's choice;
 *                       default globalThis.localStorage; key "<ns>:lockInterval"
 */
export function createSessionStore({ cryptoCore: cc, store = null, lockIntervalStorage = undefined } = {}) {
  if (!cc) throw new Error('createSessionStore needs a cryptoCore');
  const ns = cc.profile.namespace;
  const backend = store || indexedDbStore({ dbName: `${ns}-session` });
  const intervalKey = `${ns}:lockInterval`;
  const intervalStorage = () => (lockIntervalStorage === undefined ? globalThis.localStorage : lockIntervalStorage);

  function loadLockInterval() {
    try {
      const s = intervalStorage();
      const v = s && s.getItem(intervalKey);
      return Object.prototype.hasOwnProperty.call(LOCK_INTERVALS, v) ? v : DEFAULT_LOCK_INTERVAL;
    } catch { return DEFAULT_LOCK_INTERVAL; }
  }

  function saveLockInterval(interval) {
    if (!Object.prototype.hasOwnProperty.call(LOCK_INTERVALS, interval)) throw new Error(`unknown lock interval: ${interval}`);
    try { intervalStorage().setItem(intervalKey, interval); } catch { /* private mode: the default applies */ }
  }

  /**
   * Seals rootKey under a new non-extractable session key and stores it.
   * ttlMs (a LOCK_INTERVALS value) wins over days; zero means "do not keep
   * this device unlocked" and is the caller's job to turn into clearSession.
   */
  async function saveSession(rootKey, routingPublicKeyRaw, { now = Date.now(), days = SESSION_DAYS, ttlMs = null, sessionGeneration = null } = {}) {
    if (!(rootKey instanceof Uint8Array) || rootKey.length !== 32) throw new Error('saveSession: rootKey must be 32 bytes');
    if (!(routingPublicKeyRaw instanceof Uint8Array) || routingPublicKeyRaw.length !== 32) throw new Error('saveSession: a 32-byte routing public key is required');
    const lifetime = Number.isFinite(ttlMs) && ttlMs !== null ? ttlMs : days * 24 * 60 * 60 * 1000;
    if (!(lifetime > 0)) throw new Error('saveSession: a session must last longer than zero -- clear it instead');
    const expiresAt = now + lifetime;
    const generation = Number.isInteger(sessionGeneration) ? sessionGeneration : null;
    const sessionKey = await cc.generateNonExtractableSymmetricKey();
    const wrappedRootKey = await cc.sealSymmetric(sessionKey, rootKey, sessionContext(cc, routingPublicKeyRaw, expiresAt, generation));
    await backend.put(RECORD_KEY, {
      v: SESSION_RECORD_VERSION,
      sessionKey,
      wrappedRootKey,
      routingPublicKey: cc.toBase64Url(routingPublicKeyRaw),
      unlockedAt: now,
      expiresAt,
      sessionGeneration: generation,
    });
  }

  /**
   * True when the record was saved under an older generation than the server
   * now reports: a method was removed, the code rotated or "sign out
   * everywhere" pressed since. Unknown on either side is never stale.
   * Cooperative, not cryptographic.
   */
  function isSessionStale(session, serverGeneration) {
    if (!session || !Number.isInteger(session.sessionGeneration) || !Number.isInteger(serverGeneration)) return false;
    return serverGeneration > session.sessionGeneration;
  }

  /**
   * The stored session, or null — and null whenever the record is expired,
   * malformed, edited or fails to open, in which case it is deleted so a bad
   * session cannot keep failing on every load.
   */
  async function loadSession({ now = Date.now() } = {}) {
    let rec;
    try { rec = await backend.get(RECORD_KEY); } catch { return null; }
    if (!rec) return null;
    try {
      if (rec.v !== SESSION_RECORD_VERSION || !rec.sessionKey || !rec.wrappedRootKey || typeof rec.routingPublicKey !== 'string') throw new Error('malformed');
      if (typeof rec.expiresAt !== 'number' || now >= rec.expiresAt) throw new Error('expired');
      const routingPublicKeyRaw = cc.fromBase64Url(rec.routingPublicKey);
      const generation = Number.isInteger(rec.sessionGeneration) ? rec.sessionGeneration : null;
      const rootKey = await cc.openSymmetric(rec.sessionKey, new Uint8Array(rec.wrappedRootKey), sessionContext(cc, routingPublicKeyRaw, rec.expiresAt, generation));
      if (rootKey.length !== 32) throw new Error('bad root key length');
      return { rootKey, routingPublicKey: rec.routingPublicKey, routingPublicKeyRaw, unlockedAt: rec.unlockedAt, expiresAt: rec.expiresAt, sessionGeneration: generation };
    } catch {
      await clearSession();
      return null;
    }
  }

  /** Forgets the session. Idempotent; never throws (locking must always succeed). */
  async function clearSession() {
    try { await backend.delete(RECORD_KEY); } catch { /* nothing to forget, or storage gone */ }
  }

  return { saveSession, loadSession, clearSession, isSessionStale, loadLockInterval, saveLockInterval, LOCK_INTERVALS, DEFAULT_LOCK_INTERVAL, SESSION_DAYS };
}
