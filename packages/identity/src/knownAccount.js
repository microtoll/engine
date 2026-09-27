/**
 * The device's own records: which account this browser knows, whether its
 * built-in passkey has proved unable to protect one, and the highest
 * identity-blob revision it has seen per account. Kept behind a
 * localStorage-like adapter and namespaced by the profile.
 *
 * Non-sensitive: a credential id is an opaque WebAuthn identifier, not a
 * secret; knowing it is not enough to unlock without the authenticator.
 */

export function memoryStorage() {
  const m = new Map();
  return { getItem: (k) => (m.has(k) ? m.get(k) : null), setItem: (k, v) => { m.set(k, String(v)); }, removeItem: (k) => { m.delete(k); } };
}

export function createKnownAccountStore({ cryptoCore: cc, storage = undefined } = {}) {
  if (!cc) throw new Error('createKnownAccountStore needs a cryptoCore');
  const ns = cc.profile.namespace;
  const KNOWN = `${ns}:knownAccount`;
  const BLOCKED = `${ns}:devicePasskeyBlocked`;
  const REVISIONS = `${ns}:blobRevisions`;
  const store = () => (storage === undefined ? globalThis.localStorage : storage);
  const get = (k) => { try { return store().getItem(k); } catch { return null; } };
  const set = (k, v) => { try { store().setItem(k, v); } catch { /* private mode */ } };
  const del = (k) => { try { store().removeItem(k); } catch { /* nothing */ } };

  /** A passkey now works here for this account. Clears any "blocked" note. */
  function rememberDevicePasskey(credentialId, label, routingPublicKeyRaw, transports = []) {
    set(KNOWN, JSON.stringify({
      credentialId: cc.toBase64Url(credentialId),
      label: label || null,
      routingPublicKey: routingPublicKeyRaw ? cc.toBase64Url(routingPublicKeyRaw) : null,
      transports: Array.isArray(transports) ? transports.filter((t) => typeof t === 'string') : [],
    }));
    del(BLOCKED);
  }

  /** This device signs into the account by recovery code. Never overwrites a passkey record. */
  function rememberDeviceRecoveryAccount(label, routingPublicKeyRaw) {
    const existing = loadKnownAccount();
    if (existing && existing.credentialId) return;
    set(KNOWN, JSON.stringify({ credentialId: null, label: label || null, routingPublicKey: routingPublicKeyRaw ? cc.toBase64Url(routingPublicKeyRaw) : null, transports: [] }));
  }

  function loadKnownAccount() {
    const raw = get(KNOWN);
    if (!raw) return null;
    try {
      const p = JSON.parse(raw);
      return {
        credentialId: p.credentialId ? cc.fromBase64Url(p.credentialId) : null,
        label: p.label || null,
        routingPublicKey: p.routingPublicKey ? cc.fromBase64Url(p.routingPublicKey) : null,
        transports: Array.isArray(p.transports) ? p.transports.filter((t) => typeof t === 'string') : [],
      };
    } catch { return null; }
  }

  function clearKnownAccount() { del(KNOWN); del(BLOCKED); }

  function markDevicePasskeyBlocked(reason) { set(BLOCKED, JSON.stringify({ reason: reason || 'prf-unsupported', at: Date.now() })); }
  function isDevicePasskeyBlocked() { return get(BLOCKED) !== null; }
  function clearDevicePasskeyBlocked() { del(BLOCKED); }

  // The highest blob revision seen per account (FORMATS.md §2.2), so a
  // rolled-back blob is refused on a device that saw a later one.
  function readRevisions() { try { const p = JSON.parse(get(REVISIONS) || '{}'); return p && typeof p === 'object' ? p : {}; } catch { return {}; } }
  function knownBlobRevision(routingPublicKeyRaw) {
    const r = readRevisions()[cc.toBase64Url(routingPublicKeyRaw)];
    return Number.isSafeInteger(r) && r >= 0 ? r : 0;
  }
  function rememberBlobRevision(routingPublicKeyRaw, revision) {
    if (!Number.isSafeInteger(revision) || revision < 0) return;
    const all = readRevisions();
    const key = cc.toBase64Url(routingPublicKeyRaw);
    if ((all[key] || 0) < revision) { all[key] = revision; set(REVISIONS, JSON.stringify(all)); }
  }
  function forgetBlobRevision(routingPublicKeyRaw) {
    const all = readRevisions();
    delete all[cc.toBase64Url(routingPublicKeyRaw)];
    set(REVISIONS, JSON.stringify(all));
  }

  return {
    rememberDevicePasskey, rememberDeviceRecoveryAccount, loadKnownAccount, clearKnownAccount,
    markDevicePasskeyBlocked, isDevicePasskeyBlocked, clearDevicePasskeyBlocked,
    knownBlobRevision, rememberBlobRevision, forgetBlobRevision,
  };
}
