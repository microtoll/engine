/**
 * The passkey ceremonies. No user-facing wording lives here: every failure
 * carries a `code` the app words, and a `diagnostic` string (stage, exception, timing, PRF state) that
 * never contains anything secret.
 *
 * WebAuthn is used ONLY as a pseudo-random-function (PRF) oracle: the 32-byte
 * PRF output, run through HKDF, is the root key's unwrap key. The server never
 * sees an assertion and never verifies a passkey (D-20). So every ceremony
 * requires user verification, and the PRF salt is per credential.
 *
 * Codes: 'webauthn-unavailable' | 'prf-unsupported' | 'not-allowed' |
 *        'already-exists' | 'invalid-state' | 'no-credential-id'
 */

const CEREMONY_TIMEOUT_MS = 120000;

function failure(code, message, { stage, cause = null, t0 = null, notes = [] } = {}) {
  const ms = t0 !== null && typeof performance !== 'undefined' ? Math.round(performance.now() - t0) : null;
  const diagnostic = [
    stage ? `stage: ${stage}` : null,
    cause ? `${cause.name || 'Error'}: ${cause.message || ''}` : null,
    ms !== null ? `after ${ms} ms` : null,
    ...notes.filter(Boolean),
  ].filter(Boolean).join(' · ');
  return Object.assign(new Error(message), { code, stage, diagnostic, cause: cause || undefined });
}

/** WebAuthn L3 hints matching where a credential lives, so the browser opens the right UI first. */
export function hintsForTransports(transports) {
  const hints = [];
  for (const t of transports || []) {
    const hint = t === 'internal' ? 'client-device'
      : t === 'hybrid' ? 'hybrid'
        : (t === 'usb' || t === 'nfc' || t === 'ble' || t === 'smart-card') ? 'security-key' : null;
    if (hint && !hints.includes(hint)) hints.push(hint);
  }
  return hints;
}

/**
 * Whether a freshly created passkey reports itself as a SYNCED credential:
 * the backup-eligible (0x08) and backup-state (0x10) flags of the
 * authenticator data, byte 32. Both set is the only yes. On iOS this
 * describes the KIND of credential, never the sync setting. Null where the
 * bytes cannot be read; callers treat null as false.
 */
export function backupStateFromAuthData(authData) {
  const bytes = authData instanceof Uint8Array ? authData : (authData ? new Uint8Array(authData) : null);
  if (!bytes || bytes.length < 37) return null;
  return Boolean(bytes[32] & 0x08) && Boolean(bytes[32] & 0x10);
}

function readBackupState(credential) {
  try {
    const r = credential && credential.response;
    if (r && typeof r.getAuthenticatorData === 'function') return backupStateFromAuthData(r.getAuthenticatorData());
  } catch { /* unreadable: false */ }
  return null;
}
function readTransports(credential) {
  try {
    const r = credential && credential.response;
    if (r && typeof r.getTransports === 'function') return (r.getTransports() || []).filter((t) => typeof t === 'string');
  } catch { /* transports are an optimisation only */ }
  return [];
}
function extensionResults(credential) {
  try { return (credential && typeof credential.getClientExtensionResults === 'function' && credential.getClientExtensionResults()) || {}; } catch { return {}; }
}
function prfResultBytes(prfExt) {
  if (!prfExt || !prfExt.results || !prfExt.results.first) return null;
  const bytes = new Uint8Array(prfExt.results.first);
  return bytes.length === 32 ? bytes : null; // a PRF output is 32 bytes; anything else is not one
}

/**
 * createWebAuthn({ credentials, rpName, rpId, randomBytes }):
 *   credentials  navigator.credentials, or a stand-in in tests
 *   rpName       what the passkey provider shows as the site's name
 *   rpId         omitted by default (the host); set only when the app knows why
 *   randomBytes  the random source; crypto-core's by default
 */
export function createWebAuthn({ credentials = undefined, rpName, rpId = undefined, randomBytes = null } = {}) {
  if (typeof rpName !== 'string' || !rpName) throw new Error('createWebAuthn needs an rpName');
  const creds = () => (credentials !== undefined ? credentials : (globalThis.navigator && globalThis.navigator.credentials));
  const rand = randomBytes || ((n) => globalThis.crypto.getRandomValues(new Uint8Array(n)));
  let supportCache = null;

  function present() {
    const c = creds();
    return Boolean(c && typeof c.create === 'function' && typeof c.get === 'function');
  }
  function assertPresent(stage) {
    if (!present()) throw failure('webauthn-unavailable', 'this browser has no passkey support', { stage });
  }

  /** Advisory: chooses wording; refuses only when there is no WebAuthn or the client says it has no PRF. */
  async function probePasskeySupport() {
    if (supportCache) return supportCache;
    const webauthn = present();
    let platform = false, prf = null, hybrid = null;
    try {
      const PKC = globalThis.PublicKeyCredential;
      if (PKC && typeof PKC.isUserVerifyingPlatformAuthenticatorAvailable === 'function') platform = await PKC.isUserVerifyingPlatformAuthenticatorAvailable();
      if (PKC && typeof PKC.getClientCapabilities === 'function') {
        const caps = await PKC.getClientCapabilities();
        if (caps && typeof caps['extension:prf'] === 'boolean') prf = caps['extension:prf'];
        if (caps && typeof caps.hybridTransport === 'boolean') hybrid = caps.hybridTransport;
      }
    } catch { /* capability queries are advisory */ }
    supportCache = { webauthn, platform, prf, hybrid };
    return supportCache;
  }

  /** Asks the provider to drop a credential that opens nothing (Chrome 132+; others ignore it). Fire and forget. */
  function disownCredential(credentialId) {
    try {
      const PKC = globalThis.PublicKeyCredential;
      if (PKC && typeof PKC.signalUnknownCredential === 'function' && globalThis.location) {
        PKC.signalUnknownCredential({ rpId: rpId || globalThis.location.hostname, credentialId: toB64u(credentialId) }).catch(() => {});
      }
    } catch { /* nothing to signal */ }
  }
  function toB64u(bytes) {
    let s = ''; for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function explain(e, stage, { t0, crossDevice = false, notes = [] } = {}) {
    const name = e && e.name;
    if (name === 'NotAllowedError') return failure('not-allowed', crossDevice ? 'the phone or security key did not complete' : 'the passkey prompt was closed or refused', { stage, cause: e, t0, notes });
    if (name === 'InvalidStateError') return failure('already-exists', 'a passkey for this account already exists on this device', { stage, cause: e, t0, notes });
    if (name === 'NotSupportedError' || name === 'SecurityError') return failure('webauthn-unavailable', 'this browser cannot run the passkey ceremony here', { stage, cause: e, t0, notes });
    return failure('invalid-state', 'the passkey ceremony failed', { stage, cause: e, t0, notes });
  }

  /**
   * Creates a passkey and evaluates PRF with a fresh 32-byte salt: one prompt
   * where the authenticator answers at creation, two where it only does so on
   * assertion. attachment 'platform' (the built-in authenticator) or
   * 'cross-platform' (a phone via QR, or a security key). userName is what
   * the provider shows; userId is 16 random bytes.
   * Returns { credentialId, prfSalt, prfOutput32, transports, backedUp }.
   */
  async function createPasskeyWithPrf(userName, { attachment = 'platform' } = {}) {
    const stage = `create (${attachment})`;
    assertPresent(stage);
    const crossDevice = attachment === 'cross-platform';
    const challenge = rand(32);
    const userId = rand(16);
    const prfSalt = rand(32);
    const t0 = typeof performance !== 'undefined' ? performance.now() : null;
    let credential;
    try {
      credential = await creds().create({
        publicKey: {
          challenge,
          rp: rpId ? { name: rpName, id: rpId } : { name: rpName },
          user: { id: userId, name: uniqueUserName(userName, userId), displayName: userName },
          pubKeyCredParams: [
            { type: 'public-key', alg: -8 },   // Ed25519
            { type: 'public-key', alg: -7 },   // ES256
            { type: 'public-key', alg: -257 }, // RS256: RSA-only TPMs can sign with nothing above it
          ],
          authenticatorSelection: {
            authenticatorAttachment: attachment,
            residentKey: crossDevice ? 'preferred' : 'required',
            userVerification: 'required',
          },
          hints: crossDevice ? ['hybrid', 'security-key'] : ['client-device'],
          extensions: { prf: { eval: { first: prfSalt } } },
          timeout: CEREMONY_TIMEOUT_MS,
        },
      });
    } catch (e) {
      throw explain(e, stage, { t0, crossDevice });
    }
    const credentialId = new Uint8Array(credential.rawId);
    const transports = readTransports(credential);
    const backedUp = readBackupState(credential);
    const prfAtCreate = extensionResults(credential).prf;
    if (prfAtCreate && prfAtCreate.enabled === false) {
      // The definitive "no PRF": stop before a second prompt, and disown the orphan.
      disownCredential(credentialId);
      throw failure('prf-unsupported', 'this passkey cannot protect an account here (no PRF)', { stage, t0, notes: ['prf enabled:false at create'] });
    }
    let prfOutput32 = prfResultBytes(prfAtCreate);
    if (!prfOutput32) {
      ({ prfOutput32 } = await evaluatePrf(credentialId, prfSalt, transports, { afterCreate: true }));
    }
    return { credentialId, prfSalt, prfOutput32, transports, backedUp };
  }

  /**
   * Evaluates PRF for a known credential with its salt: every unlock, and the
   * fallback when the authenticator did not answer at creation.
   */
  async function evaluatePrf(credentialId, prfSalt, transports = [], { afterCreate = false } = {}) {
    const stage = afterCreate ? 'get after create' : 'get';
    assertPresent(stage);
    if (!(prfSalt instanceof Uint8Array) || prfSalt.length !== 32) throw failure('invalid-state', 'a PRF salt is 32 bytes', { stage });
    const allow = { id: credentialId, type: 'public-key' };
    if (transports.length) allow.transports = transports;
    const hints = hintsForTransports(transports);
    const t0 = typeof performance !== 'undefined' ? performance.now() : null;
    let assertion;
    try {
      assertion = await creds().get({
        publicKey: {
          challenge: rand(32),
          allowCredentials: [allow],
          userVerification: 'required',
          ...(hints.length ? { hints } : {}),
          extensions: { prf: { eval: { first: prfSalt } } },
          timeout: CEREMONY_TIMEOUT_MS,
        },
      });
    } catch (e) {
      throw explain(e, stage, { t0 });
    }
    const prfOutput32 = prfResultBytes(extensionResults(assertion).prf);
    if (!prfOutput32) {
      if (afterCreate) disownCredential(credentialId);
      throw failure('prf-unsupported', afterCreate ? 'this passkey cannot protect an account here (no PRF on assertion)' : 'this passkey did not return the unlock secret', { stage, t0, notes: ['assertion returned no prf result'] });
    }
    return { prfOutput32 };
  }

  /**
   * "Which of your passkeys for this site is this?" — the one ceremony with
   * no allowCredentials, for a browser that has never seen the account. No
   * PRF here: the salt belongs to the credential this finds. Returns
   * { credentialId, transports, userHandle }.
   */
  async function assertAnyCredential() {
    const stage = 'get (discoverable)';
    assertPresent(stage);
    const t0 = typeof performance !== 'undefined' ? performance.now() : null;
    let assertion;
    try {
      // allowCredentials is OMITTED, not [], for engines that read [] as "none acceptable".
      assertion = await creds().get({ publicKey: { challenge: rand(32), userVerification: 'required', hints: ['client-device'], timeout: CEREMONY_TIMEOUT_MS } });
    } catch (e) {
      throw explain(e, stage, { t0, notes: ['no allowCredentials'] });
    }
    const credentialId = new Uint8Array(assertion.rawId);
    if (!credentialId.length) throw failure('no-credential-id', 'that passkey did not identify itself', { stage, t0 });
    const transports = typeof assertion.response.getTransports === 'function' ? (assertion.response.getTransports() || []) : [];
    const userHandle = assertion.response.userHandle ? new Uint8Array(assertion.response.userHandle) : null;
    return { credentialId, transports, userHandle };
  }

  function uniqueUserName(label, userId) {
    const short = toB64u(userId).slice(0, 6);
    return `${String(label || rpName).slice(0, 40)} (${short})`;
  }

  return { probePasskeySupport, createPasskeyWithPrf, evaluatePrf, assertAnyCredential, backupStateFromAuthData, hintsForTransports, present };
}
