// Writes test/fixtures/frozen-v2.json ONCE, and then never again.
//
//   node packages/identity/test/tooling/generate-frozen-fixtures.mjs
//
// The file holds the version-2 bytes this package wrote (FORMATS.md §2),
// under the test namespace "example": every later version must open them and
// reproduce every deterministic value in them, so a changed label, version
// byte, parameter or layout turns test/fixtures.test.mjs red instead of
// silently locking people out of their accounts. It refuses to overwrite the
// file. A NEW format gets a new entry beside the old ones (or a new file),
// never a regenerated one.
//
// Everything goes through the package's own writers. Where a writer draws
// its own randomness (the recovery code and its salt, the session key), a
// stand-in for that one call supplies a fixed value instead, so the file's
// inputs are readable; the construction around it is the package's. Random
// AEAD nonces stay random: those blobs are stored and must open. Every key in
// the file is a throwaway made for it.
//
// The calls below are the API as it stood when the file was written, before
// D-46 and D-47: `formatRecoveryCode(bytes)` then wrote a version-2 code
// (now `{ version: 2 }`), and `labelContext` and `sealMethodLabel` then took
// the routing key (the version-2 binding, now `labelContextV2`; nothing
// writes it any more). The script refuses to run once the file exists, so it
// is kept as the record of how the bytes were made, not updated. The
// version-3 bytes are generate-frozen-fixtures-v3.mjs's.
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '../../src/index.js';
import { createFakeWebAuthn, socketPair } from './fakeServer.mjs';

const OUT = fileURLToPath(new URL('../fixtures/frozen-v2.json', import.meta.url));
if (existsSync(OUT)) {
  console.error(`${OUT} exists and is frozen. Nothing was written.`);
  process.exit(1);
}

const NAMESPACE = 'example';
const cc = createCryptoCore({ namespace: NAMESPACE });
const hex = cc.toHex;
const b64u = cc.toBase64Url;

// Fixed inputs. Byte patterns rather than randomness, so a reader can see
// what went in.
const ROOT = Uint8Array.from({ length: 32 }, (_, i) => 0x20 + i);             // 20 21 … 3f
const CREDENTIAL_ID = Uint8Array.from({ length: 16 }, (_, i) => 0xc0 + i);    // c0 … cf
const PRF_SALT = Uint8Array.from({ length: 32 }, (_, i) => 0x60 + i);         // 60 … 7f
const RECOVERY_CODE_BYTES = Uint8Array.from({ length: 16 }, (_, i) => (0x0f + i * 29) & 0xff);
const PBKDF2_SALT = Uint8Array.from({ length: 16 }, (_, i) => 0xe0 + i);      // e0 … ef
const SESSION_KEY = Uint8Array.from({ length: 32 }, (_, i) => 0x80 + i);      // 80 … 9f
const UNLOCKED_AT = Date.UTC(2026, 8, 27, 12, 0, 0);                          // 2026-09-27T12:00:00Z
const ORIGIN = 'https://example.test';
const NONCE = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);            // a0 … bf

// The account: keys derived from the fixed root, plus a sealing key that is
// generated (never derived; keys.js) and so is stored here as its JWK.
const me = await id.identityFromRootKey(cc, ROOT);
const sealing = await cc.generateSealingKeyPair();
await id.adoptSealingKey(cc, me, { sealingKey: sealing.jwk });

const out = {
  source: `Frozen by test/tooling/generate-frozen-fixtures.mjs on 2026-09-27 under namespace "${NAMESPACE}". Never regenerated or edited.`,
  namespace: NAMESPACE,
  labels: {
    unlockMethod: cc.label('aad/unlock-method', 2),
    unlockLabel: cc.label('aad/unlock-label', 2),
    identityBlob: cc.label('aad/identity-blob', 2),
    session: cc.label('aad/session', 2),
    auth: cc.label('auth', 2),
  },
  identity: {
    rootKey: hex(ROOT),
    routingPublicKey: hex(me.routing.publicKeyRaw),
    routingHandle: id.encodeRoutingHandle(cc, me.routing.publicKeyRaw),
    identitySigningPublicKey: hex(me.identitySigning.publicKeyRaw),
    sealingKeyJwk: sealing.jwk,
    identityPublicKey: hex(me.identity.publicKeyRaw),
  },
};

// --- §2.1 the wrapped root key, passkey method --------------------------------
// The PRF output comes from the scripted WebAuthn the identity tests use, for
// a fixed credential id and PRF salt. The output is stored: the envelope
// depends on it, never on how the stand-in computes it.
const webauthn = createFakeWebAuthn({ cryptoCore: cc });
webauthn.credentials.set(b64u(CREDENTIAL_ID), { id: CREDENTIAL_ID });
const { prfOutput32 } = await webauthn.evaluatePrf(CREDENTIAL_ID, PRF_SALT);
const passkey = await id.wrapRootKeyWithPrf(cc, ROOT, prfOutput32, CREDENTIAL_ID, PRF_SALT, 'phone');
out.passkeyMethod = {
  type: passkey.type,
  credentialId: hex(CREDENTIAL_ID),
  prfSalt: hex(PRF_SALT),
  prfOutput: hex(prfOutput32),
  context: hex(await id.unlockMethodContext(cc, id.METHOD_PASSKEY, CREDENTIAL_ID)),
  wrappedRootKey: hex(passkey.wrappedRootKey),
};

// --- §2.1 the wrapped root key, recovery-code method ---------------------------
// wrapRootKeyWithNewRecoveryCode draws the code and the salt itself; this
// stand-in answers those two draws with the fixed values above. Nothing else
// in the call is replaced (the AEAD nonce is drawn inside sealSymmetric).
const fixedDraws = {
  ...cc,
  generateRecoveryCode: async () => ({ secretBytes: RECOVERY_CODE_BYTES.slice(), displayString: await cc.formatRecoveryCode(RECOVERY_CODE_BYTES) }),
  randomBytes: (n) => {
    if (n !== PBKDF2_SALT.length) throw new Error(`unexpected draw of ${n} bytes`);
    return PBKDF2_SALT.slice();
  },
};
const { method: recovery, displayString } = await id.wrapRootKeyWithNewRecoveryCode(fixedDraws, ROOT, 'code');
out.recoveryMethod = {
  type: recovery.type,
  codeBytes: hex(RECOVERY_CODE_BYTES),
  code: displayString,
  pbkdf2Salt: hex(recovery.salt),
  lookupHash: recovery.lookupHash,
  context: hex(await id.unlockMethodContext(cc, id.METHOD_RECOVERY, cc.fromHex(recovery.lookupHash))),
  wrappedRootKey: hex(recovery.wrappedRootKey),
};

// --- §2.3 the sealed unlock-method labels --------------------------------------
out.methodLabels = {
  context: hex(id.labelContext(cc, me.routing.publicKeyRaw)),
  sealed: {
    phone: hex(await id.sealMethodLabel(cc, me.masterSymmKey, me.routing.publicKeyRaw, 'phone')),
    code: hex(await id.sealMethodLabel(cc, me.masterSymmKey, me.routing.publicKeyRaw, 'code')),
  },
};

// --- §2.2 the identity blob, two revisions ------------------------------------
const plaintext1 = id.buildIdentityBlobPlaintext(cc, me, { contacts: [{ name: 'Grace' }], theme: 'dark' });
const plaintext2 = id.buildIdentityBlobPlaintext(cc, me, { ...plaintext1, theme: 'light' });
out.identityBlob = {
  context: hex(id.blobContext(cc, me.routing.publicKeyRaw)),
  revision1: { plaintext: plaintext1, sealed: hex(await id.sealIdentityBlob(cc, me, plaintext1)) },
  revision2: { plaintext: plaintext2, sealed: hex(await id.sealIdentityBlob(cc, me, plaintext2)) },
};

// --- §2.4 the trusted-device session record -----------------------------------
// The real session key is non-extractable and can never be written down; this
// stand-in hands saveSession a key imported from fixed bytes instead. The
// adapter records what saveSession stores, under the key it chooses.
function recordingStore() {
  const writes = [];
  return { writes, get: async () => undefined, put: async (k, v) => { writes.push([k, v]); }, delete: async () => {} };
}
const sessionDraws = { ...cc, generateNonExtractableSymmetricKey: () => cc.importSymmetricKey(SESSION_KEY) };
async function sessionRecord(options) {
  const store = recordingStore();
  const sessions = id.createSessionStore({ cryptoCore: sessionDraws, store, lockIntervalStorage: id.memoryStorage() });
  await sessions.saveSession(ROOT, me.routing.publicKeyRaw, options);
  const [[storeKey, rec]] = store.writes;
  return {
    storeKey,
    record: {
      v: rec.v, wrappedRootKey: hex(rec.wrappedRootKey), routingPublicKey: rec.routingPublicKey,
      unlockedAt: rec.unlockedAt, expiresAt: rec.expiresAt, sessionGeneration: rec.sessionGeneration,
    },
    context: hex(id.sessionContext(cc, me.routing.publicKeyRaw, rec.expiresAt, rec.sessionGeneration)),
  };
}
out.session = {
  sessionKey: hex(SESSION_KEY),
  // The default lifetime (SESSION_DAYS) and a known generation.
  thirtyDays: await sessionRecord({ now: UNLOCKED_AT, sessionGeneration: 3 }),
  // A lock-interval lifetime and an unknown generation, which binds as 0.
  thirtyMinutes: await sessionRecord({ now: UNLOCKED_AT, ttlMs: id.LOCK_INTERVALS['30-min'] }),
};

// --- §2.5 the handshake ------------------------------------------------------------
// The auth message the package sends for a fixed nonce and origin, captured on
// the scripted socket. Ed25519 is deterministic (RFC 8032 §5.1.6), so the
// whole message reproduces.
const [client, server] = socketPair();
server.addEventListener('message', () => server.send(JSON.stringify({ type: 'auth-ok', hasAccount: false })));
await id.respondToChallenge(cc, client, NONCE, me.routing, ORIGIN);
client.close();
out.handshake = {
  origin: ORIGIN,
  nonce: hex(NONCE),
  signedMessage: hex(await id.authMessage(cc, ORIGIN, NONCE)),
  wire: JSON.parse(client.sent[0]),
};

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log('wrote', OUT, Object.keys(out).join(', '));
