// Frozen fixtures: the version-2 bytes an earlier version of this package
// wrote (test/tooling/generate-frozen-fixtures.mjs, never regenerated), which
// every later version must open, and whose deterministic parts it must
// reproduce. A changed label, version byte, parameter or layout fails here
// instead of silently locking people out of their accounts. Everything is
// checked through the package's public API.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '../src/index.js';
import { socketPair } from './tooling/fakeServer.mjs';

const fx = JSON.parse(readFileSync(new URL('./fixtures/frozen-v2.json', import.meta.url), 'utf8'));
const cc = createCryptoCore({ namespace: fx.namespace });
const H = cc.fromHex;
const flip = (hex, at) => { const b = H(hex); b[at] ^= 1; return b; };

/** The frozen account: keys derived from the stored root, and the stored sealing key adopted. */
async function frozenAccount() {
  const me = await id.identityFromRootKey(cc, H(fx.identity.rootKey));
  assert.equal(await id.adoptSealingKey(cc, me, { sealingKey: fx.identity.sealingKeyJwk }), true);
  return me;
}

test('the frozen root key derives the same routing and signing keys; the stored sealing key is adopted', async () => {
  const me = await frozenAccount();
  assert.equal(cc.toHex(me.routing.publicKeyRaw), fx.identity.routingPublicKey);
  assert.equal(id.encodeRoutingHandle(cc, me.routing.publicKeyRaw), fx.identity.routingHandle);
  assert.equal(cc.toHex(me.identitySigning.publicKeyRaw), fx.identity.identitySigningPublicKey);
  assert.equal(cc.toHex(me.identity.publicKeyRaw), fx.identity.identityPublicKey);
});

test('every version-2 context reproduces byte for byte, each under its own label (FORMATS.md §2.1–§2.5)', async () => {
  const me = await frozenAccount();
  const routing = me.routing.publicKeyRaw;
  const contexts = [
    // §2.1: label ‖ 0x00 ‖ 0x01 ‖ SHA-256(credentialId), and label ‖ 0x00 ‖ 0x02 ‖ lookup hash.
    [fx.labels.unlockMethod, await id.unlockMethodContext(cc, id.METHOD_PASSKEY, H(fx.passkeyMethod.credentialId)), fx.passkeyMethod.context],
    [fx.labels.unlockMethod, await id.unlockMethodContext(cc, id.METHOD_RECOVERY, H(fx.recoveryMethod.lookupHash)), fx.recoveryMethod.context],
    [fx.labels.identityBlob, id.blobContext(cc, routing), fx.identityBlob.context],                 // §2.2
    [fx.labels.unlockLabel, id.labelContextV2(cc, routing), fx.methodLabels.context],               // §2.3, version 2 (read only since D-47)
    // §2.4: routing ‖ u64be(expiresAt) ‖ u32be(generation, an unknown one as 0).
    [fx.labels.session, id.sessionContext(cc, routing, fx.session.thirtyDays.record.expiresAt, fx.session.thirtyDays.record.sessionGeneration), fx.session.thirtyDays.context],
    [fx.labels.session, id.sessionContext(cc, routing, fx.session.thirtyMinutes.record.expiresAt, fx.session.thirtyMinutes.record.sessionGeneration), fx.session.thirtyMinutes.context],
    [fx.labels.auth, await id.authMessage(cc, fx.handshake.origin, H(fx.handshake.nonce)), fx.handshake.signedMessage], // §2.5
  ];
  for (const [label, got, frozen] of contexts) {
    assert.equal(cc.toHex(got), frozen);
    // The frame starts with the NUL-terminated purpose label, so no context can be taken for another.
    assert.ok(frozen.startsWith(cc.toHex(new TextEncoder().encode(label)) + '00'), `${label} heads its context`);
  }
  assert.equal(new Set(Object.values(fx.labels)).size, Object.keys(fx.labels).length, 'five distinct labels');
});

test('the passkey-wrapped root key opens with the stored PRF output, and only for its own credential (FORMATS.md §2.1)', async () => {
  const method = {
    type: fx.passkeyMethod.type, wrappedRootKey: H(fx.passkeyMethod.wrappedRootKey),
    credentialId: H(fx.passkeyMethod.credentialId), prfSalt: H(fx.passkeyMethod.prfSalt),
  };
  const prf = H(fx.passkeyMethod.prfOutput);
  assert.equal(cc.toHex(await id.unwrapRootKeyWithPrf(cc, method, prf)), fx.identity.rootKey);
  // AEAD v1 layout: version byte, 12-byte nonce, 32-byte key, 16-byte tag.
  assert.equal(method.wrappedRootKey.length, 1 + 12 + 32 + 16);
  assert.equal(method.wrappedRootKey[0], 0x01);
  await assert.rejects(id.unwrapRootKeyWithPrf(cc, { ...method, wrappedRootKey: flip(fx.passkeyMethod.wrappedRootKey, 30) }, prf), 'a flipped byte');
  await assert.rejects(id.unwrapRootKeyWithPrf(cc, method, flip(fx.passkeyMethod.prfOutput, 0)), 'another PRF output');
  await assert.rejects(id.unwrapRootKeyWithPrf(cc, { ...method, credentialId: flip(fx.passkeyMethod.credentialId, 0) }, prf), 'moved to another credential');
});

test('the recovery-code-wrapped root key opens with the stored code; the code and its lookup hash reproduce (FORMATS.md §2.1, §2.7)', async () => {
  const r = fx.recoveryMethod;
  // The stored code is version 2 (D-26); since D-46 it is read only when version 2 is named.
  const v2 = { recoveryCodeVersion: 2 };
  assert.equal(await cc.formatRecoveryCode(H(r.codeBytes), { version: 2 }), r.code);
  assert.equal(await id.lookupHashForEnteredCode(cc, r.code, v2), r.lookupHash);
  assert.equal(await id.lookupHashForEnteredCode(cc, r.code.toLowerCase(), v2), r.lookupHash, 'as a person might type it');
  if (await cc.formatRecoveryCode(H(r.codeBytes)) !== r.code) {
    await assert.rejects(id.lookupHashForEnteredCode(cc, r.code), (e) => e.code === 'recovery-code-checksum', 'never read as version 3');
  }
  const method = { type: r.type, wrappedRootKey: H(r.wrappedRootKey), salt: H(r.pbkdf2Salt), lookupHash: r.lookupHash };
  assert.equal(cc.toHex(await id.unwrapRootKeyWithRecoveryCode(cc, method, r.code, v2)), fx.identity.rootKey);
  assert.equal(cc.toHex(await id.unwrapRootKeyWithRecoveryCode(cc, { ...method, lookupHash: null }, r.code, v2)), fx.identity.rootKey, 'the lookup hash re-derived from the code');
  await assert.rejects(id.unwrapRootKeyWithRecoveryCode(cc, { ...method, wrappedRootKey: flip(r.wrappedRootKey, 30) }, r.code, v2), 'a flipped byte');
  // The same blob served under another row's lookup hash: the context refuses it.
  await assert.rejects(id.unwrapRootKeyWithRecoveryCode(cc, { ...method, lookupHash: cc.toHex(flip(r.lookupHash, 0)) }, r.code, v2), 'moved to another row');
  // A passkey row's blob served on the recovery path is refused (another unwrap key, and another type byte).
  await assert.rejects(id.unwrapRootKeyWithRecoveryCode(cc, { ...method, wrappedRootKey: H(fx.passkeyMethod.wrappedRootKey) }, r.code, v2));
});

test('the sealed version-2 unlock-method labels open for this account and read as null anywhere else (FORMATS.md §2.3)', async () => {
  const me = await frozenAccount();
  const other = await id.createIdentity(cc);
  const passkey = { type: id.METHOD_PASSKEY, credentialId: H(fx.passkeyMethod.credentialId) };
  for (const [label, sealed] of Object.entries(fx.methodLabels.sealed)) {
    assert.equal(await id.openMethodLabelV2(cc, me.masterSymmKey, me.routing.publicKeyRaw, H(sealed)), label);
    assert.equal(await id.openMethodLabelV2(cc, me.masterSymmKey, other.routing.publicKeyRaw, H(sealed)), null, 'moved to another account');
    assert.equal(await id.openMethodLabelV2(cc, me.masterSymmKey, me.routing.publicKeyRaw, flip(sealed, 20)), null, 'a flipped byte');
    // Version 3 (D-47) binds to the method instead; a version-2 label never opens there.
    assert.equal(await id.openMethodLabel(cc, me.masterSymmKey, passkey, H(sealed)), null);
  }
});

test('the identity blobs open to their stored plaintext, bound to the account, and the revision counter refuses a rollback (FORMATS.md §2.2)', async () => {
  const me = await frozenAccount();
  const { revision1, revision2 } = fx.identityBlob;
  assert.deepEqual(await id.openIdentityBlob(cc, me, H(revision1.sealed)), revision1.plaintext);
  assert.deepEqual(await id.openIdentityBlob(cc, me, H(revision2.sealed)), revision2.plaintext);
  assert.equal(revision1.plaintext.revision, 1);
  assert.equal(revision2.plaintext.revision, 2);
  // The package's own keys in the plaintext are the account's.
  assert.equal(revision1.plaintext.identityPublicKey, cc.toBase64Url(me.identity.publicKeyRaw));
  assert.equal(revision1.plaintext.identitySigningKey, cc.toBase64Url(me.identitySigning.publicKeyRaw));
  assert.deepEqual(revision1.plaintext.sealingKey, fx.identity.sealingKeyJwk);
  await assert.rejects(id.openIdentityBlob(cc, me, H(revision1.sealed), { minRevision: 2 }), (e) => e.code === id.IDENTITY_BLOB_ROLLED_BACK);
  await assert.rejects(id.openIdentityBlob(cc, me, flip(revision2.sealed, 40)), (e) => e.code === id.IDENTITY_BLOB_UNREADABLE);
  const other = await id.createIdentity(cc);
  await assert.rejects(id.openIdentityBlob(cc, { ...me, routing: other.routing }, H(revision2.sealed)), (e) => e.code === id.IDENTITY_BLOB_UNREADABLE, 'moved to another account');
});

test('the trusted-device session records open through the session store; an edited expiry or generation refuses (FORMATS.md §2.4)', async () => {
  async function storeWith(entry, edit = (r) => r) {
    const store = id.memoryStore();
    const rec = edit({ ...entry.record, sessionKey: await cc.importSymmetricKey(H(fx.session.sessionKey)), wrappedRootKey: H(entry.record.wrappedRootKey) });
    await store.put(entry.storeKey, rec);
    return { store, sessions: id.createSessionStore({ cryptoCore: cc, store, lockIntervalStorage: id.memoryStorage() }) };
  }
  const { thirtyDays, thirtyMinutes } = fx.session;
  assert.equal(thirtyDays.record.v, id.SESSION_RECORD_VERSION);
  assert.equal(thirtyDays.record.expiresAt - thirtyDays.record.unlockedAt, id.SESSION_DAYS * 24 * 60 * 60 * 1000);
  assert.equal(thirtyMinutes.record.expiresAt - thirtyMinutes.record.unlockedAt, id.LOCK_INTERVALS['30-min']);
  for (const entry of [thirtyDays, thirtyMinutes]) {
    const { sessions } = await storeWith(entry);
    const got = await sessions.loadSession({ now: entry.record.unlockedAt + 1000 });
    assert.ok(got, 'the frozen record opens');
    assert.equal(cc.toHex(got.rootKey), fx.identity.rootKey);
    assert.equal(got.routingPublicKey, fx.identity.routingHandle);
    assert.equal(got.sessionGeneration, entry.record.sessionGeneration);
    assert.equal(got.expiresAt, entry.record.expiresAt);
  }
  for (const edit of [
    (r) => ({ ...r, expiresAt: r.expiresAt + 1 }),                          // pushed forward: the context refuses it
    (r) => ({ ...r, sessionGeneration: 99 }),                               // raised to defeat "sign out everywhere"
    (r) => ({ ...r, routingPublicKey: cc.toBase64Url(new Uint8Array(32)) }),
    (r) => ({ ...r, wrappedRootKey: flip(thirtyDays.record.wrappedRootKey, 20) }),
    (r) => ({ ...r, v: 1 }),
  ]) {
    const { store, sessions } = await storeWith(thirtyDays, edit);
    assert.equal(await sessions.loadSession({ now: thirtyDays.record.unlockedAt + 1000 }), null);
    assert.equal(await store.get(thirtyDays.storeKey), undefined, 'a record that will not open is deleted');
  }
  const { sessions } = await storeWith(thirtyDays);
  assert.equal(await sessions.loadSession({ now: thirtyDays.record.expiresAt }), null, 'expired');
});

test('the handshake: the package sends the frozen auth message byte for byte, and it verifies for its origin only (FORMATS.md §2.5)', async () => {
  const me = await frozenAccount();
  const [client, server] = socketPair();
  server.addEventListener('message', () => server.send(JSON.stringify({ type: 'auth-ok', hasAccount: false })));
  await id.respondToChallenge(cc, client, H(fx.handshake.nonce), me.routing, fx.handshake.origin);
  client.close();
  // Ed25519 is deterministic (RFC 8032 §5.1.6): the same key, origin and nonce give the same signature.
  assert.deepEqual(JSON.parse(client.sent[0]), fx.handshake.wire);
  const signature = cc.fromBase64Url(fx.handshake.wire.signature);
  const routing = cc.fromBase64Url(fx.handshake.wire.routingPublicKey);
  assert.equal(await id.verifyAuthSignature(cc, routing, fx.handshake.origin, H(fx.handshake.nonce), signature), true);
  assert.equal(await id.verifyAuthSignature(cc, routing, 'https://other.example.test', H(fx.handshake.nonce), signature), false, 'another origin');
  assert.equal(await cc.verifyBytes(routing, H(fx.handshake.nonce), signature), false, 'not a signature over the bare nonce');
  const other = createCryptoCore({ namespace: 'other' });
  assert.equal(await id.verifyAuthSignature(other, routing, fx.handshake.origin, H(fx.handshake.nonce), signature), false, 'the namespace is in the label');
});
