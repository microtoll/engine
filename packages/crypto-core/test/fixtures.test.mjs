// Frozen fixtures: bytes an earlier version of this package wrote
// (test/tooling/generate-frozen-fixtures.mjs, never regenerated), which every
// later version must open and reproduce. A changed label, version byte,
// parameter or layout fails here instead of silently making stored data
// unreadable. Fixtures for the identity, access and mailbox layers are stored
// here too and consumed by those packages' tests.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCryptoCore } from '../src/index.js';
import { installPqShim } from './tooling/pq-test-shim.mjs';

const fx = JSON.parse(readFileSync(new URL('./fixtures/frozen-v1.json', import.meta.url), 'utf8'));
const cc = createCryptoCore({ namespace: fx.namespace });
const H = cc.fromHex;

test('the profile reproduces every frozen label and parameter', () => {
  assert.equal(cc.label('routing'), fx.labels.routing);
  assert.equal(cc.label('identity-sign'), fx.labels.identitySign);
  assert.equal(cc.label('symm'), fx.labels.symm);
  assert.equal(cc.label('identity-kem'), fx.labels.identityKem);
  assert.equal(cc.label('envelope/prf'), fx.labels.envelopePrf);
  assert.equal(cc.label('recovery-lookup'), fx.labels.recoveryLookup);
  assert.equal(cc.profile.eciesV3, fx.labels.eciesV3);
  assert.equal(cc.profile.eciesV2, fx.labels.eciesV2);
  assert.equal(cc.label('read'), fx.labels.read);
  assert.equal(cc.label('detail-grant'), fx.labels.detailGrant);
  assert.equal(cc.label('url-invite'), fx.labels.urlInvite);
  assert.equal(cc.label('invite-mailbox', 2), fx.labels.inviteMailbox);
  assert.equal(cc.profile.pbkdf2Iterations, fx.constants.pbkdf2Iterations);
  assert.equal(cc.RECOVERY_CODE_ENTROPY_BYTES, fx.constants.recoveryCodeEntropyBytes);
  assert.equal(cc.RECOVERY_CODE_GROUP_SIZE, fx.constants.recoveryCodeGroupSize);
});

test('frozen AEAD v1 blobs open, with and without AAD, including the empty plaintext', async () => {
  const key = await cc.importSymmetricKey(H(fx.aeadV1.key));
  assert.equal(cc.toHex(await cc.openSymmetric(key, H(fx.aeadV1.sealed))), fx.aeadV1.plaintext);
  assert.equal(cc.toHex(await cc.openSymmetric(key, H(fx.aeadV1.sealedWithAad), H(fx.aeadV1.aad))), fx.aeadV1.plaintext);
  await assert.rejects(cc.openSymmetric(key, H(fx.aeadV1.sealedWithAad)), 'AAD must be supplied');
  assert.equal((await cc.openSymmetric(key, H(fx.aeadV1.sealedEmpty))).length, 0);
});

test('labelled derivations from a fixed root are unchanged: routing key, signing key, K_master_symm, signatures', async () => {
  const root = H(fx.derivations.root);
  const routingSeed = await cc.deriveBits(root, 'routing');
  const routingPriv = await cc.importEd25519PrivateKeyFromSeed(routingSeed);
  assert.equal(cc.toHex(await cc.exportPublicKeyRawFromPrivate(routingPriv)), fx.derivations.routingPublicKey);
  assert.equal(cc.toBase64Url(H(fx.derivations.routingPublicKey)), fx.derivations.routingHandle);
  // Ed25519 is deterministic (RFC 8032 §5.1.6), so the signature over the fixed nonce is reproduced exactly.
  assert.equal(cc.toHex(await cc.signBytes(routingPriv, H(fx.derivations.nonce))), fx.derivations.nonceSignature);

  const signingSeed = await cc.deriveBits(root, 'identity-sign');
  const signingPriv = await cc.importEd25519PrivateKeyFromSeed(signingSeed);
  const signingPub = await cc.exportPublicKeyRawFromPrivate(signingPriv);
  assert.equal(cc.toHex(signingPub), fx.derivations.identitySigningPublicKey);
  assert.equal(cc.toHex(await cc.signBytes(signingPriv, H(fx.derivations.identitySignedMessage))), fx.derivations.identitySignature);
  assert.equal(await cc.verifyBytes(signingPub, H(fx.derivations.identitySignedMessage), H(fx.derivations.identitySignature)), true);

  const masterSymm = await cc.deriveAesKey(root, 'symm');
  assert.equal(cc.toHex(await cc.openSymmetric(masterSymm, H(fx.derivations.masterSymmSealed))), fx.derivations.masterSymmPlaintext);

  assert.equal(cc.toHex(await cc.deriveBits(root, 'read')), fx.derivations.readCapabilityOfRoot);
  assert.equal(cc.toHex(await cc.deriveBits(root.slice(0, 16), 'recovery-lookup')), fx.derivations.recoveryLookupHashOfRootPrefix);
});

test('a frozen ECIES v3 blob sealed to a stored P-256 key opens with the same JWK', async () => {
  const alice = await cc.importSealingKeyPair(fx.eciesV3.recipientJwk);
  assert.equal(cc.toHex(alice.publicKeyRaw), fx.eciesV3.recipientPublicKey);
  assert.equal(cc.toHex(await cc.openWithPrivateKey(alice, H(fx.eciesV3.sealed))), fx.eciesV3.plaintext);
  assert.equal(cc.toHex(await cc.openWithPrivateKey(alice, H(fx.eciesV3.sealedViaDispatch))), fx.eciesV3.plaintext);
  assert.equal(H(fx.eciesV3.sealed)[0], cc.ECIES_VERSION_3);
});

test('recovery codes version 3 (D-46): every frozen code parses to its bytes, and the bytes format to the same code', async () => {
  const v3 = JSON.parse(readFileSync(new URL('./fixtures/frozen-recovery-v3.json', import.meta.url), 'utf8'));
  assert.equal(v3.version, 3);
  assert.equal(v3.codes.length, 8);
  for (const { name, bytes, code } of v3.codes) {
    assert.equal(await cc.formatRecoveryCode(H(bytes)), code, name);
    assert.equal(await cc.formatRecoveryCode(H(bytes), { version: 3 }), code, name);
    assert.equal(cc.toHex(await cc.parseRecoveryCode(code)), bytes, name);
    assert.equal(cc.toHex(await cc.parseRecoveryCode(code.toLowerCase().replace(/-/g, ' '))), bytes, `${name}, as typed`);
  }
});

test('the recovery-code envelope: PBKDF2 with the profile iterations unwraps the frozen root key', async () => {
  // Identity-layer fixture, but its two primitives (PBKDF2 → AEAD v1) are crypto-core's.
  // The display string was written as a version-2 code (D-26); since D-46 it
  // is read only when version 2 is asked for by name.
  assert.equal(await cc.formatRecoveryCode(H(fx.envelopes.recoveryCodeBytes), { version: 2 }), fx.envelopes.recoveryCodeDisplay);
  assert.equal(cc.toHex(await cc.parseRecoveryCode(fx.envelopes.recoveryCodeDisplay, { version: 2 })), fx.envelopes.recoveryCodeBytes);
  const unwrapKey = await cc.deriveAesKeyFromSecret(H(fx.envelopes.recoveryCodeBytes), H(fx.envelopes.pbkdf2Salt));
  assert.equal(cc.toHex(await cc.openSymmetric(unwrapKey, H(fx.envelopes.wrappedByRecoveryCode))), fx.envelopes.rootKey);
  const prfKey = await cc.deriveAesKey(H(fx.envelopes.prfOutput), 'envelope/prf');
  assert.equal(cc.toHex(await cc.openSymmetric(prfKey, H(fx.envelopes.wrappedByPrf))), fx.envelopes.rootKey);
  assert.equal(cc.toHex(await cc.deriveBits(H(fx.envelopes.recoveryCodeBytes), 'recovery-lookup')), fx.envelopes.recoveryLookupHash);
});

test('the URL-token payload key (access layer) is the labelled derivation of the UTF-8 token', async () => {
  const key = await cc.deriveAesKey(new TextEncoder().encode(fx.access.urlToken), 'url-invite');
  assert.equal(cc.toHex(await cc.openSymmetric(key, H(fx.access.urlTokenSealed))), fx.access.urlTokenPlaintext);
  assert.equal(cc.toHex(await cc.sha256(new TextEncoder().encode(fx.access.urlToken))), fx.access.urlTokenHash);
  assert.equal(cc.toHex(await cc.deriveBits(H(fx.access.kEvent), 'read')), fx.access.readCapability);
  assert.equal(cc.toHex(await cc.sha256(H(fx.access.readCapability))), fx.access.readCapabilityHash);
});

test('the detail-grant label pins the literal NUL byte: label ‖ 0x00 ‖ SHA-256(recipient key)', async () => {
  const alice = await cc.importSealingKeyPair(fx.eciesV3.recipientJwk);
  const info = cc.concatBytes(new TextEncoder().encode(cc.label('detail-grant')), new Uint8Array([0]), await cc.sha256(alice.publicKeyRaw));
  const label = cc.toBase64Url(await cc.hkdfDeriveBits(H(fx.access.kEvent), new Uint8Array(0), info, 256));
  assert.equal(label, fx.access.detailGrantLabelForAlice);
});

// --- v2 through the shim ----------------------------------------------------
let uninstall;
before(() => { uninstall = installPqShim(); });
after(() => uninstall && uninstall());

test('a frozen ECIES v2 blob (sealed through the test shim) opens with the KEM key from the same seed', async () => {
  const cc2 = createCryptoCore({ namespace: fx.namespace, hybridSealing: true });
  const kem = await cc2.kemKeyPairFromSeed(H(fx.eciesV2.seed));
  assert.equal(cc2.toHex(kem.publicKeyRaw), fx.eciesV2.recipientPublicKey);
  assert.equal(cc2.toHex(await cc2.openWithKemPrivateKey(kem.privateKey, H(fx.eciesV2.sealed))), fx.eciesV2.plaintext);
  const identityKem = await cc2.kemKeyPairFromSeed(await cc2.deriveBits(H(fx.derivations.root), 'identity-kem'));
  assert.equal(cc2.toHex(identityKem.publicKeyRaw), fx.eciesV2.identityKemPublicKeyOfRoot);
});
