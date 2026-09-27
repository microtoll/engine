// Writes test/fixtures/frozen-v1.json ONCE, and then never again.
//
//   node packages/crypto-core/test/tooling/generate-frozen-fixtures.mjs
//
// The file holds bytes this version of the engine wrote, under the test
// namespace "example", and every later version must open and reproduce
// them: a change to a label, a version byte, a parameter or a layout turns a
// test red instead of silently making stored data unreadable. It refuses to
// overwrite the file. A NEW format gets a new entry added beside the old ones
// (or a new file), never a regenerated one: the old entries are what prove
// old data still opens.
//
// Fixtures for the identity, access and mailbox layers live here too, because
// their primitives are crypto-core's; those packages' tests read this file.
// Every key in it is a throwaway made for this file.
//
// The calls below are the API as it stood when the file was written: the
// recovery code was then version 2, so `formatRecoveryCode(codeBytes)` wrote
// a version-2 code, which is `formatRecoveryCode(codeBytes, { version: 2 })`
// since D-46. The script refuses to run once the file exists, so it is kept
// as the record of how the bytes were made, not updated.
import { existsSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '../../src/index.js';
import { installPqShim } from './pq-test-shim.mjs';
import { mailboxId, pollEpochs, pushEpochs } from '../../../mailbox/src/labels.js';

const OUT = fileURLToPath(new URL('../fixtures/frozen-v1.json', import.meta.url));
if (existsSync(OUT)) {
  console.error(`${OUT} exists and is frozen. Nothing was written.`);
  process.exit(1);
}

const NAMESPACE = 'example';
const cc = createCryptoCore({ namespace: NAMESPACE });
const hex = cc.toHex;
const utf8 = (s) => new TextEncoder().encode(s);
const ROOT = Uint8Array.from({ length: 32 }, (_, i) => i);          // 00 01 … 1f
const ROOT2 = Uint8Array.from({ length: 32 }, (_, i) => 0xff - i);  // ff fe … e0
const KEY = Uint8Array.from({ length: 32 }, (_, i) => 0x40 + i);
const AAD = cc.frameContext(cc.label('fixture'), cc.uuidBytes('123e4567-e89b-12d3-a456-426614174000'), cc.u32be(3));

const out = {
  source: `Frozen by test/tooling/generate-frozen-fixtures.mjs on 2026-09-27 under namespace "${NAMESPACE}". Never regenerated or edited.`,
  namespace: NAMESPACE,
  labels: {
    routing: cc.label('routing'), identitySign: cc.label('identity-sign'), symm: cc.label('symm'),
    identityKem: cc.label('identity-kem'), envelopePrf: cc.label('envelope/prf'), recoveryLookup: cc.label('recovery-lookup'),
    eciesV3: cc.profile.eciesV3, eciesV2: cc.profile.eciesV2, read: cc.label('read'), detailGrant: cc.label('detail-grant'),
    urlInvite: cc.label('url-invite'), inviteMailbox: cc.label('invite-mailbox', 2),
  },
  constants: {
    pbkdf2Iterations: cc.profile.pbkdf2Iterations, pbkdf2SaltBytes: 16,
    recoveryCodeEntropyBytes: cc.RECOVERY_CODE_ENTROPY_BYTES, recoveryCodeGroupSize: cc.RECOVERY_CODE_GROUP_SIZE,
    capabilitySecretBytes: 32,
  },
};

// --- AEAD v1 --------------------------------------------------------------
const aeadKey = await cc.importSymmetricKey(KEY);
out.aeadV1 = {
  key: hex(KEY),
  plaintext: hex(utf8('the engine wrote this under AEAD v1')),
  sealed: hex(await cc.sealSymmetric(aeadKey, utf8('the engine wrote this under AEAD v1'))),
  aad: hex(AAD),
  sealedWithAad: hex(await cc.sealSymmetric(aeadKey, utf8('the engine wrote this under AEAD v1'), AAD)),
  sealedEmpty: hex(await cc.sealSymmetric(aeadKey, new Uint8Array(0))),
};

// --- Labelled derivations from a fixed root --------------------------------
async function ed25519(seed) {
  const privateKey = await cc.importEd25519PrivateKeyFromSeed(seed);
  return { privateKey, publicKeyRaw: await cc.exportPublicKeyRawFromPrivate(privateKey) };
}
const routing = await ed25519(await cc.deriveBits(ROOT, 'routing'));
const signing = await ed25519(await cc.deriveBits(ROOT, 'identity-sign'));
const masterSymm = await cc.deriveAesKey(ROOT, 'symm');
const NONCE = Uint8Array.from({ length: 32 }, (_, i) => 0xa0 + i);
out.derivations = {
  root: hex(ROOT),
  routingPublicKey: hex(routing.publicKeyRaw),
  routingHandle: cc.toBase64Url(routing.publicKeyRaw),
  identitySigningPublicKey: hex(signing.publicKeyRaw),
  nonce: hex(NONCE),
  nonceSignature: hex(await cc.signBytes(routing.privateKey, NONCE)),
  identitySignature: hex(await cc.signBytes(signing.privateKey, utf8('signed by the identity key'))),
  identitySignedMessage: hex(utf8('signed by the identity key')),
  masterSymmSealed: hex(await cc.sealSymmetric(masterSymm, utf8('sealed under K_master_symm'))),
  masterSymmPlaintext: hex(utf8('sealed under K_master_symm')),
  recoveryLookupHashOfRootPrefix: hex(await cc.deriveBits(ROOT.slice(0, 16), 'recovery-lookup')),
  readCapabilityOfRoot: hex(await cc.deriveBits(ROOT, 'read')),
};

// --- ECIES v3 ------------------------------------------------------------
const alice = await cc.generateSealingKeyPair();
out.eciesV3 = {
  recipientJwk: alice.jwk,
  recipientPublicKey: hex(alice.publicKeyRaw),
  plaintext: hex(utf8('sealed to Alice under ECIES v3')),
  sealed: hex(await cc.sealToPublicKey(alice.publicKeyRaw, utf8('sealed to Alice under ECIES v3'))),
  sealedViaDispatch: hex(await cc.sealToRecipient(alice.publicKeyRaw, utf8('sealed to Alice under ECIES v3'))),
};

// --- Root-key envelopes at the primitive level (identity's unwrap keys) ----
// No additional data here: these pin the two unwrap-key derivations. The
// identity package's own bound envelopes are frozen by its own tests.
const PRF = Uint8Array.from({ length: 32 }, (_, i) => 0x70 + i);
const SALT = Uint8Array.from({ length: 16 }, (_, i) => 0x50 + i);
const codeBytes = Uint8Array.from({ length: 16 }, (_, i) => (i * 37) & 0xff);
out.envelopes = {
  rootKey: hex(ROOT2),
  prfOutput: hex(PRF),
  wrappedByPrf: hex(await cc.sealSymmetric(await cc.deriveAesKey(PRF, 'envelope/prf'), ROOT2)),
  recoveryCodeBytes: hex(codeBytes),
  recoveryCodeDisplay: await cc.formatRecoveryCode(codeBytes),
  pbkdf2Salt: hex(SALT),
  wrappedByRecoveryCode: hex(await cc.sealSymmetric(await cc.deriveAesKeyFromSecret(codeBytes, SALT), ROOT2)),
  recoveryLookupHash: hex(await cc.deriveBits(codeBytes, 'recovery-lookup')),
};

// --- Access-layer derivations and the mailbox label ------------------------
const K_OBJECT = Uint8Array.from({ length: 32 }, (_, i) => 0x90 + i);
const bob = await cc.generateSealingKeyPair();
const TOKEN = 'fixture-url-token-AbC123_-xyz';
const readCapability = await cc.deriveBits(K_OBJECT, 'read');
const grantInfo = cc.concatBytes(utf8(cc.label('detail-grant')), new Uint8Array([0]), await cc.sha256(alice.publicKeyRaw));
out.access = {
  kEvent: hex(K_OBJECT),
  readCapability: hex(readCapability),
  readCapabilityHash: hex(await cc.sha256(readCapability)),
  detailGrantLabelForAlice: cc.toBase64Url(await cc.hkdfDeriveBits(K_OBJECT, new Uint8Array(0), grantInfo, 256)),
  urlToken: TOKEN,
  urlTokenHash: hex(await cc.sha256(utf8(TOKEN))),
  urlTokenSealed: hex(await cc.sealSymmetric(await cc.deriveAesKey(utf8(TOKEN), 'url-invite'), utf8('link payload'))),
  urlTokenPlaintext: hex(utf8('link payload')),
};
out.mailbox = {
  aliceJwk: alice.jwk, bobJwk: bob.jwk,
  epoch: '2026-09',
  labelAliceToBob: hex(await mailboxId(cc, alice.privateKey, bob.publicKeyRaw, alice.publicKeyRaw, bob.publicKeyRaw, '2026-09')),
  pollEpochsOn20260915: pollEpochs(new Date(Date.UTC(2026, 8, 15))),
  pushEpochsOn20260915: pushEpochs(new Date(Date.UTC(2026, 8, 15))),
};

// --- ECIES v2, through the test-only platform shim --------------------------
const uninstall = installPqShim();
const pq = createCryptoCore({ namespace: NAMESPACE, hybridSealing: true });
const SEED = Uint8Array.from({ length: 32 }, (_, i) => 0x30 + i);
const kem = await pq.kemKeyPairFromSeed(SEED);
if (!kem) throw new Error('the shim did not provide the hybrid KEM');
out.eciesV2 = {
  seed: hex(SEED),
  recipientPublicKey: hex(kem.publicKeyRaw),
  plaintext: hex(utf8('sealed under the hybrid ECIES v2')),
  sealed: hex(await pq.sealToKemPublicKey(kem.publicKeyRaw, utf8('sealed under the hybrid ECIES v2'))),
  identityKemPublicKeyOfRoot: hex((await pq.kemKeyPairFromSeed(await pq.deriveBits(ROOT, 'identity-kem'))).publicKeyRaw),
};
uninstall();

writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log('wrote', OUT, Object.keys(out).join(', '));
