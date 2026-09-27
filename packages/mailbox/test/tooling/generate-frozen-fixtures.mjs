// Writes test/fixtures/frozen-v2.json ONCE, and then never again.
//
//   node packages/mailbox/test/tooling/generate-frozen-fixtures.mjs
//
// The file holds version-2 bundles this package wrote (FORMATS.md §2), under
// the test namespace "example": every later version must open them and
// reproduce their signatures, so a changed label, version byte, parameter or
// layout turns test/fixtures.test.mjs red instead of silently dropping
// invitations. It refuses to overwrite the file. A NEW format gets a new
// entry beside the old ones (or a new file), never a regenerated one.
//
// The pairwise label (FORMATS.md §1) is NOT stored here: crypto-core's frozen
// file already pins it, with Alice's and Bob's sealing keys, in its `mailbox`
// section. This file names that section and builds on those keys; the test
// reads both files. The signing keys come from fixed roots. Bundles are
// ECIES seals with random ephemeral keys, so they are stored and must open;
// the signatures inside are Ed25519 and so reproduce exactly. The hybrid
// bundle goes through crypto-core's test-only platform shim, as crypto-core's
// own frozen fixtures do. Every key here is a throwaway.
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import { identityFromRootKey, adoptSealingKey } from '@microtoll/identity';
import { installPqShim } from '../../../crypto-core/test/tooling/pq-test-shim.mjs';
import * as mb from '../../src/index.js';

const OUT = fileURLToPath(new URL('../fixtures/frozen-v2.json', import.meta.url));
if (existsSync(OUT)) {
  console.error(`${OUT} exists and is frozen. Nothing was written.`);
  process.exit(1);
}

const LABEL_FILE = 'packages/crypto-core/test/fixtures/frozen-v1.json';
const v1 = JSON.parse(readFileSync(new URL('../../../crypto-core/test/fixtures/frozen-v1.json', import.meta.url), 'utf8'));
const NAMESPACE = v1.namespace;
if (NAMESPACE !== 'example') throw new Error('the label fixture is not under the test namespace');
const cc = createCryptoCore({ namespace: NAMESPACE });
const hex = cc.toHex;
const text = (b) => new TextDecoder().decode(b);

// Fixed inputs.
const ALICE_ROOT = Uint8Array.from({ length: 32 }, (_, i) => 0x0a + i);
const BOB_ROOT = Uint8Array.from({ length: 32 }, (_, i) => 0xb0 + i);
const OBJECT_ID = '7a8b9cad-becf-4d0e-9f1a-2b3c4d5e6f70';
const K_OBJECT = Uint8Array.from({ length: 32 }, (_, i) => 0xe0 - i);
const HASHED_TOKEN = 'ab'.repeat(32);

/** An account from a fixed root, with the sealing key crypto-core's label fixture holds for it. */
async function account(core, root, sealingKeyJwk) {
  const identity = await identityFromRootKey(core, root);
  await adoptSealingKey(core, identity, { sealingKey: sealingKeyJwk });
  return identity;
}
const alice = await account(cc, ALICE_ROOT, v1.mailbox.aliceJwk);
const bob = await account(cc, BOB_ROOT, v1.mailbox.bobJwk);

// The mailbox Alice writes to Bob under: crypto-core's frozen label, recomputed.
const mailbox = await mb.mailboxForSending(cc, alice, bob.identity.publicKeyRaw, v1.mailbox.epoch);
if (hex(mailbox) !== v1.mailbox.labelAliceToBob) throw new Error('the mailbox label no longer matches the crypto-core fixture');

/** A bundle, what it carries inside (read with the recipient's key, to record it), and the bytes its signature covers. */
async function frozenBundle(core, sealed, recipientKeyRaw, open) {
  const envelope = text(await open(sealed));
  return {
    recipientKeyHash: hex(await core.sha256(recipientKeyRaw)),
    signedMessage: hex(await mb.inviteSigningMessage(core, mailbox, recipientKeyRaw, JSON.parse(envelope).payloadJson)),
    envelope,
    sealed: hex(sealed),
  };
}

const out = {
  source: `Frozen by test/tooling/generate-frozen-fixtures.mjs on 2026-09-27 under namespace "${NAMESPACE}". Never regenerated or edited.`,
  namespace: NAMESPACE,
  labels: { inviteSignature: cc.label('sig/invite', 2) },
  bundleVersion: mb.BUNDLE_VERSION,
  // Where the pairwise label, the epoch and both sealing keys are frozen. Not copied here.
  mailbox: {
    file: LABEL_FILE,
    section: 'mailbox',
    label: 'labelAliceToBob',
    epoch: 'epoch',
    senderSealingKey: 'aliceJwk',
    recipientSealingKey: 'bobJwk',
  },
  accounts: {
    alice: { rootKey: hex(ALICE_ROOT), identitySigningPublicKey: hex(alice.identitySigning.publicKeyRaw) },
    bob: { rootKey: hex(BOB_ROOT), identitySigningPublicKey: hex(bob.identitySigning.publicKeyRaw) },
  },
  objectId: OBJECT_ID,
  kObject: hex(K_OBJECT),
};

// --- an invitation and an acknowledgement, Alice to Bob, sealed to Bob's P-256 key (ECIES v3)
const openAsBob = (sealed) => cc.openWithPrivateKey(bob.identity, sealed);
out.invite = await frozenBundle(cc, await mb.buildInvite(cc, alice, bob.identity.publicKeyRaw, {
  mailboxId: mailbox, objectId: OBJECT_ID, kObjectRaw: K_OBJECT, keyEpoch: 3, senderName: 'Alice', claims: { greeting: 'hello' },
}), bob.identity.publicKeyRaw, openAsBob);
out.ack = await frozenBundle(cc, await mb.buildAck(cc, alice, bob.identity.publicKeyRaw, {
  mailboxId: mailbox, objectId: OBJECT_ID, senderName: 'Alice', hashedToken: HASHED_TOKEN, stage: 'seen',
}), bob.identity.publicKeyRaw, openAsBob);

// --- hybrid: the same invitation sealed to Bob's KEM key (ECIES v2) -------------
// Bob's KEM key is derived from his root, so it reproduces; the signature binds
// ITS hash, not the P-256 key's.
const uninstall = installPqShim();
const pq = createCryptoCore({ namespace: NAMESPACE, hybridSealing: true });
const bobPq = await account(pq, BOB_ROOT, v1.mailbox.bobJwk);
if (!bobPq.identityKem) throw new Error('the shim did not provide the hybrid KEM');
out.accounts.bob.identityKemPublicKey = hex(bobPq.identityKem.publicKeyRaw);
out.hybridInvite = await frozenBundle(pq, await mb.buildInvite(pq, alice, bobPq.identityKem.publicKeyRaw, {
  mailboxId: mailbox, objectId: OBJECT_ID, kObjectRaw: K_OBJECT, keyEpoch: 3, senderName: 'Alice', claims: { greeting: 'hello' },
}), bobPq.identityKem.publicKeyRaw, (sealed) => pq.openWithKemPrivateKey(bobPq.identityKem.privateKey, sealed));
uninstall();

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log('wrote', OUT, Object.keys(out).join(', '));
