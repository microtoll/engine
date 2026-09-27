// The version 2 bundle: sealed to the recipient, signed with the mailbox
// and the recipient bound in. The adversarial cases are re-sealing ones (a
// contact passing on somebody else's signed invitation as the signer's): a
// bundle re-sealed into another mailbox, or for another recipient, or with
// a changed payload, verifies for nobody.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '@microtoll/identity';
import { createMailbox, inviteSigningMessage, BUNDLE_VERSION } from '../src/index.js';

const cc = createCryptoCore({ namespace: 'testapp' });
const m = createMailbox({ cryptoCore: cc });
const objectId = '11111111-2222-4333-8444-555555555555';

async function pair() {
  const alice = await id.createIdentity(cc);
  const bob = await id.createIdentity(cc);
  const mailbox = await m.mailboxForSending(alice, bob.identity.publicKeyRaw, '2026-09');
  return { alice, bob, mailbox };
}

test('an invitation round-trips: the key, the epoch, the name, the claims, all verified', async () => {
  const { alice, bob, mailbox } = await pair();
  const kObjectRaw = cc.generateSymmetricKey();
  const sealed = await m.buildInvite(alice, bob.identity.publicKeyRaw, { mailboxId: mailbox, objectId, kObjectRaw, keyEpoch: 3, senderName: 'Alice', claims: { greeting: 'hello' } });
  assert.equal(sealed[0], cc.ECIES_VERSION_3);
  const opened = await m.openBundle(bob, mailbox, sealed);
  assert.equal(opened.verified, true);
  assert.equal(opened.kind, 'invite');
  assert.equal(opened.objectId, objectId);
  assert.equal(cc.toHex(opened.kObjectRaw), cc.toHex(kObjectRaw));
  assert.equal(opened.keyEpoch, 3);
  assert.equal(opened.senderName, 'Alice');
  assert.deepEqual(opened.claims, { greeting: 'hello' });
  assert.equal(cc.toHex(opened.senderSigningKeyRaw), cc.toHex(alice.identitySigning.publicKeyRaw));
  assert.equal(cc.toHex(opened.senderIdentityKeyRaw), cc.toHex(alice.identity.publicKeyRaw));
});

test('re-sealing: the same bundle in another mailbox, or re-sealed to another recipient, or with a changed payload, is unverified -- usable, but nobody\'s', async () => {
  const { alice, bob, mailbox } = await pair();
  const kObjectRaw = cc.generateSymmetricKey();
  const sealed = await m.buildInvite(alice, bob.identity.publicKeyRaw, { mailboxId: mailbox, objectId, kObjectRaw, keyEpoch: 1, senderName: 'Alice', claims: { greeting: 'hello' } });
  // Another mailbox (Bob forwards Alice's drop into a mailbox he shares with Carol, re-sealed to Carol).
  const carol = await id.createIdentity(cc);
  const bobToCarol = await m.mailboxForSending(bob, carol.identity.publicKeyRaw, '2026-09');
  const plaintext = await cc.openWithPrivateKey(bob.identity, sealed);           // Bob can read what was sent to him...
  const resealed = await cc.sealToRecipient(carol.identity.publicKeyRaw, plaintext); // ...and seal the same envelope to Carol
  const atCarol = await m.openBundle(carol, bobToCarol, resealed);
  assert.equal(atCarol.verified, false);
  assert.equal(atCarol.senderName, null);
  assert.equal(atCarol.senderSigningKeyRaw, null);
  assert.deepEqual(atCarol.claims, {});
  assert.equal(cc.toHex(atCarol.kObjectRaw), cc.toHex(kObjectRaw), 'the key is still there; the attribution is not');
  // The right recipient, but presented as another mailbox's drop.
  const wrongMailbox = await m.openBundle(bob, await m.mailboxForSending(alice, bob.identity.publicKeyRaw, '2026-10'), sealed);
  assert.equal(wrongMailbox.verified, false);
  // A changed payload under the original signature.
  const outer = JSON.parse(new TextDecoder().decode(plaintext));
  const forged = { ...outer, payloadJson: outer.payloadJson.replace('"Alice"', '"Mallory"') };
  const forgedSealed = await cc.sealToRecipient(bob.identity.publicKeyRaw, new TextEncoder().encode(JSON.stringify(forged)));
  assert.equal((await m.openBundle(bob, mailbox, forgedSealed)).verified, false);
  // Sealed to somebody else entirely: cannot even be opened.
  await assert.rejects(m.openBundle(carol, mailbox, sealed));
});

test('an acknowledgement carries no key, names the link and the stage, and is verified the same way', async () => {
  const { alice, bob, mailbox } = await pair();
  const ackMailbox = await m.mailboxForSending(bob, alice.identity.publicKeyRaw, '2026-09');
  const sealed = await m.buildAck(bob, alice.identity.publicKeyRaw, { mailboxId: ackMailbox, objectId, senderName: 'Bob', hashedToken: 'ab'.repeat(32), stage: 'seen' });
  const opened = await m.openBundle(alice, ackMailbox, sealed);
  assert.equal(opened.kind, 'invite-ack');
  assert.equal(opened.verified, true);
  assert.equal(opened.kObjectRaw, null);
  assert.equal(opened.keyEpoch, null);
  assert.equal(opened.hashedToken, 'ab'.repeat(32));
  assert.equal(opened.stage, 'seen');
  assert.equal(opened.senderName, 'Bob');
  assert.equal((await m.openBundle(alice, mailbox, sealed)).verified, false, 'an ack in the wrong mailbox');
});

test('a version 1 bundle (payload signed alone, v: 1) is not read; a claim cannot shadow a bundle field', async () => {
  const { alice, bob, mailbox } = await pair();
  const payloadJson = JSON.stringify({ kind: 'invite', objectId, kObject: cc.toBase64Url(cc.generateSymmetricKey()), keyEpoch: 1, senderSigningKey: cc.toBase64Url(alice.identitySigning.publicKeyRaw) });
  const sig = await cc.signBytes(alice.identitySigning.privateKey, new TextEncoder().encode(payloadJson));
  const v1 = await cc.sealToRecipient(bob.identity.publicKeyRaw, new TextEncoder().encode(JSON.stringify({ v: 1, payloadJson, sig: cc.toBase64Url(sig) })));
  await assert.rejects(m.openBundle(bob, mailbox, v1), /version 2/);
  await assert.rejects(m.buildInvite(alice, bob.identity.publicKeyRaw, { mailboxId: mailbox, objectId, kObjectRaw: cc.generateSymmetricKey(), keyEpoch: 1, claims: { senderName: 'x' } }), /bundle field/);
  assert.equal(BUNDLE_VERSION, 2);
});

test('the signed bytes: the purpose label, the mailbox id and the recipient key hash, then the payload', async () => {
  const { alice, bob, mailbox } = await pair();
  const payloadJson = '{"kind":"invite"}';
  const message = await inviteSigningMessage(cc, mailbox, bob.identity.publicKeyRaw, payloadJson);
  const label = new TextEncoder().encode('testapp/sig/invite/v2');
  assert.equal(message.length, label.length + 1 + 32 + 32 + payloadJson.length);
  assert.equal(new TextDecoder().decode(message.subarray(0, label.length)), 'testapp/sig/invite/v2');
  assert.equal(message[label.length], 0);
  assert.equal(cc.toHex(message.subarray(label.length + 1, label.length + 33)), cc.toHex(mailbox));
  assert.equal(cc.toHex(message.subarray(label.length + 33, label.length + 65)), cc.toHex(await cc.sha256(bob.identity.publicKeyRaw)));
  assert.equal(new TextDecoder().decode(message.subarray(label.length + 65)), payloadJson);
  await assert.rejects(inviteSigningMessage(cc, new Uint8Array(31), bob.identity.publicKeyRaw, payloadJson), /32 bytes/);
});
