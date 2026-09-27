// Frozen fixtures: version-2 bundles an earlier version of this package wrote
// (test/tooling/generate-frozen-fixtures.mjs, never regenerated), which every
// later version must open and whose signatures it must reproduce. A changed
// label, version byte, parameter or layout fails here instead of silently
// dropping invitations. The pairwise label and both sealing keys are read
// from crypto-core's frozen file, which pins them; this file only builds on
// them. Everything is checked through the package's public API; the hybrid
// bundle runs through crypto-core's test-only platform shim, as crypto-core's
// own fixtures do.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCryptoCore } from '@microtoll/crypto-core';
import { identityFromRootKey, adoptSealingKey } from '@microtoll/identity';
import { installPqShim } from '../../crypto-core/test/tooling/pq-test-shim.mjs';
import * as mb from '../src/index.js';

const fx = JSON.parse(readFileSync(new URL('./fixtures/frozen-v2.json', import.meta.url), 'utf8'));
const labelFile = JSON.parse(readFileSync(new URL(`../../../${fx.mailbox.file}`, import.meta.url), 'utf8'));
const frozenMailbox = labelFile[fx.mailbox.section];
const cc = createCryptoCore({ namespace: fx.namespace });
const H = cc.fromHex;
const text = (b) => new TextDecoder().decode(b);
const flip = (hex, at) => { const b = H(hex); b[at] ^= 1; return b; };
const MAILBOX = H(frozenMailbox[fx.mailbox.label]);
const EPOCH = frozenMailbox[fx.mailbox.epoch];

/** A frozen account: signing key from the stored root, sealing key from crypto-core's label fixture. */
async function frozenAccount(core, who, jwkField) {
  const identity = await identityFromRootKey(core, H(fx.accounts[who].rootKey));
  await adoptSealingKey(core, identity, { sealingKey: frozenMailbox[jwkField] });
  assert.equal(core.toHex(identity.identitySigning.publicKeyRaw), fx.accounts[who].identitySigningPublicKey);
  return identity;
}
const accounts = async () => ({
  alice: await frozenAccount(cc, 'alice', fx.mailbox.senderSealingKey),
  bob: await frozenAccount(cc, 'bob', fx.mailbox.recipientSealingKey),
});

test('the fixture builds on crypto-core\'s frozen label: both ends still compute it from the same sealing keys (FORMATS.md §1)', async () => {
  const { alice, bob } = await accounts();
  assert.equal(labelFile.namespace, fx.namespace);
  assert.equal(cc.toHex(await mb.mailboxForSending(cc, alice, bob.identity.publicKeyRaw, EPOCH)), cc.toHex(MAILBOX));
  assert.equal(cc.toHex(await mb.mailboxForReceiving(cc, bob, alice.identity.publicKeyRaw, EPOCH)), cc.toHex(MAILBOX));
  assert.equal(mb.BUNDLE_VERSION, fx.bundleVersion);
});

test('the signed bytes reproduce: "<ns>/sig/invite/v2" ‖ 0x00 ‖ mailbox label ‖ SHA-256(recipient key) ‖ payload (FORMATS.md §2)', async () => {
  const { bob } = await accounts();
  for (const bundle of [fx.invite, fx.ack]) {
    assert.equal(cc.toHex(await cc.sha256(bob.identity.publicKeyRaw)), bundle.recipientKeyHash);
    const message = await mb.inviteSigningMessage(cc, MAILBOX, bob.identity.publicKeyRaw, JSON.parse(bundle.envelope).payloadJson);
    assert.equal(cc.toHex(message), bundle.signedMessage);
    // The frame starts with the NUL-terminated purpose label, then the mailbox and the recipient's key hash.
    const head = cc.toHex(new TextEncoder().encode(fx.labels.inviteSignature)) + '00';
    assert.ok(bundle.signedMessage.startsWith(head + cc.toHex(MAILBOX) + bundle.recipientKeyHash));
  }
});

test('the frozen invitation opens for Bob in its mailbox, verified; the envelope and its signature reproduce (FORMATS.md §2)', async () => {
  const { alice, bob } = await accounts();
  const sealed = H(fx.invite.sealed);
  assert.equal(sealed[0], cc.ECIES_VERSION_3, 'sealed to the 65-byte P-256 key');
  // The sealed envelope, byte for byte: { v: 2, payloadJson, sig }.
  assert.equal(text(await cc.openWithPrivateKey(bob.identity, sealed)), fx.invite.envelope);
  const envelope = JSON.parse(fx.invite.envelope);
  assert.deepEqual(Object.keys(envelope), ['v', 'payloadJson', 'sig']);
  assert.equal(envelope.v, 2);
  // Ed25519 is deterministic (RFC 8032 §5.1.6): Alice's key over the same bytes gives the same signature.
  assert.equal(cc.toBase64Url(await cc.signBytes(alice.identitySigning.privateKey, H(fx.invite.signedMessage))), envelope.sig);
  const opened = await mb.openBundle(cc, bob, MAILBOX, sealed);
  assert.equal(opened.verified, true);
  assert.equal(opened.kind, 'invite');
  assert.equal(opened.objectId, fx.objectId);
  assert.equal(cc.toHex(opened.kObjectRaw), fx.kObject);
  assert.equal(opened.keyEpoch, 3);
  assert.equal(opened.senderName, 'Alice');
  assert.deepEqual(opened.claims, { greeting: 'hello' });
  assert.equal(cc.toHex(opened.senderSigningKeyRaw), fx.accounts.alice.identitySigningPublicKey);
  assert.equal(cc.toHex(opened.senderIdentityKeyRaw), cc.toHex(alice.identity.publicKeyRaw));
  // The payload's fields and their order are the frozen ones.
  assert.deepEqual(Object.keys(JSON.parse(envelope.payloadJson)), ['kind', 'objectId', 'kObject', 'keyEpoch', 'senderName', 'greeting', 'senderIdentityKey', 'senderSigningKey']);
});

test('the binding: in another mailbox the frozen bundle verifies for nobody; a flipped byte, or the wrong recipient, does not open', async () => {
  const { alice, bob } = await accounts();
  const sealed = H(fx.invite.sealed);
  const nextMonth = await mb.mailboxForSending(cc, alice, bob.identity.publicKeyRaw, '2026-10');
  for (const mailbox of [nextMonth, flip(cc.toHex(MAILBOX), 0)]) {
    const opened = await mb.openBundle(cc, bob, mailbox, sealed);
    assert.equal(opened.verified, false);
    assert.equal(opened.senderName, null);
    assert.equal(opened.senderSigningKeyRaw, null);
    assert.deepEqual(opened.claims, {});
    assert.equal(cc.toHex(opened.kObjectRaw), fx.kObject, 'the key is still there; the attribution is not');
  }
  await assert.rejects(mb.openBundle(cc, bob, MAILBOX, flip(fx.invite.sealed, 120)), 'a flipped byte');
  await assert.rejects(mb.openBundle(cc, alice, MAILBOX, sealed), 'sealed to Bob, not Alice');
});

test('the frozen acknowledgement opens verified, names the link and the stage, and carries no key', async () => {
  const { alice, bob } = await accounts();
  const envelope = JSON.parse(fx.ack.envelope);
  assert.equal(text(await cc.openWithPrivateKey(bob.identity, H(fx.ack.sealed))), fx.ack.envelope);
  assert.equal(cc.toBase64Url(await cc.signBytes(alice.identitySigning.privateKey, H(fx.ack.signedMessage))), envelope.sig);
  const opened = await mb.openBundle(cc, bob, MAILBOX, H(fx.ack.sealed));
  assert.equal(opened.verified, true);
  assert.equal(opened.kind, 'invite-ack');
  assert.equal(opened.objectId, fx.objectId);
  assert.equal(opened.kObjectRaw, null);
  assert.equal(opened.keyEpoch, null);
  assert.equal(opened.hashedToken, 'ab'.repeat(32));
  assert.equal(opened.stage, 'seen');
  assert.equal(opened.senderName, 'Alice');
});

test('hybrid: the frozen bundle sealed to Bob\'s KEM key binds that key\'s hash, and opens only with it (through the test shim)', async () => {
  const uninstall = installPqShim();
  try {
    const pq = createCryptoCore({ namespace: fx.namespace, hybridSealing: true });
    const bob = await frozenAccount(pq, 'bob', fx.mailbox.recipientSealingKey);
    const alice = await frozenAccount(pq, 'alice', fx.mailbox.senderSealingKey);
    const h = fx.hybridInvite;
    assert.equal(pq.toHex(bob.identityKem.publicKeyRaw), fx.accounts.bob.identityKemPublicKey, 'the KEM key derived from the root');
    assert.equal(pq.toHex(await pq.sha256(bob.identityKem.publicKeyRaw)), h.recipientKeyHash);
    const envelope = JSON.parse(h.envelope);
    assert.equal(pq.toHex(await mb.inviteSigningMessage(pq, MAILBOX, bob.identityKem.publicKeyRaw, envelope.payloadJson)), h.signedMessage);
    assert.equal(pq.toBase64Url(await pq.signBytes(alice.identitySigning.privateKey, H(h.signedMessage))), envelope.sig);
    const sealed = H(h.sealed);
    assert.equal(sealed[0], pq.ECIES_VERSION_2, 'sealed to the 1216-byte hybrid key');
    const opened = await mb.openBundle(pq, bob, MAILBOX, sealed);
    assert.equal(opened.verified, true);
    assert.equal(pq.toHex(opened.kObjectRaw), fx.kObject);
    assert.equal(opened.senderName, 'Alice');
    // The same payload signed for the P-256 key is a different signature: the recipient key is in the signed bytes.
    assert.notEqual(envelope.sig, JSON.parse(fx.invite.envelope).sig);
    assert.equal(envelope.payloadJson, JSON.parse(fx.invite.envelope).payloadJson);
    const classicalOnly = await frozenAccount(cc, 'bob', fx.mailbox.recipientSealingKey);
    await assert.rejects(mb.openBundle(cc, classicalOnly, MAILBOX, sealed), (e) => e.code === 'pq-key-unavailable');
  } finally {
    uninstall();
  }
});
