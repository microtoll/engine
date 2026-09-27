// Sending, collecting, withdrawing and checking, against the server stand-in
// (the real server's mailbox half is proved in blind-store's suites).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '@microtoll/identity';
import { createFakeServer } from '../../identity/test/tooling/fakeServer.mjs';
import { mailboxProtocol } from './tooling/mailboxServer.mjs';
import { createMailbox } from '../src/index.js';

const cc = createCryptoCore({ namespace: 'testapp' });
const ORIGIN = 'https://example.test';
const m = createMailbox({ cryptoCore: cc });
const objectId = '11111111-2222-4333-8444-555555555555';

async function person(server) {
  const identity = await id.createIdentity(cc);
  const ws = await server.connect();
  await id.authenticateConnection(cc, ws, identity.routing, ORIGIN);
  const { method } = await id.wrapRootKeyWithNewRecoveryCode(cc, identity.rootKey);
  const blob = await id.sealIdentityBlob(cc, identity, id.buildIdentityBlobPlaintext(cc, identity, {}));
  await id.registerAccount(cc, ws, identity, blob, [method], { sealLabel: async () => new Uint8Array(0) });
  const contact = { signingKey: cc.toBase64Url(identity.identitySigning.publicKeyRaw), identityKey: cc.toBase64Url(identity.identity.publicKeyRaw) };
  return { identity, ws, contact };
}

test('Alice invites Bob directly: sent under their label, collected with a verified name, consumed by the app, then seen as collected by Alice', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN], extensions: [mailboxProtocol] });
  const alice = await person(server); const bob = await person(server); const carol = await person(server);
  const kObjectRaw = cc.generateSymmetricKey();
  const sent = await m.send(alice.ws, alice.identity, [bob.contact, { signingKey: 'nobody', identityKey: null }], { objectId, kObjectRaw, keyEpoch: 2, senderName: 'Alice', claims: { greeting: 'hello' } });
  assert.equal(sent.length, 2);
  assert.equal(sent[0].ok, true); assert.ok(sent[0].inviteId); assert.equal(sent[0].epoch, m.epoch());
  assert.equal(sent[1].ok, false);
  // Bob polls his contacts' labels; Carol, who has no such contact, sees nothing.
  const got = await m.collect(bob.ws, bob.identity, [alice.contact, carol.contact]);
  assert.equal(got.counts.labels, 4);
  assert.equal(got.invites.length, 1);
  const inv = got.invites[0];
  assert.equal(inv.verified, true); assert.equal(inv.senderName, 'Alice'); assert.equal(inv.senderSigningKey, alice.contact.signingKey);
  assert.equal(inv.viaContact, alice.contact); assert.equal(inv.objectId, objectId); assert.equal(inv.keyEpoch, 2);
  assert.equal(cc.toHex(inv.kObjectRaw), cc.toHex(kObjectRaw));
  assert.deepEqual(inv.claims, { greeting: 'hello' });
  assert.deepEqual(await m.collect(carol.ws, carol.identity, [alice.contact]), { invites: [], acks: [], unsigned: [], counts: { labels: 2, rows: 0, already: 0, unreadable: 0, other: 0 } });
  // Not consumed until the app says so; then Alice sees it collected.
  assert.equal((await m.status(alice.ws, alice.identity, [{ identityKey: bob.contact.identityKey, epoch: sent[0].epoch, inviteId: sent[0].inviteId }]))[0].collected, false);
  assert.equal((await m.collect(bob.ws, bob.identity, [alice.contact])).invites.length, 1, 'seen again until consumed');
  await m.consumeInvite(bob.ws, inv.rowId);
  assert.equal((await m.collect(bob.ws, bob.identity, [alice.contact])).counts.already, 1);
  assert.equal((await m.status(alice.ws, alice.identity, [{ identityKey: bob.contact.identityKey, epoch: sent[0].epoch, inviteId: sent[0].inviteId }]))[0].collected, true);
  assert.deepEqual(await m.withdraw(alice.ws, alice.identity, cc.fromBase64Url(bob.contact.identityKey), sent[0].epoch, sent[0].inviteId), { burned: 0, collected: true });
});

test('withdrawal: an uncollected invitation is taken back and never opens; the row itself when named, every pending one otherwise', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN], extensions: [mailboxProtocol] });
  const alice = await person(server); const bob = await person(server);
  const [first] = await m.send(alice.ws, alice.identity, [bob.contact], { objectId, kObjectRaw: cc.generateSymmetricKey(), keyEpoch: 1 });
  const [second] = await m.send(alice.ws, alice.identity, [bob.contact], { objectId: '22222222-2222-4333-8444-555555555555', kObjectRaw: cc.generateSymmetricKey(), keyEpoch: 1 });
  assert.deepEqual(await m.withdraw(alice.ws, alice.identity, cc.fromBase64Url(bob.contact.identityKey), first.epoch, first.inviteId), { burned: 1, collected: false });
  const got = await m.collect(bob.ws, bob.identity, [alice.contact]);
  assert.equal(got.invites.length, 1, 'the other invitation in the same monthly mailbox is untouched');
  assert.equal(got.invites[0].rowId, second.inviteId);
  assert.equal(got.counts.already, 1);
  assert.deepEqual(await m.withdraw(alice.ws, alice.identity, cc.fromBase64Url(bob.contact.identityKey), second.epoch), { burned: 1, collected: false });
  assert.deepEqual((await m.status(alice.ws, alice.identity, [{ identityKey: bob.contact.identityKey, epoch: first.epoch, inviteId: 'no-such-row' }]))[0].collected, null);
  assert.deepEqual(await m.withdraw(alice.ws, alice.identity, cc.fromBase64Url(bob.contact.identityKey), '2020-01'), { burned: 0, collected: false }, 'nothing there');
});

test('acknowledgements are collected and consumed; an unsigned drop is usable, unattributed and left in place; a re-sealed drop from a contact is downgraded', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN], extensions: [mailboxProtocol] });
  const alice = await person(server); const bob = await person(server); const carol = await person(server);
  // Bob acknowledges Alice's link.
  const ackMailbox = await m.mailboxForSending(bob.identity, alice.identity.identity.publicKeyRaw);
  await m.sendInvite(bob.ws, ackMailbox, await m.buildAck(bob.identity, alice.identity.identity.publicKeyRaw, { mailboxId: ackMailbox, objectId, senderName: 'Bob', hashedToken: 'cd'.repeat(32) }));
  let got = await m.collect(alice.ws, alice.identity, [bob.contact]);
  assert.equal(got.acks.length, 1);
  assert.equal(got.acks[0].senderName, 'Bob'); assert.equal(got.acks[0].hashedToken, 'cd'.repeat(32)); assert.equal(got.acks[0].verified, true);
  assert.equal((await m.collect(alice.ws, alice.identity, [bob.contact])).counts.already, 1, 'consumed');
  // An unsigned drop: somebody sealed a payload without a signature into Bob's mailbox from Alice.
  const aliceToBob = await m.mailboxForSending(alice.identity, bob.identity.identity.publicKeyRaw);
  const unsignedEnvelope = JSON.stringify({ v: 2, payloadJson: JSON.stringify({ kind: 'invite', objectId, kObject: cc.toBase64Url(cc.generateSymmetricKey()), keyEpoch: 1, senderName: 'Alice' }), sig: null });
  await m.sendInvite(alice.ws, aliceToBob, await cc.sealToRecipient(bob.identity.identity.publicKeyRaw, new TextEncoder().encode(unsignedEnvelope)));
  got = await m.collect(bob.ws, bob.identity, [alice.contact]);
  assert.equal(got.invites.length, 0);
  assert.equal(got.unsigned.length, 1);
  assert.equal(got.unsigned[0].viaContact, alice.contact);
  assert.ok(got.unsigned[0].kObjectRaw);
  assert.equal((await m.collect(bob.ws, bob.identity, [alice.contact])).unsigned.length, 1, 'still there: held, not consumed');
  // Carol drops a bundle Alice signed for Carol's mailbox into the mailbox Carol shares with Bob: the mailbox binding fails it.
  const aliceToCarol = await m.mailboxForSending(alice.identity, carol.identity.identity.publicKeyRaw);
  const forCarol = await m.buildInvite(alice.identity, carol.identity.identity.publicKeyRaw, { mailboxId: aliceToCarol, objectId, kObjectRaw: cc.generateSymmetricKey(), keyEpoch: 1, senderName: 'Alice' });
  const plaintext = await cc.openWithPrivateKey(carol.identity.identity, forCarol);
  const carolToBob = await m.mailboxForSending(carol.identity, bob.identity.identity.publicKeyRaw);
  await m.sendInvite(carol.ws, carolToBob, await cc.sealToRecipient(bob.identity.identity.publicKeyRaw, plaintext));
  got = await m.collect(bob.ws, bob.identity, [alice.contact, carol.contact]);
  const viaCarol = got.unsigned.find((u) => u.viaContact === carol.contact);
  assert.ok(viaCarol, 'downgraded to unsigned: no name, no claim');
  assert.equal(got.invites.length, 0);
});
