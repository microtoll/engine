// The pairwise label, frozen: crypto-core's fixture file holds Alice's and
// Bob's sealing keys and the label an earlier version of the engine derived
// for September 2026 under the test namespace, which every later version
// must reproduce; the epoch helpers are pinned by the same fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '@microtoll/identity';
import { createMailbox, epoch, pollEpochs, pushEpochs, mailboxId, mailboxForSending, mailboxForReceiving } from '../src/index.js';

const frozen = JSON.parse(fs.readFileSync(new URL('../../crypto-core/test/fixtures/frozen-v1.json', import.meta.url), 'utf8'));
const fx = frozen.mailbox;
const frozenCc = createCryptoCore({ namespace: frozen.namespace });

test('the frozen label for Alice -> Bob, September 2026, from both ends', async () => {
  const alice = await frozenCc.importSealingKeyPair(fx.aliceJwk);
  const bob = await frozenCc.importSealingKeyPair(fx.bobJwk);
  const fromAlice = await mailboxId(frozenCc, alice.privateKey, bob.publicKeyRaw, alice.publicKeyRaw, bob.publicKeyRaw, fx.epoch);
  assert.equal(frozenCc.toHex(fromAlice), fx.labelAliceToBob);
  const fromBob = await mailboxId(frozenCc, bob.privateKey, alice.publicKeyRaw, alice.publicKeyRaw, bob.publicKeyRaw, fx.epoch);
  assert.equal(frozenCc.toHex(fromBob), fx.labelAliceToBob, 'the recipient derives the same value from the other side');
  // The direction matters: Bob -> Alice is a different mailbox.
  const reverse = await mailboxId(frozenCc, bob.privateKey, alice.publicKeyRaw, bob.publicKeyRaw, alice.publicKeyRaw, fx.epoch);
  assert.notEqual(frozenCc.toHex(reverse), fx.labelAliceToBob);
  // And so does the month, and the namespace.
  assert.notEqual(frozenCc.toHex(await mailboxId(frozenCc, alice.privateKey, bob.publicKeyRaw, alice.publicKeyRaw, bob.publicKeyRaw, '2026-10')), fx.labelAliceToBob);
  const other = createCryptoCore({ namespace: 'other' });
  assert.notEqual(other.toHex(await mailboxId(other, alice.privateKey, bob.publicKeyRaw, alice.publicKeyRaw, bob.publicKeyRaw, fx.epoch)), fx.labelAliceToBob);
});

test('the epochs: a calendar month in UTC; poll this month and the previous; subscribe to this and the next', () => {
  const on = new Date(Date.UTC(2026, 8, 15));
  assert.equal(epoch(on), '2026-09');
  assert.deepEqual(pollEpochs(on), fx.pollEpochsOn20260915);
  assert.deepEqual(pushEpochs(on), fx.pushEpochsOn20260915);
  assert.deepEqual(pollEpochs(new Date(Date.UTC(2027, 0, 1))), ['2027-01', '2026-12']);
  assert.deepEqual(pushEpochs(new Date(Date.UTC(2026, 11, 31, 23, 59))), ['2026-12', '2027-01']);
});

test('mailboxForSending and mailboxForReceiving agree for two full identities, and refuse bad input', async () => {
  const cc = createCryptoCore({ namespace: 'testapp' });
  const m = createMailbox({ cryptoCore: cc });
  const alice = await id.createIdentity(cc);
  const bob = await id.createIdentity(cc);
  const a = await m.mailboxForSending(alice, bob.identity.publicKeyRaw, '2026-09');
  const b = await m.mailboxForReceiving(bob, alice.identity.publicKeyRaw, '2026-09');
  assert.equal(cc.toHex(a), cc.toHex(b));
  assert.equal(a.length, 32);
  await assert.rejects(mailboxForSending(cc, alice, bob.identity.publicKeyRaw, '2026-9'), /calendar month/);
  await assert.rejects(mailboxForReceiving(cc, bob, new Uint8Array(32), '2026-09'), /65 bytes/);
  // The retired first label can never be reached through the profile.
  assert.throws(() => cc.label('invite-mailbox', 1), /retired/);
});
