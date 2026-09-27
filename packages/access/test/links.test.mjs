import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity } from '@microtoll/identity';
import * as ac from '../src/index.js';
import { cc } from './helpers.mjs';

const objectId = '11111111-2222-4333-8444-555555555555';
const later = new Date(Date.now() + 86400000).toISOString();

test('an attributed link names its creator; an anonymous one still redeems; the wrong token fails', async () => {
  const creator = await createIdentity(cc);
  const kObjectRaw = cc.generateSymmetricKey();
  const link = await ac.createShareLink(cc, { objectId, kObjectRaw, maxUses: 3, expiresAt: later, creator, creatorName: 'Ada', keyEpoch: 1, label: 'for the group' });
  assert.equal(link.hashedToken, await ac.hashToken(cc, link.token));
  assert.equal(link.record.manageSecret, cc.toBase64Url(link.manageSecret));
  const r = await ac.redeemShareLink(cc, link.token, link.encryptedPayload);
  assert.equal(r.verified, true); assert.equal(r.creatorName, 'Ada'); assert.deepEqual(r.kObjectRaw, kObjectRaw); assert.equal(r.objectId, objectId);
  assert.equal(cc.toHex(r.creatorSigningKeyRaw), cc.toHex(creator.identitySigning.publicKeyRaw));
  const anon = await ac.createShareLink(cc, { objectId, kObjectRaw, expiresAt: later });
  const a = await ac.redeemShareLink(cc, anon.token, anon.encryptedPayload);
  assert.equal(a.verified, false); assert.equal(a.creatorName, null); assert.deepEqual(a.kObjectRaw, kObjectRaw);
  await assert.rejects(ac.redeemShareLink(cc, ac.randomToken(cc), link.encryptedPayload));
  await assert.rejects(ac.createShareLink(cc, { objectId, kObjectRaw, maxUses: 0, expiresAt: later }), /maxUses/);
  await assert.rejects(ac.createShareLink(cc, { objectId, kObjectRaw }), /expiresAt/);
});

test('a signed payload cannot be re-wrapped under a fresh token (the token hash is in the signature and the AAD)', async () => {
  const creator = await createIdentity(cc); const forwarder = await createIdentity(cc);
  const kObjectRaw = cc.generateSymmetricKey();
  const link = await ac.createShareLink(cc, { objectId, kObjectRaw, expiresAt: later, creator, creatorName: 'Ada' });
  const key = await cc.deriveAesKey(new TextEncoder().encode(link.token), 'url-invite');
  const inner = await cc.openSymmetric(key, link.encryptedPayload, ac.linkContext(cc, link.hashedToken));
  const fresh = ac.randomToken(cc); const freshHash = await ac.hashToken(cc, fresh);
  const freshKey = await cc.deriveAesKey(new TextEncoder().encode(fresh), 'url-invite');
  const rewrapped = await cc.sealSymmetric(freshKey, inner, ac.linkContext(cc, freshHash));
  const r = await ac.redeemShareLink(cc, fresh, rewrapped);
  assert.equal(r.verified, false, 'delivers the key, claims nobody');
  assert.equal(r.creatorName, null);
  // A signature by another key claims nobody either.
  const env = JSON.parse(new TextDecoder().decode(inner));
  const forged = { ...env, sig: cc.toBase64Url(await cc.signBytes(forwarder.identitySigning.privateKey, ac.linkSigningMessage(cc, link.hashedToken, env.payloadJson))) };
  const sealedForged = await cc.sealSymmetric(key, new TextEncoder().encode(JSON.stringify(forged)), ac.linkContext(cc, link.hashedToken));
  assert.equal((await ac.redeemShareLink(cc, link.token, sealedForged)).verified, false);
  // The payload served under another link's hash fails at the AAD.
  await assert.rejects(cc.openSymmetric(key, link.encryptedPayload, ac.linkContext(cc, freshHash)));
});

test('tokenFromFragment and the creator\'s records', () => {
  assert.equal(ac.tokenFromFragment('#token=' + 'A'.repeat(27)), 'A'.repeat(27));
  assert.equal(ac.tokenFromFragment('#other=XXXX'), null);
  assert.equal(ac.tokenFromFragment('#token=<script>'), null);
  const recs = ac.normaliseLinkRecords(['bare', { hashedToken: 'h', token: 't', manageSecret: 'm' }]);
  assert.equal(recs[0].manageable, false); assert.equal(recs[0].shareable, false);
  assert.equal(recs[1].manageable, true); assert.equal(recs[1].shareable, true);
});
