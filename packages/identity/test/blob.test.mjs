// The identity blob (v2, D-28): bound to the routing key, absent vs
// unreadable, and the cooperative revision counter.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '../src/index.js';

const cc = createCryptoCore({ namespace: 'example' });

test('build → seal → open round trip; the identity is authoritative for its own keys; revision increments', async () => {
  const me = await id.createIdentity(cc);
  const p1 = id.buildIdentityBlobPlaintext(cc, me, { contacts: [1], sealingKey: 'stale', identityPublicKey: 'stale' });
  assert.equal(p1.revision, 1);
  assert.deepEqual(p1.sealingKey, me.identity.jwk);
  assert.equal(p1.identityPublicKey, cc.toBase64Url(me.identity.publicKeyRaw));
  assert.equal(p1.identitySigningKey, cc.toBase64Url(me.identitySigning.publicKeyRaw));
  const sealed = await id.sealIdentityBlob(cc, me, p1);
  assert.deepEqual(await id.openIdentityBlob(cc, me, sealed), p1);
  const p2 = id.buildIdentityBlobPlaintext(cc, me, p1);
  assert.equal(p2.revision, 2);
});

test('absent opens as {}; present-but-unreadable throws with a code; not-an-object throws', async () => {
  const me = await id.createIdentity(cc);
  assert.deepEqual(await id.openIdentityBlob(cc, me, null), {});
  assert.deepEqual(await id.openIdentityBlob(cc, me, new Uint8Array(0)), {});
  const sealed = await id.sealIdentityBlob(cc, me, id.buildIdentityBlobPlaintext(cc, me, {}));
  const t = sealed.slice(); t[t.length - 1] ^= 1;
  await assert.rejects(id.openIdentityBlob(cc, me, t), (e) => e.code === id.IDENTITY_BLOB_UNREADABLE);
  const arr = await cc.sealSymmetric(me.masterSymmKey, new TextEncoder().encode('[1]'), id.blobContext(cc, me.routing.publicKeyRaw));
  await assert.rejects(id.openIdentityBlob(cc, me, arr), (e) => e.code === id.IDENTITY_BLOB_UNREADABLE);
});

test('a blob cannot be moved between accounts (the routing key is bound in)', async () => {
  const me = await id.createIdentity(cc);
  const other = await id.createIdentity(cc);
  const sealed = await id.sealIdentityBlob(cc, me, id.buildIdentityBlobPlaintext(cc, me, {}));
  // Even with the same K_master_symm, a different routing key refuses.
  const spliced = { ...me, routing: other.routing };
  await assert.rejects(id.openIdentityBlob(cc, spliced, sealed), (e) => e.code === id.IDENTITY_BLOB_UNREADABLE);
});

test('a rolled-back blob is refused when the device has seen a later revision', async () => {
  const me = await id.createIdentity(cc);
  const p1 = id.buildIdentityBlobPlaintext(cc, me, {});
  const p2 = id.buildIdentityBlobPlaintext(cc, me, p1);
  const old = await id.sealIdentityBlob(cc, me, p1);
  await assert.rejects(id.openIdentityBlob(cc, me, old, { minRevision: p2.revision }), (e) => e.code === id.IDENTITY_BLOB_ROLLED_BACK && e.revision === 1 && e.minRevision === 2);
  assert.deepEqual(await id.openIdentityBlob(cc, me, old, { minRevision: 1 }), p1);
});
