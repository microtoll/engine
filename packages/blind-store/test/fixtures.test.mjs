// The runtime half of "the server cannot decrypt" (DESIGN.md §5.4): every
// sealed fixture from crypto-core's frozen fixture file, stored
// through the server as the field it would be, reads back byte-identical --
// the server holds ciphertext and hands it back unchanged, and nothing in
// this package could open any of it (cannot-decrypt.test.mjs proves the
// static half).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as id from '@microtoll/identity';
import { requireDatabase } from './tooling/db.mjs';
import { startServer, person, makeAccess, cc, daysAhead } from './tooling/harness.mjs';

const fixturesPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'crypto-core', 'test', 'fixtures', 'frozen-v1.json');

let db = null;
let s = null;
// The daily caps are raised: this suite makes one link and one drop per fixture.
before(async () => { db = await requireDatabase(); if (db) s = await startServer({ db, rateLimits: { 'create-url-invite': 100000, 'send-invite': 100000, 'create-event': 100000 } }); });
after(async () => { if (s) await s.close(); if (db) await db.owner.end(); });

/** Every hex string of 32 bytes or more anywhere in the fixture file: the ciphertexts, and the keys an earlier version of the engine sealed them with. */
function sealedBytes() {
  const out = [];
  const walk = (v, where) => {
    if (typeof v === 'string' && /^[0-9a-f]{64,}$/.test(v) && v.length % 2 === 0) out.push({ where, bytes: cc.fromHex(v) });
    else if (Array.isArray(v)) v.forEach((x, i) => walk(x, `${where}[${i}]`));
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) walk(x, `${where}.${k}`);
  };
  walk(JSON.parse(fs.readFileSync(fixturesPath, 'utf8')), 'fixtures');
  return out;
}

test('the fixture file has sealed material to store', () => {
  assert.ok(sealedBytes().length >= 10, 'expected the frozen fixtures');
});

test('every fixture stored as an identity blob, a pointer, an object\'s content, a link payload and a mailbox bundle reads back byte-identical', async (t) => {
  if (!db) { t.skip('no test database'); return; }
  const access = makeAccess();
  const me = await person(s);
  const fixtures = sealedBytes().filter((f) => f.bytes.length <= 4096);
  let stored = 0;
  for (const { where, bytes } of fixtures) {
    // The identity blob: written whole, read back on the next sign-in.
    const { identityBlobToken } = await id.updateIdentityBlob(cc, me.ws, bytes, null);
    assert.ok(identityBlobToken);
    const row = await db.owner.query('SELECT sealed_identity_blob FROM users WHERE routing_public_key = $1', [Buffer.from(me.identity.routing.publicKeyRaw)]);
    assert.equal(cc.toHex(new Uint8Array(row.rows[0].sealed_identity_blob)), cc.toHex(bytes), `${where} as an identity blob`);
    // A share link's payload, filed under a fresh hash, redeemed once.
    const hashedToken = cc.toHex(cc.randomBytes(32));
    await id.sendAndAwait(me.ws, { type: 'create-url-invite', hashedToken, encryptedPayload: cc.toBase64Url(bytes), maxUses: 1, expiresAt: daysAhead(1), manageCapabilityHash: cc.toBase64Url(cc.randomBytes(32)) }, 'create-url-invite-ok', 'create-url-invite-failed');
    assert.equal(cc.toHex(await access.redeemShareLinkMessage(me.ws, hashedToken)), cc.toHex(bytes), `${where} as a link payload`);
    // A mailbox bundle, polled back.
    const mailboxId = cc.randomBytes(32);
    const sent = await id.sendAndAwait(me.ws, { type: 'send-invite', mailboxId: cc.toBase64Url(mailboxId), encryptedBundle: cc.toBase64Url(bytes), expiresAt: daysAhead(1) }, 'send-invite-ok', 'send-invite-failed');
    const polled = await id.sendAndAwait(me.ws, { type: 'poll-invites', mailboxIds: [cc.toBase64Url(mailboxId)] }, 'invites', 'poll-invites-failed');
    assert.equal(polled.invites.find((i) => i.id === sent.inviteId).encryptedBundle, cc.toBase64Url(bytes), `${where} as a mailbox bundle`);
    stored++;
  }
  // An object's content, second tier, member row, sealed key and pointer: one object per fixture is too slow, so the largest few.
  const few = fixtures.sort((a, b) => b.bytes.length - a.bytes.length).slice(0, 5);
  for (const { where, bytes } of few) {
    const c = await access.createObject({ identity: me.identity, content: {} });
    const forged = { ...c, encryptedContent: bytes, encryptedDetail: bytes, pointer: bytes, ownerRow: { ...c.ownerRow, encryptedRow: bytes, encryptedObjectKey: bytes } };
    await access.createObjectMessage(me.ws, forged, { collection: 'notes', selector: 'fx' });
    const fetched = await access.fetchObject(me.ws, c.objectId);
    assert.equal(cc.toHex(fetched.encryptedContent), cc.toHex(bytes), `${where} as content`);
    assert.equal(cc.toHex(fetched.encryptedDetail), cc.toHex(bytes), `${where} as the second tier`);
    const mine = await access.fetchMyRow(me.ws, c.objectId, c.ownerRow.rowCapabilitySecret);
    assert.equal(cc.toHex(mine.encryptedRow), cc.toHex(bytes), `${where} as a member row`);
    assert.equal(cc.toHex(mine.encryptedObjectKey), cc.toHex(bytes), `${where} as a sealed key`);
    const pointers = await access.fetchPointers(me.ws);
    assert.ok(pointers.some((p) => cc.toHex(p.sealed) === cc.toHex(bytes)), `${where} as a pointer`);
  }
  assert.ok(stored >= 10);
  me.close();
});
