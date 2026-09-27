// The whole protocol against the real server and a real database, driven
// by the real client packages: what the identity and access suites proved
// against their server stand-ins, proved here against the thing itself.
// Every case of the handshake and the core messages is here, plus the
// collection model's own (D-33).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import * as id from '@microtoll/identity';
import * as ac from '@microtoll/access';
import { requireDatabase } from './tooling/db.mjs';
import { startServer, connect, signIn, nextMessage, closedWith, person, makeAccess, cc, ORIGIN, daysAhead, utf8 } from './tooling/harness.mjs';

let db = null;
let s = null;
const access = makeAccess();
const sel = () => Math.random().toString(36).slice(2, 7).padEnd(5, 'x');
const events = (extra = {}) => ({ collection: 'events', selector: sel(), windowStart: '2026-10-01', windowEnd: '2026-10-02', ...extra });
const noLabel = { sealLabel: async () => new Uint8Array(0) };
const raw = (ws, msg, ok, fail) => id.sendAndAwait(ws, msg, ok, fail);
const reason = (r) => (e) => { if (e.reason !== r) throw new Error(`expected ${r}, got ${e.reason}${e.detail ? ': ' + e.detail : ''}`); return true; };

// No wipe: the suites run in parallel against one database (the live,
// fixture and example suites too), so every test uses fresh identities,
// random ids and random selectors instead. `npm run db:reset` empties it.
before(async () => {
  db = await requireDatabase();
  if (!db) return;
  s = await startServer({ db });
});
after(async () => { if (s) await s.close(); if (db) await db.owner.end(); });
const needsDb = (t) => { if (!db) { t.skip('no test database'); return false; } return true; };

/** An object published on the shared server by `owner`, at a fresh selector. */
async function published(owner, { content = { title: 'x' }, selector = events(), ...extra } = {}) {
  const c = await access.createObject({ identity: owner.identity, content, ownerRowContent: { status: 'going' }, ...extra });
  await access.createObjectMessage(owner.ws, c, selector);
  return { ...c, selector };
}

// ---------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------

test('register: a new socket finds the account, the blob, its token and generation 1; auth-ok carries no host field; the same key twice is refused', async (t) => {
  if (!needsDb(t)) return;
  const a = await person(s);
  assert.equal(a.ok.hasAccount, false);
  const ws = await connect(s);
  const ok = await signIn(ws, a.identity);
  assert.equal(ok.hasAccount, true);
  assert.equal(ok.sessionGeneration, 1);
  assert.equal(ok.identityBlobToken, a.identityBlobToken);
  assert.equal('termsVersionAccepted' in ok.fields, false);
  const opened = await id.openIdentityBlob(cc, a.identity, ok.encryptedIdentityBlob);
  assert.equal(typeof opened, 'object');
  const blob = await id.sealIdentityBlob(cc, a.identity, id.buildIdentityBlobPlaintext(cc, a.identity, {}));
  await assert.rejects(id.registerAccount(cc, ws, a.identity, blob, [a.method], noLabel), reason('already-registered'));
  await assert.rejects(raw(ws, { type: 'register', encryptedIdentityBlob: cc.toBase64Url(blob), unlockMethods: [] }, 'register-ok', 'register-failed'), reason('invalid'));
  const rows = await db.owner.query('SELECT count(*)::int AS n FROM users WHERE routing_public_key = $1', [Buffer.from(a.identity.routing.publicKeyRaw)]);
  assert.equal(rows.rows[0].n, 1);
  ws.close(); a.close();
});

test('unlock: the recovery code finds the wrapped root key before sign-in, opens it, and signs in as the same account; unknown, malformed and too many lookups are refused', async (t) => {
  if (!needsDb(t)) return;
  const a = await person(s);
  a.close();
  const ws = await connect(s);
  const found = await id.lookupUnlockMethod(cc, ws, { recoveryLookupHash: await id.lookupHashForEnteredCode(cc, a.code) });
  assert.equal(found.type, 'recovery-code');
  const rootKey = await id.unwrapRootKeyWithRecoveryCode(cc, found, a.code);
  assert.equal(cc.toHex(rootKey), cc.toHex(a.identity.rootKey));
  const again = await id.identityFromRootKey(cc, rootKey);
  await assert.rejects(id.lookupUnlockMethod(cc, ws, { recoveryLookupHash: cc.toHex(cc.randomBytes(32)) }), reason('not-found'));
  await assert.rejects(raw(ws, { type: 'lookup-unlock-method' }, 'unlock-method', 'lookup-unlock-method-failed'), reason('invalid'));
  // The fourth lookup on this socket is refused (D-20: three per socket), and the socket can still sign in.
  await assert.rejects(id.lookupUnlockMethod(cc, ws, { credentialId: cc.randomBytes(16) }), reason('rate-limited'));
  const ok = await signIn(ws, again);
  assert.equal(ok.hasAccount, true);
  ws.close();
});

test('the identity blob: a write against the current token lands; a stale one is refused with the current blob; the retry wins; a write with no token still works; another account is never touched', async (t) => {
  if (!needsDb(t)) return;
  const a = await person(s); const b = await person(s);
  const seal = (who, extra) => id.sealIdentityBlob(cc, who.identity, id.buildIdentityBlobPlaintext(cc, who.identity, extra));
  const first = await id.updateIdentityBlob(cc, a.ws, await seal(a, { ownName: 'One' }), a.identityBlobToken);
  assert.notEqual(first.identityBlobToken, a.identityBlobToken);
  let refused = null;
  try { await id.updateIdentityBlob(cc, a.ws, await seal(a, { ownName: 'Two' }), a.identityBlobToken); } catch (e) { refused = e; }
  assert.equal(refused && refused.conflict, true);
  assert.equal(refused.identityBlobToken, first.identityBlobToken);
  assert.equal((await id.openIdentityBlob(cc, a.identity, refused.encryptedIdentityBlob)).ownName, 'One');
  const second = await id.updateIdentityBlob(cc, a.ws, await seal(a, { ownName: 'Two' }), first.identityBlobToken);
  assert.notEqual(second.identityBlobToken, first.identityBlobToken);
  const third = await id.updateIdentityBlob(cc, a.ws, await seal(a, { ownName: 'Three' }), null);
  assert.equal(third.identityBlobToken, second.identityBlobToken, 'an unconditional write leaves the token alone');
  await assert.rejects(raw(a.ws, { type: 'update-identity-blob', encryptedIdentityBlob: cc.toBase64Url(await seal(a, {})), baseToken: third.identityBlobToken }, 'update-identity-blob-ok', 'update-identity-blob-failed'), reason('invalid'), 'one token without the other');
  const bWs = await connect(s);
  const bOk = await signIn(bWs, b.identity);
  assert.equal(bOk.identityBlobToken, b.identityBlobToken, "a's writes never moved b's token");
  const guest = await person(s, { account: false });
  await assert.rejects(id.updateIdentityBlob(cc, guest.ws, await seal(guest, {}), null), reason('no-account'));
  a.close(); b.close(); bWs.close(); guest.close();
});

test('unlock methods: add a passkey, list both with labels, refuse a reused credential, remove one (generation bumps), never the last, never a stranger\'s', async (t) => {
  if (!needsDb(t)) return;
  const a = await person(s);
  const sealLabel = (label, method) => id.sealMethodLabel(cc, a.identity.masterSymmKey, method, label);
  const openLabel = (sealed, method) => id.openMethodLabel(cc, a.identity.masterSymmKey, method, sealed);
  const credentialId = cc.randomBytes(16);
  const passkey = await id.wrapRootKeyWithPrf(cc, a.identity.rootKey, cc.randomBytes(32), credentialId, cc.randomBytes(32), 'my laptop');
  await id.addUnlockMethod(cc, a.ws, a.identity, passkey, { sealLabel });
  await assert.rejects(id.addUnlockMethod(cc, a.ws, a.identity, passkey, { sealLabel }), reason('already-used'));
  let methods = await id.listUnlockMethods(cc, a.ws, { openLabel });
  assert.equal(methods.length, 2);
  const pk = methods.find((m) => m.type === 'passkey-prf');
  assert.equal(pk.label, 'my laptop');
  assert.equal(cc.toHex(pk.credentialId), cc.toHex(credentialId));
  // The lookup finds the passkey by credential id, before sign-in, with no owner.
  const ws = await connect(s);
  const found = await id.lookupUnlockMethod(cc, ws, { credentialId });
  assert.equal(found.type, 'passkey-prf');
  assert.equal('owner' in found, false);
  ws.close();
  const stranger = await person(s);
  await assert.rejects(id.removeUnlockMethod(stranger.ws, pk.id), reason('not-found'));
  const gen = await id.removeUnlockMethod(a.ws, pk.id);
  assert.equal(gen, 2);
  methods = await id.listUnlockMethods(cc, a.ws, { openLabel });
  assert.equal(methods.length, 1);
  await assert.rejects(id.removeUnlockMethod(a.ws, methods[0].id), reason('last-method'));
  const again = await connect(s);
  assert.equal((await signIn(again, a.identity)).sessionGeneration, 2);
  again.close();
  const guest = await person(s, { account: false });
  await assert.rejects(id.removeUnlockMethod(guest.ws, methods[0].id), reason('no-account'));
  a.close(); stranger.close(); guest.close();
});

test('a method\'s name the server moves to another of the same account\'s methods reads as null (labels version 3, D-47)', async (t) => {
  if (!needsDb(t)) return;
  const a = await person(s);
  const sealLabel = (label, method) => id.sealMethodLabel(cc, a.identity.masterSymmKey, method, label);
  const openLabel = (sealed, method) => id.openMethodLabel(cc, a.identity.masterSymmKey, method, sealed);
  const laptop = cc.randomBytes(16), phone = cc.randomBytes(16);
  for (const [credentialId, label] of [[laptop, 'my laptop'], [phone, 'my phone']]) {
    const method = await id.wrapRootKeyWithPrf(cc, a.identity.rootKey, cc.randomBytes(32), credentialId, cc.randomBytes(32), label);
    await id.addUnlockMethod(cc, a.ws, a.identity, method, { sealLabel });
  }
  const labels = async () => Object.fromEntries((await id.listUnlockMethods(cc, a.ws, { openLabel }))
    .filter((m) => m.credentialId).map((m) => [cc.toHex(m.credentialId), m.label]));
  assert.deepEqual(await labels(), { [cc.toHex(laptop)]: 'my laptop', [cc.toHex(phone)]: 'my phone' });
  // A dishonest server swaps the two sealed names, hoping the person removes
  // the wrong passkey. Version 2 bound a name to the account only, and both
  // would have opened; version 3 binds it to its credential.
  await db.owner.query(
    `UPDATE unlock_methods SET sealed_label = CASE credential_id
       WHEN $1 THEN (SELECT sealed_label FROM unlock_methods WHERE credential_id = $2)
       ELSE (SELECT sealed_label FROM unlock_methods WHERE credential_id = $1) END
     WHERE credential_id IN ($1, $2)`,
    [Buffer.from(laptop), Buffer.from(phone)],
  );
  assert.deepEqual(await labels(), { [cc.toHex(laptop)]: null, [cc.toHex(phone)]: null });
  a.close();
});

test('rotate-recovery-code is atomic: the new code opens the account, the old finds nothing, the generation bumps; a passkey or a stranger\'s id cannot be cancelled, and then nothing has changed', async (t) => {
  if (!needsDb(t)) return;
  const a = await person(s);
  const sealLabel = async () => new Uint8Array(0);
  const passkey = await id.wrapRootKeyWithPrf(cc, a.identity.rootKey, cc.randomBytes(32), cc.randomBytes(16), cc.randomBytes(32));
  await id.addUnlockMethod(cc, a.ws, a.identity, passkey, { sealLabel });
  const methods = await id.listUnlockMethods(cc, a.ws, { openLabel: async () => null });
  const oldCode = methods.find((m) => m.type === 'recovery-code');
  const pk = methods.find((m) => m.type === 'passkey-prf');
  const fresh = await id.wrapRootKeyWithNewRecoveryCode(cc, a.identity.rootKey);
  await assert.rejects(id.rotateRecoveryCode(cc, a.ws, a.identity, fresh.method, [pk.id], { sealLabel }), reason('not-a-recovery-code'));
  await assert.rejects(id.rotateRecoveryCode(cc, a.ws, a.identity, fresh.method, [globalThis.crypto.randomUUID()], { sealLabel }), reason('not-found'));
  assert.equal((await id.listUnlockMethods(cc, a.ws, { openLabel: async () => null })).length, 2, 'nothing changed');
  const r = await id.rotateRecoveryCode(cc, a.ws, a.identity, fresh.method, [oldCode.id], { sealLabel });
  assert.equal(r.sessionGeneration, 2);
  const ws = await connect(s);
  await assert.rejects(id.lookupUnlockMethod(cc, ws, { recoveryLookupHash: await id.lookupHashForEnteredCode(cc, a.code) }), reason('not-found'));
  const found = await id.lookupUnlockMethod(cc, ws, { recoveryLookupHash: await id.lookupHashForEnteredCode(cc, fresh.displayString) });
  assert.equal(cc.toHex(await id.unwrapRootKeyWithRecoveryCode(cc, found, fresh.displayString)), cc.toHex(a.identity.rootKey));
  ws.close();
  assert.equal(await id.bumpSessionGeneration(a.ws), 3);
  const guest = await person(s, { account: false });
  await assert.rejects(id.bumpSessionGeneration(guest.ws), reason('no-account'));
  a.close(); guest.close();
});

test('the registration policy: a refusal names its reason, the value is stored, and auth-ok carries the host field between the blob and the generation', async (t) => {
  if (!needsDb(t)) return;
  await db.owner.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS terms_version_accepted TEXT');
  const p = await startServer({
    db,
    registration: {
      columns: ['terms_version_accepted'],
      onRegister(msg) { if (msg.termsVersion !== '1.0') throw new Error('policy says no'); return { terms_version_accepted: msg.termsVersion }; },
      authOkFields(row) { return { termsVersionAccepted: row ? row.terms_version_accepted : null }; },
    },
  });
  try {
    const me = await id.createIdentity(cc);
    const ws = await connect(p);
    const first = await signIn(ws, me);
    assert.equal(first.fields.termsVersionAccepted, null);
    const { method } = await id.wrapRootKeyWithNewRecoveryCode(cc, me.rootKey);
    const blob = await id.sealIdentityBlob(cc, me, id.buildIdentityBlobPlaintext(cc, me, {}));
    await assert.rejects(id.registerAccount(cc, ws, me, blob, [method], { ...noLabel, policyFields: { termsVersion: '9' } }), (e) => e.reason === 'invalid' && e.detail === 'policy says no');
    await id.registerAccount(cc, ws, me, blob, [method], { ...noLabel, policyFields: { termsVersion: '1.0' } });
    ws.close();
    const ws2 = await connect(p);
    const ok = await signIn(ws2, me);
    assert.equal(ok.fields.termsVersionAccepted, '1.0');
    const keys = Object.keys(ok.fields);
    assert.equal(keys.indexOf('termsVersionAccepted'), keys.indexOf('encryptedIdentityBlob') + 1);
    ws2.close();
  } finally {
    await p.close();
    await db.owner.query('ALTER TABLE users DROP COLUMN terms_version_accepted');
  }
});

test('delete-account erases the account, its methods, pointers and counters, runs the host hook after, touches nobody else, and a guest deletes nothing', async (t) => {
  if (!needsDb(t)) return;
  let seen = null;
  const p = await startServer({ db, onDeleteAccount: async (pool, key) => { seen = (await pool.query('SELECT 1 FROM users WHERE routing_public_key = $1', [key])).rows.length; } });
  try {
    const a = await person(p); const b = await person(p);
    await published(a);
    await published(b);
    const key = Buffer.from(a.identity.routing.publicKeyRaw);
    assert.equal((await db.owner.query('SELECT count(*)::int AS n FROM pointers WHERE owner_routing_public_key = $1', [key])).rows[0].n, 1);
    assert.equal((await db.owner.query('SELECT count(*)::int AS n FROM rate_limit_counters WHERE routing_key = $1', [key])).rows[0].n, 1);
    assert.equal(await id.deleteAccount(a.ws), true);
    assert.equal(seen, 0, 'the hook ran after the row was gone');
    for (const table of ['users', 'unlock_methods', 'pointers', 'rate_limit_counters']) {
      const col = table === 'users' ? 'routing_public_key' : table === 'rate_limit_counters' ? 'routing_key' : 'owner_routing_public_key';
      assert.equal((await db.owner.query(`SELECT count(*)::int AS n FROM ${table} WHERE ${col} = $1`, [key])).rows[0].n, 0, table);
    }
    const bWs = await connect(p);
    assert.equal((await signIn(bWs, b.identity)).hasAccount, true);
    bWs.close();
    const guest = await person(p, { account: false });
    assert.equal(await id.deleteAccount(guest.ws), false);
    a.close(); b.close(); guest.close();
  } finally { await p.close(); }
});

// ---------------------------------------------------------------------
// Objects, members, pointers
// ---------------------------------------------------------------------

test('create: the object, the owner\'s row and the owner\'s pointer land in one transaction; the selector query finds it, and only where it is', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s);
  const c = await published(owner);
  const pointers = await access.fetchPointers(owner.ws);
  assert.equal(pointers.length, 1);
  const opened = await access.pointerCodec.open(owner.identity, pointers[0].sealed);
  assert.equal(cc.toHex(opened.kObject), cc.toHex(c.kObjectRaw));
  const found = await access.queryObjects(owner.ws, { collection: 'events', selectors: [c.selector.selector, 'zzzzz'], windowStart: '2026-10-02' });
  assert.equal(found.objects.length, 1);
  const o = found.objects[0];
  assert.equal(o.objectId, c.objectId);
  assert.equal(o.keyEpoch, 1);
  assert.equal(o.adminCapabilityHash, null, 'the admin hash is not on the wire: it would be a stable per-object token for every querier');
  assert.equal(o.fields.selector, c.selector.selector);
  assert.equal(o.fields.windowStart, '2026-10-01');
  assert.equal(o.fields.collection, 'events');
  const kObjectKey = await cc.importSymmetricKey(c.kObjectRaw);
  assert.equal((await ac.openContent(cc, kObjectKey, c.objectId, 1, o.encryptedContent)).title, 'x');
  assert.equal((await access.queryObjects(owner.ws, { collection: 'events', selectors: ['zzzzz'], windowStart: '2026-10-01' })).objects.length, 0, 'another selector');
  assert.equal((await access.queryObjects(owner.ws, { collection: 'events', selectors: [c.selector.selector], windowStart: '2026-10-03', windowEnd: '2026-10-09' })).objects.length, 0, 'another window');
  assert.equal((await access.queryObjects(owner.ws, { collection: 'events', all: true, windowStart: '2026-09-01', windowEnd: '2026-10-31' })).objects.some((x) => x.objectId === c.objectId), true, 'all');
  const fetched = await access.fetchObject(owner.ws, c.objectId);
  assert.equal(fetched.adminCapabilityHash, null);
  await assert.rejects(access.fetchObject(owner.ws, globalThis.crypto.randomUUID()), reason('not-found'));
  owner.close();
});

test('create refuses: a guest, an unknown collection, a wrong-length selector, a window on a windowless collection, a reversed window (nothing persisted), a duplicate id, an owner row not at epoch 1', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const guest = await person(s, { account: false });
  const c = await access.createObject({ identity: owner.identity, content: { title: 'x' } });
  await assert.rejects(access.createObjectMessage(guest.ws, c, events()), reason('no-account'));
  await assert.rejects(access.createObjectMessage(owner.ws, c, events({ collection: 'nope' })), reason('invalid'));
  await assert.rejects(access.createObjectMessage(owner.ws, c, events({ selector: 'abcd' })), reason('invalid'));
  await assert.rejects(access.createObjectMessage(owner.ws, c, { collection: 'notes', selector: 'ab', windowStart: '2026-10-01', windowEnd: '2026-10-01' }), reason('invalid'));
  await assert.rejects(access.createObjectMessage(owner.ws, c, events({ windowStart: '2026-10-05', windowEnd: '2026-10-01' })), reason('invalid-date-range'));
  assert.equal((await db.owner.query('SELECT count(*)::int AS n FROM objects WHERE id = $1', [c.objectId])).rows[0].n, 0);
  await access.createObjectMessage(owner.ws, c, events());
  await assert.rejects(access.createObjectMessage(owner.ws, c, events()), reason('duplicate-event-id'));
  const d = await access.createObject({ identity: owner.identity, content: { title: 'y' } });
  d.ownerRow.keyEpoch = 2;
  await assert.rejects(access.createObjectMessage(owner.ws, d, events()), reason('invalid'));
  // A windowless collection: created without a window, queried without one, and a window in the query is refused.
  const n = await access.createObject({ identity: owner.identity, content: { title: 'note' } });
  await access.createObjectMessage(owner.ws, n, { collection: 'notes', selector: 'q7' });
  assert.equal((await access.queryObjects(owner.ws, { collection: 'notes', selectors: ['q7'] })).objects.some((x) => x.objectId === n.objectId), true);
  await assert.rejects(access.queryObjects(owner.ws, { collection: 'notes', selectors: ['q7'], windowStart: '2026-10-01' }), reason('invalid'));
  await assert.rejects(access.queryObjects(owner.ws, { collection: 'notes', all: true }), reason('invalid'), 'all is not allowed on notes');
  await assert.rejects(access.queryObjects(owner.ws, { collection: 'events', selectors: [], windowStart: '2026-10-01' }), reason('invalid'));
  await assert.rejects(access.queryObjects(owner.ws, { collection: 'events', all: true, selectors: ['abcde'], windowStart: '2026-10-01' }), reason('invalid'));
  await assert.rejects(access.queryObjects(owner.ws, { collection: 'events', selectors: ['abcde'], windowStart: '2026-10-05', windowEnd: '2026-10-01' }), reason('invalid'));
  owner.close(); guest.close();
});

test('a link holder reads and lists the roster; after revoke the link is not-found; the holder keeps reading; a first reaction makes a member; a removal rotates them out', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const guest = await person(s);
  const c = await published(owner);
  const link = await access.createShareLink({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, maxUses: 1, expiresAt: daysAhead(1), creator: owner.identity, creatorName: 'Ada', keyEpoch: 1 });
  await access.publishShareLink(owner.ws, link);
  const payload = await access.redeemShareLinkMessage(guest.ws, link.hashedToken);
  const redeemed = await access.redeemShareLink(link.token, payload);
  assert.equal(redeemed.creatorName, 'Ada');
  const ro = await access.buildReadOnlyPointer({ identity: guest.identity, objectId: c.objectId, kObjectRaw: redeemed.kObjectRaw, keyEpoch: 1 });
  await access.joinObject(guest.ws, { objectId: c.objectId, pointer: ro });
  const fetched = await access.fetchObject(guest.ws, c.objectId);
  const kObjectKey = await cc.importSymmetricKey(redeemed.kObjectRaw);
  assert.equal((await ac.openContent(cc, kObjectKey, c.objectId, fetched.keyEpoch, fetched.encryptedContent)).title, 'x');
  const readSecret = await access.readCapability(redeemed.kObjectRaw);
  assert.equal((await access.fetchMembers(guest.ws, c.objectId, { readCapabilitySecret: readSecret })).length, 1);
  assert.equal(await access.revokeShareLink(owner.ws, link.hashedToken, link.manageSecret), 1);
  await assert.rejects(access.redeemShareLinkMessage(guest.ws, link.hashedToken), reason('not-found'));
  const first = await access.buildFirstReaction({ identity: guest.identity, objectId: c.objectId, kObjectRaw: redeemed.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  const pointers = await access.fetchPointers(guest.ws);
  await access.createMemberRow(guest.ws, { objectId: c.objectId, row: first.row, pointerId: pointers[0].pointerId, pointer: first.pointer, readCapabilitySecret: first.readCapabilitySecret });
  const rows = await access.fetchMembers(owner.ws, c.objectId, { adminCapabilitySecret: c.adminCapabilitySecret });
  assert.equal(rows.length, 2);
  const roster = access.roster(await access.openRows({ kObjectRaw: c.kObjectRaw, objectId: c.objectId, rows }));
  assert.equal(roster.filter((e) => e.verified).length, 2);
  const plan = await access.buildRotationPlan({ objectId: c.objectId, identity: owner.identity, oldKObjectRaw: c.kObjectRaw, oldEpoch: 1, content: c.previewContent, rows, remove: [first.row.rowId], selfRowId: c.ownerRow.rowId });
  assert.equal(await access.rotateObjectKey(owner.ws, c.objectId, c.adminCapabilitySecret, plan), 2);
  const after = await access.fetchObject(guest.ws, c.objectId);
  assert.equal(after.keyEpoch, 2);
  await assert.rejects(ac.openContent(cc, kObjectKey, c.objectId, after.keyEpoch, after.encryptedContent), 'the old key opens nothing new');
  await assert.rejects(access.fetchMembers(guest.ws, c.objectId, { readCapabilitySecret: readSecret }), reason('unauthorized'));
  await assert.rejects(access.fetchMyRow(guest.ws, c.objectId, first.row.rowCapabilitySecret), reason('not-found'));
  assert.equal((await db.owner.query('SELECT status FROM object_members WHERE id = $1', [first.row.rowId])).rows[0].status, 'removed_by_admin');
  owner.close(); guest.close();
});

test('the server refuses: a join without the key, an incomplete or stale plan, an old admin secret, a stale-epoch row write; a member heals, leaves; the owner deletes; a stale pointer remains', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const bob = await person(s); const eve = await person(s);
  const c = await published(owner);
  const bobRow = await access.buildMemberRow({ identity: bob.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  const bobPtr = await access.buildReadOnlyPointer({ identity: bob.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1 });
  await assert.rejects(access.joinObject(bob.ws, { objectId: c.objectId, pointer: bobPtr, row: bobRow, readCapabilitySecret: cc.randomBytes(32) }), reason('unauthorized'));
  await assert.rejects(access.joinObject(bob.ws, { objectId: globalThis.crypto.randomUUID(), pointer: bobPtr }), reason('event-not-found'));
  await access.joinObject(bob.ws, { objectId: c.objectId, pointer: bobPtr, row: bobRow, readCapabilitySecret: c.readCapabilitySecret });
  const eveRow = await access.buildMemberRow({ identity: eve.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1, content: { status: 'going' } });
  await access.joinObject(eve.ws, { objectId: c.objectId, pointer: await access.buildReadOnlyPointer({ identity: eve.identity, objectId: c.objectId, kObjectRaw: c.kObjectRaw, keyEpoch: 1 }), row: eveRow, readCapabilitySecret: c.readCapabilitySecret });
  const rows = await access.fetchMembers(owner.ws, c.objectId, { adminCapabilitySecret: c.adminCapabilitySecret });
  assert.equal(rows.length, 3);
  const incomplete = await access.buildRotationPlan({ objectId: c.objectId, identity: owner.identity, oldKObjectRaw: c.kObjectRaw, oldEpoch: 1, content: c.previewContent, rows: rows.filter((r) => r.rowId !== bobRow.rowId), remove: [eveRow.rowId], selfRowId: c.ownerRow.rowId });
  await assert.rejects(access.rotateObjectKey(owner.ws, c.objectId, c.adminCapabilitySecret, incomplete), reason('stale'));
  assert.equal((await access.fetchObject(owner.ws, c.objectId)).keyEpoch, 1, 'nothing changed');
  await assert.rejects(access.rotateObjectKey(owner.ws, c.objectId, cc.randomBytes(32), incomplete), reason('unauthorized'));
  const plan = await access.buildRotationPlan({ objectId: c.objectId, identity: owner.identity, oldKObjectRaw: c.kObjectRaw, oldEpoch: 1, content: c.previewContent, rows, remove: [eveRow.rowId], selfRowId: c.ownerRow.rowId });
  assert.equal(await access.rotateObjectKey(owner.ws, c.objectId, c.adminCapabilitySecret, plan), 2);
  await assert.rejects(access.rotateObjectKey(owner.ws, c.objectId, plan.adminCapabilitySecret, plan), reason('stale'));
  await assert.rejects(access.updateObject(owner.ws, { objectId: c.objectId, adminCapabilitySecret: c.adminCapabilitySecret, keyEpoch: 2, encryptedContent: plan.encryptedContent, selector: c.selector }), reason('unauthorized'), 'the old admin secret');
  await assert.rejects(access.deleteObject(owner.ws, c.objectId, c.adminCapabilitySecret), reason('unauthorized'));
  await assert.rejects(access.updateMemberRowMessage(eve.ws, { objectId: c.objectId, rowCapabilitySecret: eveRow.rowCapabilitySecret, encryptedRow: eveRow.encryptedRow, keyEpoch: 1 }), reason('not-found'), 'a removed row');
  await assert.rejects(access.updateMemberRowMessage(bob.ws, { objectId: c.objectId, rowCapabilitySecret: bobRow.rowCapabilitySecret, encryptedRow: bobRow.encryptedRow, keyEpoch: 1 }), reason('stale'));
  const mine = await access.fetchMyRow(bob.ws, c.objectId, bobRow.rowCapabilitySecret);
  assert.equal(mine.keyEpoch, 2);
  const healed = await access.refreshPointerAfterRotation({ identity: bob.identity, objectId: c.objectId, myRow: mine, existingPointer: await access.pointerCodec.open(bob.identity, bobPtr) });
  assert.deepEqual(healed.kObjectRaw, plan.newKObjectRaw);
  const newKey = await cc.importSymmetricKey(healed.kObjectRaw);
  const opened = await ac.openMemberRow(cc, newKey, c.objectId, mine.rowId, mine.encryptedRow);
  const edited = await ac.updateMemberRow(cc, newKey, bob.identity, c.objectId, mine.rowId, { status: 'interested' }, opened.payload);
  await access.updateMemberRowMessage(bob.ws, { objectId: c.objectId, rowCapabilitySecret: bobRow.rowCapabilitySecret, encryptedRow: edited, keyEpoch: 2, extra: { quietPush: true } });
  assert.equal(await access.deleteMyRow(bob.ws, c.objectId, bobRow.rowCapabilitySecret), true);
  assert.equal(await access.deleteMyRow(bob.ws, c.objectId, bobRow.rowCapabilitySecret), false, 'nothing of yours here');
  await access.deleteObject(owner.ws, c.objectId, plan.adminCapabilitySecret);
  await assert.rejects(access.fetchObject(owner.ws, c.objectId), reason('not-found'));
  assert.equal((await access.fetchPointers(bob.ws)).length, 1, 'the pointer stays until the client discards it');
  owner.close(); bob.close(); eve.close();
});

test('members-only roster: the read capability no longer opens it; a row capability does, and so does the admin; another object\'s row capability does not; an ordinary object still serves any key holder', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const bob = await person(s);
  const c = await published(owner, { selector: events({ rosterMembersOnly: true }) });
  const other = await published(owner);
  const read = { readCapabilitySecret: c.readCapabilitySecret };
  await assert.rejects(access.fetchMembers(bob.ws, c.objectId, read), reason('unauthorized'));
  assert.equal((await access.fetchMembers(owner.ws, c.objectId, { rowCapabilitySecret: c.ownerRow.rowCapabilitySecret })).length, 1);
  assert.equal((await access.fetchMembers(owner.ws, c.objectId, { adminCapabilitySecret: c.adminCapabilitySecret })).length, 1);
  await assert.rejects(access.fetchMembers(owner.ws, c.objectId, { rowCapabilitySecret: other.ownerRow.rowCapabilitySecret }), reason('unauthorized'));
  assert.equal((await access.fetchMembers(bob.ws, other.objectId, { readCapabilitySecret: other.readCapabilitySecret })).length, 1, 'control');
  assert.equal((await access.fetchObject(bob.ws, c.objectId)).fields.rosterMembersOnly, true);
  owner.close(); bob.close();
});

test('update: re-seals the content, moves the selector and window, keeps the second tier when none is sent, and is refused with a wrong secret, a wrong epoch or a wrong collection', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s);
  const c = await published(owner, { content: { title: 'x', address: '12 Secret St' }, twoTier: true });
  const key = await cc.importSymmetricKey(c.kObjectRaw);
  const moved = events();
  const content = await ac.sealContent(cc, key, c.objectId, 1, { ...c.previewContent, title: 'y' });
  await access.updateObject(owner.ws, { objectId: c.objectId, adminCapabilitySecret: c.adminCapabilitySecret, keyEpoch: 1, encryptedContent: content, selector: moved });
  const at = await access.queryObjects(owner.ws, { collection: 'events', selectors: [moved.selector], windowStart: '2026-10-01' });
  assert.equal(at.objects.length, 1);
  assert.equal((await ac.openContent(cc, key, c.objectId, 1, at.objects[0].encryptedContent)).title, 'y');
  assert.ok(at.objects[0].encryptedDetail, 'COALESCE kept the second tier');
  assert.equal((await access.queryObjects(owner.ws, { collection: 'events', selectors: [c.selector.selector], windowStart: '2026-10-01' })).objects.length, 0, 'gone from the old selector');
  await assert.rejects(access.updateObject(owner.ws, { objectId: c.objectId, adminCapabilitySecret: cc.randomBytes(32), keyEpoch: 1, encryptedContent: content, selector: moved }), reason('unauthorized'));
  await assert.rejects(access.updateObject(owner.ws, { objectId: c.objectId, adminCapabilitySecret: c.adminCapabilitySecret, keyEpoch: 2, encryptedContent: content, selector: moved }), reason('stale'));
  await assert.rejects(access.updateObject(owner.ws, { objectId: c.objectId, adminCapabilitySecret: c.adminCapabilitySecret, keyEpoch: 1, encryptedContent: content, selector: { collection: 'notes', selector: 'ab' } }), reason('event-not-found'));
  await assert.rejects(access.updateObject(owner.ws, { objectId: c.objectId, adminCapabilitySecret: c.adminCapabilitySecret, keyEpoch: 1, encryptedContent: content, selector: events({ windowStart: '2026-10-09', windowEnd: '2026-10-01' }) }), reason('invalid-date-range'));
  // A rotation must re-seal the second tier of a two-tier object.
  const rows = await access.fetchMembers(owner.ws, c.objectId, { adminCapabilitySecret: c.adminCapabilitySecret });
  const plan = await access.buildRotationPlan({ objectId: c.objectId, identity: owner.identity, oldKObjectRaw: c.kObjectRaw, oldEpoch: 1, content: c.previewContent, rows, selfRowId: c.ownerRow.rowId });
  await assert.rejects(access.rotateObjectKey(owner.ws, c.objectId, c.adminCapabilitySecret, { ...plan, encryptedDetail: null }), (e) => e.reason === 'invalid' && /second tier/.test(e.detail));
  owner.close();
});

test('a hidden object (a host set its status) is not found, not queried, not pushed to, and refuses every admin and member action', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s);
  const c = await published(owner);
  await db.owner.query("UPDATE objects SET status = 'hidden' WHERE id = $1", [c.objectId]);
  await assert.rejects(access.fetchObject(owner.ws, c.objectId), reason('not-found'));
  assert.equal((await access.queryObjects(owner.ws, { collection: 'events', selectors: [c.selector.selector], windowStart: '2026-10-01' })).objects.length, 0);
  await assert.rejects(access.fetchMembers(owner.ws, c.objectId, { adminCapabilitySecret: c.adminCapabilitySecret }), reason('unauthorized'));
  await assert.rejects(access.deleteObject(owner.ws, c.objectId, c.adminCapabilitySecret), reason('unauthorized'));
  await assert.rejects(access.updateMemberRowMessage(owner.ws, { objectId: c.objectId, rowCapabilitySecret: c.ownerRow.rowCapabilitySecret, encryptedRow: c.ownerRow.encryptedRow, keyEpoch: 1 }), reason('not-found'), 'a member row on a hidden object is not there either');
  await assert.rejects(access.fetchMyRow(owner.ws, c.objectId, c.ownerRow.rowCapabilitySecret), reason('not-found'));
  await assert.rejects(access.joinObject(owner.ws, { objectId: c.objectId, pointer: c.pointer }), reason('event-not-found'));
  assert.equal((await db.owner.query('SELECT count(*)::int AS n FROM objects WHERE id = $1', [c.objectId])).rows[0].n, 1, 'still there for the host');
  owner.close();
});

test('the query backstops: too many selectors is invalid; an answer past maxQueryRows is refused as too-many; a host\'s extras ride the same reply', async (t) => {
  if (!needsDb(t)) return;
  const p = await startServer({ db, query: { maxQueryRows: 2, maxSelectors: 3 }, collections: { events: { selectorLength: 5, window: true, allowAll: true, queryExtras: async (pool, q) => ({ listings: [q.collection.name, q.selectors ? q.selectors.length : 'all'] }) } } });
  try {
    const owner = await person(p);
    const cell = sel();
    for (let i = 0; i < 3; i++) await published(owner, { selector: events({ selector: cell }) });
    await assert.rejects(access.queryObjects(owner.ws, { collection: 'events', selectors: [cell, 'aaaaa', 'bbbbb', 'ccccc'], windowStart: '2026-10-01' }), reason('invalid'));
    await assert.rejects(access.queryObjects(owner.ws, { collection: 'events', selectors: [cell], windowStart: '2026-10-01' }), (e) => e.reason === 'too-many' && e.serverMessage.limit === 2);
    const two = await access.queryObjects(owner.ws, { collection: 'events', selectors: [sel()], windowStart: '2026-10-01' });
    assert.deepEqual(two.extras, { listings: ['events', 1] });
    owner.close();
  } finally { await p.close(); }
});

test('the caps: an over-long content, a nested over-long row and a short hash are refused with the field named, and an ordinary one goes through', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s);
  const c = await access.createObject({ identity: owner.identity, content: { title: 'x' } });
  const big = { ...c, encryptedContent: new Uint8Array(512 * 1024 + 1) };
  await assert.rejects(access.createObjectMessage(owner.ws, big, events()), (e) => e.reason === 'invalid' && /encryptedEventData is too large/.test(e.detail));
  const bigRow = { ...c, ownerRow: { ...c.ownerRow, encryptedObjectKey: new Uint8Array(4097) } };
  await assert.rejects(access.createObjectMessage(owner.ws, bigRow, events()), (e) => e.reason === 'invalid' && /creatorParticipation.encryptedSharedEventKey is too large/.test(e.detail));
  const shortHash = { ...c, readCapabilityHash: 'ab'.repeat(16) };
  await assert.rejects(access.createObjectMessage(owner.ws, shortHash, events()), (e) => e.reason === 'invalid' && /readCapabilityHash must be 32 bytes/.test(e.detail));
  await access.createObjectMessage(owner.ws, c, events());
  await assert.rejects(access.updatePointer(owner.ws, (await access.fetchPointers(owner.ws))[0].pointerId, new Uint8Array(256 * 1024 + 1)), reason('invalid'));
  owner.close();
});

test('pointers: update-pointer cannot reach another account\'s pointer; fetch-pointers returns only the caller\'s', async (t) => {
  if (!needsDb(t)) return;
  const a = await person(s); const b = await person(s);
  await published(a);
  const [mine] = await access.fetchPointers(a.ws);
  assert.equal((await access.fetchPointers(b.ws)).length, 0);
  await assert.rejects(access.updatePointer(b.ws, mine.pointerId, new Uint8Array(16)), reason('not-found'));
  await access.updatePointer(a.ws, mine.pointerId, mine.sealed);
  assert.equal(await access.deletePointer(b.ws, mine.pointerId), false, 'another account cannot delete it');
  assert.equal(await access.deletePointer(a.ws, mine.pointerId), true);
  assert.equal(await access.deletePointer(a.ws, mine.pointerId), false, 'already gone');
  assert.equal((await access.fetchPointers(a.ws)).length, 0);
  a.close(); b.close();
});

// ---------------------------------------------------------------------
// Share links
// ---------------------------------------------------------------------

test('links: N uses then exhausted; expired; stats only with the management secret; a recipient cannot revoke; limits on uses and expiry', async (t) => {
  if (!needsDb(t)) return;
  const owner = await person(s); const a = await person(s); const b = await person(s);
  const c = await published(owner);
  const link = await access.createShareLink({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, maxUses: 2, expiresAt: daysAhead(1) });
  await access.publishShareLink(owner.ws, link);
  await access.redeemShareLinkMessage(a.ws, link.hashedToken);
  await access.redeemShareLinkMessage(b.ws, link.hashedToken);
  await assert.rejects(access.redeemShareLinkMessage(b.ws, link.hashedToken), reason('exhausted'));
  const stats = await access.fetchShareLinkStats(owner.ws, [{ hashedToken: link.hashedToken, manageSecret: link.manageSecret }]);
  assert.equal(stats[0].useCount, 2);
  assert.equal(stats[0].maxUses, 2);
  assert.deepEqual(await access.fetchShareLinkStats(a.ws, [{ hashedToken: link.hashedToken, manageSecret: cc.randomBytes(32) }]), []);
  assert.equal(await access.revokeShareLink(a.ws, link.hashedToken, cc.randomBytes(32)), 0);
  await assert.rejects(access.publishShareLink(owner.ws, { ...link, hashedToken: 'ab'.repeat(32), maxUses: 999 }), reason('invalid'));
  await assert.rejects(access.publishShareLink(owner.ws, { ...link, hashedToken: 'cd'.repeat(32), expiresAt: daysAhead(401) }), reason('invalid'));
  await assert.rejects(access.publishShareLink(owner.ws, { ...link, hashedToken: 'ef'.repeat(32), expiresAt: daysAhead(-1) }), reason('invalid'));
  await assert.rejects(access.publishShareLink(owner.ws, { ...link }), reason('token-collision'));
  const soon = await access.createShareLink({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, expiresAt: new Date(Date.now() + 1500).toISOString() });
  await access.publishShareLink(owner.ws, soon);
  await new Promise((r) => setTimeout(r, 1600));
  await assert.rejects(access.redeemShareLinkMessage(a.ws, soon.hashedToken), reason('expired'));
  await assert.rejects(access.redeemShareLinkMessage(a.ws, 'ff'.repeat(32)), reason('not-found'));
  owner.close(); a.close(); b.close();
});

// ---------------------------------------------------------------------
// The mailbox's server half
// ---------------------------------------------------------------------

test('a mailbox drop: sent, polled with its bundle, consumed, then served without it and emptied in the row; malformed labels refused', async (t) => {
  if (!needsDb(t)) return;
  const a = await person(s);
  const mailboxId = cc.randomBytes(32);
  const bundle = cc.randomBytes(64);
  const sent = await raw(a.ws, { type: 'send-invite', mailboxId: cc.toBase64Url(mailboxId), encryptedBundle: cc.toBase64Url(bundle), expiresAt: daysAhead(1) }, 'send-invite-ok', 'send-invite-failed');
  const polled = await raw(a.ws, { type: 'poll-invites', mailboxIds: [cc.toBase64Url(mailboxId)] }, 'invites', 'poll-invites-failed');
  const mine = polled.invites.find((i) => i.id === sent.inviteId);
  assert.equal(mine.consumed, false);
  assert.equal(mine.encryptedBundle, cc.toBase64Url(bundle));
  await raw(a.ws, { type: 'consume-invite', inviteId: sent.inviteId }, 'consume-invite-ok', 'consume-invite-failed');
  const after = (await raw(a.ws, { type: 'poll-invites', mailboxIds: [cc.toBase64Url(mailboxId)] }, 'invites', 'poll-invites-failed')).invites.find((i) => i.id === sent.inviteId);
  assert.equal(after.consumed, true);
  assert.equal(after.encryptedBundle, null);
  assert.equal((await db.owner.query('SELECT octet_length(sealed_bundle) AS n FROM mailbox_drops WHERE id = $1', [sent.inviteId])).rows[0].n, 0);
  await assert.rejects(raw(a.ws, { type: 'send-invite', mailboxId: cc.toBase64Url(cc.randomBytes(31)), encryptedBundle: cc.toBase64Url(bundle), expiresAt: daysAhead(1) }, 'send-invite-ok', 'send-invite-failed'), reason('invalid'));
  await assert.rejects(raw(a.ws, { type: 'send-invite', mailboxId: cc.toBase64Url(mailboxId), encryptedBundle: cc.toBase64Url(bundle) }, 'send-invite-ok', 'send-invite-failed'), reason('invalid'), 'no expiry');
  await assert.rejects(raw(a.ws, { type: 'poll-invites', mailboxIds: [] }, 'invites', 'poll-invites-failed'), reason('invalid'));
  await assert.rejects(raw(a.ws, { type: 'consume-invite', inviteId: 'nope' }, 'consume-invite-ok', 'consume-invite-failed'), reason('invalid'));
  a.close();
});

// ---------------------------------------------------------------------
// The daily counters, and the sweep
// ---------------------------------------------------------------------

test('the daily caps: the third object is refused, the counter row holds the key, the action and a DATE and nothing else, another account is unaffected, a guest draws on nothing', async (t) => {
  if (!needsDb(t)) return;
  const p = await startServer({ db, rateLimits: { 'create-event': 2, 'create-url-invite': 1, 'send-invite': 1 } });
  try {
    const a = await person(p); const b = await person(p);
    await published(a); await published(a);
    const c = await access.createObject({ identity: a.identity, content: {} });
    await assert.rejects(access.createObjectMessage(a.ws, c, events()), (e) => e.reason === 'rate-limited' && e.serverMessage.limit === 2);
    await published(b);
    const row = await db.owner.query('SELECT * FROM rate_limit_counters WHERE routing_key = $1 AND action = $2', [Buffer.from(a.identity.routing.publicKeyRaw), 'create-event']);
    assert.deepEqual(Object.keys(row.rows[0]).sort(), ['action', 'count', 'day', 'routing_key']);
    assert.equal(row.rows[0].count, 3);
    const link = await access.createShareLink({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, expiresAt: daysAhead(1) });
    await access.publishShareLink(a.ws, link);
    const link2 = await access.createShareLink({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, expiresAt: daysAhead(1) });
    await assert.rejects(access.publishShareLink(a.ws, link2), reason('rate-limited'));
    const drop = { type: 'send-invite', mailboxId: cc.toBase64Url(cc.randomBytes(32)), encryptedBundle: cc.toBase64Url(cc.randomBytes(8)), expiresAt: daysAhead(1) };
    await raw(a.ws, drop, 'send-invite-ok', 'send-invite-failed');
    await assert.rejects(raw(a.ws, drop, 'send-invite-ok', 'send-invite-failed'), reason('rate-limited'));
    a.close(); b.close();
  } finally { await p.close(); }
});

test('the sweep empties a used-up or expired link\'s payload, deletes it a week after expiry, deletes an expired drop, and old counters', async (t) => {
  if (!needsDb(t)) return;
  const a = await person(s);
  const c = await published(a);
  const used = await access.createShareLink({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, maxUses: 1, expiresAt: daysAhead(1) });
  const old = await access.createShareLink({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, expiresAt: daysAhead(1) });
  const gone = await access.createShareLink({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, expiresAt: daysAhead(1) });
  const live = await access.createShareLink({ objectId: c.objectId, kObjectRaw: c.kObjectRaw, expiresAt: daysAhead(1) });
  for (const l of [used, old, gone, live]) await access.publishShareLink(a.ws, l);
  await access.redeemShareLinkMessage(a.ws, used.hashedToken);
  await db.owner.query("UPDATE share_links SET expires_at = now() - interval '1 day' WHERE hashed_token = $1", [old.hashedToken]);
  await db.owner.query("UPDATE share_links SET expires_at = now() - interval '8 days' WHERE hashed_token = $1", [gone.hashedToken]);
  const drop = await raw(a.ws, { type: 'send-invite', mailboxId: cc.toBase64Url(cc.randomBytes(32)), encryptedBundle: cc.toBase64Url(cc.randomBytes(8)), expiresAt: daysAhead(1) }, 'send-invite-ok', 'send-invite-failed');
  await db.owner.query("UPDATE mailbox_drops SET expires_at = now() - interval '1 hour' WHERE id = $1", [drop.inviteId]);
  await db.owner.query("INSERT INTO rate_limit_counters (routing_key, action, day, count) VALUES ($1, 'create-event', current_date - 3, 1)", [Buffer.from(cc.randomBytes(32))]);
  // Run as the service role, as the library does.
  const { default: pg } = await import('pg');
  const app = new pg.Client(db.appConfig);
  await app.connect();
  const n = (await app.query('SELECT blind_store_sweep() AS n')).rows[0].n;
  await app.end();
  assert.ok(n >= 5, `swept ${n}`);
  const len = async (h) => { const r = await db.owner.query('SELECT octet_length(sealed_payload) AS n FROM share_links WHERE hashed_token = $1', [h]); return r.rows.length ? r.rows[0].n : null; };
  assert.equal(await len(used.hashedToken), 0);
  assert.equal(await len(old.hashedToken), 0);
  assert.equal(await len(gone.hashedToken), null);
  assert.ok((await len(live.hashedToken)) > 0);
  assert.equal((await db.owner.query('SELECT count(*)::int AS n FROM mailbox_drops WHERE id = $1', [drop.inviteId])).rows[0].n, 0);
  assert.equal((await db.owner.query('SELECT count(*)::int AS n FROM rate_limit_counters WHERE day < current_date - 2')).rows[0].n, 0);
  await assert.rejects(access.redeemShareLinkMessage(a.ws, used.hashedToken), reason('exhausted'));
  a.close();
});

test('/healthz answers 200 with a database', async (t) => {
  if (!needsDb(t)) return;
  const h = await fetch(`http://127.0.0.1:${s.port}/healthz`);
  assert.equal(h.status, 200);
  assert.equal(await h.text(), 'ok');
});
