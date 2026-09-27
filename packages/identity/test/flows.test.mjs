// The flows end to end against the fake server and the fake WebAuthn: the
// hard cases (step-up grace, restore, generation checks, deletion order, a
// half-failed sign-up, an unreadable or rolled-back blob) each have a case
// here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '../src/index.js';
import { createFakeServer, createFakeWebAuthn } from './tooling/fakeServer.mjs';

const cc = createCryptoCore({ namespace: 'example' });
const ORIGIN = 'https://example.test';

function device(server, { webauthn = createFakeWebAuthn({ cryptoCore: cc }), ui = {}, hooks = {}, clock = null } = {}) {
  const sessionStore = createSessionStore();
  const knownAccounts = id.createKnownAccountStore({ cryptoCore: cc, storage: id.memoryStorage() });
  const time = clock || { t: 1_000_000, now() { return this.t; } };
  const session = id.createIdentitySession({
    cryptoCore: cc, origin: ORIGIN, transport: { connect: () => server.connect() },
    sessionStore, knownAccounts, webauthn, ui, hooks, now: () => time.now(),
  });
  return { session, sessionStore, knownAccounts, webauthn, time };
  function createSessionStore() { return id.createSessionStore({ cryptoCore: cc, store: id.memoryStore(), lockIntervalStorage: id.memoryStorage() }); }
}

async function registered(server, opts = {}) {
  const d = device(server, opts);
  await d.session.bootGuest();
  const reg = await d.session.registerCurrentIdentity({ label: 'phone', passkey: 'platform' });
  return { ...d, reg };
}

test('guest → register (passkey + recovery code in one message) → the account is open, remembered, and both methods listed', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server);
  const s = d.session.state();
  assert.equal(s.hasAccount, true);
  assert.equal(s.blob.revision, 1);
  assert.equal(d.reg.passkey, true);
  assert.match(d.reg.recoveryCode, /^[0-9A-Z-]{33}$/);
  assert.equal(server.log.filter((t) => t === 'register').length, 1);
  assert.equal(server.log.includes('add-unlock-method'), false, 'one message, one transaction');
  const methods = await d.session.listUnlockMethods();
  assert.deepEqual(methods.map((m) => m.type), ['passkey-prf', 'recovery-code']);
  assert.equal(methods[0].label, 'phone');
  assert.equal(d.knownAccounts.loadKnownAccount().credentialId.length, 16);
  assert.ok(await d.sessionStore.loadSession({ now: d.time.now() }), 'a trusted session was saved');
});

test('a registration whose server call fails leaves no account and nothing remembered', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = device(server);
  await d.session.bootGuest();
  server.failNext('register', 'server-error');
  await assert.rejects(d.session.registerCurrentIdentity({ passkey: 'platform' }), (e) => e.reason === 'server-error');
  assert.equal(d.session.state().hasAccount, false);
  assert.equal(d.knownAccounts.loadKnownAccount(), null);
  assert.equal(await d.sessionStore.loadSession(), null);
  assert.equal(server.users.size, 0);
});

test('unlock by passkey, by discoverable passkey on a new browser, and by recovery code all open the same account', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server);
  const routing = cc.toBase64Url(d.session.state().identity.routing.publicKeyRaw);
  await d.session.lock();
  assert.equal(d.session.state().locked, true);
  const s1 = await d.session.unlockWithPasskey();
  assert.equal(cc.toBase64Url(s1.identity.routing.publicKeyRaw), routing);

  // A second browser: same passkeys (synced), no known-account record.
  const fresh = device(server, { webauthn: d.webauthn });
  assert.equal(fresh.knownAccounts.loadKnownAccount(), null);
  const s2 = await fresh.session.unlockWithDiscoverablePasskey();
  assert.equal(cc.toBase64Url(s2.identity.routing.publicKeyRaw), routing);
  assert.ok(fresh.knownAccounts.loadKnownAccount().credentialId, 'the record is written only after the proof');

  // A third, with nothing at all: the recovery code.
  const bare = device(server, { webauthn: createFakeWebAuthn({ cryptoCore: cc }) });
  const s3 = await bare.session.unlockWithRecoveryCode(d.reg.recoveryCode.toLowerCase());
  assert.equal(cc.toBase64Url(s3.identity.routing.publicKeyRaw), routing);
  await assert.rejects(bare.session.unlockWithRecoveryCode('ABCD-EFGH-JKMN-PQRS-TVWX-YZ01-234'), (e) => e.reason === 'not-found' || e.code === 'recovery-code-checksum');
});

test('trusted session: restores; is stale after another device removes a method; offline keeps it; a routing mismatch clears it', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server);
  const restored = await d.session.bootFromTrustedSession();
  assert.equal(restored.restored, true);
  assert.equal(restored.state.hasAccount, true);

  // Another device rotates the recovery code: generation bumps.
  const other = device(server);
  await other.session.unlockWithRecoveryCode(d.reg.recoveryCode);
  other.time.t += 1; // still within the step-up grace from the unlock
  await other.session.rotateRecoveryCode();
  const stale = await d.session.bootFromTrustedSession();
  assert.deepEqual(stale, { restored: false, reason: 'stale' });
  assert.equal(await d.sessionStore.loadSession(), null, 'the stale session is forgotten');

  // Offline: the connect throws a transport error; the session is kept.
  const off = await registered(server);
  const saved = await off.sessionStore.loadSession({ now: off.time.now() });
  const offline = id.createIdentitySession({
    cryptoCore: cc, origin: ORIGIN, sessionStore: off.sessionStore, knownAccounts: off.knownAccounts, now: () => off.time.now(),
    transport: { connect: async () => { throw Object.assign(new Error('down'), { transport: true, kind: 'closed' }); } },
  });
  const r = await offline.bootFromTrustedSession();
  assert.equal(r.reason, 'offline');
  assert.ok(r.identity, 'the identity is handed back for an offline copy');
  assert.ok(await off.sessionStore.loadSession({ now: off.time.now() }), 'kept');
  assert.equal(saved.routingPublicKey, r.session.routingPublicKey);

  // A record whose stored routing key was edited fails at the AAD before the mismatch check can run (session.test.mjs);
  // an account deleted elsewhere restores as 'no-account' and the session is forgotten.
  const gone = await registered(server);
  gone.time.t += id.STEP_UP_GRACE_MS + 1;
  const twin = device(server, { webauthn: gone.webauthn, ui: { confirmDeletion: async () => true } });
  await twin.session.unlockWithDiscoverablePasskey();
  await twin.session.deleteAccount();
  assert.deepEqual(await gone.session.bootFromTrustedSession(), { restored: false, reason: 'no-account' });
  assert.equal(await gone.sessionStore.loadSession({ now: gone.time.now() }), null);
});

test('step-up: within the grace nothing is asked; after it the passkey proves; the code is asked when the passkey fails; a different account is refused', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const asked = [];
  const d = await registered(server, { ui: { askRecoveryCode: async (reason, hint) => { asked.push([reason, hint]); return d.reg.recoveryCode; } } });
  const calls0 = d.webauthn.calls();
  await d.session.requireFreshUnlock('test');
  assert.equal(d.webauthn.calls(), calls0, 'registration just proved the person: no ceremony');
  d.time.t += id.STEP_UP_GRACE_MS + 1;
  await d.session.requireFreshUnlock('test');
  assert.equal(d.webauthn.calls(), calls0 + 1, 'the passkey proved it');
  assert.deepEqual(asked, []);

  // The passkey fails (not-allowed): the code is asked instead.
  d.time.t += id.STEP_UP_GRACE_MS + 1;
  const real = d.webauthn.evaluatePrf;
  d.webauthn.evaluatePrf = async () => { throw Object.assign(new Error('closed'), { code: 'not-allowed' }); };
  await d.session.requireFreshUnlock('remove');
  d.webauthn.evaluatePrf = real;
  assert.deepEqual(asked, [['remove', 'passkey-failed']]);

  // A code that opens a different account is refused.
  const otherDevice = await registered(server);
  d.time.t += id.STEP_UP_GRACE_MS + 1;
  d.webauthn.evaluatePrf = async () => { throw Object.assign(new Error('closed'), { code: 'not-allowed' }); };
  const askedOnce = d.session; void askedOnce;
  const wrong = id.createIdentitySession({
    cryptoCore: cc, origin: ORIGIN, transport: { connect: () => server.connect() }, sessionStore: d.sessionStore, knownAccounts: d.knownAccounts,
    webauthn: null, ui: { askRecoveryCode: async () => otherDevice.reg.recoveryCode }, now: () => d.time.now(),
  });
  await wrong.unlockWithRecoveryCode(d.reg.recoveryCode);
  d.time.t += id.STEP_UP_GRACE_MS + 1;
  await assert.rejects(wrong.requireFreshUnlock('x'), (e) => e.code === 'different-account');
  d.webauthn.evaluatePrf = real;
});

test('the grace is bound to the account: switching back to another identity proves nothing', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server, { ui: { askRecoveryCode: async () => null } });
  const a = d.session.state().identity;
  // A second account on the same device, opened by code (a fresh proof of B).
  const b = await registered(server);
  await d.session.switchTo(b.session.state().identity, { freshProof: false });
  await assert.rejects(d.session.requireFreshUnlock('x'), (e) => e.code === 'cancelled' || e.code === 'cannot-ask');
  await d.session.switchTo(a, { freshProof: true });
  await d.session.requireFreshUnlock('x'); // proved, within grace
});

test('saveIdentityBlob: read-modify-write, a conflict re-applies the change on the winner, revisions climb', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server);
  const e = device(server);
  await e.session.unlockWithRecoveryCode(d.reg.recoveryCode);
  await d.session.saveIdentityBlob((b) => ({ ...b, contacts: ['x'] }));
  assert.equal(d.session.state().blob.revision, 2);
  // e still holds the old token: its write conflicts, adopts d's blob and re-applies.
  const blob = await e.session.saveIdentityBlob((b) => ({ ...b, name: 'Ada' }));
  assert.deepEqual(blob.contacts, ['x']);
  assert.equal(blob.name, 'Ada');
  assert.equal(blob.revision, 3);
  assert.equal(e.knownAccounts.knownBlobRevision(e.session.state().identity.routing.publicKeyRaw), 3);
});

test('an unreadable blob stops the unlock with nothing written; a rolled-back blob is refused on a device that saw a later one', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server);
  const routing = cc.toBase64Url(d.session.state().identity.routing.publicKeyRaw);
  const user = server.users.get(routing);
  const good = user.blob;
  const bytes = cc.fromBase64Url(good); bytes[bytes.length - 1] ^= 1; user.blob = cc.toBase64Url(bytes);
  await d.session.lock();
  await assert.rejects(d.session.unlockWithPasskey(), (e) => e.code === id.IDENTITY_BLOB_UNREADABLE);
  assert.equal(user.blob, cc.toBase64Url(bytes), 'nothing was written over it');
  assert.equal(server.log.includes('update-identity-blob'), false);
  user.blob = good;
  await d.session.unlockWithPasskey();
  await d.session.saveIdentityBlob((b) => ({ ...b, later: true })); // revision 2, remembered on this device
  const rolledBack = user.blob; void rolledBack;
  user.blob = good; user.token = 'stale'; // the server serves revision 1 again
  await d.session.lock();
  await assert.rejects(d.session.unlockWithPasskey(), (e) => e.code === id.IDENTITY_BLOB_ROLLED_BACK);
});

test('removing a method: never the last; the generation bumps and this device re-saves its session; sign out everywhere likewise', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server);
  const methods = await d.session.listUnlockMethods();
  await d.session.removeUnlockMethod(methods[0].id); // the passkey; step-up is within grace
  assert.equal(d.session.state().serverGeneration, 2);
  assert.equal((await d.sessionStore.loadSession({ now: d.time.now() })).sessionGeneration, 2);
  assert.equal(d.knownAccounts.loadKnownAccount().credentialId, null, 'the device forgets a passkey it no longer holds for this account');
  const left = await d.session.listUnlockMethods();
  await assert.rejects(d.session.removeUnlockMethod(left[0].id), (e) => e.code === 'last-method');
  assert.equal(await d.session.signOutEverywhere(), 3);
  assert.equal((await d.sessionStore.loadSession({ now: d.time.now() })).sessionGeneration, 3);
  await assert.rejects(d.session.removeUnlockMethod('nope'), (e) => e.code === 'not-found');
});

test('reconnecting after another device signed out everywhere locks this one', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server);
  const other = device(server);
  await other.session.unlockWithRecoveryCode(d.reg.recoveryCode);
  await other.session.signOutEverywhere();
  d.session.state().ws.close();
  await new Promise((r) => setTimeout(r, 5));
  await assert.rejects(d.session.ensureConnected(), (e) => e.code === 'stale-session');
  assert.equal(d.session.state().locked, true);
});

test('deletion order: confirm, prove, forget the session, the app\'s sweep with the connection, delete, then the device records', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const order = [];
  const d = await registered(server, {
    ui: { confirmDeletion: async () => { order.push('confirm'); return true; } },
    hooks: { beforeDeleteAccount: async ({ ws, identity }) => { order.push('sweep'); assert.ok(ws && identity); }, onLocked: async () => order.push('locked') },
  });
  d.time.t += id.STEP_UP_GRACE_MS + 1;
  const deleted = await d.session.deleteAccount();
  assert.equal(deleted, true);
  assert.deepEqual(order, ['confirm', 'sweep', 'locked']);
  assert.equal(server.users.size, 0);
  assert.equal(d.knownAccounts.loadKnownAccount(), null);
  assert.equal(await d.sessionStore.loadSession(), null);
  assert.equal(d.session.state().locked, true);
  // The sweep ran before delete-account on the wire.
  assert.ok(server.log.indexOf('delete-account') > server.log.indexOf('list-unlock-methods'));
});

test('deletion: a declined confirmation or a cancelled proof changes nothing', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server, { ui: { confirmDeletion: async () => false } });
  assert.equal(await d.session.deleteAccount(), false);
  assert.equal(server.users.size, 1);
  const e = await registered(server, { ui: { confirmDeletion: async () => true, askRecoveryCode: async () => null } });
  e.time.t += id.STEP_UP_GRACE_MS + 1;
  e.webauthn.evaluatePrf = async () => { throw Object.assign(new Error('closed'), { code: 'not-allowed' }); };
  await assert.rejects(e.session.deleteAccount(), (e2) => e2.code === 'cancelled');
  assert.equal(server.users.size, 2);
  assert.equal(e.session.state().hasAccount, true);
});

test('checkDeviceAccountMatch: in sync, diverged (another live account), stale (credential gone)', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = await registered(server);
  assert.equal((await d.session.checkDeviceAccountMatch()).status, 'in-sync');
  // Open a second account on this device by code; the device passkey still points at the first.
  const second = await registered(server);
  await d.session.unlockWithRecoveryCode(second.reg.recoveryCode);
  assert.equal((await d.session.checkDeviceAccountMatch()).status, 'diverged');
  // Delete the first account: the device's credential now opens nothing.
  d.time.t += id.STEP_UP_GRACE_MS + 1;
  const firstDevice = device(server, { webauthn: d.webauthn, ui: { confirmDeletion: async () => true } });
  await firstDevice.session.unlockWithDiscoverablePasskey();
  await firstDevice.session.deleteAccount();
  assert.equal((await d.session.checkDeviceAccountMatch()).status, 'stale-device-passkey');
});

test('the lock interval "every-open" keeps no session; adding a passkey on a code-only device makes it known', async () => {
  const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN] });
  const d = device(server);
  await d.session.bootGuest();
  await d.session.registerCurrentIdentity({ passkey: 'none' });
  assert.equal(d.knownAccounts.loadKnownAccount().credentialId, null);
  d.sessionStore.saveLockInterval('every-open');
  await d.session.rememberUnlockedSession();
  assert.equal(await d.sessionStore.loadSession(), null);
  await d.session.addPasskey({ label: 'laptop' });
  assert.ok(d.knownAccounts.loadKnownAccount().credentialId);
  assert.equal((await d.session.listUnlockMethods()).length, 2);
});
