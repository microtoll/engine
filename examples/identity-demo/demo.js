// The identity demo: the packages wired to a plain page. Only crypto-core and
// identity are used; the server is the identity package's in-process
// stand-in (test tooling) until @microtoll/blind-store exists.
import { createCryptoCore } from '/packages/crypto-core/src/index.js';
import {
  createIdentitySession, createSessionStore, createKnownAccountStore, createWebAuthn,
} from '/packages/identity/src/index.js';
import { createFakeServer } from '/packages/identity/test/tooling/fakeServer.mjs';

const cc = createCryptoCore({ namespace: 'demo' });
const server = createFakeServer({ cryptoCore: cc, allowedOrigins: [location.origin] });
const $ = (id) => document.getElementById(id);
const log = (line) => { $('log').textContent = `${new Date().toISOString().slice(11, 19)}  ${line}\n` + $('log').textContent; };

const session = createIdentitySession({
  cryptoCore: cc,
  origin: location.origin,
  transport: { connect: () => server.connect() },
  sessionStore: createSessionStore({ cryptoCore: cc }),                 // IndexedDB "demo-session"
  knownAccounts: createKnownAccountStore({ cryptoCore: cc }),           // localStorage "demo:*"
  webauthn: createWebAuthn({ rpName: 'Microtoll demo' }),
  ui: {
    askRecoveryCode: async (reason, hint) => prompt(`Recovery code needed to ${reason} (${hint})`),
    confirmDeletion: async () => confirm('Delete the account and everything in it?'),
    passkeyName: () => 'Microtoll demo account',
  },
  hooks: {
    afterUnlock: (state) => log(`unlocked: account ${state.hasAccount ? 'open' : 'none (guest)'}, blob revision ${state.blob.revision || 0}`),
    onLocked: () => log('locked'),
    beforeDeleteAccount: () => log('the app would sweep its own rows here, while the keys still exist'),
  },
});

function render() {
  const s = session.state();
  const rows = {
    locked: s.locked,
    account: s.hasAccount ? 'yes' : (s.identity ? 'guest' : 'none'),
    'routing handle': s.identity ? cc.toBase64Url(s.identity.routing.publicKeyRaw) : '—',
    'sealing key stored': s.identity ? String(s.identity.identity.stored) : '—',
    'blob revision': s.blob && s.blob.revision ? s.blob.revision : '—',
    'note in blob': s.blob && s.blob.note ? s.blob.note : '—',
    'session generation': s.serverGeneration ?? '—',
    'server accounts': server.users.size,
  };
  $('state').innerHTML = Object.entries(rows).map(([k, v]) => `<b>${k}</b><span>${String(v)}</span>`).join('');
}

async function run(name, fn) {
  try { const r = await fn(); log(`${name}: ok`); return r; }
  catch (e) { log(`${name}: ${e.code || e.name || 'error'} — ${e.message}${e.diagnostic ? ` (${e.diagnostic})` : ''}`); }
  finally { render(); }
}

$('boot').onclick = () => run('boot', async () => {
  const r = await session.bootFromTrustedSession();
  $('boot-note').textContent = r.restored ? 'restored from the trusted-device session' : `no session restored (${r.reason})`;
  if (!r.restored) await session.bootGuest();
});
$('register-passkey').onclick = () => run('register (passkey)', async () => {
  const { recoveryCode, passkeyBackedUp } = await session.registerCurrentIdentity({ label: 'this browser', passkey: 'platform' });
  $('recovery').textContent = `Your recovery code (shown once): ${recoveryCode}`;
  log(`the passkey reports a synced kind: ${passkeyBackedUp}`);
});
$('register-code').onclick = () => run('register (code only)', async () => {
  const { recoveryCode } = await session.registerCurrentIdentity({ label: 'this browser', passkey: 'none' });
  $('recovery').textContent = `Your recovery code (shown once): ${recoveryCode}`;
});
$('lock').onclick = () => run('lock', () => session.lock());
$('unlock-passkey').onclick = () => run('unlock (passkey)', () => session.unlockWithPasskey());
$('unlock-discoverable').onclick = () => run('unlock (any passkey)', () => session.unlockWithDiscoverablePasskey());
$('unlock-code').onclick = () => run('unlock (code)', () => session.unlockWithRecoveryCode($('code').value));
$('save-note').onclick = () => run('save note', () => session.saveIdentityBlob((b) => ({ ...b, note: $('note').value })));
$('add-passkey').onclick = () => run('add passkey', () => session.addPasskey({ label: 'another passkey' }));
$('rotate').onclick = () => run('rotate recovery code', async () => {
  const { recoveryCode } = await session.rotateRecoveryCode();
  $('recovery').textContent = `Your NEW recovery code (the old one no longer works): ${recoveryCode}`;
});
$('signout-all').onclick = () => run('sign out everywhere', () => session.signOutEverywhere());
$('delete').onclick = () => run('delete account', () => session.deleteAccount());

render();
log('ready — press Boot');
