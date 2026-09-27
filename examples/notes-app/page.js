// The page: the identity session wired to buttons, and notes.js wired to a
// list. Nothing here touches a key; the packages do, in this browser only.
import { createCryptoCore } from '@microtoll/crypto-core';
import { createIdentitySession, createSessionStore, createKnownAccountStore, createWebAuthn } from '@microtoll/identity';
import { createNotes, tokenFromLocation } from './notes.js';

const cc = createCryptoCore({ namespace: 'notes-example' });
const $ = (id) => document.getElementById(id);
const log = (line) => { $('log').textContent = `${new Date().toISOString().slice(11, 19)}  ${line}\n` + $('log').textContent; };

// The socket: the same host as the page, at /ws (nginx forwards it).
function connect() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
    ws.addEventListener('open', () => resolve(ws), { once: true });
    ws.addEventListener('error', () => reject(new Error('could not reach the server')), { once: true });
  });
}

const session = createIdentitySession({
  cryptoCore: cc,
  origin: location.origin,
  transport: { connect },
  sessionStore: createSessionStore({ cryptoCore: cc }),
  knownAccounts: createKnownAccountStore({ cryptoCore: cc }),
  webauthn: createWebAuthn({ rpName: 'Microtoll notes' }),
  ui: {
    askRecoveryCode: async (reason) => prompt(`Recovery code needed to ${reason}`),
    confirmDeletion: async () => confirm('Delete the account and every note it owns?'),
    passkeyName: () => 'Microtoll notes',
  },
  hooks: {
    afterUnlock: () => { log('unlocked'); refresh(); },
    onLocked: () => { log('locked'); render([]); },
  },
});
const notes = createNotes({ cryptoCore: cc, session });
let stopWatch = null;

function setSignedIn(on) {
  $('signed-out').hidden = on;
  $('signed-in').hidden = !on;
}

async function run(name, fn) {
  try { const r = await fn(); log(`${name}: ok`); return r; }
  catch (e) { log(`${name}: ${e.code || e.reason || 'error'} — ${e.message}`); }
}

function render(list) {
  const ul = $('notes');
  ul.innerHTML = '';
  for (const n of list) {
    const li = document.createElement('li');
    const title = document.createElement('b');
    title.textContent = n.stale ? '(re-keyed — press heal, or you were removed)' : (n.title || '(untitled)');
    li.append(title, ' ', n.mine ? '· yours' : n.member ? '· member' : '· reader', ' ');
    const b = (label, fn) => { const x = document.createElement('button'); x.textContent = label; x.onclick = fn; li.append(x); };
    if (!n.stale) b('open', () => { $('editor').hidden = false; $('note-id').value = n.id; $('title').value = n.title || ''; $('body').value = n.body || ''; $('save').hidden = !n.mine; });
    if (n.mine) {
      b('share', () => run('share', async () => { const { fragment } = await notes.share(n.id); $('share-url').value = `${location.origin}${location.pathname}${fragment}`; }));
      b('members', () => run('members', async () => showMembers(n.id)));
      b('delete', () => run('delete', async () => { await notes.destroy(n.id); await refresh(); }));
    } else if (!n.member && !n.stale) {
      b('join as member', () => run('join', async () => { await notes.join(n.id, { name: prompt('Your name, as the owner will see it') || 'someone' }); await refresh(); }));
    } else if (n.member && n.stale) {
      b('heal', () => run('heal', async () => { const ok = await notes.heal(n.id); log(ok ? 'new key picked up' : 'no new key for you: you were removed'); await refresh(); }));
    }
    ul.append(li);
  }
}

async function showMembers(id) {
  const list = await notes.members(id);
  const ul = $('members');
  ul.innerHTML = '';
  for (const m of list) {
    const li = document.createElement('li');
    li.textContent = `${m.name || '(unverified row: nothing shown)'} ${m.verified ? '✓' : ''} `;
    if (m.name !== 'owner') {
      const x = document.createElement('button'); x.textContent = 'remove';
      x.onclick = () => run('remove', async () => { await notes.remove(id, m.rowId); await showMembers(id); await refresh(); });
      li.append(x);
    }
    ul.append(li);
  }
  $('members-panel').hidden = false;
}

async function refresh() {
  const s = session.state();
  setSignedIn(!s.locked && s.hasAccount);
  if (s.locked || !s.hasAccount) return;
  const list = await run('list', () => notes.list());
  render(list || []);
  if (!stopWatch) stopWatch = await notes.watch(() => refresh()).catch(() => null);
}

$('boot').onclick = () => run('boot', async () => {
  const r = await session.bootFromTrustedSession();
  if (!r.restored) { await session.bootGuest(); log(`no trusted session (${r.reason}); started as a guest — sign up or unlock`); }
  await refresh();
});
$('signup').onclick = () => run('sign up', async () => {
  const { recoveryCode } = await session.registerCurrentIdentity({ label: 'this browser', passkey: 'none' });
  $('recovery').textContent = `Your recovery code (shown once, keep it): ${recoveryCode}`;
  await refresh();
});
$('signup-passkey').onclick = () => run('sign up with a passkey', async () => {
  const { recoveryCode } = await session.registerCurrentIdentity({ label: 'this browser', passkey: 'platform' });
  $('recovery').textContent = `Your recovery code (shown once, keep it): ${recoveryCode}`;
  await refresh();
});
$('unlock').onclick = () => run('unlock', async () => { await session.unlockWithRecoveryCode($('code').value); await refresh(); });
$('lock').onclick = () => run('lock', () => session.lock());
$('new').onclick = () => run('create', async () => { await notes.create({ title: $('new-title').value || 'Untitled', body: '' }); $('new-title').value = ''; await refresh(); });
$('save').onclick = () => run('save', async () => { await notes.update($('note-id').value, { title: $('title').value, body: $('body').value }); await refresh(); });
$('open-link').onclick = () => run('open link', async () => {
  const token = tokenFromLocation($('link').value.includes('#') ? $('link').value.slice($('link').value.indexOf('#')) : `#note=${$('link').value}`);
  if (!token) throw new Error('no token in that address');
  const note = await notes.open(token);
  log(`opened "${note.title}" (creator ${note.verifiedCreator ? 'verified' : 'not verified'})`);
  await refresh();
});
$('delete-account').onclick = () => run('delete account', async () => { await session.deleteAccount(); await refresh(); });

const token = tokenFromLocation(location.hash);
if (token) { $('link').value = location.href; log('a shared note is in this address: boot, sign up or unlock, then press "open link"'); }
setSignedIn(false);
log('ready — press Boot');
