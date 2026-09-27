// The page: the identity session, the notes model and direct invitations
// wired to buttons. Nothing here touches a key; the packages do, in this
// browser only.
import { createCryptoCore } from '@microtoll/crypto-core';
import { createIdentitySession, createSessionStore, createKnownAccountStore, createWebAuthn } from '@microtoll/identity';
import { tokenFromLocation } from '../notes-app/notes.js';
import { createInvites } from './invites.js';

const cc = createCryptoCore({ namespace: 'invite-example' });
const $ = (id) => document.getElementById(id);
const log = (line) => { $('log').textContent = `${new Date().toISOString().slice(11, 19)}  ${line}\n` + $('log').textContent; };
const myName = () => $('my-name').value || 'someone';

function connect() {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws`);
    ws.addEventListener('open', () => resolve(ws), { once: true });
    ws.addEventListener('error', () => reject(new Error('could not reach the server')), { once: true });
  });
}

const session = createIdentitySession({
  cryptoCore: cc, origin: location.origin, transport: { connect },
  sessionStore: createSessionStore({ cryptoCore: cc }),
  knownAccounts: createKnownAccountStore({ cryptoCore: cc }),
  webauthn: createWebAuthn({ rpName: 'Microtoll invites' }),
  ui: { askRecoveryCode: async (reason) => prompt(`Recovery code needed to ${reason}`), confirmDeletion: async () => confirm('Delete the account?'), passkeyName: () => 'Microtoll invites' },
  hooks: { afterUnlock: () => { log('unlocked'); refresh(); }, onLocked: () => { log('locked'); render([]); } },
});
const app = createInvites({ cryptoCore: cc, session });
const { notes } = app;
let stopWatch = null;

async function run(name, fn) {
  try { const r = await fn(); log(`${name}: ok`); return r; }
  catch (e) { log(`${name}: ${e.code || e.reason || 'error'} — ${e.message}`); }
}

function button(label, fn) { const b = document.createElement('button'); b.textContent = label; b.onclick = fn; return b; }

function render(list) {
  const ul = $('notes');
  ul.innerHTML = '';
  for (const n of list) {
    const li = document.createElement('li');
    const title = document.createElement('b');
    title.textContent = n.stale ? '(re-keyed or removed)' : (n.title || '(untitled)');
    li.append(title, ` · ${n.mine ? 'yours' : n.member ? 'member' : 'reader'} `);
    if (!n.stale) {
      li.append(button('open', () => run('open', async () => {
        $('editor').hidden = false; $('note-id').value = n.id; $('title').value = n.title || ''; $('body').value = n.body || ''; $('save').hidden = !n.mine;
        if (await app.acknowledge(n.id, { name: myName() })) log('the sender is told you have seen it');
      })));
      li.append(button('remember people', () => run('remember', async () => { const added = await app.rememberContacts(n.id); log(`${added} new contact(s)`); await refresh(); })));
    }
    if (n.mine) {
      li.append(button('share by link', () => run('share', async () => { const { fragment } = await notes.share(n.id); $('share-url').value = `${location.origin}${location.pathname}${fragment}`; })));
      for (const c of app.contacts()) li.append(button(`invite ${c.name || 'contact'} directly`, () => run('invite', async () => { await app.invite(n.id, c.signingKey, { name: myName() }); await showInvitations(n.id); })));
      li.append(button('invitations', () => run('invitations', () => showInvitations(n.id))));
      li.append(button('delete', () => run('delete', async () => { await notes.destroy(n.id); await refresh(); })));
    } else if (!n.member && !n.stale) {
      li.append(button('join as member', () => run('join', async () => { await notes.join(n.id, { name: myName() }); await refresh(); })));
    }
    ul.append(li);
  }
  const cl = $('contacts');
  cl.innerHTML = '';
  for (const c of app.contacts()) { const li = document.createElement('li'); li.textContent = `${c.name || '(no name)'} — ${c.signingKey.slice(0, 12)}…`; cl.append(li); }
}

async function showInvitations(noteId) {
  const list = await app.invitations(noteId);
  const ul = $('invitations');
  ul.innerHTML = '';
  for (const i of list) {
    const li = document.createElement('li');
    li.textContent = `${i.name || i.signingKey.slice(0, 12)}: ${i.collected === null ? 'gone' : i.collected ? 'collected' : 'waiting'}${i.seen ? `, ${i.seen}` : ''} `;
    if (i.collected === false) li.append(button('take back', () => run('withdraw', async () => { log(JSON.stringify(await app.withdraw(noteId, i.signingKey))); await showInvitations(noteId); })));
    ul.append(li);
  }
  $('invitations-panel').hidden = false;
}

async function refresh() {
  const s = session.state();
  $('signed-out').hidden = !s.locked && s.hasAccount;
  $('signed-in').hidden = !( !s.locked && s.hasAccount);
  if (s.locked || !s.hasAccount) return;
  const got = await run('collect', () => app.collect());
  if (got && got.newNotes.length) log(`${got.newNotes.length} new invitation(s) collected: ${got.newNotes.map((n) => `from ${n.from || 'someone unverified'}`).join(', ')}`);
  render((await run('list', () => notes.list())) || []);
  if (!stopWatch) stopWatch = await app.watch(() => refresh()).catch(() => null);
}

$('boot').onclick = () => run('boot', async () => {
  const r = await session.bootFromTrustedSession();
  if (!r.restored) { await session.bootGuest(); log(`no trusted session (${r.reason}); started as a guest — sign up or unlock`); }
  await refresh();
});
$('signup').onclick = () => run('sign up', async () => { const { recoveryCode } = await session.registerCurrentIdentity({ label: 'this browser', passkey: 'none' }); $('recovery').textContent = `Your recovery code (shown once): ${recoveryCode}`; await refresh(); });
$('unlock').onclick = () => run('unlock', async () => { await session.unlockWithRecoveryCode($('code').value); await refresh(); });
$('lock').onclick = () => run('lock', () => session.lock());
$('new').onclick = () => run('create', async () => { await notes.create({ title: $('new-title').value || 'Untitled', body: '' }); $('new-title').value = ''; await refresh(); });
$('save').onclick = () => run('save', async () => { await notes.update($('note-id').value, { title: $('title').value, body: $('body').value }); await refresh(); });
$('open-link').onclick = () => run('open link', async () => {
  const v = $('link').value;
  const token = tokenFromLocation(v.includes('#') ? v.slice(v.indexOf('#')) : `#note=${v}`);
  if (!token) throw new Error('no token in that address');
  const note = await notes.open(token);
  log(`opened "${note.title}"; now "join as member" so the owner can see you and remember you`);
  await refresh();
});

if (tokenFromLocation(location.hash)) { $('link').value = location.href; log('a shared note is in this address: boot, sign up or unlock, then press "open link"'); }
$('signed-in').hidden = true;
log('ready — press Boot');
