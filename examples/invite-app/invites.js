// The invite app, without a page: the notes model (../notes-app/notes.js)
// plus direct invitations through @microtoll/mailbox. Read notes.js first;
// this file adds three ideas.
//
// CONTACTS. Two people who share a note can see each other's keys in its
// roster (every member row carries its author's signing key and sealing
// key, signed). "Remember the people on this note" copies them into this
// account's identity blob. Nothing is exchanged with a server: the roster
// was there anyway.
//
// A DIRECT INVITATION. To invite a contact to a note, the app drops a
// sealed, signed bundle (the note's key and epoch, the sender's name) under
// a mailbox label only the two of them can compute for this month. The
// recipient's app polls the labels of everyone it knows, opens what is its
// own, keeps a read-only pointer to the note, and consumes the drop. No
// link, nothing to forward, and the server cannot say who invited whom.
//
// ACKNOWLEDGEMENT AND WITHDRAWAL. When the recipient opens the note, their
// app drops an acknowledgement back ("seen") -- on opening, never on
// collection, because collection happens by itself whenever the app runs
// and says nothing about the person. Until a drop is collected the sender
// can take it back, and a taken-back drop opens for nobody.
import { createMailbox } from '@microtoll/mailbox';
import { createNotes } from '../notes-app/notes.js';

export function createInvites({ cryptoCore: cc, session }) {
  const notes = createNotes({ cryptoCore: cc, session });
  const mailbox = createMailbox({ cryptoCore: cc });
  const me = () => { const s = session.state(); if (s.locked || !s.identity) throw new Error('unlock first'); return s.identity; };
  const ws = () => session.ensureConnected();
  const blob = () => session.state().blob || {};
  const mySigningKey = () => cc.toBase64Url(me().identitySigning.publicKeyRaw);

  /** The people this account knows: { signingKey, identityKey, sealToKey, name }, kept in the identity blob. */
  function contacts() { return Object.values(blob().contacts || {}); }

  /** The people on a note's roster, from its member rows, verified only; never this account itself. */
  async function peopleOn(noteId) {
    const held = await notes.held(noteId);
    if (!held) throw new Error('no pointer for this note');
    const auth = held.p.adminCapabilitySecret ? { adminCapabilitySecret: held.p.adminCapabilitySecret } : { readCapabilitySecret: await notes.access.readCapability(held.p.kObject) };
    const rows = await notes.access.fetchMembers(await ws(), noteId, auth);
    const roster = notes.access.roster(await notes.access.openRows({ kObjectRaw: held.p.kObject, objectId: noteId, rows }));
    const mine = mySigningKey();
    return roster.filter((e) => e.verified && e.identityPublicKeyRaw).map((e) => ({
      signingKey: cc.toBase64Url(e.identitySigningKeyRaw),
      identityKey: cc.toBase64Url(e.identityPublicKeyRaw),
      // The strongest key they advertised: the hybrid KEM key when they have one, else the classical sealing key.
      sealToKey: e.sealTargetKeyRaw && e.sealTargetKeyRaw.length !== 65 ? cc.toBase64Url(e.sealTargetKeyRaw) : null,
      name: (e.content && (e.content.name || e.content.role)) || null,
    })).filter((c) => c.signingKey !== mine);
  }

  /** Remembers the people on a note as contacts. Returns how many are new. */
  async function rememberContacts(noteId) {
    const people = await peopleOn(noteId);
    let added = 0;
    await session.saveIdentityBlob((b) => {
      const next = { ...(b.contacts || {}) };
      for (const p of people) { if (!next[p.signingKey]) added++; next[p.signingKey] = { ...(next[p.signingKey] || {}), ...p }; }
      return { ...b, contacts: next };
    });
    return added;
  }

  /** Invites a contact to a note this account holds a key for. */
  async function invite(noteId, signingKey, { name = null } = {}) {
    const contact = (blob().contacts || {})[signingKey];
    if (!contact) throw new Error('not a contact');
    const held = await notes.held(noteId);
    if (!held) throw new Error('no pointer for this note');
    const [sent] = await mailbox.send(await ws(), me(), [contact], { objectId: noteId, kObjectRaw: held.p.kObject, keyEpoch: held.p.keyEpoch, senderName: name });
    if (!sent.ok) throw new Error(sent.error);
    // What the sender keeps: enough to check who collected and to take one back.
    await session.saveIdentityBlob((b) => ({ ...b, sent: { ...(b.sent || {}), [noteId]: { ...((b.sent || {})[noteId] || {}), [signingKey]: { identityKey: contact.identityKey, epoch: sent.epoch, inviteId: sent.inviteId } } } }));
    return sent;
  }

  /**
   * Collects what is waiting from every contact: a new invitation becomes a
   * read-only pointer to the note (as opening a link does), then the drop is
   * consumed; an acknowledgement is recorded against the note it is for.
   */
  async function collect() {
    const identity = me();
    const socket = await ws();
    const got = await mailbox.collect(socket, identity, contacts());
    const newNotes = [];
    for (const inv of got.invites) {
      if (!(await notes.held(inv.objectId))) {
        let fetched;
        try { fetched = await notes.access.fetchObject(socket, inv.objectId); } catch { continue; } // gone: the drop is left, and expires
        const pointer = await notes.access.buildReadOnlyPointer({
          identity, objectId: inv.objectId, kObjectRaw: inv.kObjectRaw, keyEpoch: fetched.keyEpoch,
          invitedBy: { signingKey: inv.senderSigningKey, nameSnapshot: inv.senderName, via: 'direct' },
          extra: { shelf: fetched.fields.selector },
        });
        await notes.access.joinObject(socket, { objectId: inv.objectId, pointer });
        newNotes.push({ id: inv.objectId, from: inv.senderName, signingKey: inv.senderSigningKey });
      }
      await mailbox.consumeInvite(socket, inv.rowId);
      await session.saveIdentityBlob((b) => ({ ...b, received: { ...(b.received || {}), [inv.objectId]: { signingKey: inv.senderSigningKey, name: inv.senderName } } }));
    }
    if (got.acks.length) {
      await session.saveIdentityBlob((b) => {
        const acks = { ...(b.acks || {}) };
        for (const a of got.acks) if (a.verified && a.objectId) acks[a.objectId] = { ...(acks[a.objectId] || {}), [a.senderSigningKey]: a.stage || 'responded' };
        return { ...b, acks };
      });
    }
    return { newNotes, acks: got.acks.length, unsigned: got.unsigned.length, counts: got.counts };
  }

  /** On opening a note that came by invitation: tell the sender it was seen. */
  async function acknowledge(noteId, { name = null } = {}) {
    const from = (blob().received || {})[noteId];
    if (!from) return false;
    const contact = (blob().contacts || {})[from.signingKey];
    if (!contact) return false;
    const identity = me();
    const recipientKeyRaw = cc.fromBase64Url(contact.identityKey);
    const label = await mailbox.mailboxForSending(identity, recipientKeyRaw);
    const sealTo = contact.sealToKey ? cc.fromBase64Url(contact.sealToKey) : recipientKeyRaw;
    await mailbox.sendInvite(await ws(), label, await mailbox.buildAck(identity, sealTo, { mailboxId: label, objectId: noteId, senderName: name, stage: 'seen' }));
    return true;
  }

  /** Who this account invited to a note, and whether each has collected and seen it. */
  async function invitations(noteId) {
    const sent = (blob().sent || {})[noteId] || {};
    const records = Object.entries(sent).map(([signingKey, r]) => ({ signingKey, ...r }));
    const checked = records.length ? await mailbox.status(await ws(), me(), records) : [];
    const acks = (blob().acks || {})[noteId] || {};
    const people = blob().contacts || {};
    return checked.map((r) => ({ signingKey: r.signingKey, name: (people[r.signingKey] && people[r.signingKey].name) || null, collected: r.collected, seen: acks[r.signingKey] || null }));
  }

  /** Takes an uncollected invitation back. Returns { burned, collected }. */
  async function withdraw(noteId, signingKey) {
    const r = ((blob().sent || {})[noteId] || {})[signingKey];
    if (!r) throw new Error('no invitation to take back');
    const result = await mailbox.withdraw(await ws(), me(), cc.fromBase64Url(r.identityKey), r.epoch, r.inviteId);
    await session.saveIdentityBlob((b) => { const s = { ...((b.sent || {})[noteId] || {}) }; delete s[signingKey]; return { ...b, sent: { ...(b.sent || {}), [noteId]: s } }; });
    return result;
  }

  /** Live: `onChange` when a drop lands under any label this account polls. Returns a stop function. */
  async function watch(onChange) {
    const labels = await mailbox.receivingLabels(me(), contacts());
    const socket = await ws();
    if (labels.size) await mailbox.watchInvites(socket, [...labels.values()].map((l) => l.mailboxId));
    return mailbox.onLiveInvite(socket, () => onChange());
  }

  return { notes, mailbox, contacts, peopleOn, rememberContacts, invite, collect, acknowledge, invitations, withdraw, watch };
}
