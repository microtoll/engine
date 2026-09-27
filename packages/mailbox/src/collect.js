/**
 * Sending, collecting, withdrawing and checking direct invitations, without
 * product policy: which senders are favourites, what is held for a tray,
 * who is blocked, which labels are dismissed -- the app decides those from
 * what this returns.
 *
 * A contact, as the app keeps it in its identity blob: `{ signingKey,
 * identityKey }`, both base64url -- the person's Ed25519 signing key (how
 * they are recognised) and their P-256 sealing key (how a mailbox with them
 * is computed). `sealToKey`, when the app has seen the contact advertise a
 * hybrid KEM key, is the key a bundle is sealed to instead.
 */
import { epoch as currentEpoch, pollEpochs, mailboxForSending, mailboxForReceiving } from './labels.js';
import { buildInvite, openBundle } from './bundle.js';
import { sendInvite, pollInvites, consumeInvite } from './wire.js';

/**
 * Every label this account could receive a drop under: one per contact per
 * polled epoch. Exactly the set collect() polls, so a live watch registers
 * the same labels. Returns Map<base64url label, { contact, epoch, mailboxId }>.
 */
export async function receivingLabels(cc, identity, contacts, epochs = pollEpochs()) {
  const labels = new Map();
  for (const contact of contacts || []) {
    if (!contact || typeof contact.identityKey !== 'string') continue; // nobody could address a mailbox to this account through them
    const senderKeyRaw = cc.fromBase64Url(contact.identityKey);
    for (const e of epochs) {
      const mailboxId = await mailboxForReceiving(cc, identity, senderKeyRaw, e);
      labels.set(cc.toBase64Url(mailboxId), { contact, epoch: e, mailboxId });
    }
  }
  return labels;
}

/**
 * One sealed drop per recipient, each under the label only that pair can
 * compute. Returns one entry per recipient, failures included, so a partial
 * send is visible: { signingKey, epoch, mailboxId, inviteId, ok, error }.
 * The (epoch, inviteId) pairs are what the sender keeps (in its own pointer)
 * to check later who has picked the invitation up, and to take one back: a
 * label is per PAIR per month, not per object, so two invitations to one
 * person in a month share a mailbox and status has to name the row.
 */
export async function send(cc, ws, sender, recipients, { objectId, kObjectRaw, keyEpoch, senderName = null, claims = {}, expiresAt = null, epoch = currentEpoch() }) {
  const results = [];
  for (const recipient of recipients || []) {
    try {
      if (!recipient || typeof recipient.identityKey !== 'string') throw new Error('the recipient has no sealing key');
      const recipientKeyRaw = cc.fromBase64Url(recipient.identityKey);
      const sealTo = typeof recipient.sealToKey === 'string' ? cc.fromBase64Url(recipient.sealToKey) : recipientKeyRaw;
      const mailboxId = await mailboxForSending(cc, sender, recipientKeyRaw, epoch);
      const bundle = await buildInvite(cc, sender, sealTo, { mailboxId, objectId, kObjectRaw, keyEpoch, senderName, claims });
      const inviteId = await sendInvite(cc, ws, mailboxId, bundle, expiresAt);
      results.push({ signingKey: recipient.signingKey || null, epoch, mailboxId, inviteId, ok: true, error: null });
    } catch (e) {
      results.push({ signingKey: (recipient && recipient.signingKey) || null, epoch, mailboxId: null, inviteId: null, ok: false, error: e.message });
    }
  }
  return results;
}

/**
 * Everything waiting for this account from these contacts, opened:
 *   invites   verified invitations, with the contact they came through --
 *             NOT consumed: the app consumes each (consumeInvite) once it
 *             has acted on it, or holds it, or leaves it for next time;
 *   acks      acknowledgements (consumed here unless told otherwise);
 *   unsigned  invitations nobody put their name to -- usable, unattributed,
 *             not consumed (an app might hold these for a tray, and let
 *             a pairwise label be dismissed);
 *   counts    one line of arithmetic: labels polled, rows, already consumed,
 *             unreadable, other kinds -- so an invitation that never arrives
 *             leaves a trace somewhere, without a label, a key or a name.
 *
 * Two locks against a re-sealed invitation (a contact passing on somebody
 * else's signed invitation as the signer's): the signature binds the
 * mailbox and the recipient (bundle.js), and the signer must still be the
 * contact whose mailbox it arrived in.
 */
export async function collect(cc, ws, identity, contacts, { epochs = pollEpochs(), consumeAcks = true } = {}) {
  const labels = await receivingLabels(cc, identity, contacts, epochs);
  const counts = { labels: labels.size, rows: 0, already: 0, unreadable: 0, other: 0 };
  const out = { invites: [], acks: [], unsigned: [], counts };
  if (labels.size === 0) return out;
  const rows = await pollInvites(cc, ws, [...labels.values()].map((l) => l.mailboxId));
  counts.rows = rows.length;
  for (const row of rows) {
    if (row.consumed) { counts.already++; continue; }
    const key = cc.toBase64Url(row.mailboxId);
    const via = labels.get(key) || null;
    let opened;
    try {
      opened = await openBundle(cc, identity, row.mailboxId, row.encryptedBundle);
    } catch {
      // Not addressed to this account, or corrupted: discarded as an
      // undecryptable object is, but counted.
      counts.unreadable++;
      continue;
    }
    if (opened.verified && !(via && opened.senderSigningKeyRaw && cc.toBase64Url(opened.senderSigningKeyRaw) === via.contact.signingKey)) {
      opened = { ...opened, verified: false, senderName: null, senderSigningKeyRaw: null, claims: {} };
    }
    const base = { rowId: row.id, mailboxId: key, epoch: via ? via.epoch : null, viaContact: via ? via.contact : null, objectId: opened.objectId };
    if (opened.kind === 'invite-ack') {
      out.acks.push({ ...base, verified: opened.verified, senderName: opened.senderName, senderSigningKey: opened.senderSigningKeyRaw ? cc.toBase64Url(opened.senderSigningKeyRaw) : null, hashedToken: opened.hashedToken, stage: opened.stage, claims: opened.claims });
      if (consumeAcks) { try { await consumeInvite(ws, row.id); } catch { /* seen again next time */ } }
      continue;
    }
    if (opened.kind !== 'invite') {
      // A kind this package does not know (a retired one that claimed to
      // grant admin rights among them): consumed, so it is not read again,
      // and never acted on -- only invitations and acknowledgements are.
      counts.other++;
      try { await consumeInvite(ws, row.id); } catch { /* seen again next time */ }
      continue;
    }
    if (!opened.verified) {
      out.unsigned.push({ ...base, kObjectRaw: opened.kObjectRaw, keyEpoch: opened.keyEpoch });
      continue;
    }
    out.invites.push({
      ...base, kObjectRaw: opened.kObjectRaw, keyEpoch: opened.keyEpoch, verified: true,
      senderName: opened.senderName, senderSigningKey: cc.toBase64Url(opened.senderSigningKeyRaw), senderIdentityKeyRaw: opened.senderIdentityKeyRaw, claims: opened.claims,
    });
  }
  return out;
}

/**
 * Takes an invitation back: the row itself when the sender kept its id,
 * otherwise every pending row in the pair's mailbox for that month. Returns
 * { burned, collected }: how many pending rows were withdrawn, and whether
 * the only rows found had already been picked up. A row that is gone was
 * swept or already withdrawn -- nothing left to open, nothing to report.
 */
export async function withdraw(cc, ws, sender, recipientIdentityKeyRaw, epoch, inviteId = null) {
  const mailboxId = await mailboxForSending(cc, sender, recipientIdentityKeyRaw, epoch);
  const rows = await pollInvites(cc, ws, [mailboxId]);
  if (inviteId) {
    const row = rows.find((r) => r.id === inviteId);
    if (!row) return { burned: 0, collected: false };
    if (row.consumed) return { burned: 0, collected: true };
    await consumeInvite(ws, row.id);
    return { burned: 1, collected: false };
  }
  const pending = rows.filter((r) => !r.consumed);
  if (rows.length > 0 && pending.length === 0) return { burned: 0, collected: true };
  for (const row of pending) await consumeInvite(ws, row.id);
  return { burned: pending.length, collected: false };
}

/**
 * Who has picked up an invitation and who has not. Labels are
 * deterministic, so the sender re-derives them from what it kept
 * ({ identityKey, epoch, inviteId }) and polls. Returns one entry per
 * record: collected true, false (still waiting), or null (the row is gone:
 * swept, or withdrawn).
 */
export async function status(cc, ws, sender, invited) {
  const wanted = [];
  for (const entry of invited || []) {
    if (!entry || typeof entry.identityKey !== 'string' || typeof entry.epoch !== 'string') continue;
    const mailboxId = await mailboxForSending(cc, sender, cc.fromBase64Url(entry.identityKey), entry.epoch);
    wanted.push({ entry, key: cc.toBase64Url(mailboxId), mailboxId });
  }
  if (wanted.length === 0) return [];
  const rows = await pollInvites(cc, ws, wanted.map((w) => w.mailboxId));
  return wanted.map(({ entry, key }) => {
    const mine = rows.filter((r) => cc.toBase64Url(r.mailboxId) === key && (!entry.inviteId || r.id === entry.inviteId));
    const collected = mine.length === 0 ? null : mine.every((r) => r.consumed);
    return { ...entry, collected };
  });
}
