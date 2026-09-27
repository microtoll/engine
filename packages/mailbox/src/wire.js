/**
 * The mailbox messages, their names fixed by D-27: send-invite,
 * poll-invites, consume-invite, watch-invites and the invite-live push. The
 * server side is blind-store's.
 */
import { sendAndAwait } from '@microtoll/identity';

const DEFAULT_DROP_DAYS = 30;

/** Files a sealed bundle under a label. Every drop expires (the server takes none without); a month by default. Resolves with the row id. */
export async function sendInvite(cc, ws, mailboxIdBytes, sealedBundle, expiresAt = null) {
  const response = await sendAndAwait(ws, {
    type: 'send-invite',
    mailboxId: cc.toBase64Url(mailboxIdBytes),
    encryptedBundle: cc.toBase64Url(sealedBundle),
    expiresAt: expiresAt || new Date(Date.now() + DEFAULT_DROP_DAYS * 24 * 60 * 60 * 1000).toISOString(),
  }, 'send-invite-ok', 'send-invite-failed');
  return response.inviteId;
}

/** Every live row under these labels, consumed ones included (without their bundle). */
export async function pollInvites(cc, ws, mailboxIds) {
  const response = await sendAndAwait(ws, { type: 'poll-invites', mailboxIds: mailboxIds.map((m) => cc.toBase64Url(m)) }, 'invites', 'poll-invites-failed');
  return response.invites.map((i) => ({
    id: i.id,
    mailboxId: cc.fromBase64Url(i.mailboxId),
    // null on a consumed row: the server empties the bundle when a drop is
    // collected or taken back, and never serves it again.
    encryptedBundle: typeof i.encryptedBundle === 'string' ? cc.fromBase64Url(i.encryptedBundle) : null,
    consumed: i.consumed === true,
  }));
}

/** Marks a drop collected -- or, from the sender's end, takes it back. Idempotent. */
export async function consumeInvite(ws, inviteId) {
  await sendAndAwait(ws, { type: 'consume-invite', inviteId }, 'consume-invite-ok', 'consume-invite-failed');
}

/** Registers the labels this connection wants waking up for; the last watch replaces the previous one. */
export async function watchInvites(cc, ws, mailboxIds) {
  await sendAndAwait(ws, { type: 'watch-invites', mailboxIds: mailboxIds.map((m) => cc.toBase64Url(m)) }, 'watch-invites-ok', 'watch-invites-failed');
}

/** A drop landed under a watched label: `handler({ mailboxId })` with the label as hex. Returns the function that stops listening. */
export function onLiveInvite(ws, handler) {
  function onMessage(event) {
    let msg;
    try { msg = JSON.parse(event.data); } catch { return; }
    if (msg.type !== 'invite-live') return;
    handler({ mailboxId: msg.mailboxId });
  }
  ws.addEventListener('message', onMessage);
  return () => ws.removeEventListener('message', onMessage);
}
