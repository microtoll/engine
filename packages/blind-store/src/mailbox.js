/**
 * Pairwise dead-drop mailboxes: opaque rows under opaque labels, sent,
 * polled, consumed, and watched for a live wake-up (live.js). The client
 * half is the mailbox package (M3b); the server's entire role is to hold
 * rows it cannot attribute.
 *
 * The server cannot compute a mailbox id (that needs one of two private
 * keys), cannot attribute one to an account, and cannot read a bundle
 * (sealed to the recipient on top). No routing key is involved at any
 * point. Deliberately NOT gated by anything beyond authentication: the gate
 * is the address itself -- only someone who already holds your public key
 * can compute a mailbox you will ever look in.
 */
import { send, fromB64u, toB64u, blobField, expiryField, UUID_RE } from './wire.js';

export const MAILBOX_ID_BYTES = 32;
const MAX_MAILBOX_IDS = 500;

export function parseMailboxIds(value) {
  if (!Array.isArray(value) || value.length === 0) throw new Error('missing or empty mailboxIds');
  if (value.length > MAX_MAILBOX_IDS) throw new Error('too many mailboxIds');
  return value.map((m) => {
    if (typeof m !== 'string') throw new Error('mailboxIds must be strings');
    const bytes = fromB64u(m);
    if (bytes.length !== MAILBOX_ID_BYTES) throw new Error('mailboxIds must be 32 bytes');
    return bytes;
  });
}

export async function handleSendInvite(pool, ws, routingPublicKey, msg, { rateLimit, limits }) {
  let mailboxId, bundle, expiresAt = null;
  try {
    if (typeof msg.mailboxId !== 'string') throw new Error('missing mailboxId');
    mailboxId = fromB64u(msg.mailboxId);
    if (mailboxId.length !== MAILBOX_ID_BYTES) throw new Error('mailboxId must be 32 bytes');
    if (typeof msg.encryptedBundle !== 'string') throw new Error('missing encryptedBundle');
    bundle = blobField(msg, 'encryptedBundle', { limits });
    // Required and bounded, as a link's is: the row is swept once it has
    // passed, and until then a consumed row is the sender's only record
    // that it was collected.
    expiresAt = expiryField(msg.expiresAt, 'expiresAt');
  } catch (e) {
    send(ws, { type: 'send-invite-failed', reason: 'invalid', detail: e.message });
    return;
  }
  // Daily cap on drops -- one per recipient, so fifty covers any real
  // evening; hygiene, fail open. The counter never sees a mailbox label.
  const quota = await rateLimit.consume(pool, routingPublicKey, 'send-invite');
  if (!quota.allowed) {
    send(ws, { type: 'send-invite-failed', reason: 'rate-limited', limit: quota.limit });
    return;
  }
  try {
    const result = await pool.query(
      'INSERT INTO mailbox_drops (mailbox_id, sealed_bundle, expires_at) VALUES ($1, $2, $3) RETURNING id',
      [mailboxId, bundle, expiresAt]
    );
    send(ws, { type: 'send-invite-ok', inviteId: result.rows[0].id });
  } catch {
    send(ws, { type: 'send-invite-failed', reason: 'server-error' });
  }
}

/**
 * Returns every live row under the given labels, consumed ones included --
 * a recipient skips those, and a SENDER polls their own outgoing labels to
 * see which drops have been collected.
 *
 * A consumed row comes back WITHOUT its bundle. Consuming is both
 * collection and the sender's "take back", and a bundle carries a key: a
 * withdrawn drop that was still served would leave the withdrawal up to
 * whichever client polled it next. consume-invite empties the column too,
 * so this is the second of two locks on the same door.
 */
export async function handlePollInvites(pool, ws, msg) {
  let mailboxIds;
  try {
    mailboxIds = parseMailboxIds(msg.mailboxIds);
  } catch (e) {
    send(ws, { type: 'poll-invites-failed', reason: 'invalid', detail: e.message });
    return;
  }
  try {
    const result = await pool.query(
      `SELECT id, mailbox_id, CASE WHEN consumed THEN NULL ELSE sealed_bundle END AS sealed_bundle, consumed
         FROM mailbox_drops
        WHERE mailbox_id = ANY($1) AND expires_at > now()`,
      [mailboxIds]
    );
    send(ws, {
      type: 'invites',
      invites: result.rows.map((r) => ({
        id: r.id,
        mailboxId: toB64u(r.mailbox_id),
        encryptedBundle: r.consumed ? null : toB64u(r.sealed_bundle),
        consumed: r.consumed,
      })),
    });
  } catch {
    send(ws, { type: 'poll-invites-failed', reason: 'server-error' });
  }
}

/**
 * Marks one drop collected -- or, from the sender's end, takes it back.
 * Knowing the row id is the authorisation: ids only come back from polling
 * a mailbox, and computing a mailbox needs one of the two private keys.
 * Idempotent. The bundle is emptied in the same statement: once the row is
 * consumed nobody has a use for it, and a withdrawn drop must not be
 * openable by a client that chooses to ignore the flag. The row stays,
 * because the sender's roster reads "collected" from it.
 */
export async function handleConsumeInvite(pool, ws, msg) {
  if (typeof msg.inviteId !== 'string' || !UUID_RE.test(msg.inviteId)) {
    send(ws, { type: 'consume-invite-failed', reason: 'invalid' });
    return;
  }
  try {
    await pool.query("UPDATE mailbox_drops SET consumed = TRUE, sealed_bundle = ''::bytea WHERE id = $1", [msg.inviteId]);
    send(ws, { type: 'consume-invite-ok' });
  } catch {
    send(ws, { type: 'consume-invite-failed', reason: 'server-error' });
  }
}

/**
 * Registers the mailbox labels this connection wants waking up for. A drop
 * is invisible to the selector watch: the recipient has no pointer for the
 * object yet. Reuses parseMailboxIds, the same validator poll-invites
 * applies to the same values: one place decides what a well-formed label is.
 */
export function handleWatchInvites(live, ws, msg) {
  if (!live) {
    send(ws, { type: 'watch-invites-failed', reason: 'unsupported' });
    return;
  }
  let mailboxIds;
  try {
    mailboxIds = parseMailboxIds(msg.mailboxIds);
  } catch (e) {
    send(ws, { type: 'watch-invites-failed', reason: 'invalid', detail: e.message });
    return;
  }
  // Hex, to match what the trigger emits via encode(mailbox_id, 'hex'): the
  // wire format is base64url, the notification payload is hex, converted
  // once here.
  live.setMailboxWatch(ws, mailboxIds.map((id) => Buffer.from(id).toString('hex')));
  send(ws, { type: 'watch-invites-ok' });
}
