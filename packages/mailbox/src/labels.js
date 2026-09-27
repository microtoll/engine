/**
 * The pairwise mailbox label, its epochs (the month to write under, the
 * months to poll, the months a standing subscription covers) and its two
 * directions (mailboxForSending, mailboxForReceiving). Frozen by the
 * crypto-core fixture file (its `mailbox` section), which the label test
 * reads: a change to these bytes turns that test red.
 *
 *   label = HKDF-SHA-256(ECDH-P256(myPrivate, theirPublic), salt ∅,
 *             info "<ns>/invite-mailbox/v2|<YYYY-MM>|<sender>|<recipient>", 256 bits)
 *
 * The same non-interactive agreement from either end (a.B == b.A), so the
 * sender and the recipient derive one value from opposite sides. The server
 * sees the label and nothing else: it cannot compute one (that needs one of
 * the two private keys), attribute one, or read what is under it. The label
 * changes every calendar month, so a stable polling fingerprint lasts at
 * most two months. Classical by necessity: there is no standard
 * post-quantum non-interactive key exchange (THREATMODEL §7).
 */

const PURPOSE_MAILBOX = 'invite-mailbox';
const MAILBOX_LABEL_VERSION = 2;
const EPOCH_RE = /^\d{4}-\d{2}$/;

/** The calendar month, UTC: "2026-09". */
export function epoch(date = new Date()) {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, '0')}`;
}

/** The epochs a recipient polls: this month and the previous, so a drop written on the last day of a month is still found on the first of the next. */
export function pollEpochs(date = new Date()) {
  const previous = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() - 1, 1));
  return [epoch(date), epoch(previous)];
}

/** The epochs a standing subscription covers: this month and the NEXT, since it has to exist before a drop arrives. */
export function pushEpochs(date = new Date()) {
  const next = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() + 1, 1));
  return [epoch(date), epoch(next)];
}

/**
 * myPrivateKey: this account's P-256 sealing private key.
 * otherPublicKeyRaw: the other party's P-256 sealing public key (65 bytes).
 * senderPublicKeyRaw / recipientPublicKeyRaw: which direction the label is
 * for -- the sender passes (mine, theirs), the recipient (theirs, mine), and
 * both compute the identical 32 bytes.
 */
export async function mailboxId(cc, myPrivateKey, otherPublicKeyRaw, senderPublicKeyRaw, recipientPublicKeyRaw, epochValue) {
  if (typeof epochValue !== 'string' || !EPOCH_RE.test(epochValue)) throw new Error('mailboxId: the epoch is a calendar month, "YYYY-MM"');
  for (const [name, key] of [['otherPublicKeyRaw', otherPublicKeyRaw], ['senderPublicKeyRaw', senderPublicKeyRaw], ['recipientPublicKeyRaw', recipientPublicKeyRaw]]) {
    if (!(key instanceof Uint8Array) || key.length !== 65) throw new Error(`mailboxId: ${name} must be a raw P-256 public key (65 bytes)`);
  }
  const shared = await cc.deriveSealingSharedBits(myPrivateKey, otherPublicKeyRaw);
  const info = `${cc.label(PURPOSE_MAILBOX, MAILBOX_LABEL_VERSION)}|${epochValue}|${cc.toBase64Url(senderPublicKeyRaw)}|${cc.toBase64Url(recipientPublicKeyRaw)}`;
  return cc.hkdfDeriveSeedBits(shared, info);
}

/** The label a sender writes under when inviting a recipient. */
export function mailboxForSending(cc, sender, recipientPublicKeyRaw, epochValue = epoch()) {
  return mailboxId(cc, sender.identity.privateKey, recipientPublicKeyRaw, sender.identity.publicKeyRaw, recipientPublicKeyRaw, epochValue);
}

/** The label a recipient looks under for drops from a sender: the same value, from the other side. */
export function mailboxForReceiving(cc, recipient, senderPublicKeyRaw, epochValue = epoch()) {
  return mailboxId(cc, recipient.identity.privateKey, senderPublicKeyRaw, senderPublicKeyRaw, recipient.identity.publicKeyRaw, epochValue);
}
