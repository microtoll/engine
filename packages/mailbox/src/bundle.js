/**
 * The sealed, signed bundle that travels in a mailbox: a direct invitation
 * (the object id, its key and epoch, the sender's name and keys) or an
 * acknowledgement. This is **version 2** (FORMATS.md; D-31's reserved M3b
 * item, D-40):
 *
 *   payloadJson = JSON of the claims plus senderIdentityKey and senderSigningKey
 *   message     = frameContext("<ns>/sig/invite/v2", mailboxId, SHA-256(recipientKey)) ‖ UTF-8(payloadJson)
 *   signature   = Ed25519(senderSigningKey, message)
 *   bundle      = sealToRecipient(recipientKey, UTF-8(JSON { v: 2, payloadJson, sig }))
 *
 * Version 1 signed the payload alone, which let a re-sealed bundle pass as
 * its signer's: a contact who received somebody else's signed invitation
 * could seal it again into the mailbox they share with a third person, and
 * it arrived as the original sender's. Version 2 binds the mailbox the drop is for and the key it is
 * sealed to, so a bundle verifies only in the mailbox and for the recipient
 * it was made for. Version 1 bundles are not read (no data exists).
 *
 * The rule for what is shown, as everywhere in the engine: an unverified
 * bundle is still usable (the key in it either works or it does not), but
 * nothing about WHO sent it may be displayed -- a name a signature does not
 * back would be the impersonation the signing key exists to prevent.
 */
const PURPOSE_INVITE_SIGNATURE = 'sig/invite';
const SIGNATURE_VERSION = 2;
export const BUNDLE_VERSION = 2;
const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();
const RESERVED = new Set(['kind', 'objectId', 'kObject', 'keyEpoch', 'senderName', 'senderIdentityKey', 'senderSigningKey', 'hashedToken', 'stage']);

/** The exact bytes a bundle's signature covers. */
export async function inviteSigningMessage(cc, mailboxIdBytes, recipientKeyRaw, payloadJson) {
  if (!(mailboxIdBytes instanceof Uint8Array) || mailboxIdBytes.length !== 32) throw new Error('inviteSigningMessage: a mailbox id is 32 bytes');
  const context = cc.frameContext(cc.label(PURPOSE_INVITE_SIGNATURE, SIGNATURE_VERSION), mailboxIdBytes, await cc.sha256(recipientKeyRaw));
  return cc.concatBytes(context, utf8.encode(payloadJson));
}

function claimsOf(claims) {
  const out = {};
  for (const [k, v] of Object.entries(claims || {})) {
    if (RESERVED.has(k)) throw new Error(`claims: "${k}" is a bundle field, not a claim`);
    out[k] = v;
  }
  return out;
}

async function sealBundle(cc, sender, recipientKeyRaw, mailboxIdBytes, fields) {
  if (!sender || !sender.identity || !sender.identitySigning) throw new Error('a sender identity (sealing and signing keys) is required');
  const payloadJson = JSON.stringify({
    ...fields,
    senderIdentityKey: cc.toBase64Url(sender.identity.publicKeyRaw),
    senderSigningKey: cc.toBase64Url(sender.identitySigning.publicKeyRaw),
  });
  const sig = await cc.signBytes(sender.identitySigning.privateKey, await inviteSigningMessage(cc, mailboxIdBytes, recipientKeyRaw, payloadJson));
  const envelope = JSON.stringify({ v: BUNDLE_VERSION, payloadJson, sig: cc.toBase64Url(sig) });
  // sealToRecipient, not sealToPublicKey: the recipient key handed in may be
  // the classical sealing key (65 bytes) or the hybrid KEM key (1216 bytes),
  // and the dispatcher picks the format from its length. The caller chooses
  // which key: the strongest the recipient has advertised.
  return cc.sealToRecipient(recipientKeyRaw, utf8.encode(envelope));
}

/**
 * An invitation: the object's id, its key and epoch, the sender's name, and
 * any app claims (a greeting, say), all inside the signed
 * payload so every one is a statement the sender's key stands behind.
 */
export async function buildInvite(cc, sender, recipientKeyRaw, { mailboxId, objectId, kObjectRaw, keyEpoch, senderName = null, claims = {} }) {
  if (typeof objectId !== 'string' || !objectId) throw new Error('buildInvite: objectId is required');
  if (!(kObjectRaw instanceof Uint8Array) || kObjectRaw.length !== 32) throw new Error('buildInvite: kObjectRaw (32 bytes) is required');
  if (!Number.isInteger(keyEpoch) || keyEpoch < 1) throw new Error('buildInvite: keyEpoch must be an integer >= 1');
  return sealBundle(cc, sender, recipientKeyRaw, mailboxId, {
    kind: 'invite', objectId, kObject: cc.toBase64Url(kObjectRaw), keyEpoch, senderName: senderName || null, ...claimsOf(claims),
  });
}

/**
 * An acknowledgement: "I responded to your link" (with the link's hash, so
 * the creator's own list can say which) or a stage the app defines ("seen").
 * Carries no key -- there is nothing to grant, only something to report.
 */
export async function buildAck(cc, sender, recipientKeyRaw, { mailboxId, objectId, senderName = null, hashedToken = null, stage = null, claims = {} }) {
  if (typeof objectId !== 'string' || !objectId) throw new Error('buildAck: objectId is required');
  return sealBundle(cc, sender, recipientKeyRaw, mailboxId, {
    kind: 'invite-ack', objectId, kObject: null, keyEpoch: null, senderName: senderName || null,
    hashedToken: typeof hashedToken === 'string' ? hashedToken : null,
    stage: typeof stage === 'string' ? stage : null,
    ...claimsOf(claims),
  });
}

/**
 * Opens a bundle that arrived under `mailboxId` for this recipient. The
 * ECIES version byte says which of the recipient's keys it was sealed to
 * (the classical sealing key, or the hybrid KEM key), and the signature is
 * checked against that key and that mailbox.
 */
export async function openBundle(cc, recipient, mailboxIdBytes, sealed) {
  if (!(sealed instanceof Uint8Array) || sealed.length === 0) throw new Error('openBundle: a sealed bundle is required');
  let bytes, recipientKeyRaw;
  if (sealed[0] === cc.ECIES_VERSION_2) {
    if (!recipient.identityKem) throw Object.assign(new Error('a hybrid bundle, and this identity holds no hybrid key'), { code: 'pq-key-unavailable' });
    bytes = await cc.openWithKemPrivateKey(recipient.identityKem.privateKey, sealed);
    recipientKeyRaw = recipient.identityKem.publicKeyRaw;
  } else {
    bytes = await cc.openWithPrivateKey(recipient.identity, sealed);
    recipientKeyRaw = recipient.identity.publicKeyRaw;
  }
  const outer = JSON.parse(fromUtf8.decode(bytes));
  if (!outer || outer.v !== BUNDLE_VERSION || typeof outer.payloadJson !== 'string') throw new Error('not a version 2 mailbox bundle');
  const payload = JSON.parse(outer.payloadJson);
  if (!payload || typeof payload !== 'object') throw new Error('not a version 2 mailbox bundle');
  const senderSigningKeyRaw = typeof payload.senderSigningKey === 'string' ? cc.fromBase64Url(payload.senderSigningKey) : null;
  let verified = false;
  if (senderSigningKeyRaw && typeof outer.sig === 'string') {
    verified = await cc.verifyBytes(senderSigningKeyRaw, await inviteSigningMessage(cc, mailboxIdBytes, recipientKeyRaw, outer.payloadJson), cc.fromBase64Url(outer.sig));
  }
  const claims = {};
  for (const [k, v] of Object.entries(payload)) if (!RESERVED.has(k)) claims[k] = v;
  return {
    verified,
    kind: typeof payload.kind === 'string' ? payload.kind : 'invite',
    objectId: typeof payload.objectId === 'string' ? payload.objectId : null,
    kObjectRaw: typeof payload.kObject === 'string' ? cc.fromBase64Url(payload.kObject) : null,
    keyEpoch: Number.isInteger(payload.keyEpoch) ? payload.keyEpoch : null,
    // Shown only when signed: a name, and every claim, is a statement about a person.
    senderName: verified ? (payload.senderName || null) : null,
    senderIdentityKeyRaw: typeof payload.senderIdentityKey === 'string' ? cc.fromBase64Url(payload.senderIdentityKey) : null,
    senderSigningKeyRaw: verified ? senderSigningKeyRaw : null,
    hashedToken: typeof payload.hashedToken === 'string' ? payload.hashedToken : null,
    stage: typeof payload.stage === 'string' ? payload.stage : null,
    claims: verified ? claims : {},
  };
}
