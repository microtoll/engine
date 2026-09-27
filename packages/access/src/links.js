/**
 * Share links, format version 2 (FORMATS.md §3):
 *
 *   token        20 random bytes, base64url, carried in the URL fragment and never sent to the server
 *   hashedToken  hex SHA-256(UTF-8 token): the server's key for the row
 *   payload key  HKDF(UTF-8 token, "<ns>/url-invite/v1") → AES-256-GCM
 *   payload      AEAD v1 of JSON { v: 2, payloadJson, sig|null },
 *                AAD frameContext("<ns>/aad/share-link/v2", hashedTokenBytes)
 *   payloadJson  { objectId, kObject (b64u), creatorName|null, creatorSigningKey|null }
 *   sig          Ed25519(creator signing key, frameContext("<ns>/sig/share-link/v2", hashedTokenBytes) ‖ UTF-8(payloadJson))
 *   manageSecret 32 random bytes, NOT derived from the token (every recipient
 *                knows the token); the server stores its SHA-256 and lets only
 *                its holder revoke the link or count its opens
 *
 * The signature covers the token hash, so a signed payload cannot be lifted
 * into a fresh link and published as its creator's. Only the signing key
 * travels: enough to recognise the creator, not enough to address them.
 */

const TOKEN_BYTES = 20;
const PURPOSE_URL_KEY = 'url-invite';
const SIG_SHARE_LINK = 'sig/share-link';
const AAD_SHARE_LINK = 'aad/share-link';
const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

export function randomToken(cc) { return cc.toBase64Url(cc.randomBytes(TOKEN_BYTES)); }
export async function hashToken(cc, token) { return cc.toHex(await cc.sha256(utf8.encode(token))); }
export function linkSigningMessage(cc, hashedTokenHex, payloadJson) {
  return cc.concatBytes(cc.frameContext(cc.label(SIG_SHARE_LINK, 2), cc.fromHex(hashedTokenHex)), utf8.encode(payloadJson));
}
export function linkContext(cc, hashedTokenHex) { return cc.frameContext(cc.label(AAD_SHARE_LINK, 2), cc.fromHex(hashedTokenHex)); }

/**
 * createShareLink(cc, { objectId, kObjectRaw, maxUses, expiresAt, creator, creatorName, keyEpoch, label })
 * Returns { token, hashedToken, encryptedPayload, maxUses, expiresAt, manageSecret, manageCapabilityHash, record }.
 * `record` is what the creator keeps in its pointer (sharedLinks): the only
 * record there will ever be of which links are theirs.
 */
export async function createShareLink(cc, { objectId, kObjectRaw, maxUses = 1, expiresAt, creator = null, creatorName = null, keyEpoch = null, label = null }) {
  if (!Number.isInteger(maxUses) || maxUses < 1) throw new Error('maxUses must be a positive integer');
  if (typeof expiresAt !== 'string' || Number.isNaN(Date.parse(expiresAt))) throw new Error('expiresAt (an ISO instant) is required');
  const token = randomToken(cc);
  const hashedToken = await hashToken(cc, token);
  const manageSecret = cc.randomBytes(32);
  const manageCapabilityHash = cc.toHex(await cc.sha256(manageSecret));
  const key = await cc.deriveAesKey(utf8.encode(token), PURPOSE_URL_KEY);
  const payloadJson = JSON.stringify({
    objectId, kObject: cc.toBase64Url(kObjectRaw),
    creatorName: creator ? (creatorName || null) : null,
    creatorSigningKey: creator ? cc.toBase64Url(creator.identitySigning.publicKeyRaw) : null,
  });
  const envelope = { v: 2, payloadJson, sig: null };
  if (creator) envelope.sig = cc.toBase64Url(await cc.signBytes(creator.identitySigning.privateKey, linkSigningMessage(cc, hashedToken, payloadJson)));
  const encryptedPayload = await cc.sealSymmetric(key, utf8.encode(JSON.stringify(envelope)), linkContext(cc, hashedToken));
  return {
    token, hashedToken, encryptedPayload, maxUses, expiresAt, manageSecret, manageCapabilityHash,
    record: { hashedToken, token, manageSecret: cc.toBase64Url(manageSecret), label, createdAt: new Date().toISOString().slice(0, 10), maxUses, expiresAt, keyEpoch },
  };
}

/** Recovers { objectId, kObjectRaw, verified, creatorName, creatorSigningKeyRaw } from the token and the payload the server returned for its hash. */
export async function redeemShareLink(cc, token, encryptedPayload) {
  const hashedToken = await hashToken(cc, token);
  const key = await cc.deriveAesKey(utf8.encode(token), PURPOSE_URL_KEY);
  const outer = JSON.parse(fromUtf8.decode(await cc.openSymmetric(key, encryptedPayload, linkContext(cc, hashedToken))));
  if (!outer || outer.v !== 2 || typeof outer.payloadJson !== 'string') throw new Error('not a version 2 share-link payload');
  const payload = JSON.parse(outer.payloadJson);
  const creatorSigningKeyRaw = payload.creatorSigningKey ? cc.fromBase64Url(payload.creatorSigningKey) : null;
  const verified = Boolean(creatorSigningKeyRaw && typeof outer.sig === 'string')
    && await cc.verifyBytes(creatorSigningKeyRaw, linkSigningMessage(cc, hashedToken, outer.payloadJson), cc.fromBase64Url(outer.sig));
  return {
    objectId: payload.objectId, kObjectRaw: cc.fromBase64Url(payload.kObject), verified,
    creatorName: verified ? (payload.creatorName || null) : null,
    creatorSigningKeyRaw: verified ? creatorSigningKeyRaw : null,
  };
}

/** The token in a URL fragment `#token=<token>`, or null. */
export function tokenFromFragment(hash) {
  const m = /^#token=([A-Za-z0-9_-]{20,64})$/.exec(String(hash || ''));
  return m ? m[1] : null;
}

/** The creator's records, with `manageable` (can be revoked / counted) and `shareable` (the token is kept) flags. */
export function normaliseLinkRecords(records = []) {
  return records.map((e) => (typeof e === 'string'
    ? { hashedToken: e, token: null, manageSecret: null, label: null, createdAt: null, maxUses: null, expiresAt: null, keyEpoch: null, manageable: false, shareable: false }
    : { ...e, token: e.token || null, manageable: Boolean(e.manageSecret), shareable: Boolean(e.token) }));
}
