/**
 * The identity blob: the account's private store, sealed under K_master_symm
 * and written whole through the server's compare-and-swap. Record version 2
 * (FORMATS.md §2.2, D-28): bound to the routing public key, and carrying a
 * cooperative `revision` counter so a rolled-back blob is refused on a
 * device that saw a later one.
 *
 * The package owns these keys of the plaintext: identityPublicKey,
 * identitySigningKey, sealingKey (every writer must carry it), revision.
 * Everything else belongs to the app and is carried through untouched.
 */

const AAD_IDENTITY_BLOB = 'aad/identity-blob';

export const IDENTITY_BLOB_UNREADABLE = 'identity-blob-unreadable';
export const IDENTITY_BLOB_ROLLED_BACK = 'identity-blob-rolled-back';

export function blobContext(cc, routingPublicKeyRaw) {
  return cc.frameContext(cc.label(AAD_IDENTITY_BLOB, 2), routingPublicKeyRaw);
}

/**
 * The identity is authoritative for its own keys, which is why they are
 * written AFTER `extra`: a stale copy in an older blob can never overwrite
 * the key this device has adopted. `revision` is one more than the base's.
 */
export function buildIdentityBlobPlaintext(cc, identity, extra = {}) {
  const base = extra && typeof extra === 'object' && !Array.isArray(extra) ? extra : {};
  const revision = Number.isSafeInteger(base.revision) && base.revision >= 0 ? base.revision + 1 : 1;
  return {
    ...base,
    identityPublicKey: cc.toBase64Url(identity.identity.publicKeyRaw),
    identitySigningKey: cc.toBase64Url(identity.identitySigning.publicKeyRaw),
    sealingKey: identity.identity.jwk,
    revision,
  };
}

export async function sealIdentityBlob(cc, identity, plaintext) {
  return cc.sealSymmetric(
    identity.masterSymmKey,
    new TextEncoder().encode(JSON.stringify(plaintext)),
    blobContext(cc, identity.routing.publicKeyRaw),
  );
}

function unreadable(cause) {
  return Object.assign(new Error('the identity blob is present but did not open; nothing was written'), {
    code: IDENTITY_BLOB_UNREADABLE,
    cause: cause || undefined,
  });
}

/**
 * ABSENT AND UNREADABLE ARE TWO DIFFERENT ANSWERS. No blob (null or empty)
 * is a new account and opens as {}. A blob that is there and will not open —
 * a failed tag, bytes that are not JSON, JSON that is not an object — throws
 * IDENTITY_BLOB_UNREADABLE, and the caller must let it stop whatever was
 * about to write. A blob whose revision is below `minRevision` (the highest
 * this device has seen) throws IDENTITY_BLOB_ROLLED_BACK the same way.
 */
export async function openIdentityBlob(cc, identity, sealed, { minRevision = 0 } = {}) {
  if (!sealed || sealed.length === 0) return {};
  let parsed;
  try {
    const bytes = await cc.openSymmetric(identity.masterSymmKey, sealed, blobContext(cc, identity.routing.publicKeyRaw));
    parsed = JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    throw unreadable(e);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw unreadable(null);
  const revision = Number.isSafeInteger(parsed.revision) ? parsed.revision : 0;
  if (revision < minRevision) {
    throw Object.assign(new Error(`the identity blob is older (revision ${revision}) than one this device already saw (${minRevision})`), {
      code: IDENTITY_BLOB_ROLLED_BACK, revision, minRevision,
    });
  }
  return parsed;
}
