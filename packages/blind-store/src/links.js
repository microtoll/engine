/**
 * Share links. A link is a sealed payload filed under the hash of a token
 * that never reaches the server, with a use count, an expiry, and a
 * management hash that lets its creator revoke it and count its opens. No
 * owner and no object id: the server cannot say whose link it is or what it
 * opens.
 */
import { send, fromB64u, toB64u, blobField, hashField, hashSecret, expiryField } from './wire.js';
import { URL_INVITE_MAX_USES } from './limits.js';

/**
 * Validates and decodes a 'create-url-invite' message: the link's uses, its
 * expiry and its management capability are all required and bounded. The
 * management hash is what lets its creator revoke it and count its opens; a
 * link without one could never be withdrawn.
 */
function parseCreateUrlInviteMessage(msg, limits) {
  if (typeof msg.hashedToken !== 'string' || !/^[0-9a-f]{64}$/.test(msg.hashedToken)) throw new Error('missing or malformed hashedToken');
  if (typeof msg.encryptedPayload !== 'string') throw new Error('missing encryptedPayload');
  const maxUses = msg.maxUses === undefined ? 1 : msg.maxUses;
  if (!Number.isInteger(maxUses) || maxUses < 1 || maxUses > URL_INVITE_MAX_USES) throw new Error(`maxUses must be an integer from 1 to ${URL_INVITE_MAX_USES}`);
  return {
    hashedToken: msg.hashedToken,
    sealedPayload: blobField(msg, 'encryptedPayload', { limits }),
    maxUses,
    expiresAt: expiryField(msg.expiresAt, 'expiresAt'),
    manageCapabilityHash: hashField(msg.manageCapabilityHash, 'manageCapabilityHash'),
  };
}

/**
 * Stores a share link. No owner column and none added here: possessing
 * K_object (needed to build the payload at all) is the only thing that
 * gates who can create one -- the same capability-not-identity rule as
 * everything else object-scoped.
 */
export async function handleCreateUrlInvite(pool, ws, routingPublicKey, msg, { rateLimit, limits }) {
  let fields;
  try {
    fields = parseCreateUrlInviteMessage(msg, limits);
  } catch (e) {
    send(ws, { type: 'create-url-invite-failed', reason: 'invalid', detail: e.message });
    return;
  }
  // Daily cap on links -- hygiene, fail open; the counter records that this
  // routing key made links today, never which object they open.
  const quota = await rateLimit.consume(pool, routingPublicKey, 'create-url-invite');
  if (!quota.allowed) {
    send(ws, { type: 'create-url-invite-failed', reason: 'rate-limited', limit: quota.limit });
    return;
  }
  try {
    await pool.query(
      `INSERT INTO share_links (hashed_token, sealed_payload, max_uses, expires_at, manage_capability_hash)
       VALUES ($1, $2, $3, $4, $5)`,
      [fields.hashedToken, fields.sealedPayload, fields.maxUses, fields.expiresAt, fields.manageCapabilityHash]
    );
    send(ws, { type: 'create-url-invite-ok' });
  } catch (e) {
    if (e.code === '23505') { // hashed_token collision -- astronomically unlikely for a 160-bit token
      send(ws, { type: 'create-url-invite-failed', reason: 'token-collision' });
    } else {
      send(ws, { type: 'create-url-invite-failed', reason: 'server-error' });
    }
  }
}

/**
 * Atomically claims one use of a link and returns its payload. The UPDATE
 * ... WHERE use_count < max_uses ... RETURNING is what makes this atomic
 * under concurrent redemptions: two simultaneous redeems of the last
 * remaining use cannot both succeed. The token itself never appears in any
 * query here, only its hash.
 */
export async function handleRedeemUrlInvite(pool, ws, msg) {
  if (typeof msg.hashedToken !== 'string') {
    send(ws, { type: 'redeem-url-invite-failed', reason: 'invalid' });
    return;
  }
  try {
    const claim = await pool.query(
      `UPDATE share_links
         SET use_count = use_count + 1
       WHERE hashed_token = $1
         AND use_count < max_uses
         AND expires_at > now()
       RETURNING sealed_payload`,
      [msg.hashedToken]
    );
    if (claim.rows.length > 0) {
      send(ws, { type: 'redeem-url-invite-ok', encryptedPayload: toB64u(claim.rows[0].sealed_payload) });
      return;
    }
    // The UPDATE matched nothing -- work out which of the three reasons why,
    // for a clearer client-side message. One extra read on an already-cold
    // path; the token itself still never appears in it, only its hash.
    const existing = await pool.query(
      'SELECT use_count, max_uses, expires_at FROM share_links WHERE hashed_token = $1',
      [msg.hashedToken]
    );
    if (existing.rows.length === 0) {
      send(ws, { type: 'redeem-url-invite-failed', reason: 'not-found' });
    } else if (existing.rows[0].expires_at <= new Date()) {
      send(ws, { type: 'redeem-url-invite-failed', reason: 'expired' });
    } else {
      send(ws, { type: 'redeem-url-invite-failed', reason: 'exhausted' });
    }
  } catch {
    send(ws, { type: 'redeem-url-invite-failed', reason: 'server-error' });
  }
}

/**
 * Revokes one share link. Nothing already joined is affected -- that needs
 * a key rotation, a different action with a different effect. Gated by the
 * link's management secret, which lives only in its creator's pointer.
 * Gating on the hashed token instead would let any RECIPIENT of a link
 * revoke it for everybody else.
 */
export async function handleRevokeUrlInvite(pool, ws, msg) {
  if (typeof msg.hashedToken !== 'string' || msg.hashedToken.length === 0 || msg.hashedToken.length > 128) {
    send(ws, { type: 'revoke-url-invite-failed', reason: 'invalid' });
    return;
  }
  let secretBytes;
  try {
    if (typeof msg.manageSecret !== 'string') throw new Error('missing manageSecret');
    secretBytes = fromB64u(msg.manageSecret);
  } catch { send(ws, { type: 'revoke-url-invite-failed', reason: 'invalid' }); return; }
  try {
    const result = await pool.query(
      'DELETE FROM share_links WHERE hashed_token = $1 AND manage_capability_hash = $2',
      [msg.hashedToken, hashSecret(secretBytes)]
    );
    // A link already revoked, or never there, reports the same thing: there
    // is nothing useful in telling a caller which.
    send(ws, { type: 'revoke-url-invite-ok', revoked: result.rowCount });
  } catch {
    send(ws, { type: 'revoke-url-invite-failed', reason: 'server-error' });
  }
}

/**
 * How many times each of these links has been redeemed. Authorised by each
 * link's management secret: share_links carries no owner and no object id,
 * so there is nothing else to check against. A pair that does not match is
 * simply absent from the reply rather than reported as missing: whether a
 * given hash is a real token is not worth confirming to whoever guessed it.
 *
 * Counts redemptions, not people -- one person opening a link on two devices
 * counts twice. The UI must say "about N".
 */
export async function handleFetchInviteTokenStats(pool, ws, msg) {
  if (!Array.isArray(msg.links) || msg.links.length === 0 || msg.links.length > 200) {
    send(ws, { type: 'fetch-invite-token-stats-failed', reason: 'invalid' });
    return;
  }
  let pairs;
  try {
    pairs = msg.links.map((l) => {
      if (!l || typeof l.hashedToken !== 'string' || l.hashedToken.length === 0 || l.hashedToken.length > 128) throw new Error('bad hashedToken');
      if (typeof l.manageSecret !== 'string') throw new Error('bad manageSecret');
      return { hashedToken: l.hashedToken, hash: hashSecret(fromB64u(l.manageSecret)) };
    });
  } catch {
    send(ws, { type: 'fetch-invite-token-stats-failed', reason: 'invalid' });
    return;
  }
  try {
    const result = await pool.query(
      `SELECT hashed_token, use_count, max_uses, expires_at FROM share_links
       WHERE (hashed_token, manage_capability_hash) IN (SELECT * FROM UNNEST($1::text[], $2::bytea[]))`,
      [pairs.map((x) => x.hashedToken), pairs.map((x) => x.hash)]
    );
    send(ws, {
      type: 'invite-token-stats',
      tokens: result.rows.map((r) => ({
        hashedToken: r.hashed_token,
        useCount: r.use_count,
        maxUses: r.max_uses,
        expiresAt: r.expires_at ? r.expires_at.toISOString() : null,
      })),
    });
  } catch {
    send(ws, { type: 'fetch-invite-token-stats-failed', reason: 'server-error' });
  }
}
