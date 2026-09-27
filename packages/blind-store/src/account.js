/**
 * The account handlers: the pre-authentication lookup of a wrapped root
 * key, the users row and its unlock methods, the identity blob's
 * compare-and-swap, the session generation and deletion. The host's policy
 * (for example an age declaration and a terms version) enters through the
 * `policy` object server.js hands to handleRegister and findUser, and its
 * clean-up through the delete hook. The engine itself stores nothing about a person beyond
 * ciphertext, the generation counter and the blob token.
 */
import { send, fromB64u, toB64u, UUID_RE, blobValue, blobField, hashField, IDENTITY_BLOB_TOKEN_BYTES } from './wire.js';

/**
 * Validates a 'lookup-unlock-method' message -- exactly one of credentialId
 * (passkey path) or recoveryLookupHash (recovery-code path), never both,
 * never neither.
 */
function parseLookupUnlockMethodMessage(msg, limits) {
  const hasCredentialId = typeof msg.credentialId === 'string';
  const hasRecoveryLookupHash = typeof msg.recoveryLookupHash === 'string';
  if (hasCredentialId === hasRecoveryLookupHash) {
    throw new Error('provide exactly one of credentialId or recoveryLookupHash');
  }
  return hasCredentialId
    ? { by: 'credentialId', value: blobValue(msg.credentialId, 'credentialId', 'credentialId', { limits }) }
    : { by: 'recoveryLookupHash', value: hashField(msg.recoveryLookupHash, 'recoveryLookupHash') };
}

/**
 * Pre-authentication lookup of a device's own wrapped root key --
 * deliberately unauthenticated, and structurally has to be: the handshake
 * needs a routing key derived FROM the unwrapped root key, so a returning
 * device cannot authenticate before it unlocks. Safe to leave open (D-20):
 * credentialId and recoveryLookupHash are high-entropy values an attacker
 * would have to already possess, and the returned wrapped_root_key is
 * useless ciphertext without the matching PRF output or recovery code.
 * server.js counts these per socket.
 */
export async function handleLookupUnlockMethod(pool, ws, msg, limits) {
  let lookup;
  try {
    lookup = parseLookupUnlockMethodMessage(msg, limits);
  } catch (e) {
    send(ws, { type: 'lookup-unlock-method-failed', reason: 'invalid', detail: e.message });
    return;
  }
  try {
    const result = await pool.query(
      `SELECT method_type, wrapped_root_key, prf_salt, pbkdf2_salt FROM unlock_methods
        WHERE ${lookup.by === 'credentialId' ? 'credential_id' : 'recovery_lookup_hash'} = $1`,
      [lookup.value]
    );
    if (result.rows.length === 0) {
      send(ws, { type: 'lookup-unlock-method-failed', reason: 'not-found' });
      return;
    }
    const r = result.rows[0];
    send(ws, {
      type: 'unlock-method',
      method: {
        methodType: r.method_type,
        wrappedRootKey: toB64u(r.wrapped_root_key),
        prfSalt: r.prf_salt ? toB64u(r.prf_salt) : null,
        pbkdf2Salt: r.pbkdf2_salt ? toB64u(r.pbkdf2_salt) : null,
      },
    });
  } catch {
    send(ws, { type: 'lookup-unlock-method-failed', reason: 'server-error' });
  }
}

/**
 * Whether routing_public_key has a users row, with the account's own
 * sealed identity blob, its session generation and the blob's
 * compare-and-swap token, so auth-ok hands a returning device everything it
 * needs to restore itself in the round trip that says whether the account
 * exists. The host's declared columns ride along in the same read.
 */
export async function findUser(pool, routingPublicKey, extraColumns = []) {
  const result = await pool.query(
    `SELECT sealed_identity_blob, session_generation, identity_blob_token${extraColumns.map((c) => `, ${c}`).join('')} FROM users WHERE routing_public_key = $1`,
    [routingPublicKey]
  );
  if (!result.rows[0]) return { hasAccount: false, encryptedIdentityBlob: null, sessionGeneration: null, identityBlobToken: null, extra: null };
  return {
    hasAccount: true,
    identityBlobToken: toB64u(result.rows[0].identity_blob_token),
    sessionGeneration: result.rows[0].session_generation,
    encryptedIdentityBlob: toB64u(result.rows[0].sealed_identity_blob),
    // The row itself, for the host's authOkFields. Beyond the three columns
    // above it holds only the host's declared columns, and it is scoped to
    // the connection's own routing key, which the signature just proved.
    extra: result.rows[0],
  };
}

/**
 * Erasure. Deletes the caller's OWN account row, scoped server-side to the
 * routing key the connection's signature proved -- there is no id parameter
 * to get wrong, and no way to name someone else's account.
 *
 *   cascades  unlock_methods (every passkey and recovery code)
 *   cascades  pointers (every object this account knew of)
 *   CANNOT    object_members rows in other people's objects -- the table has
 *             no identity column, by design, so the server cannot find them.
 *             The client deletes those first, one at a time, with the row
 *             capability secret out of each pointer, before it sends this.
 *   CANNOT    objects this account owns -- objects carries no owner either.
 *             Same answer: the client deletes them first, with the admin
 *             capability secret from its own pointer.
 *
 * That ordering is load-bearing: once the pointers are gone, the capability
 * secrets they held are gone with them, and nothing can address those rows
 * again. The client sweep must complete before this runs.
 */
export async function handleDeleteAccount(pool, ws, routingPublicKey, { rateLimit, onDeleteAccount }) {
  try {
    const result = await pool.query('DELETE FROM users WHERE routing_public_key = $1', [routingPublicKey]);
    // rate_limit_counters has no reference to users -- deliberately, since a
    // guest has no users row -- so nothing cascades and erasure clears it
    // explicitly: it is the one table that records "this key did something".
    await rateLimit.clearFor(pool, routingPublicKey);
    // The host's own clean-up: anything of its own that names the routing
    // key and does not cascade from users.
    if (typeof onDeleteAccount === 'function') await onDeleteAccount(pool, routingPublicKey);
    send(ws, { type: 'delete-account-ok', deleted: result.rowCount > 0 });
  } catch {
    send(ws, { type: 'delete-account-failed', reason: 'server-error' });
  }
}

/**
 * Compare-and-swap on the whole blob. The client sends the token it
 * read-modify-wrote against (`baseToken`) and a fresh random one to store
 * (`nextToken`). The UPDATE only lands if the row still holds `baseToken`;
 * if it does not, somebody else wrote in between and this write would
 * destroy their changes without a word. The refusal carries the CURRENT
 * blob and token back, so the client can re-apply its own change on top
 * and retry.
 *
 * baseToken is optional -- absent means an unconditional write -- for the
 * very first write from a device that never saw a token. A client that
 * sends one must send both: swapping to a token nobody knows, or checking
 * against one while leaving the row's token unchanged, would both leave the
 * next writer unable to make progress.
 */
export async function handleUpdateIdentityBlob(pool, ws, routingPublicKey, msg, limits) {
  if (typeof msg.encryptedIdentityBlob !== 'string') {
    send(ws, { type: 'update-identity-blob-failed', reason: 'invalid' });
    return;
  }
  let blob, baseToken = null, nextToken = null;
  try {
    blob = blobField(msg, 'encryptedIdentityBlob', { limits });
    if (msg.baseToken !== undefined && msg.baseToken !== null) {
      baseToken = fromB64u(msg.baseToken);
      if (baseToken.length !== IDENTITY_BLOB_TOKEN_BYTES) throw new Error('bad baseToken');
    }
    if (msg.nextToken !== undefined && msg.nextToken !== null) {
      nextToken = fromB64u(msg.nextToken);
      if (nextToken.length !== IDENTITY_BLOB_TOKEN_BYTES) throw new Error('bad nextToken');
    }
  } catch { send(ws, { type: 'update-identity-blob-failed', reason: 'invalid' }); return; }

  if ((baseToken === null) !== (nextToken === null)) {
    send(ws, { type: 'update-identity-blob-failed', reason: 'invalid' });
    return;
  }

  try {
    const result = baseToken === null
      ? await pool.query(
        'UPDATE users SET sealed_identity_blob = $1 WHERE routing_public_key = $2 RETURNING identity_blob_token',
        [blob, routingPublicKey]
      )
      : await pool.query(
        `UPDATE users SET sealed_identity_blob = $1, identity_blob_token = $2
          WHERE routing_public_key = $3 AND identity_blob_token = $4
          RETURNING identity_blob_token`,
        [blob, nextToken, routingPublicKey, baseToken]
      );

    if (result.rowCount === 0) {
      // Nothing changed: either the account is gone, or the token moved on.
      // Tell those two apart -- they need completely different handling on
      // the client (re-unlock versus merge and retry).
      const current = await pool.query(
        'SELECT sealed_identity_blob, identity_blob_token FROM users WHERE routing_public_key = $1',
        [routingPublicKey]
      );
      if (!current.rows[0]) {
        send(ws, { type: 'update-identity-blob-failed', reason: 'no-account' });
        return;
      }
      send(ws, {
        type: 'update-identity-blob-failed',
        reason: 'conflict',
        encryptedIdentityBlob: toB64u(current.rows[0].sealed_identity_blob),
        identityBlobToken: toB64u(current.rows[0].identity_blob_token),
      });
      return;
    }
    send(ws, { type: 'update-identity-blob-ok', identityBlobToken: toB64u(result.rows[0].identity_blob_token) });
  } catch {
    send(ws, { type: 'update-identity-blob-failed', reason: 'server-error' });
  }
}

/**
 * Validates and normalises a wire-format unlockMethod object into exactly
 * the columns unlock_methods needs -- shared by 'register', 'add-unlock-method'
 * and 'rotate-recovery-code'. Throws a short, user-safe message on anything
 * malformed -- never a raw database or decoding error. Every part is capped.
 */
export function parseUnlockMethodMessage(raw, limits) {
  if (!raw || typeof raw !== 'object') throw new Error('missing unlockMethod');
  const wrappedRootKey = blobValue(raw.wrappedRootKey, 'wrappedRootKey', 'unlockMethod.wrappedRootKey', { limits });
  const encryptedLabel = blobValue(raw.encryptedLabel, 'encryptedLabel', 'unlockMethod.encryptedLabel', { required: false, limits });

  if (raw.methodType === 'passkey-prf') {
    if (typeof raw.credentialId !== 'string' || typeof raw.prfSalt !== 'string') {
      throw new Error('passkey-prf method requires credentialId and prfSalt');
    }
    return {
      methodType: 'passkey-prf',
      credentialId: blobValue(raw.credentialId, 'credentialId', 'unlockMethod.credentialId', { limits }),
      prfSalt: blobValue(raw.prfSalt, 'prfSalt', 'unlockMethod.prfSalt', { limits }),
      pbkdf2Salt: null,
      recoveryLookupHash: null,
      wrappedRootKey,
      encryptedLabel,
    };
  }
  if (raw.methodType === 'recovery-code') {
    if (typeof raw.pbkdf2Salt !== 'string' || typeof raw.recoveryLookupHash !== 'string') {
      throw new Error('recovery-code method requires pbkdf2Salt and recoveryLookupHash');
    }
    return {
      methodType: 'recovery-code',
      credentialId: null,
      prfSalt: null,
      pbkdf2Salt: blobValue(raw.pbkdf2Salt, 'pbkdf2Salt', 'unlockMethod.pbkdf2Salt', { limits }),
      recoveryLookupHash: hashField(raw.recoveryLookupHash, 'unlockMethod.recoveryLookupHash'),
      wrappedRootKey,
      encryptedLabel,
    };
  }
  throw new Error(`unknown methodType: ${raw.methodType}`);
}

export async function insertUnlockMethodRow(queryable, routingPublicKey, method) {
  const r = await queryable.query(
    `INSERT INTO unlock_methods
       (owner_routing_public_key, method_type, credential_id, prf_salt, pbkdf2_salt, recovery_lookup_hash, wrapped_root_key, sealed_label)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     RETURNING id`,
    [routingPublicKey, method.methodType, method.credentialId, method.prfSalt, method.pbkdf2Salt, method.recoveryLookupHash, method.wrappedRootKey, method.encryptedLabel]
  );
  return r.rows[0].id;
}

/**
 * users.session_generation + 1, returned. Bumped inside the same transaction
 * as a method removal or a recovery-code rotation, and on its own for "sign
 * out everywhere". Every trusted-device session saved under the previous
 * number is discarded the next time that device connects. Cooperative, not
 * cryptographic -- a copied browser profile could ignore it.
 */
export async function bumpSessionGeneration(queryable, routingPublicKey) {
  const r = await queryable.query(
    'UPDATE users SET session_generation = session_generation + 1 WHERE routing_public_key = $1 RETURNING session_generation',
    [routingPublicKey]
  );
  if (!r.rows[0]) throw new Error('no such account');
  return r.rows[0].session_generation;
}

export async function handleRegister(pool, ws, routingPublicKey, msg, state, policy, limits) {
  let encryptedIdentityBlob, methods, policyValues;
  try {
    if (typeof msg.encryptedIdentityBlob !== 'string') throw new Error('missing encryptedIdentityBlob');
    encryptedIdentityBlob = blobField(msg, 'encryptedIdentityBlob', { limits });
    // Every unlock method the account starts with, in this ONE message:
    // the passkey and the recovery code together, or the code alone where
    // the browser cannot hold a passkey. Sent as two messages, a failure
    // between them would leave an account with only one of its two ways in.
    if (!Array.isArray(msg.unlockMethods) || msg.unlockMethods.length < 1 || msg.unlockMethods.length > 2) {
      throw new Error('unlockMethods must list one or two methods');
    }
    methods = msg.unlockMethods.map((m) => parseUnlockMethodMessage(m, limits));
    if (methods.length === 2 && methods[0].methodType === methods[1].methodType) {
      throw new Error('unlockMethods must be of two different kinds');
    }
    // The host's registration policy runs inside the same refusal. It
    // returns the values of the columns it declared, or throws with the
    // reason the client is told.
    policyValues = policy.onRegister(msg) || {};
  } catch (e) {
    send(ws, { type: 'register-failed', reason: 'invalid', detail: e.message });
    return;
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // The blob's first compare-and-swap token, taken from the client when it
    // offers one, so a brand-new account starts with real randomness rather
    // than the all-zero default.
    let initialBlobToken = null;
    try {
      if (typeof msg.identityBlobToken === 'string') {
        const t = fromB64u(msg.identityBlobToken);
        if (t.length === IDENTITY_BLOB_TOKEN_BYTES) initialBlobToken = t;
      }
    } catch { initialBlobToken = null; }
    // One INSERT: the engine's columns, the token when the client offered
    // one, and the host's declared columns with the values its policy
    // returned (a column the policy left undefined keeps the table's default).
    const columns = ['routing_public_key', 'sealed_identity_blob'];
    const values = [routingPublicKey, encryptedIdentityBlob];
    if (initialBlobToken) { columns.push('identity_blob_token'); values.push(initialBlobToken); }
    for (const column of policy.columns) {
      if (policyValues[column] === undefined) continue;
      columns.push(column);
      values.push(policyValues[column]);
    }
    await client.query(
      `INSERT INTO users (${columns.join(', ')}) VALUES (${columns.map((_, i) => `$${i + 1}`).join(', ')})`,
      values
    );
    // In the same transaction as the users row: the account exists with
    // every method, or not at all.
    for (const method of methods) await insertUnlockMethodRow(client, routingPublicKey, method);
    await client.query('COMMIT');
    state.hasAccount = true;
    send(ws, { type: 'register-ok' });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    if (e.code === '23505') { // unique_violation -- routing key, credential_id, or recovery_lookup_hash already used
      send(ws, { type: 'register-failed', reason: 'already-registered' });
    } else {
      send(ws, { type: 'register-failed', reason: 'server-error' });
    }
  } finally {
    client.release();
  }
}

/**
 * Lists the caller's OWN unlock methods -- authenticated, and scoped to the
 * connection's routing key by construction. Deliberately not folded into
 * the pre-authentication lookup: that one answers "here is a wrapped blob
 * for this credential" to anyone who holds the credential id, and must
 * never also answer "and here is who owns it".
 *
 * Returns ids, types, credential ids and sealed labels only. No wrapped
 * root keys: the caller has already unwrapped one to get here.
 */
export async function handleListUnlockMethods(pool, ws, routingPublicKey) {
  try {
    const result = await pool.query(
      `SELECT id, method_type, credential_id, sealed_label
         FROM unlock_methods
        WHERE owner_routing_public_key = $1
        ORDER BY method_type, id`,
      [routingPublicKey]
    );
    send(ws, {
      type: 'unlock-methods',
      methods: result.rows.map((r) => ({
        id: r.id,
        methodType: r.method_type,
        credentialId: r.credential_id ? toB64u(r.credential_id) : null,
        encryptedLabel: r.sealed_label ? toB64u(r.sealed_label) : null,
      })),
    });
  } catch {
    send(ws, { type: 'list-unlock-methods-failed', reason: 'server-error' });
  }
}

/**
 * Adds an unlock method to an account that must already exist. No
 * cryptographic proof that the new wrapped_root_key unwraps to the same root
 * key as the existing methods is possible server-side (the server never
 * sees the root key); that invariant is the client's, which wraps the same
 * in-memory root key it already unwrapped.
 */
export async function handleAddUnlockMethod(pool, ws, routingPublicKey, msg, state, limits) {
  if (!state.hasAccount) {
    send(ws, { type: 'add-unlock-method-failed', reason: 'no-account' });
    return;
  }
  let method;
  try {
    method = parseUnlockMethodMessage(msg.unlockMethod, limits);
  } catch (e) {
    send(ws, { type: 'add-unlock-method-failed', reason: 'invalid', detail: e.message });
    return;
  }
  try {
    await insertUnlockMethodRow(pool, routingPublicKey, method);
    send(ws, { type: 'add-unlock-method-ok' });
  } catch (e) {
    if (e.code === '23505') { // credential_id or recovery_lookup_hash already used by some row
      send(ws, { type: 'add-unlock-method-failed', reason: 'already-used' });
    } else {
      send(ws, { type: 'add-unlock-method-failed', reason: 'server-error' });
    }
  }
}

/**
 * Removes one of the caller's OWN unlock methods. The one rule the server
 * enforces is the one the data cannot survive breaking: the LAST method is
 * never removed, because the root key would then be wrapped under nothing
 * and the account lost for good -- there is no server-side recovery, and
 * none may be added. Anything stronger is client policy.
 *
 * Every owner row is locked FOR UPDATE first, so two concurrent removals of
 * an account's two methods cannot both see "two rows" and both proceed. The
 * session generation is bumped in the same transaction: a removed method is
 * often a lost or stolen device.
 */
export async function handleRemoveUnlockMethod(pool, ws, routingPublicKey, msg, state) {
  if (!state.hasAccount) {
    send(ws, { type: 'remove-unlock-method-failed', reason: 'no-account' });
    return;
  }
  if (typeof msg.methodId !== 'string' || !UUID_RE.test(msg.methodId)) {
    send(ws, { type: 'remove-unlock-method-failed', reason: 'invalid' });
    return;
  }
  const methodId = msg.methodId.toLowerCase();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const owned = await client.query(
      'SELECT id FROM unlock_methods WHERE owner_routing_public_key = $1 FOR UPDATE',
      [routingPublicKey]
    );
    const ids = owned.rows.map((r) => String(r.id).toLowerCase());
    if (!ids.includes(methodId)) {
      await client.query('ROLLBACK');
      send(ws, { type: 'remove-unlock-method-failed', reason: 'not-found' });
      return;
    }
    if (ids.length <= 1) {
      await client.query('ROLLBACK');
      send(ws, { type: 'remove-unlock-method-failed', reason: 'last-method' });
      return;
    }
    await client.query(
      'DELETE FROM unlock_methods WHERE id = $1 AND owner_routing_public_key = $2',
      [methodId, routingPublicKey]
    );
    const sessionGeneration = await bumpSessionGeneration(client, routingPublicKey);
    await client.query('COMMIT');
    send(ws, { type: 'remove-unlock-method-ok', sessionGeneration });
  } catch {
    await client.query('ROLLBACK').catch(() => {});
    send(ws, { type: 'remove-unlock-method-failed', reason: 'server-error' });
  } finally {
    client.release();
  }
}

/**
 * "Make a new recovery code and cancel the old one" as ONE transaction: the
 * new recovery-code row is inserted, the named old recovery-code rows are
 * deleted, the session generation is bumped -- or none of it happens.
 * Inserting before deleting is what makes the never-zero invariant
 * trivially true here. Only recovery-code rows can be cancelled this way: a
 * passkey goes through remove-unlock-method and its last-method guard.
 */
export async function handleRotateRecoveryCode(pool, ws, routingPublicKey, msg, state, limits) {
  if (!state.hasAccount) {
    send(ws, { type: 'rotate-recovery-code-failed', reason: 'no-account' });
    return;
  }
  let method, cancelIds;
  try {
    method = parseUnlockMethodMessage(msg.unlockMethod, limits);
    if (method.methodType !== 'recovery-code') throw new Error('rotate-recovery-code takes a recovery-code method');
    if (!Array.isArray(msg.cancelMethodIds) || msg.cancelMethodIds.length === 0 || msg.cancelMethodIds.length > 20) {
      throw new Error('cancelMethodIds required (1-20)');
    }
    cancelIds = msg.cancelMethodIds.map((id) => {
      if (typeof id !== 'string' || !UUID_RE.test(id)) throw new Error('cancelMethodIds must be UUIDs');
      return id.toLowerCase();
    });
  } catch (e) {
    send(ws, { type: 'rotate-recovery-code-failed', reason: 'invalid', detail: e.message });
    return;
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const owned = await client.query(
      'SELECT id, method_type FROM unlock_methods WHERE owner_routing_public_key = $1 FOR UPDATE',
      [routingPublicKey]
    );
    const byId = new Map(owned.rows.map((r) => [String(r.id).toLowerCase(), r.method_type]));
    for (const id of cancelIds) {
      if (!byId.has(id)) {
        await client.query('ROLLBACK');
        send(ws, { type: 'rotate-recovery-code-failed', reason: 'not-found' });
        return;
      }
      if (byId.get(id) !== 'recovery-code') {
        await client.query('ROLLBACK');
        send(ws, { type: 'rotate-recovery-code-failed', reason: 'not-a-recovery-code' });
        return;
      }
    }
    const methodId = await insertUnlockMethodRow(client, routingPublicKey, method);
    await client.query(
      'DELETE FROM unlock_methods WHERE owner_routing_public_key = $1 AND id = ANY($2::uuid[])',
      [routingPublicKey, cancelIds]
    );
    const sessionGeneration = await bumpSessionGeneration(client, routingPublicKey);
    await client.query('COMMIT');
    send(ws, { type: 'rotate-recovery-code-ok', methodId, sessionGeneration });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    if (e && e.code === '23505') { // the new code's lookup hash is already used by some row
      send(ws, { type: 'rotate-recovery-code-failed', reason: 'already-used' });
    } else {
      send(ws, { type: 'rotate-recovery-code-failed', reason: 'server-error' });
    }
  } finally {
    client.release();
  }
}

/**
 * "Sign out everywhere": bumps the session generation and nothing else.
 * Every other device's trusted session is discarded on its next connection;
 * the unlock methods stay exactly as they are.
 */
export async function handleBumpSessionGeneration(pool, ws, routingPublicKey, state) {
  if (!state.hasAccount) {
    send(ws, { type: 'bump-session-generation-failed', reason: 'no-account' });
    return;
  }
  try {
    const sessionGeneration = await bumpSessionGeneration(pool, routingPublicKey);
    send(ws, { type: 'bump-session-generation-ok', sessionGeneration });
  } catch {
    send(ws, { type: 'bump-session-generation-failed', reason: 'server-error' });
  }
}
