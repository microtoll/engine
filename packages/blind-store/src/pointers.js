/**
 * The pointer handlers. A pointer is the account's sealed record of
 * something it holds a key to; the server sees the owner and a blob, never
 * what the blob names. insertPointer and parsePointerField are exported for
 * a host handler that writes a pointer inside its own transaction.
 */
import { send, toB64u, blobValue, blobField } from './wire.js';

/** Shared by 'create-event' and 'join-event' -- both attach exactly one pointer row for the sending connection's own routing key. */
export function parsePointerField(pointer, limits) {
  if (!pointer || typeof pointer !== 'object') throw new Error('missing pointer.encryptedEventAccessBlob');
  return { sealed: blobValue(pointer.encryptedEventAccessBlob, 'encryptedEventAccessBlob', 'pointer.encryptedEventAccessBlob', { limits }) };
}

export async function insertPointer(client, routingPublicKey, pointer) {
  await client.query(
    'INSERT INTO pointers (owner_routing_public_key, sealed_pointer) VALUES ($1, $2)',
    [routingPublicKey, pointer.sealed]
  );
}

/**
 * Returns every pointer the authenticated routing key owns: the client
 * fetches all its pointers once per session, decrypts locally, then
 * intersects against query results. No filtering beyond ownership; the
 * server has no idea what is inside.
 */
export async function handleFetchPointers(pool, ws, routingPublicKey) {
  try {
    const result = await pool.query(
      'SELECT id, sealed_pointer FROM pointers WHERE owner_routing_public_key = $1',
      [routingPublicKey]
    );
    send(ws, {
      type: 'pointers',
      pointers: result.rows.map((r) => ({ id: r.id, encryptedEventAccessBlob: toB64u(r.sealed_pointer) })),
    });
  } catch {
    send(ws, { type: 'fetch-pointers-failed', reason: 'server-error' });
  }
}

/**
 * Overwrites one of the connection's own pointer rows -- the write half of
 * the lazy epoch refresh after a rotation. Scoped by owner, so a connection
 * can never touch another account's pointer: authenticated identity, not a
 * capability secret, is the right gate here, since pointers already belong
 * to a specific account.
 */
export async function handleUpdatePointer(pool, ws, routingPublicKey, msg, limits) {
  if (typeof msg.pointerId !== 'string' || typeof msg.encryptedEventAccessBlob !== 'string') {
    send(ws, { type: 'update-pointer-failed', reason: 'invalid' });
    return;
  }
  let sealed;
  try { sealed = blobField(msg, 'encryptedEventAccessBlob', { limits }); } catch (e) {
    send(ws, { type: 'update-pointer-failed', reason: 'invalid', detail: e.message });
    return;
  }
  try {
    const result = await pool.query(
      'UPDATE pointers SET sealed_pointer = $1 WHERE id = $2 AND owner_routing_public_key = $3',
      [sealed, msg.pointerId, routingPublicKey]
    );
    if (result.rowCount === 0) {
      send(ws, { type: 'update-pointer-failed', reason: 'not-found' });
      return;
    }
    send(ws, { type: 'update-pointer-ok' });
  } catch {
    send(ws, { type: 'update-pointer-failed', reason: 'server-error' });
  }
}

/**
 * Deletes one of the connection's own pointer rows: the client's way to
 * discard a pointer to an object that is gone or that it has left, so the
 * pointer count an account carries -- one of the documented trades -- does
 * not grow with everything it ever held (without it, a stale pointer stays
 * until the account goes). Scoped
 * by owner; deleting a pointer that is not there is not an error.
 */
export async function handleDeletePointer(pool, ws, routingPublicKey, msg) {
  if (typeof msg.pointerId !== 'string') {
    send(ws, { type: 'delete-pointer-failed', reason: 'invalid' });
    return;
  }
  try {
    const result = await pool.query('DELETE FROM pointers WHERE id = $1 AND owner_routing_public_key = $2', [msg.pointerId, routingPublicKey]);
    send(ws, { type: 'delete-pointer-ok', deleted: result.rowCount > 0 });
  } catch {
    send(ws, { type: 'delete-pointer-failed', reason: 'server-error' });
  }
}
