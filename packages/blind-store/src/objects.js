/**
 * The object and membership handlers: objects in collections with a coarse
 * public selector, their member rows, the capability checks that gate them,
 * the selector query and the live watches, as DESIGN.md §2 describes
 * (D-33). The wire message names keep the protocol's event vocabulary
 * (D-27): an event is an object, a participation is a member row; the
 * selector and window fields are generic.
 *
 * Capability-secret authorisation, not identity: presenting the correct
 * secret is both necessary and sufficient, and there is no separate notion
 * of "who" the admin or the member is.
 */
import { send, fromB64u, toB64u, UUID_RE, DATE_RE, blobValue, blobField, hashField, hashSecret } from './wire.js';
import { insertPointer, parsePointerField } from './pointers.js';

// ---------------------------------------------------------------------
// Collections: the configuration, validated once at createBlindStore.
// ---------------------------------------------------------------------

const COLLECTION_NAME_RE = /^[a-z][a-z0-9_-]{0,31}$/;
const SELECTOR_RE = /^[A-Za-z0-9._:-]+$/;

/**
 * collections: { name: { selectorLength, window, allowAll, imminentDays, queryExtras } }
 *   selectorLength  the exact length of every selector in this collection (1-64)
 *   window          whether objects carry a date window (default false)
 *   allowAll        whether a query may name every selector at once (default false)
 *   imminentDays    a server-owned window for watch-imminent, in days, or null
 *   queryExtras     async (pool, query) -> fields merged into the query reply, or null
 */
export function normaliseCollections(collections = {}) {
  const map = new Map();
  for (const [name, raw] of Object.entries(collections)) {
    if (!COLLECTION_NAME_RE.test(name)) throw new Error(`collections: "${name}" is not a plain collection name (a-z, 0-9, _ and -, 32 characters at most, starting with a letter)`);
    const c = raw && typeof raw === 'object' ? raw : {};
    if (!Number.isInteger(c.selectorLength) || c.selectorLength < 1 || c.selectorLength > 64) throw new Error(`collections.${name}: selectorLength must be an integer from 1 to 64`);
    const window = c.window === true;
    if (c.imminentDays != null && (!window || !Number.isInteger(c.imminentDays) || c.imminentDays < 0 || c.imminentDays > 366)) {
      throw new Error(`collections.${name}: imminentDays needs a window and an integer from 0 to 366`);
    }
    if (c.queryExtras != null && typeof c.queryExtras !== 'function') throw new Error(`collections.${name}: queryExtras must be a function`);
    map.set(name, Object.freeze({
      name, selectorLength: c.selectorLength, window, allowAll: c.allowAll === true,
      imminentDays: c.imminentDays == null ? null : c.imminentDays, queryExtras: c.queryExtras || null,
    }));
  }
  return map;
}

function collectionOf(config, name) {
  if (typeof name !== 'string') throw new Error('missing collection');
  const c = config.get(name);
  if (!c) throw new Error(`unknown collection: ${name}`);
  return c;
}

function parseSelector(c, value, name = 'selector') {
  if (typeof value !== 'string' || value.length !== c.selectorLength || !SELECTOR_RE.test(value)) {
    throw new Error(`missing or malformed ${name} (${c.selectorLength} characters of A-Z, a-z, 0-9, ".", "_", ":" or "-")`);
  }
  return value;
}

/** An object's own window: required when the collection has one, refused when it has not. */
function parseObjectWindow(c, msg) {
  if (!c.window) {
    if (msg.windowStart !== undefined || msg.windowEnd !== undefined) throw new Error(`collection ${c.name} has no window`);
    return { start: null, end: null };
  }
  if (typeof msg.windowStart !== 'string' || !DATE_RE.test(msg.windowStart)) throw new Error('missing or malformed windowStart');
  if (typeof msg.windowEnd !== 'string' || !DATE_RE.test(msg.windowEnd)) throw new Error('missing or malformed windowEnd');
  // A window that ends before it starts is left to the table's CHECK, and
  // reported as invalid-date-range.
  return { start: msg.windowStart, end: msg.windowEnd };
}

// ---------------------------------------------------------------------
// The wire shape of an object, and the one read path.
// ---------------------------------------------------------------------

/**
 * window_start/window_end come back via to_char, never as JS Date objects:
 * these are pure calendar dates with no timezone semantics, and letting the
 * driver parse them risks a timezone-dependent off-by-one-day depending on
 * the server's local zone.
 *
 * admin_capability_hash is NOT selected (D-33): served to every querier, it
 * would hand each of them -- cover-traffic recipients included -- a stable
 * per-object token; nothing in the client needs it.
 */
export const OBJECT_COLUMNS = `id, collection, selector,
       to_char(window_start, 'YYYY-MM-DD') AS window_start,
       to_char(window_end,   'YYYY-MM-DD') AS window_end,
       sealed_content, sealed_detail, key_epoch, roster_members_only`;

/**
 * Every read path that serves an object to a client MUST go through this.
 * It deliberately ends in a dangling `AND`, so a caller that appends its own
 * unfiltered `WHERE ...` produces a SQL syntax error rather than silently
 * serving a hidden object.
 */
export const OBJECT_SELECT_ACTIVE = `SELECT ${OBJECT_COLUMNS} FROM objects WHERE status = 'active' AND`;

export function rowToObjectWire(r) {
  return {
    id: r.id,
    collection: r.collection,
    selector: r.selector,
    windowStart: r.window_start,
    windowEnd: r.window_end,
    encryptedEventData: toB64u(r.sealed_content),
    encryptedEventDetail: r.sealed_detail ? toB64u(r.sealed_detail) : null,
    keyEpoch: r.key_epoch,
    rosterMembersOnly: r.roster_members_only === true,
  };
}

// ---------------------------------------------------------------------
// The capability checks.
// ---------------------------------------------------------------------

function secretHash(b64u) {
  if (typeof b64u !== 'string') return null;
  try { return hashSecret(fromB64u(b64u)); } catch { return null; }
}

/** The admin capability, on an active object. A hidden object refuses every admin action: a host that hid it keeps the evidence. */
export async function verifyAdminCapability(pool, objectId, adminCapabilitySecretB64u) {
  const hash = secretHash(adminCapabilitySecretB64u);
  if (!hash) return false;
  const r = await pool.query("SELECT 1 FROM objects WHERE id = $1 AND admin_capability_hash = $2 AND status = 'active'", [objectId, hash]);
  return r.rows.length > 0;
}

/**
 * The read capability, DERIVED from K_object by the client, so anyone who
 * legitimately holds the key can present it with nothing distributed to
 * them -- including someone who opened a link but has not reacted yet, and
 * therefore has no row of their own. A removed member loses it
 * automatically: rotation re-derives the hash from the new key.
 */
export async function verifyReadCapability(pool, objectId, readCapabilitySecretB64u) {
  const hash = secretHash(readCapabilitySecretB64u);
  if (!hash) return false;
  const r = await pool.query("SELECT 1 FROM objects WHERE id = $1 AND read_capability_hash = $2 AND status = 'active'", [objectId, hash]);
  return r.rows.length > 0;
}

/**
 * Proof of having a row on this object: a row capability secret matching one
 * active member row. Any active row of this object will do, because the
 * question is "are you in this room", not "which one are you".
 */
export async function verifyRowCapabilityForObject(pool, objectId, rowCapabilitySecretB64u) {
  const hash = secretHash(rowCapabilitySecretB64u);
  if (!hash) return false;
  const r = await pool.query(
    `SELECT 1 FROM object_members m JOIN objects o ON o.id = m.object_id
      WHERE m.object_id = $1 AND m.row_capability_hash = $2 AND m.status = 'active' AND o.status = 'active'`,
    [objectId, hash]
  );
  return r.rows.length > 0;
}

/** Does this object hide its roster from key holders without a row? Status-blind: an unknown object answers false, and the capability check then refuses it anyway. */
export async function rosterIsMembersOnly(pool, objectId) {
  const r = await pool.query('SELECT roster_members_only FROM objects WHERE id = $1', [objectId]);
  return r.rows.length > 0 && r.rows[0].roster_members_only === true;
}

/**
 * A new row names the epoch of the key it was sealed under, and it must be
 * the object's own: a row sealed under an older key is readable by
 * whoever that key was taken from, and by nobody who stayed.
 */
async function epochIsCurrent(queryable, objectId, keyEpoch) {
  const r = await queryable.query('SELECT key_epoch FROM objects WHERE id = $1', [objectId]);
  return r.rows.length > 0 && r.rows[0].key_epoch === keyEpoch;
}

// ---------------------------------------------------------------------
// Parsers. Each throws a short, user-safe message; every ciphertext field
// is capped, nested ones included, and every hash is exactly 32 bytes.
// ---------------------------------------------------------------------

/** Shared by create-event (as creatorParticipation), join-event and create-participation. */
function parseMemberRowFields(cp, fieldName, limits) {
  if (!cp || typeof cp !== 'object') throw new Error(`missing ${fieldName}`);
  // Client-generated, not a server default: the row's own id is inside what
  // the author signed, so it has to exist before the row is built. The
  // primary key constraint is what actually prevents collisions.
  if (typeof cp.eventUserId !== 'string' || !UUID_RE.test(cp.eventUserId)) throw new Error(`missing or malformed ${fieldName}.eventUserId`);
  if (!Number.isInteger(cp.keyEpoch) || cp.keyEpoch < 1) throw new Error(`missing or invalid ${fieldName}.keyEpoch`);
  return {
    rowId: cp.eventUserId,
    sealedRow: blobValue(cp.encryptedParticipationDataBlob, 'encryptedParticipationDataBlob', `${fieldName}.encryptedParticipationDataBlob`, { limits }),
    sealedObjectKey: blobValue(cp.encryptedSharedEventKey, 'encryptedSharedEventKey', `${fieldName}.encryptedSharedEventKey`, { limits }),
    rowCapabilityHash: hashField(cp.rowCapabilityHash, `${fieldName}.rowCapabilityHash`),
    keyEpoch: cp.keyEpoch,
  };
}

function parseObjectId(msg) {
  if (typeof msg.eventId !== 'string' || !UUID_RE.test(msg.eventId)) throw new Error('missing or malformed eventId');
  return msg.eventId;
}

function parseCreateMessage(config, msg, limits) {
  const objectId = parseObjectId(msg);
  const c = collectionOf(config, msg.collection);
  if (typeof msg.encryptedEventData !== 'string') throw new Error('missing encryptedEventData');
  const row = parseMemberRowFields(msg.creatorParticipation, 'creatorParticipation', limits);
  // A new object is at epoch 1, so its owner's row must be too (a row at
  // any other epoch is not under the object's key); the client always
  // sends 1. Checked here rather than left to chance.
  if (row.keyEpoch !== 1) throw new Error('creatorParticipation.keyEpoch must be 1 on a new object');
  return {
    objectId, collection: c,
    selector: parseSelector(c, msg.selector),
    window: parseObjectWindow(c, msg),
    sealedContent: blobField(msg, 'encryptedEventData', { limits }),
    sealedDetail: blobField(msg, 'encryptedEventDetail', { required: false, limits }),
    adminCapabilityHash: hashField(msg.adminCapabilityHash, 'adminCapabilityHash'),
    readCapabilityHash: hashField(msg.readCapabilityHash, 'readCapabilityHash'),
    // A boolean and nothing else: anything that is not literally true is false.
    rosterMembersOnly: msg.rosterMembersOnly === true,
    ownerRow: row,
    pointer: parsePointerField(msg.pointer, limits),
  };
}

/** The selector query and the watch share one parser, so the two can never accept different selectors. */
export function parseQueryMessage(config, msg, queryLimits) {
  const c = collectionOf(config, msg.collection);
  // `all` is the calendar-view variant: the window alone, every selector. It
  // reveals strictly LESS than a selector query. An explicit flag, never
  // inferred from an empty list -- an accidentally-empty array stays the hard
  // error it always was.
  if (msg.all !== undefined && msg.all !== true) throw new Error('all must be true when present');
  let selectors = null;
  if (msg.all) {
    if (!c.allowAll) throw new Error(`collection ${c.name} does not allow all`);
    if (msg.selectors !== undefined) throw new Error('all and selectors are mutually exclusive');
  } else {
    if (!Array.isArray(msg.selectors) || msg.selectors.length === 0) throw new Error('missing or empty selectors');
    if (msg.selectors.length > queryLimits.maxSelectors) throw new Error('too many selectors');
    selectors = msg.selectors.map((s) => parseSelector(c, s, 'selectors'));
  }
  let windowStart = null, windowEnd = null;
  if (c.window) {
    if (typeof msg.windowStart !== 'string' || !DATE_RE.test(msg.windowStart)) throw new Error('missing or malformed windowStart');
    windowStart = msg.windowStart;
    windowEnd = windowStart;
    if (msg.windowEnd !== undefined) {
      if (typeof msg.windowEnd !== 'string' || !DATE_RE.test(msg.windowEnd)) throw new Error('malformed windowEnd');
      if (msg.windowEnd < windowStart) throw new Error('windowEnd must not be before windowStart');
      windowEnd = msg.windowEnd;
    }
  } else if (msg.windowStart !== undefined || msg.windowEnd !== undefined) {
    throw new Error(`collection ${c.name} has no window`);
  }
  return { collection: c, all: !!msg.all, selectors, windowStart, windowEnd };
}

// ---------------------------------------------------------------------
// The handlers. `deps` is { config, limits, queryLimits, rateLimit, live }.
// ---------------------------------------------------------------------

async function insertMemberRowAndPointer(client, objectId, routingPublicKey, row, pointer) {
  await client.query(
    `INSERT INTO object_members (id, object_id, sealed_row, sealed_object_key, row_capability_hash, key_epoch)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [row.rowId, objectId, row.sealedRow, row.sealedObjectKey, row.rowCapabilityHash, row.keyEpoch]
  );
  await insertPointer(client, routingPublicKey, pointer);
}

/**
 * Creates an object, the owner's own member row, and the owner's own pointer
 * in one transaction. "No owner identity anywhere" means this is just
 * "insert rows", not an owner-specific code path.
 */
export async function handleCreate(pool, ws, routingPublicKey, msg, state, deps) {
  // pointers.owner_routing_public_key references users, so an unregistered
  // connection can create nothing here: refused as no-account rather than
  // letting a foreign-key violation surface as an opaque server-error.
  if (!state.hasAccount) {
    send(ws, { type: 'create-event-failed', reason: 'no-account' });
    return;
  }
  let fields;
  try {
    fields = parseCreateMessage(deps.config, msg, deps.limits);
  } catch (e) {
    send(ws, { type: 'create-event-failed', reason: 'invalid', detail: e.message });
    return;
  }
  // Daily creation cap: hygiene, fail open. After validation so a malformed
  // message costs nothing; before the transaction so a refused object
  // leaves no row.
  const quota = await deps.rateLimit.consume(pool, routingPublicKey, 'create-event');
  if (!quota.allowed) {
    send(ws, { type: 'create-event-failed', reason: 'rate-limited', limit: quota.limit });
    return;
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `INSERT INTO objects (id, collection, selector, window_start, window_end, sealed_content, sealed_detail, key_epoch, admin_capability_hash, read_capability_hash, roster_members_only)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9, $10)`,
      [fields.objectId, fields.collection.name, fields.selector, fields.window.start, fields.window.end, fields.sealedContent, fields.sealedDetail,
        fields.adminCapabilityHash, fields.readCapabilityHash, fields.rosterMembersOnly]
    );
    await insertMemberRowAndPointer(client, fields.objectId, routingPublicKey, fields.ownerRow, fields.pointer);
    await client.query('COMMIT');
    send(ws, { type: 'create-event-ok', eventId: fields.objectId });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    if (e.code === '23514') { // check_violation -- window_end < window_start
      send(ws, { type: 'create-event-failed', reason: 'invalid-date-range' });
    } else if (e.code === '23505') { // unique_violation -- object id or row id collision
      send(ws, { type: 'create-event-failed', reason: 'duplicate-event-id' });
    } else {
      send(ws, { type: 'create-event-failed', reason: 'server-error' });
    }
  } finally {
    client.release();
  }
}

/**
 * The selector query (DESIGN.md §2.2): everything active in the collection
 * whose selector is named (or all of them) and whose window overlaps --
 * deliberately not filtered by identity in any way. The client intersects
 * the answer against its own decrypted pointers, and the rows it cannot
 * decrypt are cover traffic, not waste.
 */
export async function handleQuery(pool, ws, msg, deps) {
  let q;
  try {
    q = parseQueryMessage(deps.config, msg, deps.queryLimits);
  } catch (e) {
    send(ws, { type: 'query-events-failed', reason: 'invalid', detail: e.message });
    return;
  }
  try {
    const where = ['collection = $1'];
    const params = [q.collection.name];
    if (!q.all) { params.push(q.selectors); where.push(`selector = ANY($${params.length})`); }
    if (q.collection.window) {
      params.push(q.windowEnd); where.push(`window_start <= $${params.length}`);
      params.push(q.windowStart); where.push(`window_end >= $${params.length}`);
    }
    // One row more than the cap, so "over" is told from "exactly at".
    params.push(deps.queryLimits.maxQueryRows + 1);
    const result = await pool.query(`${OBJECT_SELECT_ACTIVE} ${where.join(' AND ')} LIMIT $${params.length}`, params);
    if (result.rows.length > deps.queryLimits.maxQueryRows) {
      // The backstop: closed for this one request; the client narrows its
      // selector. A partial answer would silently break the model, since the
      // client cannot tell which of its objects it missed.
      send(ws, { type: 'query-events-failed', reason: 'too-many', limit: deps.queryLimits.maxQueryRows });
      return;
    }
    // A host's extras ride THIS reply, on THIS selector, so an app never
    // needs a second request that would reveal intent.
    const extras = q.collection.queryExtras ? await q.collection.queryExtras(pool, q) : null;
    send(ws, { type: 'events', events: result.rows.map(rowToObjectWire), ...(extras || {}) });
  } catch {
    send(ws, { type: 'query-events-failed', reason: 'server-error' });
  }
}

/**
 * One object by id -- what a link redemption needs before it can join, and
 * what heals a stale pointer. The one read path that tells the server which
 * object a routing key asked about (README: "the direct path").
 */
export async function handleFetch(pool, ws, msg) {
  if (typeof msg.eventId !== 'string' || !UUID_RE.test(msg.eventId)) {
    send(ws, { type: 'fetch-event-failed', reason: 'invalid' });
    return;
  }
  try {
    const result = await pool.query(`${OBJECT_SELECT_ACTIVE} id = $1`, [msg.eventId]);
    if (result.rows.length === 0) {
      send(ws, { type: 'fetch-event-failed', reason: 'not-found' });
      return;
    }
    send(ws, { type: 'event', event: rowToObjectWire(result.rows[0]) });
  } catch {
    send(ws, { type: 'fetch-event-failed', reason: 'server-error' });
  }
}

/**
 * Adds the caller's pointer to an object that already exists, and -- when a
 * member row is sent -- the row with it. Every production caller sends the
 * pointer alone (redeeming a link, collecting a drop); the row arrives on
 * the first reaction, through create-participation.
 *
 * A member row is gated exactly as create-participation gates it: the
 * read capability (derived from K_object, so proving it proves the key) and
 * an active object at the row's epoch. Without that, anybody who had seen an
 * object id in a query reply could put rows into it.
 */
export async function handleJoin(pool, ws, routingPublicKey, msg, state, deps) {
  if (!state.hasAccount) {
    send(ws, { type: 'join-event-failed', reason: 'no-account' });
    return;
  }
  let objectId, row = null, pointer;
  try {
    objectId = parseObjectId(msg);
    if (msg.participation !== undefined) row = parseMemberRowFields(msg.participation, 'participation', deps.limits);
    pointer = parsePointerField(msg.pointer, deps.limits);
  } catch (e) {
    send(ws, { type: 'join-event-failed', reason: 'invalid', detail: e.message });
    return;
  }
  if (row && !(await verifyReadCapability(pool, objectId, msg.readCapabilitySecret))) {
    send(ws, { type: 'join-event-failed', reason: 'unauthorized' });
    return;
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (row) {
      if (!(await epochIsCurrent(client, objectId, row.keyEpoch))) throw Object.assign(new Error('stale epoch'), { code: 'stale' });
      await insertMemberRowAndPointer(client, objectId, routingPublicKey, row, pointer);
    } else {
      // Pointer only. Pointers deliberately carry no object id column, so
      // nothing else here would notice a bogus id: check it explicitly, and
      // with the status filter, since this is a separate route onto
      // somebody's list.
      const exists = await client.query("SELECT 1 FROM objects WHERE id = $1 AND status = 'active'", [objectId]);
      if (exists.rows.length === 0) throw Object.assign(new Error('no such object'), { code: '23503' });
      await insertPointer(client, routingPublicKey, pointer);
    }
    await client.query('COMMIT');
    send(ws, { type: 'join-event-ok', eventId: objectId });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    if (e.code === '23503') send(ws, { type: 'join-event-failed', reason: 'event-not-found' });
    else if (e.code === 'stale') send(ws, { type: 'join-event-failed', reason: 'stale' });
    else if (e.code === '23505') send(ws, { type: 'join-event-failed', reason: 'duplicate-row-id' });
    else send(ws, { type: 'join-event-failed', reason: 'server-error' });
  } finally {
    client.release();
  }
}

/**
 * Every ACTIVE member row of an object: what a member needs to see who else
 * is there, and what an admin's client needs before it can build a rotation
 * plan. Gated by the read capability (any legitimate holder of K_object) or
 * the admin capability -- unless the object says otherwise: with
 * roster_members_only set, holding the key is no longer enough, and the
 * caller must present a ROW capability, which only someone with a row has.
 * Enforced here rather than in the client because the people it protects
 * are not protected by a rule a modified client can ignore.
 */
export async function handleFetchMembers(pool, ws, msg) {
  if (typeof msg.eventId !== 'string' || !UUID_RE.test(msg.eventId)) {
    send(ws, { type: 'fetch-event-members-failed', reason: 'invalid' });
    return;
  }
  const membersOnly = await rosterIsMembersOnly(pool, msg.eventId);
  const authorized = membersOnly
    ? (await verifyRowCapabilityForObject(pool, msg.eventId, msg.rowCapabilitySecret)
       || await verifyAdminCapability(pool, msg.eventId, msg.adminCapabilitySecret))
    : (await verifyReadCapability(pool, msg.eventId, msg.readCapabilitySecret)
       || await verifyAdminCapability(pool, msg.eventId, msg.adminCapabilitySecret));
  if (!authorized) {
    send(ws, { type: 'fetch-event-members-failed', reason: 'unauthorized' });
    return;
  }
  try {
    const result = await pool.query(
      "SELECT id, sealed_row, key_epoch FROM object_members WHERE object_id = $1 AND status = 'active'",
      [msg.eventId]
    );
    send(ws, {
      type: 'event-members',
      members: result.rows.map((r) => ({ id: r.id, encryptedParticipationDataBlob: toB64u(r.sealed_row), keyEpoch: r.key_epoch })),
    });
  } catch {
    send(ws, { type: 'fetch-event-members-failed', reason: 'server-error' });
  }
}

function parseRotateMessage(msg, limits) {
  const objectId = parseObjectId(msg);
  if (typeof msg.encryptedEventData !== 'string') throw new Error('missing encryptedEventData');
  if (!Array.isArray(msg.updates)) throw new Error('missing updates');
  // The epoch the plan was built on. A plan built on anything else was built
  // from rows and content that have since changed, and is refused as stale.
  if (!Number.isInteger(msg.expectedEpoch) || msg.expectedEpoch < 1) throw new Error('missing or invalid expectedEpoch');
  const seen = new Set();
  const checkId = (id, where) => {
    if (typeof id !== 'string' || !UUID_RE.test(id)) throw new Error(`${where}: missing or malformed row id`);
    const lower = id.toLowerCase();
    if (seen.has(lower)) throw new Error(`${where}: row ${lower} is named twice`);
    seen.add(lower);
    return lower;
  };
  const updates = msg.updates.map((u, i) => {
    if (!u || typeof u !== 'object') throw new Error(`updates[${i}]: not an object`);
    if (typeof u.encryptedParticipationDataBlob !== 'string') throw new Error(`updates[${i}]: missing encryptedParticipationDataBlob`);
    if (typeof u.encryptedSharedEventKey !== 'string') throw new Error(`updates[${i}]: missing encryptedSharedEventKey`);
    return {
      rowId: checkId(u.eventUserId, `updates[${i}]`),
      sealedRow: blobValue(u.encryptedParticipationDataBlob, 'encryptedParticipationDataBlob', `updates[${i}].encryptedParticipationDataBlob`, { limits }),
      sealedObjectKey: blobValue(u.encryptedSharedEventKey, 'encryptedSharedEventKey', `updates[${i}].encryptedSharedEventKey`, { limits }),
    };
  });
  const removed = msg.removedEventUserIds === undefined ? [] : msg.removedEventUserIds;
  if (!Array.isArray(removed)) throw new Error('removedEventUserIds must be an array');
  const removedRowIds = removed.map((id, i) => checkId(id, `removedEventUserIds[${i}]`));
  return {
    objectId,
    expectedEpoch: msg.expectedEpoch,
    sealedContent: blobField(msg, 'encryptedEventData', { limits }),
    // A rotation re-seals the second tier under a NEW key as well: without
    // that, a removed member keeps the exact second tier of every future
    // edit, permanently, and nothing anywhere fails.
    sealedDetail: blobField(msg, 'encryptedEventDetail', { required: false, limits }),
    readCapabilityHash: hashField(msg.readCapabilityHash, 'readCapabilityHash'),
    // The new admin capability, replaced on every rotation, so a
    // co-owner removed by it cannot carry on with the secret they were given.
    adminCapabilityHash: hashField(msg.adminCapabilityHash, 'adminCapabilityHash'),
    updates,
    removedRowIds,
  };
}

/**
 * Persists a rotation plan: re-seals the content (and the second tier),
 * replaces the read and admin capability hashes, bumps key_epoch by exactly
 * 1, rewrites every remaining row's blob and sealed key to that same new
 * epoch, and marks removed rows 'removed_by_admin' -- the entire revocation
 * mechanism.
 *
 * One transaction, and the plan must be WHOLE:
 *  - the object is locked, the admin capability checked under the lock, and
 *    its epoch must be the one the plan was built on -- two owners rotating
 *    at once cannot both win, the second is told 'stale';
 *  - every active row must be named, once, in `updates` or
 *    `removedEventUserIds`, and nothing else may be -- a row created or
 *    changed after the plan was built would otherwise be left under the old
 *    key or overwritten, silently; the client rebuilds on 'stale';
 *  - an object that has a second tier must be sent a new one. Rotation never
 *    COALESCEs: keeping the old detail sealed under the old key would be the
 *    very leak rotation exists to close.
 * The server increments key_epoch itself, never trusting a client value.
 */
export async function handleRotate(pool, ws, msg, deps) {
  let fields;
  try {
    fields = parseRotateMessage(msg, deps.limits);
  } catch (e) {
    send(ws, { type: 'rotate-event-key-failed', reason: 'invalid', detail: e.message });
    return;
  }
  const adminHash = secretHash(msg.adminCapabilitySecret);
  if (!adminHash) {
    send(ws, { type: 'rotate-event-key-failed', reason: 'unauthorized' });
    return;
  }
  const client = await pool.connect();
  const refuse = async (reason, detail) => {
    await client.query('ROLLBACK');
    send(ws, { type: 'rotate-event-key-failed', reason, ...(detail ? { detail } : {}) });
  };
  try {
    await client.query('BEGIN');
    const ob = await client.query(
      `SELECT key_epoch, sealed_detail IS NOT NULL AS has_detail FROM objects
        WHERE id = $1 AND admin_capability_hash = $2 AND status = 'active' FOR UPDATE`,
      [fields.objectId, adminHash]
    );
    if (ob.rows.length === 0) { await refuse('unauthorized'); return; }
    if (ob.rows[0].key_epoch !== fields.expectedEpoch) { await refuse('stale', 'the object has been re-keyed since this plan was built'); return; }
    if (ob.rows[0].has_detail && !fields.sealedDetail) { await refuse('invalid', 'this object has a second tier, and a rotation must re-seal it'); return; }

    const active = await client.query("SELECT id FROM object_members WHERE object_id = $1 AND status = 'active' FOR UPDATE", [fields.objectId]);
    const activeIds = new Set(active.rows.map((r) => String(r.id).toLowerCase()));
    const named = [...fields.updates.map((u) => u.rowId), ...fields.removedRowIds];
    if (named.length !== activeIds.size || !named.every((id) => activeIds.has(id))) {
      await refuse('stale', 'the plan does not name exactly the rows the object has now');
      return;
    }

    const bumped = await client.query(
      `UPDATE objects SET sealed_content = $1, sealed_detail = $2,
              read_capability_hash = $3, admin_capability_hash = $4, key_epoch = key_epoch + 1
       WHERE id = $5 RETURNING key_epoch`,
      [fields.sealedContent, fields.sealedDetail, fields.readCapabilityHash, fields.adminCapabilityHash, fields.objectId]
    );
    const newKeyEpoch = bumped.rows[0].key_epoch;
    for (const u of fields.updates) {
      await client.query(
        'UPDATE object_members SET sealed_row = $1, sealed_object_key = $2, key_epoch = $3 WHERE id = $4 AND object_id = $5',
        [u.sealedRow, u.sealedObjectKey, newKeyEpoch, u.rowId, fields.objectId]
      );
    }
    for (const removedId of fields.removedRowIds) {
      await client.query("UPDATE object_members SET status = 'removed_by_admin' WHERE id = $1 AND object_id = $2", [removedId, fields.objectId]);
    }
    await client.query('COMMIT');
    send(ws, { type: 'rotate-event-key-ok', keyEpoch: newKeyEpoch });
  } catch {
    await client.query('ROLLBACK').catch(() => {});
    send(ws, { type: 'rotate-event-key-failed', reason: 'server-error' });
  } finally {
    client.release();
  }
}

function parseUpdateMessage(config, msg, limits) {
  const objectId = parseObjectId(msg);
  const c = collectionOf(config, msg.collection);
  if (typeof msg.encryptedEventData !== 'string') throw new Error('missing encryptedEventData');
  // The epoch the content is sealed under. Content sealed under an
  // older key is readable by whoever was removed at the rotation, and by
  // nobody who stayed.
  if (!Number.isInteger(msg.keyEpoch) || msg.keyEpoch < 1) throw new Error('missing or invalid keyEpoch');
  return {
    objectId, collection: c, keyEpoch: msg.keyEpoch,
    selector: parseSelector(c, msg.selector),
    window: parseObjectWindow(c, msg),
    sealedContent: blobField(msg, 'encryptedEventData', { limits }),
    sealedDetail: blobField(msg, 'encryptedEventDetail', { required: false, limits }),
  };
}

/**
 * Content-only edit: re-seals the content, refreshes the selector and window
 * (an object can move), but never touches key_epoch or any member row --
 * nobody's access is being revoked, so there is nothing to re-key.
 */
export async function handleUpdate(pool, ws, msg, deps) {
  let fields;
  try {
    fields = parseUpdateMessage(deps.config, msg, deps.limits);
  } catch (e) {
    send(ws, { type: 'update-event-failed', reason: 'invalid', detail: e.message });
    return;
  }
  if (!(await verifyAdminCapability(pool, fields.objectId, msg.adminCapabilitySecret))) {
    send(ws, { type: 'update-event-failed', reason: 'unauthorized' });
    return;
  }
  try {
    const result = await pool.query(
      // The status filter on the statement as well as in the check above:
      // the two are separate queries, and a host hiding the object between
      // them would otherwise be overwritten. COALESCE on the second tier: an
      // edit by a client that could not open it sends none, and overwriting
      // with NULL would erase it for everyone who had been granted it. And
      // only at the epoch the content was sealed under, never over a newer
      // key's content with an older key's. The collection is fixed at
      // creation: an object never changes kind.
      `UPDATE objects SET sealed_content = $1, sealed_detail = COALESCE($2, sealed_detail),
              selector = $3, window_start = $4, window_end = $5
         WHERE id = $6 AND collection = $7 AND status = 'active' AND key_epoch = $8`,
      [fields.sealedContent, fields.sealedDetail, fields.selector, fields.window.start, fields.window.end, fields.objectId, fields.collection.name, fields.keyEpoch]
    );
    if (result.rowCount === 0) {
      const still = await pool.query("SELECT 1 FROM objects WHERE id = $1 AND collection = $2 AND status = 'active'", [fields.objectId, fields.collection.name]);
      send(ws, { type: 'update-event-failed', reason: still.rows.length ? 'stale' : 'event-not-found' });
      return;
    }
    send(ws, { type: 'update-event-ok' });
  } catch (e) {
    send(ws, { type: 'update-event-failed', reason: e.code === '23514' ? 'invalid-date-range' : 'server-error' });
  }
}

/**
 * Deletes the object outright. Member rows cascade; pointers and share
 * links deliberately carry no object id, so they cannot -- remaining
 * members' pointers go stale and are discarded client-side the next time a
 * fetch cannot find the object.
 */
export async function handleDelete(pool, ws, msg) {
  if (typeof msg.eventId !== 'string' || !UUID_RE.test(msg.eventId)) {
    send(ws, { type: 'delete-event-failed', reason: 'invalid' });
    return;
  }
  if (!(await verifyAdminCapability(pool, msg.eventId, msg.adminCapabilitySecret))) {
    send(ws, { type: 'delete-event-failed', reason: 'unauthorized' });
    return;
  }
  try {
    await pool.query("DELETE FROM objects WHERE id = $1 AND status = 'active'", [msg.eventId]);
    send(ws, { type: 'delete-event-ok' });
  } catch {
    send(ws, { type: 'delete-event-failed', reason: 'server-error' });
  }
}

/**
 * "My own" member row by its row capability secret, not by identity and not
 * by a stored row id. A wrong secret and a real-but-removed row both come
 * back as the same not-found: there is no reason to leak the distinction.
 */
export async function handleFetchMyRow(pool, ws, msg) {
  if (typeof msg.eventId !== 'string' || !UUID_RE.test(msg.eventId) || typeof msg.rowCapabilitySecret !== 'string') {
    send(ws, { type: 'fetch-my-participation-failed', reason: 'invalid' });
    return;
  }
  const hash = secretHash(msg.rowCapabilitySecret);
  if (!hash) { send(ws, { type: 'fetch-my-participation-failed', reason: 'invalid' }); return; }
  try {
    // On an active object only: a hidden object serves nothing, its member
    // rows included (a hidden object is not there on any path, so the row
    // alone is not checked).
    const result = await pool.query(
      `SELECT m.id, m.sealed_row, m.sealed_object_key, m.key_epoch FROM object_members m
         JOIN objects o ON o.id = m.object_id AND o.status = 'active'
        WHERE m.object_id = $1 AND m.row_capability_hash = $2 AND m.status = 'active'`,
      [msg.eventId, hash]
    );
    if (result.rows.length === 0) {
      send(ws, { type: 'fetch-my-participation-failed', reason: 'not-found' });
      return;
    }
    const r = result.rows[0];
    send(ws, {
      type: 'my-participation',
      member: { id: r.id, encryptedParticipationDataBlob: toB64u(r.sealed_row), encryptedSharedEventKey: toB64u(r.sealed_object_key), keyEpoch: r.key_epoch },
    });
  } catch {
    send(ws, { type: 'fetch-my-participation-failed', reason: 'server-error' });
  }
}

/**
 * The first reaction on an object this account held read-only: inserts the
 * member row that redemption deliberately did not create, and overwrites the
 * caller's existing read-only pointer with one carrying the row's brand-new
 * capability secret. One transaction, because a row whose secret never
 * reached the pointer is unreachable forever. Gated by the read capability.
 */
export async function handleCreateMemberRow(pool, ws, routingPublicKey, msg, state, deps) {
  if (!state.hasAccount) {
    send(ws, { type: 'create-participation-failed', reason: 'no-account' });
    return;
  }
  if (typeof msg.eventId !== 'string' || !UUID_RE.test(msg.eventId)) {
    send(ws, { type: 'create-participation-failed', reason: 'invalid' });
    return;
  }
  if (typeof msg.pointerId !== 'string' || !UUID_RE.test(msg.pointerId)) {
    send(ws, { type: 'create-participation-failed', reason: 'invalid', detail: 'missing or malformed pointerId' });
    return;
  }
  let row, pointer;
  try {
    row = parseMemberRowFields(msg.participation, 'participation', deps.limits);
    pointer = parsePointerField(msg.pointer, deps.limits);
  } catch (e) {
    send(ws, { type: 'create-participation-failed', reason: 'invalid', detail: e.message });
    return;
  }
  if (!(await verifyReadCapability(pool, msg.eventId, msg.readCapabilitySecret))) {
    send(ws, { type: 'create-participation-failed', reason: 'unauthorized' });
    return;
  }
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (!(await epochIsCurrent(client, msg.eventId, row.keyEpoch))) throw Object.assign(new Error('stale epoch'), { code: 'stale' });
    await client.query(
      `INSERT INTO object_members (id, object_id, sealed_row, sealed_object_key, row_capability_hash, key_epoch)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [row.rowId, msg.eventId, row.sealedRow, row.sealedObjectKey, row.rowCapabilityHash, row.keyEpoch]
    );
    // Scoped by routing key, so one account can never overwrite another's pointer.
    const updated = await client.query(
      'UPDATE pointers SET sealed_pointer = $1 WHERE id = $2 AND owner_routing_public_key = $3',
      [pointer.sealed, msg.pointerId, routingPublicKey]
    );
    if (updated.rowCount === 0) throw Object.assign(new Error('pointer not found'), { code: 'pointer-not-found' });
    await client.query('COMMIT');
    send(ws, { type: 'create-participation-ok', eventUserId: row.rowId });
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    if (e.code === 'pointer-not-found') send(ws, { type: 'create-participation-failed', reason: 'pointer-not-found' });
    else if (e.code === 'stale') send(ws, { type: 'create-participation-failed', reason: 'stale' });
    else if (e.code === '23503') send(ws, { type: 'create-participation-failed', reason: 'event-not-found' });
    else if (e.code === '23505') send(ws, { type: 'create-participation-failed', reason: 'duplicate-row-id' });
    else send(ws, { type: 'create-participation-failed', reason: 'server-error' });
  } finally {
    client.release();
  }
}

/**
 * Overwrites one of the caller's own member rows -- gated by the row
 * capability secret, not identity, and only at the epoch the row is sealed
 * under, so nothing is written under a key a removed member still holds.
 * Never touches key_epoch or the sealed key: a content edit,
 * not a rotation.
 *
 * `quietPush: true` is a request, not a permission: it sets the
 * transaction-local flag blind_store.quiet_push, which a host's own trigger
 * may read to skip a push notification for a write that should not wake
 * anybody. The engine reads nothing from it; the live watch still fires.
 */
export async function handleUpdateMemberRow(pool, ws, msg, deps) {
  if (typeof msg.eventId !== 'string' || !UUID_RE.test(msg.eventId)
      || typeof msg.rowCapabilitySecret !== 'string'
      || typeof msg.encryptedParticipationDataBlob !== 'string'
      || !Number.isInteger(msg.keyEpoch) || msg.keyEpoch < 1) {
    send(ws, { type: 'update-participation-failed', reason: 'invalid' });
    return;
  }
  let hash, sealedRow;
  try {
    hash = secretHash(msg.rowCapabilitySecret);
    if (!hash) throw new Error('bad secret');
    sealedRow = blobField(msg, 'encryptedParticipationDataBlob', { limits: deps.limits });
  } catch {
    send(ws, { type: 'update-participation-failed', reason: 'invalid' });
    return;
  }
  // On an active object only (as fetch-my-participation): a write to a row
  // of a hidden object is refused as not-found.
  const update = [
    `UPDATE object_members SET sealed_row = $1
      WHERE object_id = $2 AND row_capability_hash = $3 AND status = 'active' AND key_epoch = $4
        AND EXISTS (SELECT 1 FROM objects o WHERE o.id = object_id AND o.status = 'active')`,
    [sealedRow, msg.eventId, hash, msg.keyEpoch],
  ];
  try {
    let result;
    if (msg.quietPush !== true) {
      result = await pool.query(...update);
    } else {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        // `true` is is_local: the setting lasts for this transaction and no
        // longer, so a pooled connection handed to the next caller carries nothing.
        await client.query("SELECT set_config('blind_store.quiet_push', 'on', true)");
        result = await client.query(...update);
        await client.query('COMMIT');
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    }
    if (result.rowCount === 0) {
      // Tell a row that has moved to a newer key from one that is not there:
      // the first is healed and retried by the client, the second is gone.
      const row = await pool.query(
        `SELECT 1 FROM object_members m JOIN objects o ON o.id = m.object_id AND o.status = 'active'
          WHERE m.object_id = $1 AND m.row_capability_hash = $2 AND m.status = 'active'`,
        [msg.eventId, hash]
      );
      send(ws, { type: 'update-participation-failed', reason: row.rows.length ? 'stale' : 'not-found' });
      return;
    }
    send(ws, { type: 'update-participation-ok' });
  } catch {
    send(ws, { type: 'update-participation-failed', reason: 'server-error' });
  }
}

/**
 * Removes the caller's own member row, gated by the row capability secret.
 * Used by the account-deletion sweep; not a "leave" action (leaving is
 * expressed by the row's own content, which other members can see). Not an
 * error when nothing matched: "there is nothing of yours here" is the
 * desired end state.
 */
export async function handleDeleteMemberRow(pool, ws, msg) {
  if (typeof msg.eventId !== 'string' || !UUID_RE.test(msg.eventId) || typeof msg.rowCapabilitySecret !== 'string') {
    send(ws, { type: 'delete-participation-failed', reason: 'invalid' });
    return;
  }
  const hash = secretHash(msg.rowCapabilitySecret);
  if (!hash) { send(ws, { type: 'delete-participation-failed', reason: 'invalid' }); return; }
  try {
    const result = await pool.query('DELETE FROM object_members WHERE object_id = $1 AND row_capability_hash = $2', [msg.eventId, hash]);
    send(ws, { type: 'delete-participation-ok', deleted: result.rowCount > 0 });
  } catch {
    send(ws, { type: 'delete-participation-failed', reason: 'server-error' });
  }
}

// ---------------------------------------------------------------------
// The watches (DESIGN.md §2.3). Validated by the query's own parser, so a
// watch can never accept a selector a query would refuse.
// ---------------------------------------------------------------------

export function handleWatch(live, ws, msg, deps) {
  if (!live) {
    send(ws, { type: 'watch-events-failed', reason: 'unsupported' });
    return;
  }
  let q;
  try {
    q = parseQueryMessage(deps.config, msg, deps.queryLimits);
  } catch (e) {
    send(ws, { type: 'watch-events-failed', reason: 'invalid', detail: e.message });
    return;
  }
  live.setWatch(ws, q);
  send(ws, { type: 'watch-events-ok' });
}

/**
 * THE MESSAGE CARRIES NOTHING, and that is the entire security argument:
 * every client sends the identical empty request, the windows are the
 * server's (a collection's imminentDays), and the client sorts out which of
 * the pushed objects are its own by decrypting them. A version that let the
 * client name its selectors would be handing over the membership graph.
 */
export function handleWatchImminent(live, ws) {
  if (!live) {
    send(ws, { type: 'watch-imminent-failed', reason: 'unsupported' });
    return;
  }
  live.setImminentWatch(ws);
  send(ws, { type: 'watch-imminent-ok' });
}

/** Drops the selector watch only; the imminent watch survives. Idempotent. */
export function handleUnwatch(live, ws) {
  if (live) live.dropWatch(ws);
  send(ws, { type: 'unwatch-events-ok' });
}
