/**
 * Live updates (DESIGN.md §2.3): the object watches, generalised to
 * collections, and the mailbox wake-up, with the LISTEN connection written
 * in (D-36: no pg-listen).
 *
 * WHY ROUTING IS BY SELECTOR. The schema is built so the server cannot know
 * which objects belong to which account: member rows carry no identity and
 * pointers carry no object id. Having clients announce their object ids to
 * subscribe would hand the server exactly that membership graph. So updates
 * are routed by the selector the server ALREADY sees on every query: a
 * client registers that same selector as a standing watch, anything
 * changing inside it is pushed to every connection watching there, and each
 * client keeps what it can decrypt and discards the rest -- the same cover
 * traffic the query relies on. Net new information leaked: none.
 *
 * THE IMMINENT WATCH is a second watch, not a wider first one. The selector
 * watch cannot answer "the thing I am going to tonight just moved, and I am
 * looking elsewhere". So this watch carries NO PARAMETERS: every client
 * sends the identical empty message, the window is the collection's own
 * (`imminentDays`), and what comes back is every change to every object
 * whose window falls inside it, whatever its selector. The cost is
 * bandwidth, bounded by how often objects inside the window are EDITED.
 */
import pg from 'pg';
import { OBJECT_SELECT_ACTIVE, rowToObjectWire } from './objects.js';

export const OBJECT_CHANNEL = 'blind_store_object_live';
export const MAILBOX_CHANNEL = 'blind_store_mailbox_live';

/**
 * One rotation updates object_members once per remaining member, so a
 * single rotation fires the member trigger several times for one object.
 * Without collapsing that, every watcher would get a burst of identical
 * 'participation' messages. Short, because this is a live UI update.
 */
const PARTICIPATION_DEBOUNCE_MS = 250;

/** Server-side 'YYYY-MM-DD', n days out, on UTC: the windows are days wide, so an hours-wide zone offset at the edges cannot matter. */
function isoDayOffset(days, now = Date.now()) {
  const d = new Date(now);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

/**
 * createLive({ pool, collections, connectionConfig, extraChannels, log })
 *   pool              for re-reading a changed row before it is sent
 *   collections       the normalised collection map (objects.js)
 *   connectionConfig  a pg connection config for the LISTEN client; null
 *                     opens no connection (a test drives the handlers)
 *   extraChannels     { channel: (payload) => void } a host wants heard on
 *                     the same connection (for example its own listings)
 */
export function createLive({ pool, collections, connectionConfig = null, extraChannels = {}, debounceMs = PARTICIPATION_DEBOUNCE_MS, log = console } = {}) {
  // ws -> { collection, all, selectors: Set, windowStart, windowEnd }
  const watchers = new Map();
  // Just a set: there is nothing per-connection to remember, which is the point.
  const imminentWatchers = new Set();
  // ws -> Set<mailbox id hex>. Clients send this exact list on every poll;
  // holding it for the connection's lifetime is the same data, not a new class of it.
  const mailboxWatchers = new Map();
  const pendingParticipation = new Map(); // objectId -> Timeout

  /** Replaces (never adds to) this connection's watch: the client re-sends its whole selector on every change, so last-write-wins cannot drift. */
  function setWatch(ws, { collection, all, selectors, windowStart, windowEnd }) {
    watchers.set(ws, { collection: collection.name, all: !!all, selectors: new Set(selectors || []), windowStart, windowEnd });
  }
  function dropWatch(ws) { watchers.delete(ws); }
  function setImminentWatch(ws) { imminentWatchers.add(ws); }
  function setMailboxWatch(ws, mailboxIdsHex) { mailboxWatchers.set(ws, new Set(mailboxIdsHex)); }
  /** Everything, for a closing connection. */
  function removeWatcher(ws) {
    watchers.delete(ws);
    imminentWatchers.delete(ws);
    mailboxWatchers.delete(ws);
  }
  const counts = () => ({ watchers: watchers.size, imminent: imminentWatchers.size, mailbox: mailboxWatchers.size });

  /**
   * The same predicate as the query's WHERE clause, evaluated in JS:
   * collection, selector membership, and a date-range overlap.
   * 'YYYY-MM-DD' strings compare lexicographically in exactly the order the
   * dates do, which is the reason the payload carries them as text.
   */
  function matches(watch, collection, selector, windowStart, windowEnd) {
    if (!selector || watch.collection !== collection) return false;
    if (!watch.all && !watch.selectors.has(selector)) return false;
    const c = collections.get(collection);
    if (!c || !c.window) return true;
    if (!windowStart || !windowEnd) return false;
    return windowStart <= watch.windowEnd && windowEnd >= watch.windowStart;
  }

  /** Date-range overlap with the collection's own short window, computed fresh per notification so a long-lived connection cannot hold yesterday's. */
  function withinImminentWindow(collection, windowStart, windowEnd) {
    const c = collections.get(collection);
    if (!c || c.imminentDays == null || !windowStart || !windowEnd) return false;
    return windowStart <= isoDayOffset(c.imminentDays) && windowEnd >= isoDayOffset(0);
  }

  /**
   * The connections this change concerns -- where the object is now OR where
   * it just was, so a moved object leaves the view it moved off instead of
   * lingering at stale coordinates. A Set: a connection holding both watches
   * is told once.
   */
  function targetsFor(p) {
    const targets = new Set();
    for (const [ws, watch] of watchers) {
      if (ws.readyState !== 1 /* OPEN */) continue;
      if (matches(watch, p.collection, p.selector, p.windowStart, p.windowEnd)
        || matches(watch, p.collection, p.prevSelector, p.prevWindowStart, p.prevWindowEnd)) targets.add(ws);
    }
    if (withinImminentWindow(p.collection, p.windowStart, p.windowEnd) || withinImminentWindow(p.collection, p.prevWindowStart, p.prevWindowEnd)) {
      for (const ws of imminentWatchers) if (ws.readyState === 1) targets.add(ws);
    }
    return [...targets];
  }

  function broadcast(targets, message) {
    const text = JSON.stringify(message);
    for (const ws of targets) {
      try { ws.send(text); } catch { /* died between the readyState check and here; its close handler drops the watch */ }
    }
  }

  /**
   * Re-reads the row rather than trusting the notification to carry content:
   * pg_notify's payload is capped at 8,000 bytes, and re-reading is the only
   * way to be sure watchers get the CURRENT state rather than a snapshot
   * from whichever of several rapid updates fired this notification.
   */
  async function sendObjectRow(targets, kind, objectId) {
    let row;
    try {
      const result = await pool.query(`${OBJECT_SELECT_ACTIVE} id = $1`, [objectId]);
      row = result.rows[0];
    } catch (e) {
      log.error(`live: failed to load a changed object (${e.code || e.message})`);
      return;
    }
    // Created and deleted again before we got here: the delete's own
    // notification is already on its way, so say nothing.
    if (!row) return;
    broadcast(targets, { type: 'event-live', kind, event: rowToObjectWire(row) });
  }

  async function flushParticipation(objectId, p) {
    pendingParticipation.delete(objectId);
    const targets = targetsFor(p);
    if (targets.length === 0) return;
    // Re-check the object's status at FLUSH time, not only at trigger time:
    // the debounce puts up to debounceMs between the two, and a host hiding
    // the object inside that window would otherwise still announce activity
    // on it. Fails CLOSED: silence is the safe direction.
    try {
      const still = await pool.query("SELECT 1 FROM objects WHERE id = $1 AND status = 'active'", [objectId]);
      if (still.rows.length === 0) return;
    } catch (e) {
      log.error(`live: could not re-check an object before flush (${e.code || e.message})`);
      return;
    }
    // Deliberately content-free beyond the id: a changed member row belongs
    // to some member, and which member is precisely what the server does
    // not know and must not start appearing to. A client that cares
    // re-fetches its own row with its own row capability secret.
    broadcast(targets, { type: 'event-live', kind: 'participation', eventId: objectId });
  }

  async function handleObjectNotification(raw) {
    let p;
    try { p = typeof raw === 'string' ? JSON.parse(raw) : raw; } catch { return; }
    if (!p || typeof p.id !== 'string' || typeof p.collection !== 'string') return;
    if (p.kind === 'participation') {
      const existing = pendingParticipation.get(p.id);
      if (existing) clearTimeout(existing);
      const t = setTimeout(() => { flushParticipation(p.id, p).catch((e) => log.error(`live: participation flush failed (${e.message})`)); }, debounceMs);
      if (typeof t.unref === 'function') t.unref();
      pendingParticipation.set(p.id, t);
      return;
    }
    const targets = targetsFor(p);
    if (targets.length === 0) return;
    if (p.kind === 'deleted') {
      broadcast(targets, { type: 'event-live', kind: 'deleted', eventId: p.id });
      return;
    }
    if (p.kind === 'created' || p.kind === 'updated') await sendObjectRow(targets, p.kind, p.id);
  }

  /**
   * A drop landed under some mailbox label. Everyone watching that exact
   * label is told -- in practice exactly one connection. Carries no bundle:
   * the recipient fetches it through the normal poll-invites path, so this
   * is a wake-up, not a delivery mechanism.
   */
  function handleMailboxNotification(raw) {
    const mailboxId = typeof raw === 'string' ? raw.trim() : '';
    if (!mailboxId) return;
    const targets = [];
    for (const [ws, ids] of mailboxWatchers) {
      if (ws.readyState === 1 && ids.has(mailboxId)) targets.push(ws);
    }
    if (targets.length) broadcast(targets, { type: 'invite-live', mailboxId });
  }

  // ------------------------------------------------------------------
  // The LISTEN connection: one dedicated client (a pool connection cannot
  // hold a LISTEN across queries), reconnected with backoff when it drops,
  // and LOUD about it: a server whose live updates are silently off looks
  // exactly like a healthy one, and every cross-session behaviour then
  // quietly proves the opposite of what it seems to.
  // ------------------------------------------------------------------
  const channels = { [OBJECT_CHANNEL]: (raw) => handleObjectNotification(raw).catch((e) => log.error(`live: notification failed (${e.message})`)), [MAILBOX_CHANNEL]: handleMailboxNotification, ...extraChannels };
  let client = null;
  let stopped = false;
  let retryMs = 1000;
  let retryTimer = null;
  let subscribed = false;

  async function connect() {
    if (stopped || !connectionConfig) return;
    const c = new pg.Client(connectionConfig);
    client = c;
    c.on('notification', (n) => {
      const handler = channels[n.channel];
      if (handler) { try { handler(n.payload); } catch (e) { log.error(`live: ${n.channel} handler failed (${e.message})`); } }
    });
    const lost = (why) => {
      if (client !== c) return;
      client = null;
      subscribed = false;
      if (stopped) return;
      log.error(`live: LISTEN connection lost (${why}); live updates are OFF until it reconnects, retrying in ${retryMs / 1000}s`);
      retryTimer = setTimeout(() => { retryMs = Math.min(retryMs * 2, 30000); connect().catch(() => {}); }, retryMs);
      if (typeof retryTimer.unref === 'function') retryTimer.unref();
    };
    c.on('error', (e) => lost(e.code || e.message));
    c.on('end', () => lost('closed'));
    try {
      await c.connect();
      for (const channel of Object.keys(channels)) await c.query(`LISTEN ${channel}`);
      subscribed = true;
      retryMs = 1000;
      log.info(`live: listening on ${Object.keys(channels).join(', ')}`);
    } catch (e) {
      try { await c.end(); } catch { /* never connected */ }
      lost(e.code || e.message);
      throw e;
    }
  }

  /** Resolves once subscribed; rejects on the first failure (the reconnect loop carries on regardless). */
  function start() {
    if (!connectionConfig) return Promise.resolve();
    return connect();
  }

  async function stop() {
    stopped = true;
    if (retryTimer) clearTimeout(retryTimer);
    for (const t of pendingParticipation.values()) clearTimeout(t);
    pendingParticipation.clear();
    watchers.clear(); imminentWatchers.clear(); mailboxWatchers.clear();
    const c = client;
    client = null;
    if (c) { try { await c.end(); } catch { /* already gone */ } }
  }

  return {
    setWatch, dropWatch, setImminentWatch, setMailboxWatch, removeWatcher, counts,
    handleObjectNotification, handleMailboxNotification,
    start, stop, isSubscribed: () => subscribed,
  };
}
