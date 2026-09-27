/**
 * The daily per-routing-key counters.
 *
 * BE CLEAR ABOUT WHAT THIS BUYS AND WHAT IT COSTS.
 *
 * What it costs: this is the one place the server records a routing key
 * next to an action a person took. It learns that the key did the action --
 * never its object, because nothing here links to any other row, and no
 * other row holds a routing key. THREATMODEL.md §6 lists it as a trade.
 *
 * What it buys: less than it looks like. A guest mints a fresh routing key
 * on every page load, so a daily cap costs one reload to reset. This stops
 * the accidental retry loop and the lazy abuser; it does not stop a
 * motivated one. Written down here rather than left implied, because a
 * limit that looks stronger than it is invites people to rely on it.
 */
import { RATE_LIMIT_DEFAULTS } from './limits.js';

/**
 * createRateLimiter({ limits, log }) -> { consume, clearFor, defineLimits, limits }
 * The engine's three actions come from RATE_LIMIT_DEFAULTS (overridden by
 * `limits`); a host adds its own with defineLimits, once, at load. An action
 * already defined must be defined the same, so two modules cannot quietly
 * disagree about one.
 */
export function createRateLimiter({ limits = {}, log = console } = {}) {
  const table = { ...RATE_LIMIT_DEFAULTS };
  for (const [action, limit] of Object.entries(limits)) {
    if (!Number.isInteger(limit) || limit < 1) throw new Error(`rate limit for ${action} must be a positive integer`);
    table[action] = limit;
  }

  function defineLimits(extra) {
    for (const [action, limit] of Object.entries(extra)) {
      if (!Number.isInteger(limit) || limit < 1) throw new Error(`rate limit for ${action} must be a positive integer`);
      if (action in table && table[action] !== limit) throw new Error(`rate limit for ${action} is already ${table[action]}`);
      table[action] = limit;
    }
  }

  /**
   * Consumes one unit of `action` for this routing key, today.
   *
   * A single statement, so two concurrent connections for the same account
   * cannot both read 9, both write 10, and both be allowed through: INSERT
   * ... ON CONFLICT DO UPDATE increments and returns the post-increment
   * value atomically; the caller compares it against the limit.
   *
   * Fails OPEN on a database error, deliberately. This is a hygiene control,
   * not a security boundary -- the boundaries are the signature, the
   * capability check and the unique indexes, none of which live here --
   * and refusing a real action because a counter table was unavailable
   * would be the wrong failure by a wide margin.
   */
  async function consume(pool, routingPublicKey, action) {
    const limit = table[action];
    if (limit === undefined) throw new Error(`unknown rate-limited action: ${action}`);
    if (!routingPublicKey) return { allowed: true, count: 0, limit };
    try {
      const r = await pool.query(
        `INSERT INTO rate_limit_counters (routing_key, action, day, count)
         VALUES ($1, $2, current_date, 1)
         ON CONFLICT (routing_key, action, day)
         DO UPDATE SET count = rate_limit_counters.count + 1
         RETURNING count`,
        [routingPublicKey, action]
      );
      const count = r.rows[0].count;
      return { allowed: count <= limit, count, limit };
    } catch (e) {
      log.error(`rate limit: counter unavailable, allowing through (${e.code || e.message})`);
      return { allowed: true, count: 0, limit, degraded: true };
    }
  }

  /** Erasure: an account's counters go with it. Called from delete-account. */
  async function clearFor(queryable, routingPublicKey) {
    await queryable.query('DELETE FROM rate_limit_counters WHERE routing_key = $1', [routingPublicKey]);
  }

  return { consume, clearFor, defineLimits, limits: table };
}
