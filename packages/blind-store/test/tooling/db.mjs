// The database the suites run against, and whether there is one.
//
// BLIND_STORE_TEST_DB is a connection string for the schema OWNER (the
// tests read tables directly to check what was stored); the server under
// test connects as the service role blind_store_app, whose login the
// owner grants here, so a query the role may not run fails in the suite
// (D-35). Default: the throwaway container scripts/test-db.mjs starts.
//
// Without a reachable database the database-backed suites skip with one
// line saying so -- except in CI (CI=true), where a missing database is a
// failure, never a silently green run.
import pg from 'pg';

export const OWNER_URL = process.env.BLIND_STORE_TEST_DB || 'postgres://test:test@127.0.0.1:15433/test';
export const APP_PASSWORD = 'apptest';

let probe = null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
/**
 * Resolves with { owner, appConfig } or null when no database answers. The
 * suites run in parallel, one process per file, so each probes on its own;
 * the service role's login is granted only when it is missing, and a grant
 * that collides with another file's ("tuple concurrently updated") is
 * retried rather than read as "no database".
 */
export function database() {
  if (probe) return probe;
  probe = (async () => {
    const u = new URL(OWNER_URL);
    const appConfig = { host: u.hostname, port: Number(u.port || 5432), database: u.pathname.slice(1), user: 'blind_store_app', password: APP_PASSWORD };
    const owner = new pg.Pool({ connectionString: OWNER_URL, max: 4, connectionTimeoutMillis: 5000 });
    owner.on('error', () => {});
    const gone = async (e) => {
      await owner.end().catch(() => {});
      if (process.env.CI) throw new Error(`CI needs the test database at ${OWNER_URL}: ${e.message}`);
      return null;
    };
    try { await owner.query('SELECT 1'); } catch (e) { return gone(e); }
    for (let attempt = 0; attempt < 8; attempt++) {
      const app = new pg.Client({ ...appConfig, connectionTimeoutMillis: 5000 });
      try {
        await app.connect();
        await app.query('SELECT 1');
        await app.end();
        return { owner, appConfig };
      } catch {
        await app.end().catch(() => {});
        try { await owner.query(`ALTER ROLE blind_store_app LOGIN PASSWORD '${APP_PASSWORD}'`); } catch { /* a parallel file got there first; try the login again */ }
        await sleep(150 * (attempt + 1));
      }
    }
    return gone(new Error('the service role blind_store_app could not log in'));
  })();
  return probe;
}

/** For a suite's top: `const db = await requireDatabase(); if (!db) return;` prints the skip once. */
let said = false;
export async function requireDatabase() {
  const db = await database();
  if (!db && !said) {
    said = true;
    console.log(`# no test database at ${OWNER_URL}: database-backed tests skipped (node scripts/test-db.mjs up)`);
  }
  return db;
}

/** Everything the suites wrote, gone: the tables in dependency order. */
export async function wipe(owner) {
  await owner.query('TRUNCATE users, unlock_methods, pointers, objects, object_members, share_links, mailbox_drops, rate_limit_counters CASCADE');
}
