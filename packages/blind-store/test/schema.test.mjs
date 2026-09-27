// The M0 schema rules, checked against the live database (DESIGN.md §4.1,
// D-35). A host runs the same checks against its own extended database:
// `checkSchema(pool, { tables, allow })`.
import test from 'node:test';
import assert from 'node:assert/strict';
import { requireDatabase } from './tooling/db.mjs';

export const ENGINE_TABLES = ['users', 'unlock_methods', 'pointers', 'objects', 'object_members', 'share_links', 'mailbox_drops', 'rate_limit_counters'];

/** The whitelist of keys that are not client-random UUIDs, each justified in the schema file. */
const PK_WHITELIST = {
  users: ['routing_public_key'],            // a random 32-byte value with no identity meaning
  share_links: ['hashed_token'],            // SHA-256 hex of a token that never reaches the server
  rate_limit_counters: ['routing_key', 'action', 'day'],
};
/** Timestamp columns that exist for one functional reason: the sweep. */
const TIMESTAMP_WHITELIST = { share_links: ['expires_at'], mailbox_drops: ['expires_at'] };
/** Date columns: the coarse window, and the counters' day. */
const DATE_WHITELIST = { objects: ['window_start', 'window_end'], rate_limit_counters: ['day'] };
/** The only account-bearing columns: the account's own rows. */
const ACCOUNT_COLUMNS = { unlock_methods: ['owner_routing_public_key'], pointers: ['owner_routing_public_key'], rate_limit_counters: ['routing_key'] };
const IDENTITY_WORDS = /(^|_)(email|phone|mobile|name|first|last|surname|dob|birth|age|gender|ip|addr|address|user_agent|ua|device|created_by|updated_by|owner_id|account_id|user_id|creator|author|sender|recipient|country|city|postcode|lat|lng|lon)(_|$)/;
const HASH_COLUMNS = /_(hash)$/;

export async function checkSchema(pool, { tables = ENGINE_TABLES, allow = {} } = {}) {
  const problems = [];
  const cols = (await pool.query(
    `SELECT table_name, column_name, data_type, column_default, is_nullable
       FROM information_schema.columns WHERE table_schema = 'public' AND table_name = ANY($1) ORDER BY table_name, ordinal_position`, [tables])).rows;
  const pks = (await pool.query(
    `SELECT tc.table_name, kcu.column_name FROM information_schema.table_constraints tc
       JOIN information_schema.key_column_usage kcu ON kcu.constraint_name = tc.constraint_name AND kcu.table_schema = tc.table_schema
      WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = 'public' AND tc.table_name = ANY($1)`, [tables])).rows;
  const fks = (await pool.query(
    `SELECT tc.table_name, kcu.column_name, ccu.table_name AS ref_table FROM information_schema.table_constraints tc
       JOIN information_schema.key_column_usage kcu ON kcu.constraint_name = tc.constraint_name AND kcu.table_schema = tc.table_schema
       JOIN information_schema.constraint_column_usage ccu ON ccu.constraint_name = tc.constraint_name AND ccu.table_schema = tc.table_schema
      WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public' AND tc.table_name = ANY($1)`, [tables])).rows;
  const checks = (await pool.query(
    `SELECT tc.table_name, cc.check_clause FROM information_schema.table_constraints tc
       JOIN information_schema.check_constraints cc ON cc.constraint_name = tc.constraint_name AND cc.constraint_schema = tc.table_schema
      WHERE tc.constraint_type = 'CHECK' AND tc.table_schema = 'public' AND tc.table_name = ANY($1)`, [tables])).rows;
  const present = new Set(cols.map((c) => c.table_name));
  for (const t of tables) if (!present.has(t)) problems.push(`${t}: table missing`);

  for (const t of tables) {
    const pk = pks.filter((p) => p.table_name === t).map((p) => p.column_name);
    const whitelist = (allow.primaryKeys && allow.primaryKeys[t]) || PK_WHITELIST[t];
    if (whitelist) {
      if (pk.slice().sort().join(',') !== whitelist.slice().sort().join(',')) problems.push(`${t}: primary key ${pk} is not the whitelisted ${whitelist}`);
    } else {
      const idCol = cols.find((c) => c.table_name === t && c.column_name === 'id');
      if (pk.join(',') !== 'id' || !idCol || idCol.data_type !== 'uuid' || !/gen_random_uuid\(\)/.test(idCol.column_default || '')) {
        problems.push(`${t}: the primary key must be a random uuid id (gen_random_uuid())`);
      }
    }
  }
  for (const c of cols) {
    const t = c.table_name, n = c.column_name;
    if (/nextval\(|identity/i.test(c.column_default || '')) problems.push(`${t}.${n}: a sequence default`);
    if (/^timestamp/.test(c.data_type) && !((allow.timestamps && allow.timestamps[t]) || TIMESTAMP_WHITELIST[t] || []).includes(n)) problems.push(`${t}.${n}: a timestamp column`);
    if (c.data_type === 'date' && !((allow.dates && allow.dates[t]) || DATE_WHITELIST[t] || []).includes(n)) problems.push(`${t}.${n}: a date column`);
    if (/_at$|^created|^updated|^modified|^last_seen/.test(n)) if (!(TIMESTAMP_WHITELIST[t] || []).includes(n)) problems.push(`${t}.${n}: a time-of-something column`);
    if (IDENTITY_WORDS.test(n) && !/routing/.test(n)) problems.push(`${t}.${n}: an identity-named column`);
    if (/routing/.test(n) && !(t === 'users' && n === 'routing_public_key') && !((ACCOUNT_COLUMNS[t] || []).includes(n))) problems.push(`${t}.${n}: a routing key outside the account's own rows`);
    if (HASH_COLUMNS.test(n)) {
      const guarded = checks.some((k) => k.table_name === t && new RegExp(`octet_length\\(${n}\\)\\s*=\\s*32`).test(k.check_clause));
      if (!guarded) problems.push(`${t}.${n}: no 32-byte CHECK`);
    }
  }
  for (const f of fks) {
    if (f.ref_table === 'users' && !['unlock_methods', 'pointers'].includes(f.table_name)) problems.push(`${f.table_name}.${f.column_name}: references users`);
  }
  return problems;
}

test('the engine schema keeps the M0 rules', async () => {
  const db = await requireDatabase();
  if (!db) return;
  const problems = await checkSchema(db.owner);
  assert.deepEqual(problems, []);
});

test('the checker catches a rule broken in a scratch table (so a green run means something)', async () => {
  const db = await requireDatabase();
  if (!db) return;
  await db.owner.query('DROP TABLE IF EXISTS scratch_bad');
  await db.owner.query(`CREATE TABLE scratch_bad (id SERIAL PRIMARY KEY, email TEXT, created_at TIMESTAMPTZ DEFAULT now(),
    member_routing_public_key BYTEA REFERENCES users(routing_public_key), thing_hash BYTEA)`);
  try {
    const problems = await checkSchema(db.owner, { tables: ['scratch_bad'] });
    const kinds = problems.join('\n');
    assert.match(kinds, /random uuid id/);
    assert.match(kinds, /sequence default/);
    assert.match(kinds, /timestamp column/);
    assert.match(kinds, /identity-named column/);
    assert.match(kinds, /routing key outside/);
    assert.match(kinds, /references users/);
    assert.match(kinds, /no 32-byte CHECK/);
  } finally {
    await db.owner.query('DROP TABLE scratch_bad');
  }
});

test('the service role can read and write its eight tables and run the sweep, and nothing else', async () => {
  const db = await requireDatabase();
  if (!db) return;
  const { default: pg } = await import('pg');
  const app = new pg.Client(db.appConfig);
  await app.connect();
  try {
    for (const t of ENGINE_TABLES) await app.query(`SELECT 1 FROM ${t} LIMIT 1`);
    const n = await app.query('SELECT blind_store_sweep() AS n');
    assert.ok(Number.isInteger(n.rows[0].n));
    await assert.rejects(app.query('CREATE TABLE app_may_not (id INT)'), /permission denied/);
    await assert.rejects(app.query('ALTER TABLE users ADD COLUMN nope INT'), /must be owner/);
    await assert.rejects(app.query("CREATE ROLE nope"), /permission denied/);
    await db.owner.query('CREATE TABLE IF NOT EXISTS host_private (id UUID PRIMARY KEY DEFAULT gen_random_uuid())');
    await assert.rejects(app.query('SELECT 1 FROM host_private'), /permission denied/);
    await db.owner.query('DROP TABLE host_private');
  } finally {
    await app.end();
  }
});
