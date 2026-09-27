#!/usr/bin/env node
/**
 * The thin reference server (DESIGN.md §5.2): the library with its options
 * read from the environment, a pool connected as the service role, the live
 * hub, the sweep, /healthz, and a clean stop on SIGTERM. Logs carry counts
 * and reasons, never a message body or a routing key.
 *
 *   BLIND_STORE_NAMESPACE        required; the app's crypto-core namespace
 *   BLIND_STORE_ALLOWED_ORIGINS  required; comma-separated web origins
 *   BLIND_STORE_COLLECTIONS      JSON, e.g. {"notes":{"selectorLength":2}}
 *   BLIND_STORE_PORT             default 8020
 *   BLIND_STORE_HOST             default every interface
 *   BLIND_STORE_LIVE             "off" to run without the live watches
 *   BLIND_STORE_MAX_SOCKETS      overrides the transport default
 *   DB_HOST, DB_PORT, DB_USER, DB_NAME
 *   DB_PASSWORD_FILE             a file holding the password (preferred: never
 *                                in the environment), else DB_PASSWORD
 */
import fs from 'node:fs';
import pg from 'pg';
import { createBlindStore } from '../src/index.js';

const env = process.env;
const fail = (msg) => { console.error(`blind-store: ${msg}`); process.exit(2); };

function dbPassword() {
  // A named file that cannot be read stops the service at start, rather
  // than letting it try an empty password.
  if (env.DB_PASSWORD_FILE) {
    try { return fs.readFileSync(env.DB_PASSWORD_FILE, 'utf8').trim(); } catch (e) { fail(`cannot read DB_PASSWORD_FILE (${e.code || e.message})`); }
  }
  return env.DB_PASSWORD;
}

const connectionConfig = {
  host: env.DB_HOST || '127.0.0.1',
  port: Number(env.DB_PORT || 5432),
  user: env.DB_USER || 'blind_store_app',
  password: dbPassword(),
  database: env.DB_NAME || 'blind_store',
};

let collections = {};
if (env.BLIND_STORE_COLLECTIONS) {
  try { collections = JSON.parse(env.BLIND_STORE_COLLECTIONS); } catch (e) { fail(`BLIND_STORE_COLLECTIONS is not JSON (${e.message})`); }
}
const allowedOrigins = (env.BLIND_STORE_ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
const port = Number(env.BLIND_STORE_PORT || 8020);
const transport = {};
if (env.BLIND_STORE_MAX_SOCKETS) transport.maxSockets = Number(env.BLIND_STORE_MAX_SOCKETS);

const pool = new pg.Pool({ ...connectionConfig, max: 10 });
// A pool error (a dropped idle connection) is an event, not a crash.
pool.on('error', (e) => console.error(`blind-store: pool error (${e.code || e.message})`));

let store;
try {
  store = createBlindStore({
    namespace: env.BLIND_STORE_NAMESPACE,
    allowedOrigins,
    pool,
    port,
    host: env.BLIND_STORE_HOST || undefined,
    collections,
    transport,
    live: env.BLIND_STORE_LIVE === 'off' ? null : { connectionConfig },
  });
} catch (e) {
  fail(e.message);
}
console.log(`blind-store: listening on ws://${env.BLIND_STORE_HOST || '0.0.0.0'}:${port} (namespace ${env.BLIND_STORE_NAMESPACE}; collections: ${Object.keys(collections).join(', ') || 'none'})`);

const stop = () => {
  store.close().then(() => pool.end()).finally(() => process.exit(0));
};
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
