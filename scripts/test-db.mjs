#!/usr/bin/env node
/**
 * A throwaway Postgres for the database-backed suites, in Docker:
 *
 *   node scripts/test-db.mjs up      start postgres:17 with the engine schema, on port 15433
 *   node scripts/test-db.mjs down    stop and remove it (its data goes with it)
 *   node scripts/test-db.mjs reset   down, then up
 *   node scripts/test-db.mjs status  is it running?
 *
 * The suites read BLIND_STORE_TEST_DB (a connection string for the schema
 * OWNER) and default to this container's. It is never production. The
 * service role blind_store_app is given its login here (password
 * "apptest"), as the deployment's init script does from a secret file.
 *
 * Git Bash on Windows rewrites a container-side path unless MSYS_NO_PATHCONV
 * is set and the host path is in drive form; this script runs docker with
 * an absolute host path in the form Docker on Windows accepts.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const NAME = 'microtoll-test-pg';
const PORT = 15433;
const IMAGE = 'postgres:17';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const schemaDir = path.join(root, 'packages', 'blind-store', 'schema');
// Docker Desktop on Windows takes C:/... paths; a /c/... Git Bash path is not seen by it.
const hostPath = (p) => p.replace(/\\/g, '/');

const docker = (args, opts = {}) => spawnSync('docker', args, { encoding: 'utf8', env: { ...process.env, MSYS_NO_PATHCONV: '1' }, ...opts });
const running = () => docker(['ps', '--format', '{{.Names}}']).stdout.split('\n').includes(NAME);
const exists = () => docker(['ps', '-a', '--format', '{{.Names}}']).stdout.split('\n').includes(NAME);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function up() {
  if (running()) { console.log(`${NAME} is already running on port ${PORT}`); return; }
  let fresh = true;
  if (exists()) {
    fresh = false;
    console.log(`starting the existing ${NAME}`);
    execFileSync('docker', ['start', NAME], { stdio: 'inherit' });
  } else {
    console.log(`creating ${NAME} (${IMAGE}) on port ${PORT} with the schema from ${schemaDir}`);
    const r = docker(['run', '-d', '--name', NAME, '-p', `${PORT}:5432`,
      '-e', 'POSTGRES_USER=test', '-e', 'POSTGRES_PASSWORD=test', '-e', 'POSTGRES_DB=test', '-e', 'TZ=Etc/UTC', '-e', 'PGTZ=UTC',
      // The schema directory also holds 900_app_login.sh, which gives the service role its login from this.
      '-e', 'BLIND_STORE_APP_PASSWORD=apptest',
      '-v', `${hostPath(schemaDir)}:/docker-entrypoint-initdb.d:ro`, IMAGE]);
    if (r.status !== 0) { console.error(r.stderr || r.stdout); process.exit(1); }
  }
  // The init scripts run against a TEMPORARY server that is then shut down
  // and the real one started, so "ready to accept connections" appears TWICE
  // on a first boot. Wait for the schema, then for the second ready line,
  // then prove the real server answers.
  const wantReady = fresh ? 2 : 1;
  for (let i = 0; i < 120; i++) {
    const ready = docker(['exec', NAME, 'psql', '-U', 'test', '-d', 'test', '-tA', '-c', "select to_regclass('public.objects') is not null"]).stdout.trim();
    const readies = (docker(['logs', NAME]).stderr + docker(['logs', NAME]).stdout).split('database system is ready to accept connections').length - 1;
    if (ready === 't' && readies >= wantReady && docker(['exec', NAME, 'pg_isready', '-U', 'test', '-d', 'test', '-h', '127.0.0.1']).status === 0) {
      // The service role's login, as packages/blind-store/schema/900_app_login.sh gives it from a secret file.
      docker(['exec', NAME, 'psql', '-U', 'test', '-d', 'test', '-qc', "ALTER ROLE blind_store_app LOGIN PASSWORD 'apptest'"]);
      console.log(`ready: postgres://test:test@127.0.0.1:${PORT}/test (service role blind_store_app / apptest)`);
      return;
    }
    await sleep(1000);
  }
  console.error(`${NAME} never came up with the schema -- try: docker logs ${NAME}`);
  process.exit(1);
}

function down() {
  if (exists()) { execFileSync('docker', ['rm', '-f', NAME], { stdio: 'ignore' }); console.log(`${NAME} removed`); } else console.log(`${NAME} is not there`);
}

const cmd = process.argv[2] || 'up';
if (cmd === 'up') await up();
else if (cmd === 'down') down();
else if (cmd === 'reset') { down(); await up(); }
else if (cmd === 'status') console.log(running() ? `${NAME} is running on port ${PORT}` : `${NAME} is not running`);
else { console.log('usage: node scripts/test-db.mjs up|down|reset|status'); process.exit(2); }
