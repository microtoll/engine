// Each tool's title and behaviour hints (the MCP specification's
// "ToolAnnotations", protocol version 2025-06-18) as a host lists them, and
// the behaviour each hint claims, checked against the tools themselves.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createMicrotollServer } from '../src/index.js';

const bin = fileURLToPath(new URL('../bin/microtoll-mcp.mjs', import.meta.url));
const srcDir = fileURLToPath(new URL('../src/', import.meta.url));

// What each tool does, as the hints must say it. A new tool fails the first
// test until its hints are decided and added here.
const EXPECTED = {
  microtoll_search_docs: { title: 'Search the Microtoll Engine documentation', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  microtoll_read_doc: { title: 'Read a Microtoll Engine documentation page', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
  microtoll_scaffold: { title: 'Create a new app from the notes starter', readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false },
};

const server = createMicrotollServer();
let nextId = 1;
const call = async (name, args) => (await server.handle({ jsonrpc: '2.0', id: nextId++, method: 'tools/call', params: { name, arguments: args } })).result;

/** Every file under `dir`, with its contents: what "no further change" is measured against. */
function snapshot(dir) {
  const out = {};
  for (const entry of fs.readdirSync(dir, { recursive: true, withFileTypes: true })) {
    const full = path.join(entry.parentPath, entry.name);
    out[path.relative(dir, full)] = entry.isFile() ? fs.readFileSync(full, 'utf8') : '(directory)';
  }
  return out;
}

/** Runs the server as a host would, with extra Node options; sends `messages`, closes stdin, collects the replies by id. */
function session(nodeOptions, messages) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...nodeOptions, bin], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill(), 10_000);
    child.stdout.setEncoding('utf8').on('data', (c) => { stdout += c; });
    child.stderr.setEncoding('utf8').on('data', (c) => { stderr += c; });
    child.on('error', reject);
    child.on('exit', () => {
      clearTimeout(timer);
      const replies = new Map(stdout.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l)).map((m) => [m.id, m]));
      resolve({ replies, stderr });
    });
    for (const m of messages) child.stdin.write(`${JSON.stringify(m)}\n`);
    child.stdin.end();
  });
}

test('tools/list: every tool has a title and all four behaviour hints, as booleans, with the values its handler warrants', async () => {
  const { result } = await server.handle({ jsonrpc: '2.0', id: nextId++, method: 'tools/list' });
  assert.deepEqual(result.tools.map((t) => t.name).sort(), Object.keys(EXPECTED).sort());
  for (const t of result.tools) {
    const expected = EXPECTED[t.name];
    assert.equal(t.title, expected.title, `${t.name}: title`);
    // Exactly these keys: a misspelt hint ("readonlyHint") would be ignored
    // by a host, which would then fall back on the specification's defaults.
    assert.deepEqual(t.annotations, expected, `${t.name}: annotations`);
    for (const hint of ['readOnlyHint', 'destructiveHint', 'idempotentHint', 'openWorldHint']) {
      assert.equal(typeof t.annotations[hint], 'boolean', `${t.name}: ${hint} is a boolean`);
    }
    assert.ok(!('handler' in t), 'the handler never goes out on the wire');
  }
});

test('readOnlyHint: the two documentation tools answer with every file write forbidden; the scaffold, which writes, is refused in the same conditions', async () => {
  // Node's permission model (--permission) with reading allowed and no
  // --allow-fs-write: any attempt to write a file throws ERR_ACCESS_DENIED,
  // and starting a child process is refused too.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'microtoll-readonly-'));
  const target = path.join(dir, 'app');
  try {
    const { replies, stderr } = await session(['--permission', '--allow-fs-read=*'], [
      { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } } },
      { jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'microtoll_search_docs', arguments: { query: 'recovery code' } } },
      { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'microtoll_read_doc', arguments: { path: 'packages/access.html' } } },
      { jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'microtoll_scaffold', arguments: { directory: target } } },
    ]);
    assert.equal(replies.get(1).result.serverInfo.name, 'microtoll', stderr);
    assert.equal(replies.get(2).result.isError, false, replies.get(2).result.content[0].text);
    assert.match(replies.get(2).result.content[0].text, /packages\/identity/);
    assert.equal(replies.get(3).result.isError, false, replies.get(3).result.content[0].text);
    assert.match(replies.get(3).result.content[0].text, /^# @microtoll\/access/);
    // The control: the scaffold does write, so here it must fail, and leave nothing.
    assert.equal(replies.get(4).result.isError, true);
    assert.match(replies.get(4).result.content[0].text, /ERR_ACCESS_DENIED|Access to this API has been restricted/);
    assert.equal(fs.existsSync(target), false);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('destructiveHint false: the scaffold leaves a directory that is not empty, and a file in its way, exactly as they were', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'microtoll-additive-'));
  try {
    const busy = path.join(dir, 'busy');
    fs.mkdirSync(busy);
    fs.writeFileSync(path.join(busy, 'README.md'), 'the person\'s own file');
    fs.writeFileSync(path.join(dir, 'a-file'), 'not a directory');
    const before = snapshot(dir);
    const intoBusy = await call('microtoll_scaffold', { directory: busy });
    assert.equal(intoBusy.isError, true);
    assert.match(intoBusy.content[0].text, /not empty/);
    const ontoFile = await call('microtoll_scaffold', { directory: path.join(dir, 'a-file') });
    assert.equal(ontoFile.isError, true);
    assert.match(ontoFile.content[0].text, /not a directory/);
    assert.deepEqual(snapshot(dir), before, 'nothing changed, nothing added');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('idempotentHint true: a second scaffold call with the same arguments is refused and changes nothing', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'microtoll-idempotent-'));
  try {
    const args = { directory: path.join(dir, 'app'), namespace: 'acme-notes', origin: 'http://localhost:9000' };
    const first = await call('microtoll_scaffold', args);
    assert.equal(first.isError, false, first.content[0].text);
    const afterOne = snapshot(dir);
    assert.ok(Object.keys(afterOne).length > 1, 'the first call wrote the app');
    const second = await call('microtoll_scaffold', args);
    assert.equal(second.isError, true);
    assert.match(second.content[0].text, /not empty/);
    assert.deepEqual(snapshot(dir), afterOne, 'the same files with the same contents as after one call');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('openWorldHint false: no source file can reach the network or start a program', () => {
  // A tripwire. Node 24's permission model cannot forbid network access, so
  // this reads the code instead: any import beyond these, or a call that
  // could fetch or load more code, means the hints must be decided again.
  const ALLOWED = new Set(['node:fs', 'node:path', 'node:url', 'node:module']);
  const files = [...fs.readdirSync(srcDir).map((f) => path.join(srcDir, f)), bin];
  for (const file of files) {
    const text = fs.readFileSync(file, 'utf8');
    for (const [, specifier] of text.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g)) {
      assert.ok(specifier.startsWith('.') || ALLOWED.has(specifier), `${path.basename(file)} imports ${specifier}: decide openWorldHint and readOnlyHint again`);
    }
    assert.doesNotMatch(text, /\bfetch\s*\(|\bWebSocket\b|\bimport\s*\(|\brequire\s*\(/, `${path.basename(file)}: fetch, a socket, or code loaded at run time`);
  }
});
