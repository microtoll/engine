// The protocol over a real child process: what a host sends, line by line,
// and what comes back. Also the handler alone, for the edge cases.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer, createMicrotollServer, PROTOCOL_VERSION } from '../src/index.js';

const bin = fileURLToPath(new URL('../bin/microtoll-mcp.mjs', import.meta.url));

/** Spawns the server; `ask(msg)` resolves with the reply that carries its id. */
function host() {
  const child = spawn(process.execPath, [bin], { stdio: ['pipe', 'pipe', 'pipe'] });
  const waiting = new Map();
  const stderr = [];
  let buffer = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    buffer += chunk;
    let nl;
    while ((nl = buffer.indexOf('\n')) >= 0) {
      const line = buffer.slice(0, nl); buffer = buffer.slice(nl + 1);
      if (!line.trim()) continue;
      const m = JSON.parse(line);
      const w = waiting.get(m.id);
      if (w) { waiting.delete(m.id); w(m); }
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (c) => stderr.push(c));
  return {
    send: (msg) => child.stdin.write(`${JSON.stringify(msg)}\n`),
    raw: (text) => child.stdin.write(text),
    ask: (msg) => new Promise((resolve, reject) => { const t = setTimeout(() => reject(new Error(`no reply to ${msg.method}`)), 5000); waiting.set(msg.id, (m) => { clearTimeout(t); resolve(m); }); child.stdin.write(`${JSON.stringify(msg)}\n`); }),
    stderr,
    close: () => new Promise((resolve) => { child.on('exit', resolve); child.stdin.end(); setTimeout(() => child.kill(), 2000); }),
  };
}

test('a host session: initialize, initialized, tools/list, a search, a page, ping; stdout carries only the protocol', async () => {
  const h = host();
  try {
    const init = await h.ask({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } } });
    assert.equal(init.result.protocolVersion, PROTOCOL_VERSION);
    assert.deepEqual(init.result.capabilities, { tools: { listChanged: false } });
    assert.equal(init.result.serverInfo.name, 'microtoll');
    assert.match(init.result.instructions, /never add cryptography/);
    h.send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    const list = await h.ask({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    assert.deepEqual(list.result.tools.map((t) => t.name), ['microtoll_search_docs', 'microtoll_read_doc', 'microtoll_scaffold']);
    for (const t of list.result.tools) { assert.equal(t.inputSchema.type, 'object'); assert.ok(t.description.length > 40); }
    const search = await h.ask({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'microtoll_search_docs', arguments: { query: 'rotation removed member key' } } });
    assert.equal(search.result.isError, false);
    assert.match(search.result.content[0].text, /packages\/access/);
    const page = await h.ask({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'microtoll_read_doc', arguments: { path: 'packages/blind-store.html' } } });
    assert.match(page.result.content[0].text, /^# @microtoll\/blind-store/);
    assert.match(page.result.content[0].text, /holds only what it cannot read/);
    const missing = await h.ask({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'microtoll_read_doc', arguments: { path: 'nope' } } });
    assert.equal(missing.result.isError, true);
    const pong = await h.ask({ jsonrpc: '2.0', id: 6, method: 'ping' });
    assert.deepEqual(pong.result, {});
    const unknown = await h.ask({ jsonrpc: '2.0', id: 7, method: 'resources/list' });
    assert.equal(unknown.error.code, -32601);
    const badTool = await h.ask({ jsonrpc: '2.0', id: 8, method: 'tools/call', params: { name: 'rm-rf', arguments: {} } });
    assert.equal(badTool.error.code, -32602);
    // A parse error answers with id null; the next request is unaffected.
    h.raw('{not json\n');
    const after = await h.ask({ jsonrpc: '2.0', id: 9, method: 'ping' });
    assert.deepEqual(after.result, {});
    assert.equal(h.stderr.join(''), '', 'nothing was logged in a clean session');
  } finally { await h.close(); }
});

test('the handler alone: notifications are silent, a non-object is refused, a throwing tool is a tool error not a protocol error', async () => {
  const boom = createServer({ name: 'x', version: '0', tools: [{ name: 'boom', description: 'd', inputSchema: { type: 'object' }, handler: () => { throw new Error('bang'); } }, { name: 'echo', description: 'd', inputSchema: { type: 'object' }, handler: ({ s }) => ({ text: String(s), isError: false }) }] });
  assert.equal(await boom.handle({ jsonrpc: '2.0', method: 'notifications/cancelled', params: {} }), null);
  assert.equal(await boom.handle({ jsonrpc: '2.0', method: 'anything' }), null, 'a notification for an unknown method is ignored');
  assert.equal((await boom.handle('text')).error.code, -32600);
  assert.equal((await boom.handle({ jsonrpc: '1.0', id: 1, method: 'ping' })).error.code, -32600);
  const r = await boom.handle({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'boom' } });
  assert.equal(r.result.isError, true);
  assert.equal(r.result.content[0].text, 'bang');
  const e = await boom.handle({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'echo', arguments: { s: 'hi' } } });
  assert.deepEqual(e.result, { content: [{ type: 'text', text: 'hi' }], isError: false });
  assert.throws(() => createServer({ name: 'x', version: '0', tools: [{ name: 'bad name!', handler() {} }] }), /not allowed/);
  assert.equal(createMicrotollServer().tools.length, 3);
});
