// The search and the page reader over the shipped snapshot, and the
// scaffold into a temporary directory.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { loadDocs, searchDocs, readDoc, formatSearch, scaffold, renderScaffold } from '../src/index.js';

test('the snapshot holds every page of the site, with sections', () => {
  const docs = loadDocs();
  assert.ok(docs.length >= 20);
  for (const d of docs) { assert.match(d.url, /^https:\/\/microtoll\.dev\//); assert.ok(d.markdown.length > 100); assert.ok(d.sections.length >= 1); assert.ok(d.title); }
  assert.ok(docs.some((d) => d.path === 'index.html'));
});

test('search finds the right pages and ranks headings first; every query term must appear', () => {
  const hits = searchDocs('recovery code');
  assert.ok(hits.length > 0);
  assert.ok(hits.slice(0, 3).some((h) => h.path.startsWith('packages/identity')), JSON.stringify(hits.slice(0, 3)));
  const rotation = searchDocs('rotation');
  assert.ok(rotation.some((h) => h.path.startsWith('packages/access')), JSON.stringify(rotation.map((h) => h.path)));
  assert.deepEqual(searchDocs('zzqqxxnothing'), []);
  assert.deepEqual(searchDocs(''), []);
  assert.match(formatSearch('x', []), /No page mentions/);
  assert.match(formatSearch('recovery code', hits), /path: packages\//);
  assert.ok(searchDocs('server stores only what it cannot read', { limit: 2 }).length <= 2);
});

test('readDoc takes a path, a bare name or the full URL, and answers null for nothing', () => {
  const a = readDoc('packages/access.html');
  assert.equal(a.title, '@microtoll/access');
  assert.equal(readDoc('packages/access').path, 'packages/access.html');
  assert.equal(readDoc('https://microtoll.dev/threat-model.html').path, 'threat-model.html');
  assert.equal(readDoc('nope'), null);
  assert.equal(readDoc(''), null);
});

test('the scaffold: fills the placeholders, refuses a non-empty directory, never overwrites, validates the namespace and origin', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'microtoll-scaffold-'));
  const target = path.join(dir, 'my-notes');
  const r = scaffold({ directory: target, namespace: 'acme-notes', origin: 'http://localhost:9000' });
  assert.deepEqual(r.files.sort(), ['README.md', 'docker-compose.yml', 'index.html', 'nginx.conf', 'notes.js', 'package.json', 'page.js']);
  for (const f of r.files) {
    const text = fs.readFileSync(path.join(target, f), 'utf8');
    assert.doesNotMatch(text, /__[A-Z_]+__/, `${f} still has a placeholder`);
  }
  const compose = fs.readFileSync(path.join(target, 'docker-compose.yml'), 'utf8');
  assert.match(compose, /BLIND_STORE_NAMESPACE=acme-notes/);
  assert.match(compose, /BLIND_STORE_ALLOWED_ORIGINS=http:\/\/localhost:9000/);
  assert.match(compose, /"9000:80"/);
  assert.match(fs.readFileSync(path.join(target, 'page.js'), 'utf8'), /namespace: 'acme-notes'/);
  assert.match(fs.readFileSync(path.join(target, 'nginx.conf'), 'utf8'), /ws:\/\/localhost:9000/);
  assert.match(fs.readFileSync(path.join(target, 'package.json'), 'utf8'), /"name": "acme-notes"/);
  assert.deepEqual(r.next.slice(1, 3), ['npm install', 'docker compose up']);
  assert.throws(() => scaffold({ directory: target, namespace: 'acme-notes' }), /not empty/);
  assert.throws(() => scaffold({ directory: path.join(dir, 'x'), namespace: 'Bad Name' }), /namespace/);
  assert.throws(() => scaffold({ directory: path.join(dir, 'y'), origin: 'localhost:8088' }), /origin/);
  assert.throws(() => scaffold({ directory: path.join(dir, 'z'), origin: 'http://localhost:8088/app' }), /origin/);
  assert.throws(() => scaffold({}), /directory/);
  assert.equal(fs.existsSync(path.join(dir, 'x')), false, 'nothing written on a refusal');
  const https = renderScaffold({ namespace: 'prod', origin: 'https://app.example' });
  assert.match(https.files.find((f) => f.name === 'nginx.conf').text, /wss:\/\/app\.example/);
  assert.match(https.files.find((f) => f.name === 'docker-compose.yml').text, /"443:80"/);
  fs.rmSync(dir, { recursive: true, force: true });
});
