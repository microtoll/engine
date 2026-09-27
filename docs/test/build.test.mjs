// The docs build: every document renders with no construct the renderer
// does not know, every internal link resolves, llms.txt lists every page,
// and the snapshot @microtoll/mcp ships is the one this build produces.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { build, render, inline, PAGES, ROOT } from '../build.mjs';

test('the renderer: the Markdown subset these documents use', () => {
  const r = render('# Title\n\nA *word* and **bold** and `code` and [a link](x.md#y).\n\n- one\n- two\n  - nested\n\n1. first\n2. second\n\n> quoted\n\n| a | b |\n|---|---|\n| 1 | `2` |\n\n```js\nconst x = 1 < 2;\n```\n\n---\n\n## Second\n');
  assert.equal(r.title, 'Title');
  assert.deepEqual(r.headings.map((h) => [h.level, h.id]), [[1, 'title'], [2, 'second']]);
  assert.match(r.html, /<em>word<\/em> and <strong>bold<\/strong> and <code>code<\/code> and <a href="x\.md#y">a link<\/a>/);
  assert.match(r.html, /<ul><li>one<\/li><li>two<ul><li>nested<\/li><\/ul><\/li><\/ul>/);
  assert.match(r.html, /<ol><li>first<\/li><li>second<\/li><\/ol>/);
  assert.match(r.html, /<blockquote><p>quoted<\/p><\/blockquote>/);
  assert.match(r.html, /<th>a<\/th><th>b<\/th>.*<td>1<\/td><td><code>2<\/code><\/td>/);
  assert.match(r.html, /<pre><code class="language-js">const x = 1 &lt; 2;<\/code><\/pre>/);
  assert.match(r.html, /<hr>/);
  assert.deepEqual(r.unknown, []);
  assert.deepEqual(render('<div>raw</div>').unknown, ['line 1: raw HTML']);
  assert.deepEqual(render('```\nnever closed').unknown, ['line 1: unclosed code fence']);
  assert.equal(inline('a <script> b'), 'a &lt;script&gt; b');
  assert.equal(inline('`<b>` stays code'), '<code>&lt;b&gt;</code> stays code');
});

test('every page renders cleanly and every internal link resolves', () => {
  const r = build();
  assert.deepEqual(r.problems, []);
  assert.equal(r.pages.length, PAGES.length);
  for (const p of r.pages) assert.ok(p.title && p.title !== p.path, `${p.source} has no title heading`);
  const llms = r.files.get('llms.txt');
  for (const p of r.pages) assert.ok(llms.includes(`(https://microtoll.dev/${p.path})`), `${p.path} missing from llms.txt`);
  assert.match(llms, /^# Microtoll Engine\n\n> /);
  assert.ok(r.files.get('llms-full.txt').length > 100000);
  for (const [file, text] of r.files) if (file.endsWith('.html')) { assert.match(text, /<!doctype html>/); assert.doesNotMatch(text, /<script/i, `${file} carries script`); }
});

test('the snapshot @microtoll/mcp ships is what this build produces (run `npm run docs` when it is not)', () => {
  const r = build();
  const committed = fs.readFileSync(path.join(ROOT, 'packages', 'mcp', 'generated', 'docs.json'), 'utf8');
  assert.equal(committed, JSON.stringify(r.mcp.docs, null, 1) + '\n', 'packages/mcp/generated/docs.json is stale');
  for (const [name, text] of r.mcp.scaffold) {
    assert.equal(fs.readFileSync(path.join(ROOT, 'packages', 'mcp', 'generated', 'scaffold', 'notes', name), 'utf8'), text, `scaffold template ${name} is stale`);
  }
});
