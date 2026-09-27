#!/usr/bin/env node
/**
 * The docs site build (DESIGN-M5 §2, D-38): Markdown from docs/pages/ and
 * the repository's own documents, rendered to static HTML in docs/site/
 * with one stylesheet and no script, plus llms.txt and llms-full.txt for
 * agents, plus the snapshot @microtoll/mcp ships (generated/docs.json and
 * the scaffold templates). Zero dependencies: the renderer below covers the
 * Markdown these documents use, and docs/test/build.test.mjs fails on a
 * construct it does not.
 *
 *   node docs/build.mjs            -> docs/site/, packages/mcp/generated/
 *   node docs/build.mjs --check    -> build to memory and compare with what is on disk
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const SITE_URL = 'https://microtoll.dev/';

/** The pages, in the order the site and llms.txt list them. `source` is repository-relative. */
export const PAGES = [
  { section: 'Start', path: 'index.html', source: 'docs/pages/index.md', description: 'What the engine is, what it is for, and what it is not.' },
  { section: 'Start', path: 'start-here.html', source: 'docs/pages/start-here.md', description: 'From zero to a working end-to-end-encrypted app in one sitting: the example, then the four packages in order.' },
  { section: 'Packages', path: 'packages/crypto-core.html', source: 'packages/crypto-core/README.md', description: 'Primitives, labelled key derivation, versioned wire formats, hybrid post-quantum seal.' },
  { section: 'Packages', path: 'packages/identity.html', source: 'packages/identity/README.md', description: 'Root key, unlock methods (passkey PRF, recovery code), sessions, restore, deletion.' },
  { section: 'Packages', path: 'packages/identity-formats.html', source: 'packages/identity/FORMATS.md', description: 'What the identity layer seals and signs, version 2.' },
  { section: 'Packages', path: 'packages/access.html', source: 'packages/access/README.md', description: 'Sealed sharing, capabilities, share links, removal with key rotation, two-tier disclosure.' },
  { section: 'Packages', path: 'packages/access-formats.html', source: 'packages/access/FORMATS.md', description: 'The object model and what the access layer seals and signs, version 2.' },
  { section: 'Packages', path: 'packages/mailbox.html', source: 'packages/mailbox/README.md', description: 'Direct invitations under mailbox labels only two people can compute.' },
  { section: 'Packages', path: 'packages/mailbox-formats.html', source: 'packages/mailbox/FORMATS.md', description: 'The mailbox label and the version 2 bundle.' },
  { section: 'Packages', path: 'packages/blind-store.html', source: 'packages/blind-store/README.md', description: 'The server that holds only what it cannot read: library, schema, reference server.' },
  { section: 'Packages', path: 'packages/blind-store-design.html', source: 'packages/blind-store/DESIGN.md', description: 'The collection model, the bound handshake, the schema rules, the deployment shape.' },
  { section: 'Packages', path: 'packages/mcp.html', source: 'packages/mcp/README.md', description: 'Docs search and project scaffolding for AI coding agents, over the Model Context Protocol.' },
  { section: 'Examples and deployment', path: 'examples/notes-app.html', source: 'examples/notes-app/README.md', description: 'End-to-end-encrypted notes with sharing and revocation, in ten minutes.' },
  { section: 'Examples and deployment', path: 'examples/invite-app.html', source: 'examples/invite-app/README.md', description: 'Inviting a known person directly, with nothing to forward.' },
  { section: 'Examples and deployment', path: 'deploy.html', source: 'deploy/README.md', description: 'The hardened Compose file, the Dockerfile and the Nginx sample.' },
  { section: 'The honest part', path: 'threat-model.html', source: 'THREATMODEL.md', description: 'Adversaries, global limits, and what each package does and does not protect.' },
  { section: 'The honest part', path: 'honest-limits.html', source: 'docs/pages/honest-limits.md', description: 'What nothing here protects against, on one page.' },
  { section: 'The honest part', path: 'formats-and-stability.html', source: 'docs/pages/formats-and-stability.md', description: 'The promise about bytes, the version numbers, and how a format is allowed to change.' },
  { section: 'For agents', path: 'for-agents.html', source: 'docs/pages/for-agents.md', description: 'llms.txt, the MCP server and the scaffold: wiring the engine in from inside a coding tool.' },
  { section: 'Project', path: 'contributing.html', source: 'CONTRIBUTING.md', description: 'The rules, the sign-off, and what a pull request needs.' },
  { section: 'Project', path: 'security.html', source: 'SECURITY.md', description: 'How to report a weakness and what to expect.' },
  { section: 'Project', path: 'decisions.html', source: 'DECISIONS.md', description: 'The founder\'s decisions: every crypto, licensing and scope choice with its reasoning.' },
];

// ---------------------------------------------------------------------
// The Markdown subset: headings, paragraphs, fenced code, inline code,
// bold, italics with *, links, lists (nested by two spaces), blockquotes,
// tables, horizontal rules. Anything else is reported by `unknown`.
// ---------------------------------------------------------------------

export function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

export function slug(text) {
  return text.toLowerCase().replace(/`/g, '').replace(/[^a-z0-9\s-]/g, '').trim().replace(/\s+/g, '-').slice(0, 80) || 'section';
}

/** Inline Markdown to HTML. `link` rewrites a link target. Links first, since their text may hold code. */
export function inline(text, link = (u) => u) {
  return text.split(/(\[[^\]]+\]\([^)\s]+\))/).map((part) => {
    const m = part.match(/^\[([^\]]+)\]\(([^)\s]+)\)$/);
    if (m) return `<a href="${escapeHtml(link(m[2]))}">${spans(m[1])}</a>`;
    return spans(part);
  }).join('');
}

/** Code spans, bold, italics and bare <https://…> links, on text with no Markdown links in it. */
function spans(text) {
  const out = [];
  for (const part of text.split(/(`[^`]+`)/)) {
    if (part.startsWith('`') && part.endsWith('`') && part.length > 1) { out.push(`<code>${escapeHtml(part.slice(1, -1))}</code>`); continue; }
    let s = escapeHtml(part);
    s = s.replace(/&lt;(https?:\/\/[^&\s]+)&gt;/g, (m, u) => `<a href="${u}">${u}</a>`);
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
    s = s.replace(/(^|[\s(])\*([^*\s][^*]*?)\*(?=[\s).,;:]|$)/g, '$1<em>$2</em>');
    out.push(s);
  }
  return out.join('');
}

/**
 * Renders Markdown to { html, title, headings, unknown } where `headings`
 * is [{ level, text, id }] and `unknown` lists lines the subset does not
 * cover (raw HTML, an unclosed fence).
 */
export function render(markdown, { link = (u) => u } = {}) {
  const lines = markdown.replace(/\r\n/g, '\n').split('\n');
  const html = [];
  const headings = [];
  const unknown = [];
  let title = null;
  let i = 0;
  const paragraph = [];
  const flushParagraph = () => { if (paragraph.length) { html.push(`<p>${inline(paragraph.join(' '), link)}</p>`); paragraph.length = 0; } };

  const renderList = (start, indent) => {
    // Returns [html, nextIndex]; items at exactly `indent` spaces, nested lists deeper.
    const isItem = (l) => /^(\s*)([-*]|\d+\.)\s+/.test(l);
    const indentOf = (l) => l.match(/^(\s*)/)[1].length;
    const first = lines[start];
    const ordered = /^\s*\d+\./.test(first);
    const parts = [`<${ordered ? 'ol' : 'ul'}>`];
    let j = start;
    while (j < lines.length) {
      const l = lines[j];
      if (!l.trim()) { // a blank line ends the list unless the next non-blank line is a deeper item, or an equal one of the same kind
        let k = j + 1; while (k < lines.length && !lines[k].trim()) k++;
        if (k < lines.length && isItem(lines[k]) && (indentOf(lines[k]) > indent || (indentOf(lines[k]) === indent && /^\s*\d+\./.test(lines[k]) === ordered))) { j = k; continue; }
        break;
      }
      if (!isItem(l) || indentOf(l) < indent) {
        // A continuation line of the current item (indented text), or the end.
        if (indentOf(l) > indent && !isItem(l) && parts.length > 1) { parts[parts.length - 1] = parts[parts.length - 1].replace(/<\/li>$/, ` ${inline(l.trim(), link)}</li>`); j++; continue; }
        break;
      }
      if (indentOf(l) > indent) { const [sub, next] = renderList(j, indentOf(l)); parts[parts.length - 1] = parts[parts.length - 1].replace(/<\/li>$/, `${sub}</li>`); j = next; continue; }
      const text = l.replace(/^\s*([-*]|\d+\.)\s+/, '');
      parts.push(`<li>${inline(text, link)}</li>`);
      j++;
    }
    parts.push(`</${ordered ? 'ol' : 'ul'}>`);
    return [parts.join(''), j];
  };

  while (i < lines.length) {
    const line = lines[i];
    if (/^```/.test(line)) {
      flushParagraph();
      const lang = line.slice(3).trim();
      const code = [];
      let j = i + 1;
      while (j < lines.length && !/^```/.test(lines[j])) code.push(lines[j++]);
      if (j >= lines.length) unknown.push(`line ${i + 1}: unclosed code fence`);
      html.push(`<pre><code${lang ? ` class="language-${escapeHtml(lang)}"` : ''}>${escapeHtml(code.join('\n'))}</code></pre>`);
      i = j + 1;
      continue;
    }
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) {
      flushParagraph();
      const level = h[1].length;
      const text = h[2].trim();
      const id = slug(text);
      headings.push({ level, text, id });
      if (level === 1 && title === null) title = text.replace(/`/g, '');
      html.push(`<h${level} id="${id}">${inline(text, link)}</h${level}>`);
      i++;
      continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(line)) {
      flushParagraph();
      const [list, next] = renderList(i, line.match(/^(\s*)/)[1].length);
      html.push(list);
      i = next;
      continue;
    }
    if (/^>/.test(line)) {
      flushParagraph();
      const quote = [];
      while (i < lines.length && /^>/.test(lines[i])) quote.push(lines[i++].replace(/^>\s?/, ''));
      html.push(`<blockquote>${render(quote.join('\n'), { link }).html}</blockquote>`);
      continue;
    }
    if (/^\|/.test(line) && i + 1 < lines.length && /^\|\s*:?-+/.test(lines[i + 1])) {
      flushParagraph();
      const cells = (l) => l.replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
      const head = cells(line);
      const rows = [];
      let j = i + 2;
      while (j < lines.length && /^\|/.test(lines[j])) rows.push(cells(lines[j++]));
      html.push(`<div class="table"><table><thead><tr>${head.map((c) => `<th>${inline(c, link)}</th>`).join('')}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td>${inline(c, link)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
      i = j;
      continue;
    }
    if (/^(-{3,}|\*{3,})\s*$/.test(line)) { flushParagraph(); html.push('<hr>'); i++; continue; }
    // Raw HTML is not rendered (and is reported); an autolink <https://…> at a line's start is not HTML.
    if (/^\s*<[a-zA-Z!/]/.test(line) && !/^\s*<https?:/.test(line)) { unknown.push(`line ${i + 1}: raw HTML`); flushParagraph(); html.push(`<p>${escapeHtml(line)}</p>`); i++; continue; }
    if (!line.trim()) { flushParagraph(); i++; continue; }
    paragraph.push(line.trim());
    i++;
  }
  flushParagraph();
  return { html: html.join('\n'), title, headings, unknown };
}

// ---------------------------------------------------------------------
// The site.
// ---------------------------------------------------------------------

function relative(fromPath, toPath) {
  const up = fromPath.split('/').length - 1;
  return `${'../'.repeat(up)}${toPath}`;
}

/** Rewrites a Markdown link target for a page: repository documents that are pages become their page; the rest stay as written. */
function linkRewriter(page, bySource) {
  return (target) => {
    if (/^(https?:|mailto:|#)/.test(target)) return target;
    const [file, anchor] = target.split('#');
    const sourceDir = path.posix.dirname(page.source);
    const resolved = path.posix.normalize(path.posix.join(sourceDir, file));
    const hit = bySource.get(resolved);
    if (hit) return relative(page.path, hit.path) + (anchor ? `#${anchor}` : '');
    return target;
  };
}

function layout(page, body, pages) {
  const nav = [];
  let section = null;
  for (const p of pages) {
    if (p.section !== section) { section = p.section; nav.push(`<li class="section">${escapeHtml(section)}</li>`); }
    nav.push(`<li${p.path === page.path ? ' class="current"' : ''}><a href="${relative(page.path, p.path)}">${escapeHtml(p.title)}</a></li>`);
  }
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="${escapeHtml(page.description)}">
<title>${escapeHtml(page.title)} — Microtoll Engine</title>
<link rel="stylesheet" href="${relative(page.path, 'style.css')}">
</head>
<body>
<header><a class="home" href="${relative(page.path, 'index.html')}">Microtoll Engine</a> <span class="tag">pre-1.0 · the locks, pre-built</span></header>
<div class="wrap">
<nav><ul>${nav.join('')}</ul></nav>
<main>
${body}
<footer>Documentation is CC-BY-4.0. The browser packages are Apache-2.0; the server is AGPL-3.0-only. <a href="${relative(page.path, 'llms.txt')}">llms.txt</a></footer>
</main>
</div>
</body>
</html>
`;
}

/** Builds everything into memory: { files: Map<sitePath, text>, mcp: { docs, scaffold: Map<name, text> }, problems: [] }. */
export function build() {
  const problems = [];
  const bySource = new Map(PAGES.map((p) => [p.source, p]));
  const pages = PAGES.map((p) => ({ ...p, markdown: fs.readFileSync(path.join(ROOT, p.source), 'utf8') }));
  for (const p of pages) {
    const r = render(p.markdown, { link: linkRewriter(p, bySource) });
    p.title = r.title || p.path;
    p.body = r.html;
    p.headings = r.headings;
    for (const u of r.unknown) problems.push(`${p.source}: ${u}`);
  }
  const files = new Map();
  files.set('style.css', fs.readFileSync(path.join(ROOT, 'docs', 'style.css'), 'utf8'));
  for (const p of pages) files.set(p.path, layout(p, p.body, pages));

  // Every internal link resolves to a page, and every anchor to a heading.
  const known = new Set(pages.map((p) => p.path));
  for (const p of pages) {
    for (const m of p.body.matchAll(/href="([^"]+)"/g)) {
      const href = m[1];
      if (/^(https?:|mailto:)/.test(href)) continue;
      const [file, anchor] = href.split('#');
      if (!file) { if (anchor && !p.headings.some((h) => h.id === anchor)) problems.push(`${p.source}: anchor #${anchor} not found`); continue; }
      const target = path.posix.normalize(path.posix.join(path.posix.dirname(p.path), file));
      if (!known.has(target) && target !== 'llms.txt' && target !== 'style.css') problems.push(`${p.source}: link to ${href} does not resolve to a page`);
    }
  }

  // llms.txt: the index, one line per page; llms-full.txt: every page, Markdown.
  const llms = ['# Microtoll Engine', '', '> The locks, pre-built: sign-in, key handling, access control and revocation for end-to-end-encrypted apps, verified by published test vectors, with the threat model written down. Browser packages with zero dependencies (Apache-2.0) and a reference server (AGPL-3.0-only). Pre-1.0: function names may change; the bytes it writes never will.', ''];
  let section = null;
  for (const p of pages) {
    if (p.section !== section) { section = p.section; llms.push(`## ${section}`, ''); }
    llms.push(`- [${p.title}](${SITE_URL}${p.path}): ${p.description}`);
    if (pages[pages.indexOf(p) + 1]?.section !== section) llms.push('');
  }
  files.set('llms.txt', llms.join('\n').trimEnd() + '\n');
  files.set('llms-full.txt', pages.map((p) => `<!-- ${SITE_URL}${p.path} -->\n${p.markdown.trim()}\n`).join('\n\n'));

  // The snapshot @microtoll/mcp ships: the pages with their sections for search, and the scaffold templates.
  const docs = pages.map((p) => ({
    path: p.path, url: `${SITE_URL}${p.path}`, title: p.title, description: p.description, section: p.section, markdown: p.markdown,
    sections: splitSections(p.markdown),
  }));
  const scaffold = new Map();
  for (const f of fs.readdirSync(path.join(ROOT, 'docs', 'scaffold', 'notes'))) scaffold.set(f, fs.readFileSync(path.join(ROOT, 'docs', 'scaffold', 'notes', f), 'utf8'));
  for (const f of ['notes.js', 'page.js']) scaffold.set(f, fs.readFileSync(path.join(ROOT, 'examples', 'notes-app', f), 'utf8'));
  return { files, pages, mcp: { docs, scaffold }, problems };
}

/** A page's Markdown split at its headings: [{ heading, level, text }]. */
export function splitSections(markdown) {
  const out = [];
  let current = { heading: null, level: 0, text: [] };
  for (const line of markdown.replace(/\r\n/g, '\n').split('\n')) {
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { if (current.heading !== null || current.text.join('').trim()) out.push({ ...current, text: current.text.join('\n').trim() }); current = { heading: h[2].trim().replace(/`/g, ''), level: h[1].length, text: [] }; }
    else current.text.push(line);
  }
  out.push({ ...current, text: current.text.join('\n').trim() });
  return out.filter((s) => s.heading !== null || s.text);
}

export function writeOut(result, { siteDir = path.join(ROOT, 'docs', 'site'), mcpDir = path.join(ROOT, 'packages', 'mcp', 'generated') } = {}) {
  fs.rmSync(siteDir, { recursive: true, force: true });
  for (const [p, text] of result.files) {
    const file = path.join(siteDir, p);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
  }
  fs.mkdirSync(path.join(mcpDir, 'scaffold', 'notes'), { recursive: true });
  fs.writeFileSync(path.join(mcpDir, 'docs.json'), JSON.stringify(result.mcp.docs, null, 1) + '\n');
  for (const [name, text] of result.mcp.scaffold) fs.writeFileSync(path.join(mcpDir, 'scaffold', 'notes', name), text);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const result = build();
  if (result.problems.length) { console.error(result.problems.join('\n')); process.exit(1); }
  if (process.argv.includes('--check')) {
    const committed = fs.readFileSync(path.join(ROOT, 'packages', 'mcp', 'generated', 'docs.json'), 'utf8');
    const fresh = JSON.stringify(result.mcp.docs, null, 1) + '\n';
    if (committed !== fresh) { console.error('packages/mcp/generated/docs.json is stale: run npm run docs'); process.exit(1); }
    console.log('docs: up to date');
  } else {
    writeOut(result);
    console.log(`docs: ${result.files.size} files in docs/site, ${result.mcp.docs.length} pages in packages/mcp/generated/docs.json`);
  }
}
