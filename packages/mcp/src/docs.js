/**
 * The docs, as the package ships them: generated/docs.json is written by
 * the repository's docs build (docs/build.mjs) from the same sources as
 * microtoll.dev, so search here and the site never drift. No network: the
 * pages are inside the package.
 */
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

let cache = null;
export function loadDocs(file = new URL('../generated/docs.json', import.meta.url)) {
  if (!cache) cache = JSON.parse(fs.readFileSync(fileURLToPath(file), 'utf8'));
  return cache;
}

const tokenize = (s) => String(s || '').toLowerCase().match(/[a-z0-9][a-z0-9-]*/g) || [];
const stem = (t) => t.replace(/(ings?|ed|es|s)$/, '');

/** The page a `path` names: "packages/access.html", "packages/access", or the full URL. */
export function readDoc(path, docs = loadDocs()) {
  if (typeof path !== 'string' || !path) return null;
  let p = path.trim().replace(/^https?:\/\/microtoll\.dev\//, '').replace(/^\//, '');
  if (!/\.html$/.test(p)) p += '.html';
  const page = docs.find((d) => d.path === p);
  return page ? { path: page.path, url: page.url, title: page.title, description: page.description, markdown: page.markdown } : null;
}

/** The guides and package pages outrank the project pages (contributing, the security policy). */
const SECTION_WEIGHT = { Start: 1.3, Packages: 1.4, 'Examples and deployment': 1.2, 'The honest part': 1.1, 'For agents': 1.1, Project: 0.5 };

/**
 * Full-text search over every page's sections: a term in a heading counts
 * five, in the page title three, each occurrence in the text one (capped),
 * the whole phrase four more; every query term must appear somewhere in the
 * page for it to count; the page's part of the site weights the result.
 */
export function searchDocs(query, { limit = 8, docs = loadDocs() } = {}) {
  const phrase = String(query || '').toLowerCase().trim();
  const terms = [...new Set(tokenize(query).map(stem))].filter((t) => t.length > 1);
  if (terms.length === 0) return [];
  const hits = [];
  for (const page of docs) {
    const pageText = page.markdown.toLowerCase();
    if (!terms.every((t) => pageText.includes(t))) continue;
    const titleTokens = tokenize(page.title).map(stem);
    const weight = SECTION_WEIGHT[page.section] || 1;
    for (const section of page.sections) {
      const heading = section.heading || page.title;
      const headingTokens = tokenize(heading).map(stem);
      const text = section.text.toLowerCase();
      let score = 0;
      for (const t of terms) {
        if (headingTokens.some((h) => h.startsWith(t))) score += 5;
        if (titleTokens.some((h) => h.startsWith(t))) score += 3;
        const n = text.split(t).length - 1;
        score += Math.min(n, 4);
      }
      if (terms.length > 1 && (text.includes(phrase) || heading.toLowerCase().includes(phrase))) score += 4;
      if (score === 0) continue;
      hits.push({ path: page.path, url: page.url, title: page.title, heading, score: Math.round(score * weight * 10) / 10, excerpt: excerpt(section.text, terms) });
    }
  }
  hits.sort((a, b) => b.score - a.score || a.path.localeCompare(b.path));
  return hits.slice(0, limit);
}

function excerpt(text, terms) {
  const lines = text.split('\n').filter((l) => l.trim() && !/^```/.test(l));
  const line = lines.find((l) => terms.some((t) => l.toLowerCase().includes(t))) || lines[0] || '';
  const clean = line.replace(/[#*`>]/g, '').trim();
  return clean.length > 240 ? `${clean.slice(0, 237)}…` : clean;
}

/** The search result as the model reads it. */
export function formatSearch(query, hits) {
  if (hits.length === 0) return `No page mentions "${query}". Try other words, or read https://microtoll.dev/llms.txt for the index.`;
  return hits.map((h, i) => `${i + 1}. ${h.title} — ${h.heading}\n   ${h.url}  (path: ${h.path})\n   ${h.excerpt}`).join('\n\n');
}
