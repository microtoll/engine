/**
 * @microtoll/mcp — public entry point (D-39). `createMicrotollServer`
 * builds the three tools on the protocol in protocol.js; bin/microtoll-mcp.mjs
 * starts it on stdio.
 */
import { createRequire } from 'node:module';
import { createServer, PROTOCOL_VERSION } from './protocol.js';
import { loadDocs, searchDocs, readDoc, formatSearch } from './docs.js';
import { scaffold, renderScaffold } from './scaffold.js';

export { createServer, PROTOCOL_VERSION, loadDocs, searchDocs, readDoc, formatSearch, scaffold, renderScaffold };

// The version a host sees in initialize: package.json's, so it never drifts
// (the published 0.1.1 said 0.0.0 from a hard-coded constant).
export const VERSION = createRequire(import.meta.url)('../package.json').version;

export const INSTRUCTIONS = [
  'Microtoll Engine: sign-in, key handling, access control and revocation for end-to-end-encrypted apps, as packages.',
  'Search the docs before writing security code; never add cryptography beyond what the packages provide; keep the server storing only what it cannot read.',
  'microtoll_scaffold writes the notes starter into an empty directory and runs nothing.',
].join(' ');

/**
 * Each tool carries a `title` and `annotations`: the behaviour hints of the
 * Model Context Protocol specification ("ToolAnnotations", the same in
 * versions 2025-06-18, which this server speaks, 2025-11-25 and 2026-07-28).
 * A host may use them to decide whether to ask the person before a call.
 * They are set from what each handler does, and test/annotations.test.mjs
 * checks that behaviour:
 *   readOnlyHint     the tool changes nothing around it
 *   destructiveHint  it may delete or overwrite (false: it only adds)
 *   idempotentHint   a repeat call with the same arguments changes nothing further
 *   openWorldHint    it reaches anything outside, such as the internet (false: it does not)
 * The specification reads destructiveHint and idempotentHint only when
 * readOnlyHint is false. All four are given on every tool anyway, so that a
 * host never falls back on the specification's defaults (may destroy, not
 * idempotent, open world), none of which is true here.
 * The title is given twice on purpose: a host reads `title` first, then
 * `annotations.title` (the specification's order); version 2025-03-26 had
 * only the second.
 */
export function tools() {
  return [
    {
      name: 'microtoll_search_docs',
      title: 'Search the Microtoll Engine documentation',
      description: 'Full-text search over the Microtoll Engine documentation (the same pages as microtoll.dev, shipped inside this package). Returns pages, sections and excerpts; read a page with microtoll_read_doc.',
      inputSchema: { type: 'object', properties: { query: { type: 'string', description: 'What to look for, in words.' }, limit: { type: 'integer', minimum: 1, maximum: 20, default: 8 } }, required: ['query'] },
      // Reads generated/docs.json, inside the package, and nothing else.
      annotations: { title: 'Search the Microtoll Engine documentation', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      handler: ({ query, limit }) => formatSearch(String(query || ''), searchDocs(String(query || ''), { limit: Number.isInteger(limit) ? Math.min(Math.max(limit, 1), 20) : 8 })),
    },
    {
      name: 'microtoll_read_doc',
      title: 'Read a Microtoll Engine documentation page',
      description: 'One documentation page as Markdown: the `path` from a search result (for example "packages/access.html") or from https://microtoll.dev/llms.txt.',
      inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
      // Reads generated/docs.json, inside the package. The page's microtoll.dev
      // address is returned as text and never fetched.
      annotations: { title: 'Read a Microtoll Engine documentation page', readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
      handler: ({ path }) => {
        const page = readDoc(String(path || ''));
        if (!page) return { text: `No page at "${path}". The index is https://microtoll.dev/llms.txt; paths look like "packages/access.html".`, isError: true };
        return `# ${page.title}\n${page.url}\n\n${page.markdown}`;
      },
    },
    {
      name: 'microtoll_scaffold',
      title: 'Create a new app from the notes starter',
      description: 'Writes the notes starter (an end-to-end-encrypted notes app on Microtoll Engine: client, page, Compose file, nginx, README) into an EMPTY directory, with the namespace and origin filled in. Writes files and nothing else: no commands run, no network. The next steps (npm install, docker compose up) are returned for the person to run.',
      inputSchema: {
        type: 'object',
        properties: {
          directory: { type: 'string', description: 'Where to write the app: an empty or not-yet-existing directory.' },
          namespace: { type: 'string', description: 'The app\'s crypto namespace (a-z, 0-9, "-"); used by the client and the server alike. Default "myapp".' },
          origin: { type: 'string', description: 'The web origin the app runs at, for example http://localhost:8088. Default http://localhost:8088.' },
          name: { type: 'string', description: 'The app\'s name (a-z, 0-9, "-"); default: the namespace.' },
        },
        required: ['directory'],
      },
      annotations: {
        title: 'Create a new app from the notes starter',
        readOnlyHint: false,     // it writes files into `directory`
        // Only adds: scaffold.js refuses a directory that is not empty, and
        // writes each file with the 'wx' flag, which fails rather than
        // overwrite a file that appeared in the meantime.
        destructiveHint: false,
        // A repeat call with the same arguments finds the directory no
        // longer empty, is refused, and writes nothing.
        idempotentHint: true,
        // No network and no command run: the templates are inside the package.
        openWorldHint: false,
      },
      handler: (args) => {
        const r = scaffold({ directory: args.directory, namespace: args.namespace || 'myapp', origin: args.origin || 'http://localhost:8088', name: args.name || null });
        return `Wrote ${r.files.length} files into ${r.directory}:\n${r.files.map((f) => `  ${f}`).join('\n')}\n\nNamespace ${r.namespace}, origin ${r.origin}.\n\nNext, for the person to run:\n${r.next.map((s) => `  ${s}`).join('\n')}`;
      },
    },
  ];
}

export function createMicrotollServer() {
  return createServer({ name: 'microtoll', version: VERSION, instructions: INSTRUCTIONS, tools: tools() });
}
