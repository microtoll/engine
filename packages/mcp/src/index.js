/**
 * @microtoll/mcp — public entry point (D-39). `createMicrotollServer`
 * builds the three tools on the protocol in protocol.js; bin/microtoll-mcp.mjs
 * starts it on stdio.
 */
import { createServer, PROTOCOL_VERSION } from './protocol.js';
import { loadDocs, searchDocs, readDoc, formatSearch } from './docs.js';
import { scaffold, renderScaffold } from './scaffold.js';

export { createServer, PROTOCOL_VERSION, loadDocs, searchDocs, readDoc, formatSearch, scaffold, renderScaffold };

export const VERSION = '0.0.0';

export const INSTRUCTIONS = [
  'Microtoll Engine: sign-in, key handling, access control and revocation for end-to-end-encrypted apps, as packages.',
  'Search the docs before writing security code; never add cryptography beyond what the packages provide; keep the server storing only what it cannot read.',
  'microtoll_scaffold writes the notes starter into an empty directory and runs nothing.',
].join(' ');

export function tools() {
  return [
    {
      name: 'microtoll_search_docs',
      description: 'Full-text search over the Microtoll Engine documentation (the same pages as microtoll.dev, shipped inside this package). Returns pages, sections and excerpts; read a page with microtoll_read_doc.',
      inputSchema: { type: 'object', properties: { query: { type: 'string', description: 'What to look for, in words.' }, limit: { type: 'integer', minimum: 1, maximum: 20, default: 8 } }, required: ['query'] },
      handler: ({ query, limit }) => formatSearch(String(query || ''), searchDocs(String(query || ''), { limit: Number.isInteger(limit) ? Math.min(Math.max(limit, 1), 20) : 8 })),
    },
    {
      name: 'microtoll_read_doc',
      description: 'One documentation page as Markdown: the `path` from a search result (for example "packages/access.html") or from https://microtoll.dev/llms.txt.',
      inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] },
      handler: ({ path }) => {
        const page = readDoc(String(path || ''));
        if (!page) return { text: `No page at "${path}". The index is https://microtoll.dev/llms.txt; paths look like "packages/access.html".`, isError: true };
        return `# ${page.title}\n${page.url}\n\n${page.markdown}`;
      },
    },
    {
      name: 'microtoll_scaffold',
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
