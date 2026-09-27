# @microtoll/mcp

Microtoll Engine inside your coding tool. A Model Context Protocol server
(over standard input and output) that Claude Code, Cursor and any MCP host
can call for the engine's documentation and for a project scaffold, so an
agent can wire the engine in without leaving the editor — and without
leaving the machine: the pages are inside the package, nothing is fetched,
nothing runs but what is in `src/`.

**Status:** M5; not published (the publish gate, DECISIONS.md D-01).
Apache-2.0. Zero dependencies (D-39). Node 24 or later.

## Add it to a host

```sh
claude mcp add microtoll -- npx -y @microtoll/mcp
```

Any other host takes the same command (`npx -y @microtoll/mcp`) as a stdio
server.

## The three tools

| Tool | What it does |
|---|---|
| `microtoll_search_docs({ query, limit? })` | Full-text search over the documentation — the same pages as microtoll.dev, shipped in `generated/docs.json` by the repository's docs build so they never drift. Returns page, section and excerpt. |
| `microtoll_read_doc({ path })` | One page as Markdown, by the `path` a search result gives (`packages/access.html`) or from `llms.txt`. |
| `microtoll_scaffold({ directory, namespace?, origin?, name? })` | Writes the notes starter into an **empty** directory: `notes.js`, `page.js`, `index.html`, `docker-compose.yml`, `nginx.conf`, `package.json`, `README.md`, with the namespace and origin filled in. Writes files and nothing else; refuses a directory that is not empty; never overwrites. The next steps (`npm install`, `docker compose up`) come back as text for the person to run. |

## What it speaks

JSON-RPC 2.0, one message per line: `initialize` (protocol version
`2025-06-18`, tools capability), `ping`, `tools/list`, `tools/call`;
notifications are acknowledged by silence; a tool's failure is a tool
result with `isError`, a protocol failure a JSON-RPC error. About 120 lines
in `src/protocol.js`, tested against a transcript of what a host sends.

## Tests

`npm test`: the protocol over a real child process, the search and the
page reader over the shipped snapshot, the scaffold into a temporary
directory (placeholders filled, a non-empty directory refused).
