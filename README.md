# Microtoll Engine

The security layer of an end-to-end-encrypted app, as packages that give any
app the four things AI-generated apps get wrong: sign-in, key handling, access
control and revocation. The server stores only what it cannot read.

**Status:** 0.1.0, the first release (2026-09-27). Pre-1.0: function names
and options may change between minor versions; the bytes it writes never
will. See `docs/pages/formats-and-stability.md`.

| Package | Licence | What it does |
|---|---|---|
| `@microtoll/crypto-core` | Apache-2.0 | primitives, labelled key derivation, versioned wire formats, hybrid post-quantum seal |
| `@microtoll/identity` | Apache-2.0 | root key, unlock methods, sessions, restore, deletion |
| `@microtoll/access` | Apache-2.0 | sealed sharing, capabilities, links, removal and rotation, two-tier disclosure |
| `@microtoll/blind-store` | AGPL-3.0-only | the reference server library and its Postgres schema |
| `@microtoll/mailbox` | Apache-2.0 | pairwise unlinkable delivery: direct invitations under labels only two people can compute |
| `@microtoll/mcp` | Apache-2.0 | docs search and project scaffolding for AI coding agents (Model Context Protocol) |

Each package carries its own `LICENSE`. Documentation is CC-BY-4.0.

## Documents

- `THREATMODEL.md` — per-package threat models and honest limits.
- `docs/` — the source of microtoll.dev, `llms.txt` and the MCP snapshot
  (`npm run docs`).
- Each package's `FORMATS.md` or `DESIGN.md` — its formats, byte for byte.
- `SECURITY.md`, `CONTRIBUTING.md` — how to report a weakness; the rules and
  the sign-off.

References such as "D-04" in code comments and changelogs are to the
maintainer's decision log, which is kept privately.

## Examples and deployment

- `examples/notes-app` — end-to-end-encrypted notes with sharing and
  revocation on the reference server: `docker compose up`, then
  <http://localhost:8088>.
- `examples/identity-demo` — the identity package on a page against its
  in-process server stand-in.
- `deploy/` — the hardened Compose file, the Dockerfile and the Nginx sample
  for `blind-store`.

## How it was built, and support

The engine was written with Claude Code (Anthropic's coding agent) from a
security design the maintainer wrote and decided; the maintainer read and
accepted every change and recorded every decision with its reasons. The
checks are the ones you can run: the published test vectors (RFC 5869, RFC 8032, RFC 5903, RFC 7914, NIST CAVP, the X-Wing
draft) through the public API, the frozen fixtures, the adversarial suite,
and the threat model written down in `THREATMODEL.md`. An outside security
audit is the next step.

The packages are free and stay free. If they save you work, you can
[sponsor the work on GitHub](https://github.com/sponsors/sealwright).

## Working on it

```
npm install          # TypeScript for the declaration check; ws and pg for blind-store
npm run check        # typecheck + tests (Node >= 24)
npm run db:up        # a throwaway Postgres 17 in Docker for the database-backed suites
```

Tests use Node's built-in `node:test`. The browser packages have no runtime
dependencies; `blind-store` has exactly `ws` and `pg`. The suites that need
a database (blind-store's schema, protocol, live and fixture checks, and the
notes example) run when `npm run db:up` has started one — or a Postgres
answers at `BLIND_STORE_TEST_DB` — and skip with one line otherwise; CI runs
them.
