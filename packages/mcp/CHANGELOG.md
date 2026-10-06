# Changelog — @microtoll/mcp

Until 1.0, the API may change in any minor release and every such change is
listed with a migration note (DECISIONS.md D-04).

## 0.1.3 — 2026-10-06

Each tool now carries a plain `title` and the behaviour hints of the Model Context Protocol specification (`annotations`: `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), which a host may use to decide when to ask the person before a call. Set from what each tool does:

| Tool | Changes anything | Can delete or overwrite | A repeat call changes more | Uses the network |
|---|---|---|---|---|
| `microtoll_search_docs` | no | no | no | no |
| `microtoll_read_doc` | no | no | no | no |
| `microtoll_scaffold` | yes, writes files | no: refuses a directory that is not empty, never overwrites | no: it is refused | no |

The field names and their place were checked against protocol version 2025-06-18, which the server speaks, and against the later versions 2025-11-25 and 2026-07-28, where they are unchanged. `tools/list` now passes `title` and `annotations` through (until now it sent only the name, description and input schema). New tests list the tools and check each one's hints, and check the behaviour behind them: the two documentation tools still answer when Node's permission model forbids every file write; the scaffold leaves a directory that is not empty untouched, and a second call with the same arguments changes nothing; no source file imports anything that could reach the network.

This version also carries 0.1.2's change (the server reports package.json's version). 0.1.2 was withdrawn from npm on 30 September 2026, and npm never lets a withdrawn version number be used again.

## 0.1.2 — 2026-09-27

The server reports package.json's version to a host (0.1.1 said 0.0.0, from a hard-coded constant). `repository` in package.json, which npm requires for a provenance publish. Published through the release workflow with provenance.

## 0.1.1 — 2026-09-27

Metadata only, for the MCP registry listing: `mcpName` (`io.github.microtoll/mcp`) and `repository` in package.json, and `server.json` beside it. Nothing in `src/` changed. A one-off step out of lockstep with the other packages, recorded in DECISIONS.md.

## 0.1.0 — 2026-09-27

The first release. The publish gate opened on 2026-09-27 (`DECISIONS.md`, D-01); every package is published in lockstep at 0.1.0 (D-41). The formats are frozen from this version (D-04).

### M5 (2026-09-25; D-39)
- The stdio Model Context Protocol server, tools subset, written in (zero
  dependencies): `microtoll_search_docs`, `microtoll_read_doc`,
  `microtoll_scaffold`.
- `generated/docs.json` and `generated/scaffold/notes/`, written by the
  repository's docs build from the same sources as the site.
