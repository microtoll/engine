# Changelog — @microtoll/mcp

Until 1.0, the API may change in any minor release and every such change is
listed with a migration note (DECISIONS.md D-04).

## 0.1.0 — 2026-09-27

The first release. The publish gate opened on 2026-09-27 (`DECISIONS.md`, D-01); every package is published in lockstep at 0.1.0 (D-41). The formats are frozen from this version (D-04).

### M5 (2026-09-25; D-39)
- The stdio Model Context Protocol server, tools subset, written in (zero
  dependencies): `microtoll_search_docs`, `microtoll_read_doc`,
  `microtoll_scaffold`.
- `generated/docs.json` and `generated/scaffold/notes/`, written by the
  repository's docs build from the same sources as the site.
