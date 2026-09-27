# Changelog — @microtoll/blind-store

Until 1.0, the API may change in any minor release and every such change is
listed with a migration note; the bytes the server stores and the messages
it answers never change meaning once published (DECISIONS.md D-04).

## 0.1.2 — 2026-09-27

`repository` added to package.json: npm refuses a provenance publish without it. 0.1.1 was tagged but never published, because its release run failed on that check; nothing else changed.

## 0.1.1 — 2026-09-27 (tagged, never published)

No change to the code or the formats. Published through the release workflow with npm provenance (launch item 8); 0.1.0 had been published by hand.

## 0.1.0 — 2026-09-27

The first release. The publish gate opened on 2026-09-27 (`DECISIONS.md`, D-01); every package is published in lockstep at 0.1.0 (D-41). The formats are frozen from this version (D-04).

- A test against the real server for the identity package's version-3
  labels (D-47): a name the server moves to another of the account's
  passkeys reads as null. No change to the server: it stores sealed labels
  as opaque bytes.
- Documentation and comments made self-contained; no change to behaviour or formats.

### M4 (2026-09-25)
- The server that holds only what it cannot read: sealed objects in
  collections with a coarse public selector (D-33), and the server half of
  the bound handshake (D-34).
- `createBlindStore` (and `createCore`, another name for it): the WebSocket
  listener, the challenge-response handshake verified against the
  connection's origin, the pre-authentication allow-list, the registry and
  dispatcher, request-id correlation, the transport limits (frame,
  pre-authentication timeout, per-socket bucket, socket cap, origin
  allow-list, per-socket lookups, per-field caps), `/healthz`, the daily
  counters, the hourly sweep and the live hub with its own LISTEN client.
- The handlers: accounts and unlock methods, the identity blob's
  compare-and-swap, pointers (with `delete-pointer`), objects and
  member rows (create, query, fetch, join, members, rotation, own row,
  first reaction, row update, update, delete, row delete), the watches,
  share links, the mailbox's server half, `ping`.
- The schema (`schema/000_blind_store.sql`): eight tables, the sweep, the
  live triggers, the service role `blind_store_app`.
- The thin reference server `bin/blind-store.mjs`; the deployment kit in
  `deploy/`; the example in `examples/notes-app`.
- Tests: the handshake cross-implementation check, the transport limits over
  real sockets, "the server cannot decrypt" (static and, with Postgres, the
  fixture round trip), the schema and role conformance checks, the whole
  protocol driven by the real client packages, the live watches.
