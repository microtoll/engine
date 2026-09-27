# @microtoll/blind-store

The server that holds only what it cannot read. It authenticates a
connection by a signed challenge, authorises writes by capability secrets
rather than identity, indexes sealed objects by a coarse public selector the
app chooses, pushes live changes by that same selector, sweeps what has
expired, and never logs a message body. A **library** with a **thin
reference server** around it: a host app mounts the library and registers
its own handlers beside it; the example app runs the reference server as it
is.

**Status:** published as `@microtoll/blind-store` on npm. Licence AGPL-3.0-only (D-02). Design: `DESIGN.md` (decisions D-33
to D-36). Node 24 or later; Postgres 13 or later.

## What the server sees, in one paragraph

Eight tables (`schema/000_blind_store.sql`): `users` (a routing public key,
a sealed identity blob, a generation counter, a compare-and-swap token),
`unlock_methods` (wrapped root keys under a credential id or a lookup
hash), `pointers` (an account's sealed records that name no object),
`objects` (sealed content and second tier under a collection, a selector,
an optional date window, an epoch and two capability hashes),
`object_members` (sealed rows with no
identity and no reference to `users`), `share_links` (sealed payloads under
the hash of a token that stays in a URL fragment), `mailbox_drops` (sealed
bundles under labels only two parties can compute) and
`rate_limit_counters` (routing key × action × day, the one place a key sits
beside an action). Random UUID keys, no timestamps but two functional
expiries, no identity columns — and a test (`test/schema.test.mjs`) that
fails if any of that changes. `THREATMODEL.md` §6 lists exactly what it
learns anyway.

## Five-minute quickstart (the library)

```js
import pg from 'pg';
import { createBlindStore } from '@microtoll/blind-store';

const pool = new pg.Pool({ host: 'db', user: 'blind_store_app', password, database: 'app' });
const store = createBlindStore({
  namespace: 'myapp',                                  // the same namespace the app gives createCryptoCore
  allowedOrigins: ['https://app.example'],             // browsers elsewhere are refused at upgrade
  pool,
  port: 8020,
  collections: {
    notes:  { selectorLength: 2 },                                             // a shelf; no window
    events: { selectorLength: 5, window: true, allowAll: true, imminentDays: 2 },  // with a date window
  },
  live: { connectionConfig: { host: 'db', user: 'blind_store_app', password, database: 'app' } },
});

// A host's own message, beside the engine's:
store.handle('my-type', async ({ pool, ws, msg, state, routingPublicKey }) => { /* answer with send(ws, {...}) */ });
```

The reference server (`bin/blind-store.mjs`) is the same call with its
options read from the environment; `deploy/` holds a hardened Compose file
and an Nginx sample; `examples/notes-app` runs it unchanged.

## The protocol, briefly

Plain JSON over one WebSocket. The server opens with `challenge`; the client
signs `"<ns>/auth/v2" ‖ 0x00 ‖ SHA-256(origin) ‖ nonce` with its routing key
and sends `auth` (a version-1 signature over the bare nonce is refused: it
bound neither purpose nor origin); `auth-ok` says whether an account exists
and carries the sealed identity blob. Every request carries a `requestId`
that its answer echoes. Before sign-in only `lookup-unlock-method` (three
per socket) and what a host registers with `auth: 'none'` or `'any'` are
answered; anything else closes the socket. After it, an unknown type is
refused by name and never reflected. Message names keep the protocol's
event vocabulary (D-27); the client side of every one is in
`@microtoll/identity` (accounts) and `@microtoll/access` (objects, links,
the query and the watches). The mailbox's server half is here; its client
package is M3b.

Query and fetch replies never carry `adminCapabilityHash`: it would be a
stable per-object token handed to every querier. `delete-pointer` lets a
client discard its own stale pointer. A member-row write carrying
`quietPush: true` sets the transaction-local `blind_store.quiet_push` flag
for a host's own trigger to read.

**The selector query.** `query-events { collection, selectors | all,
windowStart?, windowEnd? }` answers everything active that matches, filtered
by nothing else. The client's obligations, which are what make the model
work: decrypt only what you hold keys for (from your pointers); query the
whole area you show, at a precision you fix; never query by a list of ids.
`fetch-event` by one id exists for redeeming a link and healing a stale
pointer, and is the one read that tells the server which object a routing
key asked about. A query whose answer would exceed `maxQueryRows` (5,000) is
refused as `too-many`; narrow the selector.

**Live watches.** `watch-events` takes the same shape as a standing watch;
changes are routed by the selector they fall in (now, or before a move) and
re-read before sending; a member-row change is pushed content-free and
debounced. `watch-imminent` carries nothing: a collection with
`imminentDays` pushes every change inside the server's own window.

## Limits, all backstops

Frame 4 MiB; sign in within 120 s; 300 messages per socket, refilled 60 a
second; 2,000 sockets; per-field ciphertext caps (`src/limits.js`); links of
at most 200 uses and 400 days; daily counters (20 objects, 20 links, 50
drops per routing key) that fail open. Every one is configurable; every one
fails closed for the connection or request that crosses it and changes
nothing for anyone else — except the counters, where refusing a real action
because a counter table was down would be the wrong failure.

## Tests

`npm test` runs the suites that need no database (the handshake
cross-implementation check, the transport limits over real sockets, "the
server cannot decrypt"). The database-backed suites (the schema and role
checks, the whole protocol, the live watches, the fixture round trip) run
when a Postgres answers at `BLIND_STORE_TEST_DB` (default: the throwaway
container `node scripts/test-db.mjs up` starts on port 15433) and skip with
one line otherwise; in CI they must run.
