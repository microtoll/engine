# `@microtoll/blind-store` — design for decision (M4)

Status: **decided**, 2026-09-25 (D-33 to D-36 in `DECISIONS.md`, all four as
recommended). This document is the design the package follows; the README
describes what was built.

## 1. What the package is, in one paragraph

The server the other three packages talk to. It holds only what it cannot
read: sealed blobs, pointer rows that name no object, hashed capabilities and
hashed link tokens. It authenticates a connection by a signed challenge,
authorises writes by capability secrets rather than identity, indexes objects
by a coarse public selector the app chooses, pushes live changes by that same
selector, sweeps what has expired, and never logs a message body. It is a
**library** with a **thin reference server** around it (D-23): a host app
mounts the library and registers its own handlers beside it; the example app
runs the reference server as it is.

## 2. Decision D-33: the collection model (the server half of D-13/D-30)

An object is a sealed record in a named collection, filed under a coarse
public selector and, where the collection has one, a date window: the
server half of the model D-30 set for the client side.

### 2.1 What an object row holds

| Column | Notes |
|---|---|
| `id UUID PK` | client-generated random UUID (the row id is inside what the owner signs) |
| `collection TEXT` | which kind of object; validated by the handler against the configured collections; one accepted low-cardinality plaintext |
| `selector TEXT` | the coarse public selector: fixed length per collection, set by the app; characters `A–Z a–z 0–9 . _ : -` |
| `window_start DATE`, `window_end DATE` | the date window, both set or both null (a collection without a window) |
| `sealed_content BYTEA` | sealed under `K_object` |
| `sealed_detail BYTEA` | the second tier, nullable |
| `key_epoch INT ≥ 1` | bumped by the server on rotation |
| `admin_capability_hash BYTEA(32)` | replaced on every rotation, so a co-owner removed by one cannot carry on with the secret they were given |
| `read_capability_hash BYTEA(32)` | derived from `K_object` by the client |
| `roster_members_only BOOLEAN` | the roster needs a row capability, not the read capability |
| `status TEXT` | `'active'`; the engine never sets anything else — a host that needs to hide an object (a moderation suspension, say) sets another value from its own code, and every engine read path then treats it as not found and every admin action refuses it |

`object_members` holds one row per member (`sealed_row`,
`sealed_object_key`, `row_capability_hash`, `key_epoch`, `status IN
('active','removed_by_admin','left')`). **No identity column and no foreign
key to `users`.** A host adds its own columns in its own init file, as it
may for `users`.

### 2.2 The query, and the cover-traffic obligation

`query-events` (the protocol's message name, D-27/D-30) takes:

```
{ collection, selectors: [ ... ] | all: true, windowStart?, windowEnd? }
```

- `selectors`: 1 to `maxSelectors` (default 10,000) values of the
  collection's fixed length; **`all: true`** is the calendar-view variant
  (the window alone, every selector) and is allowed only where the collection
  is configured `allowAll: true`; the two are mutually exclusive, and an empty
  list is a hard error.
- The window is required when the collection has one, refused when it has
  not; overlap is `window_start <= windowEnd AND window_end >= windowStart`,
  with dates as `YYYY-MM-DD` text both ways (never a JS `Date`, so the
  server's time zone cannot shift a date by a day).
- The answer is every active row matching, and nothing is filtered by
  identity. **The client's obligation**, documented in the README and the
  threat model: decrypt only the rows it holds keys for (from its pointers),
  query the whole area it shows at a fixed precision, never query by a list
  of ids. `fetch-event` by one id stays for redeeming a link and healing a
  stale pointer, and is documented as the path that does tell the server
  which object a routing key asked for.
- **A backstop:** a query whose answer would exceed `maxQueryRows`
  (default 5,000, configurable) is refused with reason `too-many` — closed
  for that request, nothing else affected; the client narrows its selector.
- **Piggy-backing hook:** a collection may supply `queryExtras(pool, query)`
  whose fields ride on the same `events` reply (a host's public listings,
  say), so an app never needs a second request that would reveal intent.

### 2.3 Live watches (D-14: kept)

`watch-events` / `unwatch-events` take the same query shape and are validated
by the same parser; a change to an object or a member row is routed to every
connection whose selector covers where it is now or where it just was,
re-reading the row before sending (the notification payload carries the
selector, never content). A member-row change is pushed as a content-free
`participation` wake-up, debounced 250 ms. `watch-imminent` carries no
parameters: a collection configured with `imminentDays: n` pushes every
change to an object whose window falls within the next `n` days, whatever
its selector — "tonight's plans changed while I was looking elsewhere",
with the server owning the window so there is no parameter to grow a
membership graph through.

### 2.4 The wire

- Selector fields are generic: `collection`, `selector`, `windowStart`,
  `windowEnd`, `rosterMembersOnly`.
- **`adminCapabilityHash` is not sent** in query and fetch replies: it
  would be a stable per-object token handed to every cover-traffic
  recipient. The access package's admin check is the admin box seat, which
  never needed it; `decodeObjectWire` keeps the field as `null`.
- Message names, reply names and reason codes keep the protocol's event
  vocabulary (D-27). The handlers keep a fixed order of checks, one
  transaction per write, epoch guards, completeness on rotation, atomic
  redemption and the link limits.
- The mailbox's server half (`send-invite`, `poll-invites`,
  `consume-invite`, `watch-invites`; the `mailbox_drops` table) is here:
  it has no cryptography. The client package is M3b.

### 2.5 Table names

`users`, `unlock_methods`, `pointers`, `objects`, `object_members`,
`share_links`, `mailbox_drops`, `rate_limit_counters`. A host extends
`users` by `ALTER TABLE` in its own later init file.

## 3. Decision D-34: the bound handshake, server half (D-29), and the transport limits

### 3.1 The verifier

```
message   = UTF-8("<ns>/auth/v2") ‖ 0x00 ‖ SHA-256(UTF-8(origin)) ‖ nonce   (nonce: 32 random bytes per connection)
verify    = Ed25519(routingPublicKey, message, signature)   (Node's crypto.verify; RFC 8037 JWK import)
```

- `namespace` is a required option (no default, as D-05).
- `origin` is the upgrade request's `Origin` header when a browser sent one
  (already checked against the allowed list before the socket exists);
  when there is none (a non-browser client) each allowed origin is tried.
- **No import of `@microtoll/crypto-core`.** The server frames the message
  with `Buffer` and verifies with `node:crypto`; a test proves the framed
  bytes equal `@microtoll/identity`'s `authMessage` and that a signature made
  with Web Crypto verifies here — the cross-implementation test D-29 asks
  for. The server package can then contain no code able to decrypt anything
  (§5.4).
- One nonce, one chance: a wrong signature sends `auth-failed` and closes
  with 1008; a second `auth` on an authenticated connection is an unknown
  type. A version-1 signature over the bare nonce is refused: it bound
  neither purpose nor origin.

### 3.2 Transport limits

| Limit | Default | Fails |
|---|---|---|
| frame size | 4 MiB (`ws` maxPayload) | that socket, 1009 |
| pre-authentication timeout | 120 s | that socket, 1008 |
| messages per socket | token bucket: 300, refilled 60/s | that socket, 1008 |
| open sockets | 2,000 | the new connection, 503 at upgrade |
| `Origin` | must be in `allowedOrigins`; no header allowed | 403 at upgrade |
| `lookup-unlock-method` per socket | 3 (D-20) | `rate-limited` |
| per-field ciphertext caps | the table in `src/limits.js` (identity blob 2 MiB, content 512 KiB, detail 256 KiB, row 64 KiB, pointer 256 KiB, link and mailbox payloads 256 KiB; nested: sealed object key 4 KiB, wrapped root key 1 KiB, label 4 KiB, credential id 1,023 B, salts 256 B) | `invalid`, with the field named |
| share links | `maxUses` ≤ 200, expiry required and ≤ 400 days | `invalid` |
| query answer | `maxQueryRows` 5,000 (§2.2) | `too-many` |
| daily counters | `create-event` 20, `create-url-invite` 20, `send-invite` 50, per routing key per day; **fail open** (a counter outage never refuses a real action); the one place a routing key is written beside an action | `rate-limited` |

All configurable in `createBlindStore({ transport, limits, rateLimits })`;
the defaults, each justified, are in `src/limits.js`. Every limit is a DoS
backstop, not a product rule, and the README says so.

## 4. Decision D-35: schema rules as tests, the sweep, the database role

### 4.1 The rules, checked against a live database

A test reads `information_schema` for the engine's tables and fails on:

- a primary key that is not a client-random UUID, outside the whitelist
  (`users.routing_public_key`, `share_links.hashed_token`,
  `rate_limit_counters` composite);
- any column default using `nextval` or an identity column;
- any `TIMESTAMP`/`TIMESTAMPTZ` column other than `expires_at` on
  `share_links` and `mailbox_drops` (functional: the sweep), and any column
  named `*_at`, `created*`, `updated*`;
- any identity-named column (`email`, `phone`, `name`, `ip`, `address`,
  `user_agent`, `created_by`, `owner_id`, `account_id`, …) — the only
  account-bearing columns are `*routing_public_key` on `unlock_methods` and
  `pointers`, the account's own rows;
- any column on `objects`, `object_members`, `share_links` or
  `mailbox_drops` that references `users`;
- a capability-hash or lookup-hash column without a 32-byte `CHECK`;
- a table in the schema file that is not in the documented list.

The same test is what a host runs against its own extended database.

### 4.2 The sweep (D-19)

`blind_store_sweep()` empties the payload of every share link used up or
past its expiry, deletes a link a week after its expiry, deletes a mailbox
drop once past its expiry, and deletes rate counters older than two days.
The library runs it at start and (`sweep: { intervalMs }`, `false` to leave it to the host) and logs a
count only. Objects past their window are **not** swept — that is the
app's decision; the threat model says what a database copy therefore holds.

### 4.3 The database role

The server never connects as the schema's owner or a superuser, so a
compromised server can touch the engine's tables and nothing else. The
schema creates `blind_store_app` (`NOLOGIN NOSUPERUSER NOCREATEROLE
NOCREATEDB NOREPLICATION`) with exactly the table rights the handlers use and
`EXECUTE` on the sweep; the schema is owned by the deployment's owner role.
The reference server and the tests connect as `blind_store_app`, so a query
the role may not run fails in the suite. The login and password are given
at deployment, never in the schema file: the Compose kit sets them from a
secret file at first start.

## 5. Decision D-36: the library, the reference server, the deployment kit, the example

### 5.1 The library

```js
import { createBlindStore } from '@microtoll/blind-store';
const store = createBlindStore({
  namespace: 'myapp',                       // required: the label prefix the handshake verifies
  pool,                                     // a pg Pool connected as blind_store_app
  port: 8020,                               // listens at creation
  allowedOrigins: ['https://app.example'],
  collections: { notes: { selectorLength: 2 } },     // window: false; or events: { selectorLength: 5, window: true, allowAll: true, imminentDays: 2, queryExtras }
  registration: { columns, onRegister, authOkFields },  // optional host policy (D-17)
  live: { connectionConfig, extraChannels },            // optional: LISTEN for the live watches
  sweep: { intervalMs: 3600_000 },
  transport, limits, rateLimits, httpRoutes, onAuthenticated, onSocketClose, onDeleteAccount, log,
});
store.handle('my-type', handler, { auth: 'required' | 'none' | 'any', needsPool });
store.setFallback(async (ctx) => false);
store.close(cb);
```

`createCore` is exported as an alias of `createBlindStore`. The wire
helpers a host's own handlers share with the engine's (`send`, the
base64url codecs, `blobField`, `hashField`, `hashSecret`, `expiryField`,
the limits, `rateLimit`, `insertPointer`, `parsePointerField`) are
exported as they are.

Dependencies: **`ws` and `pg`, pinned exactly**, nothing else. `pg-listen`
is dropped: the LISTEN connection is a plain `pg` client with a reconnect
loop (about forty lines), and a live hub that cannot subscribe logs loudly
at start and on every retry, because silent live-update failure is worse
than a crash. Ed25519, SHA-256 and random bytes come from `node:crypto`.
Node 24 or later.

### 5.2 The reference server

`packages/blind-store/bin/blind-store.mjs`: reads `BLIND_STORE_NAMESPACE`,
`BLIND_STORE_PORT`, `BLIND_STORE_ALLOWED_ORIGINS`, `BLIND_STORE_COLLECTIONS`
(JSON), `DB_HOST/PORT/USER/NAME` and `DB_PASSWORD_FILE` (a file, never the
environment), creates the pool and the live hub, starts the
sweep, serves `/healthz` (a real `SELECT 1`; 200 or 503, nothing else) and
stops on SIGTERM. Logs carry counts and reasons, never a message body or a
routing key.

### 5.3 The deployment kit (`deploy/`)

- `docker-compose.yml`: `postgres:17` on the internal network only (no host
  port), init from the package's `schema/`, `pg_isready` healthcheck, UTC;
  the server built from `deploy/Dockerfile` (`node:24-alpine`, the workspace
  copied in, `npm ci --omit=dev`), running as `node`, `read_only`, `tmpfs
  /tmp`, `cap_drop: [ALL]`, `no-new-privileges`, a memory limit,
  `depends_on: service_healthy`; the database passwords from files declared
  under `secrets:`, and the application role's login set by an init script
  from its secret at first start.
- `nginx.sample.conf`: TLS 1.2/1.3 with `X25519MLKEM768:X25519:prime256v1`,
  `server_tokens off`, `access_log off`, HSTS, `nosniff`,
  `Referrer-Policy no-referrer`, a strict CSP on every location (re-added
  per location: `add_header` there cancels inheritance), the WebSocket
  upgrade block with `limit_conn`/`limit_req` per address, blanking
  `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, `True-Client-IP`
  and the Cloudflare geo headers so the server never holds an address
  beside a routing key, and `/healthz` ungated with `no-store`.
- Deliberately absent: a superuser connection, running as root, a
  read-write source mount, a public 5432, access logs.

### 5.4 Tests

1. **Without Postgres** (always run): the registry and dispatcher rules, the
   pre-authentication surface, malformed and oversize frames, the token
   bucket, the pre-authentication timeout, origin refusal, every field cap,
   the handshake cross-implementation test (§3.1) — real sockets on
   localhost, `pool: null`.
2. **"The server cannot decrypt"** (always run): the package's runtime
   dependencies are exactly `ws` and `pg`; no `@microtoll/*` package is
   imported at runtime; a scan of `src/` finds no decrypt, decipher, unwrap,
   derive-key, HKDF, AES or private-key identifier; and, with Postgres,
   every sealed fixture from `crypto-core/test/fixtures/frozen-v1.json`
   stored through the server reads back byte-identical.
3. **With Postgres** (`BLIND_STORE_TEST_DB` set, or the throwaway container
   `scripts/test-db.mjs up` starts; CI runs a `postgres:17` service): the
   whole protocol driven by the real client packages — `@microtoll/identity`
   and `@microtoll/access` as devDependencies — covering every core
   message: register, lookup and unlock, the blob's compare-and-swap,
   methods, rotation of the recovery code, sign out everywhere, objects,
   members, pointers, epoch guards, rotation completeness, links made,
   counted, redeemed, exhausted, revoked, the mailbox, live watches, the
   daily caps, deletion, the sweep.
4. **Schema conformance** (§4.1) and **role conformance** (the tests run as
   `blind_store_app`).
5. **The example's integration test**: the notes app's own client module
   driven in Node against the running server.

### 5.5 The example: `examples/notes-app`

End-to-end-encrypted notes with sharing and revocation, small enough to read
in ten minutes, on the reference server unchanged:

- `docker compose up` in `examples/notes-app` starts Postgres, blind-store
  (collection `notes`, a 2-character selector, no window) and nginx serving
  the page and proxying `/ws`; open `http://localhost:8088`.
- Sign up with a recovery code (works in every browser; a passkey is offered
  when the browser has PRF), write a note, share it by link, open the link
  in a private window as a second person, react to become a member, remove
  them as the owner and watch the old key fail to read the next edit.
- **The selector is a random "shelf"** (one of 256), chosen when a note is
  created and kept in the note's pointer (the access package's pointer
  extension): the app asks the server for every note on the shelves it uses
  and decrypts only its own. The README states plainly what the server
  learns (which shelves this routing key reads) and that cover is only as
  deep as the crowd on a shelf — the same honesty the threat model asks of
  any coarse selector.
- The page uses the workspace packages through an import map — the packages
  as they will be published, no build step — since the publish gate is
  closed (D-01).

## 6. What stays out (D-14, confirmed)

Reporting and moderation, the public layer, operator disclosure keys, the
repeat grant, live signals (the transaction-local `blind_store.quiet_push`
flag a host's trigger may read is kept, one line), Web Push, and terms and
age-declaration columns (the registration hook replaces them).

## 7. Threat model §6, to be completed with the package

The accepted trades, each listed: the collection, selector and window per
object; which selectors and windows a connection queried and watched; one
object id per `fetch-event` and per link redemption; routing key × action ×
day in the rate counters; pointer counts and unlock-method counts per
account; the `Origin` and the request sizes and timing; what a database copy
holds until the sweep runs. The database role model; the client
obligations for cover traffic; availability limits.
