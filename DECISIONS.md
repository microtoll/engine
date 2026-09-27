# DECISIONS.md — founder decisions log

**Append-only.** A decision is recorded by adding a dated entry under
"Recorded"; it is never edited afterwards, only superseded by a later entry
that names it. Open questions sit under "Pending" with a recommendation until
the founder decides. Claude Code never resolves a crypto, licensing or IP
question silently (build plan §4).

Standing rules are in `microtoll-build-plan.md` §0 (the non-negotiables) and
are not repeated here.

**2026-09-27: this log was restated so that it names no other product** (the
founder's direction, recorded below). Each decision keeps its number, its
date and its substance; the earlier wording is in the git history. Two
entries, D-10 and D-22, were not engine decisions and were withdrawn from
this log; their numbers are not reused.

---

## Recorded

**2026-09-27 — Microtoll Engine 0.1.0 is published: six packages on npm,
the signed tag, the site.** The founder published each package by hand
from `D:\PROJECTS\engine-public` in dependency order (crypto-core,
identity, access, mailbox, blind-store, mcp), each with a passkey
approval; verified from the registry by a clean install of all six into an
empty folder, and each one loads. Shasums: crypto-core
`3d82d75f…`, identity `0fdfb9cb…`, access `7e169792…`, mailbox
`04b3c188…`, blind-store `a5041461…`, mcp `66593e8e…`. The signed tag
`v0.1.0` (`d84c7d4`) is on `microtoll/engine` and GitHub verifies it. The
release workflow's first run failed, as expected, on "cannot publish over
a previously published version"; it now skips versions already on the
registry (`engine` `67716d9`); provenance starts with 0.1.1, once trusted
publishing is set on each package. `microtoll.dev` answers over plain
http from GitHub Pages; the certificate for https is being issued. Email
routing for `security@microtoll.dev` is set up on Cloudflare with a strict
DMARC policy (`p=reject`). Launch items done: 1 to 7 and 10; 8 waits for
the next version; 9 for the certificate; 11 (the MCP listing) and 12 (Show
HN, Sponsors) remain. The public repository's CI needs `npm run docs`
before any commit that touches a document the docs snapshot includes; the
first run failed on a stale `packages/mcp/generated/docs.json`.

**2026-09-27 — The engine is public: `microtoll/engine` from a snapshot;
0.1.0 prepared; Pages deployed.** Launch items 5, 6 and 7 (the repository
half): every package is at 0.1.0 without `"private"`, in lockstep (D-41),
274 tests green with the database (`engine-record` `ebd99be`); the
variable `PUBLISH_GATE_OPEN` is `true` on both repositories; the founder
created the public repository `microtoll/engine` from the snapshot at
`engine-record` `2237d37`, one commit `c951b2f` that says where the dated
history is kept, nothing rewritten (D-01). GitHub Pages is enabled on it
from `.github/workflows/pages.yml` with the custom domain `microtoll.dev`,
and the first deployment succeeded; the domain answers once its DNS record
points at `microtoll.github.io` (item 9, the founder's Cloudflare step).
Still to do: the six packages' first publish by hand (item 7's tag, item
8), `security@microtoll.dev` (item 10), the MCP listing (item 11). From
this entry, development continues in the public repository; this private
one is the dated record up to the snapshot and this entry.

**2026-09-27 — `pqc-scan` v0.1.0 tagged and signed; trusted publishing set.**
The founder made the release signing key (`~/.ssh/microtoll-release`,
Ed25519, passphrase-protected; launch item 3), registered its public half
on GitHub as a signing key, and pushed the signed tag `v0.1.0`
(`3e7c05c`), which GitHub verifies as valid. On npm, the package trusts
`release.yml` for **staged** publishing only, npm's recommended setting: a
tag stages a version with provenance and the founder approves it by hand,
so a compromised build run can never publish alone (`pqc-scan` `5414d9d`).
Publishing access requires two-factor authentication with no bypass
tokens. Provenance starts with the next version; 0.1.0 was published by
hand.

**2026-09-27 — `@microtoll/pqc-scan` 0.1.0 is on the npm registry.** The
first public release of anything from this project. Published by the
founder from their own machine (`npm publish --access public`, two-factor
authentication by passkey), from `pqc-scan` `5955777`; shasum
`41000bdca199ed0b115b40e5c483201538741b68`; 22 files, 73.5 kB. Verified from
the registry: `npx @microtoll/pqc-scan --version` prints 0.1.0 and a scan
writes its two reports. The first publish attempt showed that npm removes a
`bin` path written with a leading `./`, which would have left the package
with no command; fixed before publishing. The npm organisation `microtoll`
was already owned by the founder's account (`npm org ls`). Still to do for
this release: trusted publishing on npmjs.com for `release.yml`, the signing
key, and the signed tag `v0.1.0` (the workflow skips a version already
published). Provenance therefore starts with the next version.

**2026-09-27 — `pqc-scan` is public.** `github.com/microtoll/pqc-scan` was
made public at `19eec51` (version 0.1.0, no longer private, a release
workflow that publishes `@microtoll/pqc-scan` with provenance on a `v*`
tag). Its history names no other product. Waiting on the founder: the
signing key (launch item 3), the `@microtoll` npm organisation with trusted
publishing for this workflow (item 4), and then the signed tag `v0.1.0`,
which publishes. The engine stays private until its own launch items.

**2026-09-27 — D-01 passed: the publish gate is OPEN. M6 accepted.** The
founder confirmed, through the question tool, that both checks of D-01 have
passed: who owns the code the engine is built from, and what the founder's
employment terms require. Recorded on the founder's word; the evidence and
any approval that was needed stay in the founder's private notes, outside
this repository. From this entry, a public repository, a registry and a
public listing are allowed for both the engine and `pqc-scan`; the launch
checklist (`docs/LAUNCH.md`) governs the order. The history is still never
rewritten. **M6 is accepted** on the same day: the founder ran the scanner
on their own application from a fresh clone on a Windows PC and read the
report, which completes the last acceptance item (the founder's reading);
that run also led to the terminal default, `--test-files` and the Windows
launcher (`pqc-scan` `6fac933`). The founder's choice for the first public
step: `pqc-scan` goes public and to npm together, as `@microtoll/pqc-scan`
0.1.0.

**2026-09-27 — M6: the three public repositories reviewed by hand; the
scanner corrected.** The founder asked for three to be proposed and run.
Chosen for three shapes, each a shallow clone read once: a JSON Web Token
library where every finding should be genuine (`panva/jose` at `55c959f`), a
large browser application with almost no cryptography (`excalidraw/excalidraw`
at `84e3f5a`), and a server application with a typical sign-in stack
(`requarks/wiki` at `712a3a5`). Every reported finding was a genuine
cryptographic use, and a hand search of jose's source and of Excalidraw
found nothing missed. Seven faults around the findings were found, each
fixed in `pqc-scan` with a fixture and a test (its `DESIGN.md` §8.12):
dependency versions printed as `\1.0.6` (an invalid Markdown escape, in
every report with a lockfile); a package listed as a transitive dependency of
itself (jose; the engine's own report had likewise listed
`@microtoll/crypto-core`); `test-d` type tests not marked as test code; two
"could not be read" pointers that led only to token decoding and header
extraction; the RSA key pair that signs Wiki.js's tokens reported High under
the comment "Generate certificates" (a certificate is a signing artefact:
Medium); Wiki.js's SAML sign-in, encrypted assertions and two-factor codes
unreported because their libraries were not catalogued (eight packages
added, 57 in all); and the SHA-1 note, which told both applications to
replace a plain content identifier as if it protected something. 50 tests
pass. The engine's own report is unchanged apart from its dependency line
(its own package is not a dependency). The reports, before and after, are in
the founder's private acceptance notes. Still open for M6: the founder's
reading of the reports (the engine's, the second application's and these
three), which is the acceptance.

**2026-09-27 — M6: the second application scanned; the public repository
will start from a snapshot.** Two founder's choices.
- **The second real application** (DESIGN §6, second item) was chosen by the
  founder and scanned read-only; the report and the hand review are in the
  founder's private notes, because they describe that application. Every
  expectation of the item was met. The review found two scanner faults,
  fixed in `pqc-scan` `ab5332f` with a fixture and a test each: a WebAuthn
  key reported High (it only verifies signatures: Medium), and a source file
  skipped as binary because of a raw control character far down (binary now
  means a NUL in the first 8,000 bytes). The first item still passes on this
  repository. Still open for M6: three public repositories for the
  false-positive review, and the founder's reading of both reports.
- **At the publish gate**, this repository stays private as the dated
  record, and the public repository starts from a snapshot of the tree, with
  a first commit that says where the private history is kept. Nothing is
  rewritten (D-01's evidence rule). `docs/LAUNCH.md` item 7 says so.

**2026-09-27 — D-46 and D-47 decided: option (a) of each, version 3.** The
founder's choice, and built the same day.
- **D-46:** new recovery codes are version 3. The check character is
  Σ aⁱ⁺¹·sᵢ over the 26 data characters in GF(32) = GF(2)[x]/(x⁵ + x² + 1),
  a = x, and the parser refuses a code whose two unused bits are not zero or
  that has more than 26 data characters. Tests prove every single wrong
  character and every swap of two different characters is refused.
- **D-47:** an unlock method's sealed label is bound to that method:
  `frameContext("<ns>/aad/unlock-label/v3", methodType, SHA-256(credentialId))`
  for a passkey, the method type alone for the recovery code. A test against
  the real server swaps two passkeys' labels in the database and both read
  as null.
- **How version 2 stays readable** (the reading of both decisions, written
  down here so that it is not silent): a version-2 code has the same shape
  as a version-3 one, and a label carries no version byte, so neither can be
  recognised by looking at it. Trying version 2 whenever version 3 fails
  would give back exactly what version 3 closes (a mistyped code accepted as
  version 2 one time in 32; a label moved between methods opening as
  version 2). Version 2 is therefore read only when a caller names it:
  `{ version: 2 }` in crypto-core, `{ recoveryCodeVersion: 2 }` and
  `openMethodLabelV2` in identity. Nothing writes version 2. No version-2
  code or label existed outside tests.
- Every earlier frozen fixture still opens; the version-3 bytes are frozen
  beside them (`crypto-core/test/fixtures/frozen-recovery-v3.json`,
  `identity/test/fixtures/frozen-v3.json`).

**2026-09-27 — M6 built; its acceptance waits on the founder.** `pqc-scan`
is built in its own repository (`D:\PROJECTS\pqc-scan`, commit `3680f12`,
no remote): the detectors, the JSON report (schema version 1) and the
Markdown report, the command line and the composite GitHub Action; 47 tests
pass on Node 20 and 24. The details settled while building are that
repository's `DESIGN.md` §8.9–§8.11. The first acceptance item passes: on
this repository it finds AES-256-GCM, HKDF-SHA-256, PBKDF2 at 310,000
iterations, SHA-256, Ed25519 (Medium), the P-256 ECDH seal (High), the
hybrid `MLKEM768-X25519` (post-quantum), the server's `node:crypto` verify
and hash, and `deploy/nginx.sample.conf` as hybrid-enabled. The other items
need the founder's choices: a second real application, and three public
repositories for the false-positive review. Also since the entries below:
`identity`, `access` and `mailbox` carry frozen version-2 fixtures (commit
`e7a4d59`, 265 tests); no format changed.

**2026-09-27 — D-42, D-43, D-44, D-45 decided: `pqc-scan` as designed
(`docs/DESIGN-M6-pqc-scan.md`).** The founder directed that the build be
completed as far as possible without further questions, which takes each
recommended option: D-42 (a) its own repository `D:\PROJECTS\pqc-scan`, npm
`@microtoll/pqc-scan`, binary `pqc-scan`, Apache-2.0, Node 20 or later,
zero runtime dependencies; D-43 (a) a tokenizer with call-site patterns;
D-44 (a) JSON schema v1 and NCSC-shaped Markdown; D-45 (a) a composite
GitHub Action, the JSON schema as the only seam for a hosted report, nothing
paid built. Crypto decisions are not covered by that direction and stay
pending (D-46, D-47).

**2026-09-27 — The repository is self-contained; a private GitHub remote is
allowed.** The founder's direction: nothing in the engine's code, tests or
documentation names another product, its files, documents or versions.
Notes that need them are kept outside the repository. The git history is
not rewritten (it is part of the ownership record, D-01). The repository is
pushed to a **private** GitHub repository; the publish gate (D-01) still
closes every public repository, registry and listing. The frozen fixtures
are now written by the engine itself under the test namespace `example`
(`packages/crypto-core/test/fixtures/frozen-v1.json`); no format changed.

**2026-09-25 — M5 approved; M6 starts.** The distribution kit accepted at
commit `216574f`: `@microtoll/mailbox` (M3b) and `examples/invite-app`, the
docs site source with `llms.txt`, `@microtoll/mcp`, `SECURITY.md`,
`CONTRIBUTING.md`, the inert release workflow and `docs/LAUNCH.md`; 242
tests green. Nothing pushed, published or listed (D-01). M6 (`pqc-scan`, a
separate repository) begins with a written design for decision.

**2026-09-25 — D-38, D-39, D-40, D-41 decided: the distribution kit as
designed (`docs/DESIGN-M5.md`).** D-38: the docs site from Markdown in
`docs/` with a zero-dependency renderer, `llms.txt` from the same build,
GitHub Pages for microtoll.dev once public, no analytics. D-39:
`@microtoll/mcp` with the stdio JSON-RPC subset written in (zero
dependencies), docs search, read-doc and an empty-directory scaffold that
runs nothing and fetches nothing. D-40: M3b (`@microtoll/mailbox`: the
pairwise labels, bundles version 2 with the recipient and mailbox bound into
the signature, withdrawal as the server does it) built inside M5, and
`examples/invite-app` as the direct-invite demo. D-41: lockstep versions
from `0.1.0`; a release workflow on a signed tag with npm provenance, inert
until the founder sets `PUBLISH_GATE_OPEN` after D-01; signed tags;
`SECURITY.md` with coordinated disclosure to `security@microtoll.dev` and no
bounty; `CONTRIBUTING.md` with DCO. D-06, D-07, D-08, D-09, D-11, D-12 and
D-18 are closed as adopted in M0–M2.

**2026-09-25 — M4 approved; M5 starts.** `@microtoll/blind-store` accepted
at commit `1efc156`: the library, schema, reference server, deployment kit
and `examples/notes-app`; 221 tests green including the database-backed
suites; the example built and ran end to end through Docker Compose on the
founder's machine. Carried forward: M3b (the mailbox client, on the server
half M4 ships); the founder's own browser run of the example; D-01 still
gates publishing. M5 (the distribution kit) begins.

**2026-09-25 — D-37 decided: the pointer's binding is the account, not the
object id (amends D-31).** The server returns an account's pointers without
an id, by design, so the M3 binding could never be opened on a fresh device
(found by the notes example). The pointer's additional authenticated data is
now `frameContext("<ns>/aad/pointer/v2", routingPublicKey)`; the object id is
read from inside the sealed pointer. Still AES-GCM with additional data; no
primitive, label or KDF change; no pointer had been written outside tests.
`packages/access/FORMATS.md` §3.2 and THREATMODEL §5 updated.

**2026-09-25 — D-33, D-34, D-35, D-36 decided: the server as designed
(`packages/blind-store/DESIGN.md`).**
D-33: an events-and-members model becomes `objects` and `object_members`
with a `collection` column, a fixed-length selector and an optional date
window; the query answers everything matching with no identity filter,
refuses past `maxQueryRows` (5,000), and carries a host's extra fields; live
watches route by the same selector, the imminent watch by a per-collection
server-owned window; the message names are fixed (D-27), the selector fields
generic, and `adminCapabilityHash` leaves the query and fetch replies (it
would give everyone who receives cover traffic a stable per-object token);
the mailbox's server half is included. This settles the server half of D-13
and confirms D-14 (what stays out).
D-34: the handshake's server half verifies `"<ns>/auth/v2" ‖ 0x00 ‖
SHA-256(origin) ‖ nonce` with `node:crypto` against the connection's
`Origin`, or each allowed origin when none was sent; the server imports no
`@microtoll` package and a cross-implementation test proves the framing
against identity's `authMessage`; the transport limits plus the query-rows
backstop; the three daily counters fail open. D-20's lookup limit (3 per
socket) is in it.
D-35: the M0 schema rules run as a test against a live database;
`blind_store_sweep()` runs hourly from the library and never sweeps objects
(resolves D-19); the schema creates the least-privilege role
`blind_store_app` that the server and the tests connect as, so a server
compromise reaches no more than the server can already read. D-17 is
resolved by the registration hook.
D-36: `createBlindStore` (with `createCore` as an alias); the thin
`bin/blind-store.mjs`; dependencies exactly `ws` and `pg`, pinned, with the
LISTEN client written in and `pg-listen` dropped; `deploy/` with the
hardened Compose file and the Nginx sample; `examples/notes-app` on the
unchanged reference server with a random-shelf selector and import-map
loading; Postgres for tests from a throwaway container locally and a
service container in CI.

**2026-09-25 — M3 approved; M4 starts.** `@microtoll/access` accepted at
commit `0ba99bf`: formats v2 (D-31), the adversarial suite green with every
case mapped in THREATMODEL §5, 160 tests across the three packages. M4 begins
with a written design of the collection and coarse-selector abstraction and
the server-side hardening for decision, then the server core as a library
with a thin reference server (D-23), and `examples/notes-app`.

**2026-09-25 — D-30, D-31, D-32 decided: the access layer as designed.**
D-30: an events-and-members model is generalised by renaming and widening
(event → object, `K_event` → `K_object`, participation row → member row,
organiser → owner); the content split and the grant rule are supplied by the
app; the pointer has an extension table; wire message names are fixed
(D-27). D-31: formats version 2 as in `packages/access/FORMATS.md` §3 —
purpose labels on the member-row and share-link signatures (and, in M3b, the
recipient inside the invite signature), additional authenticated data on
content, second tier, member rows, pointers and link payloads; the
per-member sealed `K_object` stays an ECIES seal without extra data, stated
in the threat model. D-32: M3 ships objects, members, pointers, admin seats,
rotation, two-tier disclosure, share links, the display rule, the wire
builders and the adversarial suite; direct invites wait for M3b.

**2026-09-25 — M2 approved; M3 starts.** `@microtoll/identity` accepted at
commit `cf78168`: formats v2 (D-28, D-29), 53 tests including every gap the
audit listed, the acceptance demo page, THREATMODEL §4 complete. Carried
forward: the server half of the bound handshake (M4); the founder's own run
of the demo on a real authenticator. M3 begins with the written design of the
access-layer hardening and the object model (D-13) for decision.

**2026-09-25 — D-28 decided: additional authenticated data on all four identity-layer seals.**
As designed in `packages/identity/FORMATS.md` §2.1–2.4: the wrapped root key
is bound to its method type and identifier (SHA-256 of the credential id, or
the recovery lookup hash); the identity blob and the unlock-method label are
bound to the routing public key; the trusted-device session record (version 2)
is bound to the routing public key, its expiry and its session generation, and
a restored record whose stored routing key differs from the derived one is
refused. The blob gains a cooperative `revision` counter so a rolled-back blob
is refused on a device that saw a later one. Contexts are
`frameContext("<ns>/aad/<purpose>/v2", …)`; no primitive, mode or KDF changes.

**2026-09-25 — D-29 decided: the handshake signature covers purpose, origin and nonce.**
The routing key signs `frameContext("<ns>/auth/v2", SHA-256(UTF-8(origin)), nonce)`.
The client half ships in M2; the server half in M4 (`blind-store`), verifying
against its allowed origins, with a cross-implementation test.

**2026-09-25 — M1 approved; M2 starts.** `@microtoll/crypto-core` accepted at
commit `095824c`: vectors green through the public API, fixtures proved in
both directions, zero runtime dependencies, README quickstart and threat
model complete. Carried forward: the browser cross-check of the hybrid seal
(release gate, D-07) and the non-extractable signing key (identity, D-24). M2
begins with a written design of the identity-layer format hardening for the
founder's decision (D-25).

**2026-09-25 — D-26 decided: recovery-code check character, version 2.**
The check character is the Crockford digit of the low five bits of the first
byte of SHA-256(secret bytes). Entropy (128 bits), length (27 characters) and
grouping are unchanged from version 1; only the check rule changes, so a
random transcription error of any kind is caught with probability 31/32.
The engine writes version 2 only; no version-1 data exists to read.
`formatRecoveryCode` and `parseRecoveryCode` become asynchronous (SHA-256 is
asynchronous in Web Crypto). Implemented in crypto-core `src/recovery.js`.
(Revisited by pending D-46.)

**2026-09-25 — D-27 decided: crypto-core keeps its v0 function names.**
`sealToRecipient`, `openWithPrivateKey`, `pqSealAvailable` and the rest keep
their names for v0, as do the wire message names. Any renames for outside
users come with aliases.

**2026-09-25 — D-24 decided (amends D-21): format hardening happens in the
engine, package by package.** The signature purpose labels, recipient
binding, additional authenticated data, non-extractable keys, recovery
checksum and handshake binding are designed and built as each package is
built (M1 to M4). Each change is written up before code and recorded here;
the engine freezes its own fixtures. The crypto-core formats (AEAD v1, ECIES
v3 and v2) are unchanged by the pass; the recovery-code checksum is the one
M1 format decision.

**2026-09-25 — D-25 decided: identity and access take their screens as
callbacks.** `@microtoll/identity` and `@microtoll/access` hold no DOM and no
page state; the app supplies its UI through callbacks and hooks, as D-11
recommends.

**2026-09-25 — M0 signed off.** The founder accepted the audit,
`THREATMODEL.md` and the decisions list. M1 groundwork starts: the
repository, the monorepo layout, licences, CI, the standard RFC and NIST
vectors, and the crypto-core API design. D-01 still gates publishing.

**2026-09-25 — D-04 decided: the v0.x stability promise, as drafted.**
Two promises, stated separately. Formats are frozen from the first publish: no
version byte, label, KDF parameter or signed-byte layout ever changes meaning,
and readers for every published format stay supported. The API may change in
any 0.x minor release, always listed in the package `CHANGELOG.md` with a
migration note; patch releases never break. Public wording: *"Microtoll Engine
is pre-1.0. Function names and options may change between minor versions; the
bytes it writes never will. Anything you encrypt with any published version
will decrypt with every later one."*

**2026-09-25 — D-23 decided: `blind-store` is a library first, with a thin reference server.**
`blind-store` exports its core handlers, dispatcher and schema. The Docker
reference server is a thin wrapper around them. A host application mounts
the library and registers its own handlers beside it, so there is one server
core for every consumer. Item and membership handlers stay the host's until
the generic collection model (D-13) is settled (it was, by D-30 and D-33).
**Licence consequence:** a host server that embeds AGPL-3.0 `blind-store`
must be distributed under AGPL-compatible terms.

**2026-09-24 — D-21 decided: fix format-level weaknesses before any format is frozen.**
Nothing is published, so no format is frozen yet. The format-level
weaknesses are fixed in one deliberate pass before the first publish:
- purpose (domain-separation) labels on signatures;
- recipient and mailbox binding in invitation and acknowledgement
  signatures;
- additional authenticated data (AAD) on object-layer and identity-layer
  seals;
- non-extractable Ed25519 private keys (this absorbs D-15);
- a stronger recovery-code checksum;
- binding for the handshake signature.

This adds binding to existing constructions; no primitive, mode or KDF is
added or substituted. Each change and its reason is recorded here. (Where the
pass happens: D-24.)

**2026-09-24 — D-05 decided: label namespace profile.**
The constructions are fixed and only the label prefix varies:
`createProfile({ namespace })`. A namespace is required, with no silent
default. Retired labels stay reserved in every namespace.

**2026-09-24 — D-02 decided: licensing as recommended.**
- Apache-2.0: `crypto-core`, `identity`, `access`, `mailbox` and the examples.
- AGPL-3.0-only: `blind-store`.
- CC-BY-4.0: the docs.
- Outside contributions: DCO sign-off.

This decision does not open the publish gate; D-01 still governs that.

**2026-09-24 — D-03 decided: the product name is "Microtoll Engine".**
Packages are named by function under the `@microtoll` scope.

**State of the publish gate (non-negotiable 8): OPEN since 2026-09-27.** The
entry of that date records that both checks of D-01 passed. Publishing
follows `docs/LAUNCH.md`, in order.

---

## Pending

Each entry gives the question, the options, a recommendation, and the
milestone it blocks.

### Blocks the first publish

(Nothing: D-01 passed on 2026-09-27, see Recorded. The entry is kept below
for the reasoning.)

**D-01 — IP and employment clearance (the publish gate).** *(Passed 2026-09-27 — see Recorded.)*
Two checks must both pass before anything is published: who owns the code
the engine is built from, and what the founder's employment terms require.
The details, the evidence being kept and the options are in the founder's
private notes, outside this repository.

Rules that follow from it here:
- Never rewrite git history (rebase, amend, force-push or date changes) on
  this repository: the dated history is part of the evidence.
- Local and private work may continue meanwhile.

**Record here when done:** both checks passed, the date, who confirmed, and
any approval that was needed (with its date).

### Closed questions (kept for the reasoning)

**D-46 — Recovery-code check character, version 3: a weighted check over GF(32).** *(Decided 2026-09-27, option (a) — see Recorded.)*
Version 2 (D-26) takes the check character from SHA-256 of the secret. A
random error is caught with probability 31/32, but no class of error is
caught for certain: one mistyped character, or two swapped characters, slips
through one time in 32 and is then refused by lookup as "no such account", a
confusing failure (never a wrong account).
Options, all keeping 128 bits of entropy, 27 characters and the grouping:
- (a) **Version 3:** the check is Σ aⁱ⁺¹·sᵢ over the 26 data characters in
  GF(32), with a = x under x⁵ + x² + 1 (the arithmetic bech32 uses). The 26
  weights are distinct and non-zero, so **every** single wrong character and
  **every** swap of two characters, adjacent or not, is caught; random
  errors are still caught 31/32. Synchronous again (no hash). The parser
  also refuses a code whose two unused final bits are not zero (26
  characters carry 130 bits for 128), so one string names one secret; today
  four strings parse to the same bytes. **Recommended.**
- (b) Keep version 2.
- (c) Crockford's mod-37 check symbol (catches single errors and adjacent
  swaps; the check position may show `*~$=U`).
Error detection, not cryptography: the code's 128 random bits protect the
account either way. No version-2 code exists outside tests.
**Needed before:** the first publish.

**D-47 — Bind an unlock method's name to the method, not only the account.** *(Decided 2026-09-27, option (a) — see Recorded.)*
Version 2 (D-28) binds the sealed name of an unlock method ("Alice's phone")
to the account's routing key. That stops nothing the account's own key does
not already stop (another account's name would not open), and it does **not**
stop the server showing one passkey's name against another of the same
account's passkeys — the case that misleads a person removing a method.
Options:
- (a) **Version 3 of the label context:** `frameContext("<ns>/aad/unlock-label/v3",
  methodType, SHA-256(credentialId))` for a passkey, the method type alone
  for the recovery code, matching the wrapped root key's binding (D-28).
  **Recommended.**
- (b) Keep version 2.
- (c) Bind both (routing key and method): no gain over (a), since the key is
  per account.
**Needed before:** the first publish.

**D-02 — Licensing.** *(Decided 2026-09-24 — see Recorded.)*
Apache-2.0 client packages can be used inside an AGPL application; AGPL on
`blind-store` means anyone running a modified server as a service must
publish their changes.
**Recommendation:** Apache-2.0 for `crypto-core`, `identity`, `access` and
`mailbox`; AGPL-3.0-only for `blind-store`; Apache-2.0 for the examples and
CC-BY-4.0 for the docs; a DCO sign-off (not a CLA) for outside contributions.

**D-03 — Engine product name under the Microtoll brand.** *(Decided 2026-09-24 — see Recorded.)*
- (a) "Microtoll Engine", descriptive, with packages named by function
  (`@microtoll/identity`, …).
- (b) A distinct product name, which needs a trade-mark search.

**Recommendation:** (a) for v0. It can be revisited at the eight-week review.

**D-04 — API stability promise for v0.x.** *(Decided 2026-09-25 — see Recorded.)*

**D-05 — KDF label namespace.** *(Decided 2026-09-24 — see Recorded.)*
A public library hard-wired to one product's label prefix is confusing, and
changing a label counts as substituting one (non-negotiable 1).
- (a) One fixed label set for everyone.
- (b) Labels become a *profile*: the construction is fixed, and only the
  namespace prefix varies; apps pass their own namespace, for example
  `"myapp"` → `"myapp/routing/v1"`.
- (c) A new fixed `microtoll/...` label set.

**Recommendation:** (b). Nothing in any construction changes. A namespace is
required (no silent default), so two apps never share a derivation by
accident. Retired labels stay reserved in every namespace.

**D-06 — Correct the build plan's primitive list.** *(Adopted in M1 (2026-09-25): P-256, RFC 5903 §8.1, RFC 7914 §11, X-Wing vectors — closed by the M5 design.)*
The plan listed "Ed25519/X25519 seed derivation" and RFC 7748 and RFC 6070
vectors. In fact the sealing curve is **P-256** (X25519 was retired because
Safari lacks it) and PBKDF2 is **SHA-256** (RFC 6070 is SHA-1 only).
**Recommendation:** P-256; RFC 5903 §8.1 plus a known-answer test of the v3
seal key derivation instead of RFC 7748; RFC 7914 §11 (PBKDF2-HMAC-SHA-256)
instead of RFC 6070; X25519 only inside the X-Wing hybrid, tested through the
X-Wing vectors. Adding test vectors is not new cryptography.

**D-07 — Post-quantum hybrid in crypto-core.** *(Adopted in M1: hybrid off by default; the Chrome cross-check stays a release gate — closed by the M5 design.)*
The X-Wing seal (ECIES v2, `MLKEM768-X25519`) needs native browser support
(Chrome 154 has it), Node has no native X-Wing, and no cross-check on a real
browser has been done.
**Recommendation:** off by default, behind an explicit opt-in; documented as
"hybrid mode (experimental; requires a browser with native
MLKEM768-X25519)"; tested through a test-only shim, never in a published
runtime path; the Chrome seal/open cross-check a release gate before the
opt-in is documented as usable.

**D-08 — Source language.** *(Adopted in M1: JavaScript with hand-written declarations, no bundler — closed by the M5 design.)*
JavaScript source with JSDoc; hand-written `.d.ts` declarations checked by
`tsc --noEmit` in CI (TypeScript as a development dependency only); no
bundler; zero runtime dependencies in the client packages.

**D-09 — Supported runtimes.** *(Adopted in M1: Node ≥ 24; current Chrome, Firefox, Safari, Edge; the post-quantum path as stated — closed by the M5 design.)*
Node ≥ 24; current Chrome, Firefox, Safari and Edge for the classical path;
the post-quantum path needs Node ≥ 24.7 on OpenSSL ≥ 3.5, or Chrome ≥ 154.

**D-10 — Withdrawn from this log** (2026-09-27): not an engine decision.

**D-11 — Identity package boundary.** *(Adopted in M2 as built (createIdentitySession with the UI as callbacks) — closed by the M5 design.)*
The package ends at "authenticated connection, `auth-ok` fields, identity
blob opened, sealing key adopted". All UI (asking for a code, showing a code,
confirming a deletion) comes in through injected callbacks. A deterministic
avatar and handle stay out of v0; the passkey's user name is a
caller-supplied string.

**D-12 — Where the sealing key lives.** *(Adopted in M2 as built (operations in crypto-core, storage and adoption in identity) — closed by the M5 design.)*

**D-13 — Generic collection model for access and blind-store.** *(Decided 2026-09-25 by D-30 and D-33 — see Recorded.)*
Generalise an events-and-members model, taking the stronger mechanics of a
seat-based model: an `expectedEpoch` refusal and a rotation completeness
check; role-scoped capability replacement on rotation; hash-length and
byte-cap `CHECK`s; `timingSafeEqual` comparisons; then the coarse selector
and the cover-traffic query.

**D-14 — What stays out of v0.** *(Confirmed 2026-09-25 by D-33 — see Recorded.)*
Reporting and moderation; a public layer; operator disclosure keys; repeat
grants; live signals; Web Push. Guest (ephemeral) identities and live
watches over the selector stay in. Push can follow as an optional package
once its documented join is written into THREATMODEL.md.

**D-15 — Non-extractable Ed25519 private keys.** *(Absorbed into D-21, 2026-09-24; built in identity, M2.)*
Derive the public key once with an extractable import, then re-import the
private key non-extractable: byte-identical outputs.

**D-16 — Milestone numbering.** *(Adopted: the mailbox is M3b.)*
`pqc-scan` stays M6; `mailbox` is M3b, built inside M5 (D-40).

**D-17 — Terms and 18+ columns.** *(Decided 2026-09-25 by D-35 — see Recorded.)*
The core schema carries no policy columns; a registration hook lets an app
enforce its own policy and store its own flag.

**D-18 — Repository location and version control.** *(Adopted at M0: `D:\PROJECTS\microtoll`; a private GitHub remote from 2026-09-27; public only when the gate opens.)*
`pqc-scan` has its own repository (D-42).

**D-19 — Retention sweeps.** *(Decided 2026-09-25 by D-35 — see Recorded.)*
`blind-store` sweeps expired and fully used link tokens, consumed and
expired mailbox rows, and rate counters older than two days — all of which
would otherwise keep ciphertext that carries keys, or activity records,
indefinitely. Its effect on what a database copy reveals is in
THREATMODEL.md.

**D-20 — Keep the passkey-as-PRF-only model and the open unlock lookup.** *(Decided 2026-09-25 by D-34 — see Recorded.)*
The server never verifies a WebAuthn assertion; the PRF output is the
secret; the unauthenticated lookup returns only wrapped material; the lookup
is rate-limited in `blind-store`.

**D-22 — Withdrawn from this log** (2026-09-27): not an engine decision.

**D-26 — The recovery-code check character.** *(Decided 2026-09-25 — see Recorded; revisited by D-46.)*
Version 1 was the sum of the 16 bytes mod 32, which misses a mistyped
character whose error falls only in a byte's top three bits, and misses
swapped neighbours.
- (a) Keep version 1.
- (b) Crockford's mod-37 check symbol.
- (c) One character from SHA-256 of the 16 bytes (chosen).

**D-30 — The object model (resolves D-13).** *(Decided 2026-09-25 — see Recorded.)*
- (a) As designed. **Recommended.**
- (b) Keep an event vocabulary in the package API (no renames).
- (c) A wider redesign around a seat model for members.

**D-31 — Access-layer hardening, version 2 (FORMATS.md §3).** *(Decided 2026-09-25 — see Recorded.)*
- (a) All of it. **Recommended.** Every context is known before the open, no
  schema change, no new primitive.
- (b) Signature labels only.
- (c) Keep version 1.

**D-32 — What M3 ships (FORMATS.md §4).** *(Decided 2026-09-25 — see Recorded.)*

**D-33 — The collection model on the server (DESIGN.md §2).** *(Decided 2026-09-25 — see Recorded.)*
- (a) As in DESIGN.md §2. **Recommended.**
- (b) Keep domain-specific field names (`geoBucket`, `dateStart`,
  `dateEnd`) and the admin hash on the wire.
- (c) One table per configured collection instead of a `collection` column.

**D-34 — The bound handshake, server half, and the transport limits (DESIGN.md §3).** *(Decided 2026-09-25 — see Recorded.)*
- (a) As in DESIGN.md §3. **Recommended.**
- (b) Verify against the `Origin` header only, refusing a connection that
  sends none (breaks non-browser clients and every test client).
- (c) Import `@microtoll/crypto-core` on the server for the framing (one
  implementation, but the server package then contains code that can
  decrypt).

**D-35 — Schema rules as tests, the sweep, the database role (DESIGN.md §4).** *(Decided 2026-09-25 — see Recorded.)*
- (a) As in DESIGN.md §4. **Recommended.**
- (b) Also sweep objects a configurable time after their window ends.

**D-36 — Library, reference server, deployment kit, example (DESIGN.md §5).** *(Decided 2026-09-25 — see Recorded.)*
- (a) As in DESIGN.md §5. **Recommended.**
- (b) Keep `pg-listen` as a third dependency.
- (c) Make the example a calendar rather than notes.

**D-37 — Correct the pointer's binding (amends D-31).** *(Decided 2026-09-25 — see Recorded.)*
- (a) Bind the routing public key; the id inside. **Recommended; done.**
- (b) Keep the object-id binding and add a plaintext object-id column to the
  pointer table (breaks the M0 rule: the server would hold every account's
  object list).
- (c) No binding beyond the label.

**D-38, D-39, D-40, D-41** *(Decided 2026-09-25 — see Recorded; the options
are in `docs/DESIGN-M5.md`.)*

**D-42, D-43, D-44, D-45** *(Decided 2026-09-27 — see Recorded; the options
are in `docs/DESIGN-M6-pqc-scan.md`.)*

**D-28 — Additional authenticated data on the four identity-layer seals (FORMATS.md §2.1–2.4).** *(Decided 2026-09-25 — see Recorded; the label binding revisited by D-47.)*
- (a) All four, as designed. **Recommended.**
- (b) Only the session record and the wrapped root key.
- (c) None.

**D-29 — The handshake signature is bound to its purpose and origin (FORMATS.md §2.5).** *(Decided 2026-09-25 — see Recorded.)*
- (a) Label and origin, as designed. **Recommended.**
- (b) Label only.
- (c) Keep the bare nonce.
