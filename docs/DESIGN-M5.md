# M5 — the distribution kit: design for decision

Status: **decided**, 2026-09-25 (D-38 to D-41 in `DECISIONS.md`, all four
as recommended; D-06 to D-09, D-11, D-12 and D-18 closed as adopted in
M0–M2). Everything here stays behind the publish gate (D-01): it is built
and checked locally, and nothing is pushed, published or listed until the
gate is recorded open.

The plan's words: *this is the strategy, not an afterthought*. The engine
exists for two audiences — people, and the AI coding agents that now write
most of the security code the engine replaces — and the acceptance test is
that either can go from zero to a working end-to-end-encrypted app in one
sitting without asking anything.

## 1. What M5 delivers

| Piece | Where | Licence |
|---|---|---|
| The docs site: pitch, quickstarts, threat models, honest limits, the showcase | `docs/` (source), `docs/site/` (built) | CC-BY-4.0 |
| `llms.txt` and `llms-full.txt` for agents | built into the site root | CC-BY-4.0 |
| `@microtoll/mcp`: docs search and project scaffolding inside Claude Code, Cursor and the rest | `packages/mcp` | Apache-2.0 |
| `@microtoll/mailbox` (M3b) and `examples/invite-app` | `packages/mailbox`, `examples/invite-app` | Apache-2.0 |
| CONTRIBUTING.md, SECURITY.md, the release workflow (inert), signed tags, npm provenance | repository root, `.github/workflows/release.yml` | — |
| The launch checklist, for the founder | `docs/LAUNCH.md` | — |

## 2. Decision D-38: the docs site

### 2.1 Pages

- **Home (the pitch).** One page, plain language: AI-generated apps get four
  things wrong — sign-in, key handling, access control, revocation — and get
  them wrong in ways that pass review, because the code looks right. The
  engine supplies those four as packages, test-vector-verified, with the
  threat model written down. What it is not: a hosted service, a compliance
  certificate, or "unbreakable".
- **Start here** (the one-sitting path): `docker compose up` the notes app,
  read `notes.js`, then the five-minute quickstarts in order: crypto-core →
  identity → access → blind-store.
- **Packages:** one page per package, generated from its README (the
  quickstart, what the app supplies, the API notes) plus its `FORMATS.md`
  or `DESIGN.md` where one exists.
- **Threat models:** `THREATMODEL.md` rendered as is, adversaries first.
- **Honest limits:** §2 of the threat model (what nothing here protects
  against) and every package's "does not protect" list on one page, in plain
  words.
- **Formats and stability:** the D-04 promise, the label registry, the
  version bytes — what "the bytes never change meaning" means.
- **For agents:** how to use `llms.txt`, the MCP server, and the scaffold.
- **Deploy:** `deploy/README.md` and the Nginx sample.

### 2.2 Build

- Source is Markdown in `docs/` and the repository's existing documents;
  `docs/build.mjs` renders it to static HTML in `docs/site/` with one
  stylesheet, no JavaScript needed to read a page, and the same
  no-inline-script content security policy the examples use.
- **Rendering: a small in-house Markdown renderer, zero dependencies**
  (headings, paragraphs, lists, code fences, tables, links, emphasis,
  blockquotes — the subset these documents use, and a test that every
  document renders without an unknown construct). The alternative is
  `marked`, pinned, as a development dependency for the build only.
- `llms.txt` (the index: one line per page with its description) and
  `llms-full.txt` (every page concatenated, Markdown) are written by the
  same build, following the llms.txt convention.
- `npm run docs` builds; CI builds and fails on a broken link or an
  unrendered construct. Nothing is deployed by CI until the gate opens.

### 2.3 Hosting and measurement

- **microtoll.dev, static.** Recommendation: GitHub Pages from the `engine`
  repository through a workflow, once the repository is public (after D-01);
  Cloudflare Pages is the alternative if the founder prefers the DNS to sit
  with the domain. The domain itself is a launch-checklist item.
- **No analytics.** The plan allows privacy-respecting aggregate page counts
  at the founder's decision; the recommendation is none at launch — npm and
  GitHub counts are the adoption measure (non-negotiable 5).

## 3. Decision D-39: the MCP server

`@microtoll/mcp` speaks the Model Context Protocol over standard input and
output (JSON-RPC 2.0, protocol version `2025-06-18`, the `initialize` /
`tools/list` / `tools/call` subset) so Claude Code, Cursor and any MCP host
can call:

- `microtoll_search_docs({ query })` — full-text search over the built docs
  index shipped inside the package (no network), returning page titles,
  sections and excerpts;
- `microtoll_read_doc({ path })` — one page, Markdown;
- `microtoll_scaffold({ directory, app })` — writes a starter app into a
  directory the host names: the notes example (client, page, Compose file,
  a README of next steps), with the namespace and origins filled in. It
  writes files and nothing else: no commands run, no network, no telemetry,
  and it refuses a directory that is not empty.

**Zero runtime dependencies**: the protocol subset is about 250 lines of
plain JavaScript (newline-delimited JSON on stdio, errors as JSON-RPC
errors, logs on stderr), tested against recorded host transcripts. The
alternative is the official `@modelcontextprotocol/sdk`, which brings its
own dependency tree into a package whose whole point is to be read. Node
24 or later; Apache-2.0. Registry listings (the MCP registry, the hosts'
directories) are launch-checklist items.

## 4. Decision D-40: M3b now, then `examples/invite-app`

The notes app already shows revocable sharing by link. The plan's
`invite-app` earns its place by showing what a link cannot: inviting a
known person **directly**, with no link to forward and no group object,
through a mailbox only the two of them can compute. That needs `@microtoll/mailbox` (M3b, optional until now):

- **Labels:** HKDF over the P-256 ECDH secret of the two
  long-term sealing keys, info `<ns>/invite-mailbox/v2|<YYYY-MM>|<sender>|<recipient>`,
  polled for the current and previous month. (Retired `invite-mailbox/v1`
  stays refused, D-05.)
- **Bundles** version 2 (the M3b item D-31 reserved): `{ v: 2, payloadJson,
  sig }` sealed to the recipient, with the signature over
  `frameContext("<ns>/sig/invite/v2", mailboxId, SHA-256(recipientPublicKey)) ‖ UTF-8(payloadJson)`
  (as built; `packages/mailbox/FORMATS.md` §2) — the recipient and the
  mailbox bound in, so a contact cannot re-seal a third party's signed
  invite into their own mailbox and have it verify. Kinds: `invite`, `admin-grant`, `invite-ack`.
- **Withdrawal** as the server already does it: a consumed drop is
  served without its bundle and emptied in the row.
- **Contacts, favourites and blocking stay the app's** (kept in its
  identity blob); the package derives labels, seals and opens bundles,
  polls, consumes and watches. Classical by necessity: there is no standard
  post-quantum non-interactive key exchange, and the threat model says so.
- **`examples/invite-app`**: two people who once shared a note become
  contacts; one invites the other to a new note directly; the other sees it
  arrive live, opens it, acknowledges; the sender withdraws an unopened
  invite. Same shape as the notes app, same server unchanged.

Alternatives: (b) build `invite-app` on links only (a duplicate of the notes
app); (c) leave both until after M5 (the plan lists `invite-app` in M5).

## 5. Decision D-41: releases, versions, policies

- **Versions in lockstep:** every published package is `0.1.0` at first
  publish and moves together thereafter (one engine version to name in a
  bug report or an app's pin; the packages are built and tested together).
  The D-04 promise is repeated in every README.
- **The release workflow** (`.github/workflows/release.yml`): on a signed
  `v*` tag, run the full check against Postgres, then `npm publish
  --provenance --access public` for each package through GitHub's OIDC (no
  long-lived npm token in the repository). It is **inert until the gate
  opens**: it runs only when a repository variable `PUBLISH_GATE_OPEN` is
  `true`, which the founder sets after recording D-01 — a second lock on
  the same door as the no-remote rule.
- **Signed tags:** the founder makes a signing key (SSH signing is the
  simplest: `git config gpg.format ssh`), and every release tag is
  `git tag -s`. The public key goes into `SECURITY.md` so a tag can be
  checked. No key is configured on this machine today.
- **`SECURITY.md`:** how to report (a private channel, never a public
  issue), what to expect (acknowledgement within a week, a fix or a
  statement within ninety days, credit if wanted), what is in scope (the
  packages, the reference server, the examples) and out (applications
  built on the engine, which have their own process; the docs site). **The contact address is the
  founder's decision:** the recommendation is a dedicated
  `security@microtoll.dev` mailbox created at launch; nothing here names a
  personal address unless the founder says so. No bounty (non-negotiable 4).
- **`CONTRIBUTING.md`:** DCO sign-off (D-02), the rules of the repository
  (no new cryptography, port from a pinned tag, zero dependencies in the
  client packages, tests through the public API), how to run the
  database-backed suites, and how a format or crypto question becomes a
  pending decision rather than a pull request.

## 6. The launch checklist (`docs/LAUNCH.md`, the founder executes)

In order, each a tick: D-01 recorded open → the repository made public
under `microtoll/engine` with the licences in place → signing key made and
its public half in `SECURITY.md` → `PUBLISH_GATE_OPEN` set → `v0.1.0` tag
signed and pushed → provenance checked on npm → microtoll.dev DNS and Pages
→ `security@` mailbox → MCP registry listing → one Show HN post → GitHub
Sponsors link. No other promotion (plan §2).

## 7. Closing the earlier open decisions

D-06 (the primitive list and vectors), D-07 (hybrid off by default, the
Chrome cross-check as a release gate), D-08 (JavaScript with hand-written
declarations, no bundler), D-09 (the runtimes) were adopted in M1; D-11 and
D-12 (the identity boundary and where the sealing key lives) in M2; D-18
(the repository location, no remote until D-01) at M0. The docs site states
them as facts; `DECISIONS.md` marks them adopted with this design.
