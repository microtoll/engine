# Microtoll Engine — Build Plan for Claude Code

**What this is:** the instruction document for building an open-source
secure-backend engine ("the locks, pre-built") for end-to-end-encrypted
apps, plus a post-quantum cryptography discovery scanner. Place this file in the repo root. Read it
fully before writing any code.

**Founder context:** solo founder

## 0. Non-negotiables (apply to every line of code)

1. **No new cryptography.** Keep the existing, test-vector-verified
   constructions exactly. Never invent, "improve", or substitute a primitive,
   mode, or KDF label without an explicit founder decision recorded in
   `DECISIONS.md`.
2. **Zero/minimal dependencies in crypto paths.** Web Crypto API
   (`SubtleCrypto`) only, plus the hand-built PKCS#8 wrapper. No third-party
   crypto libraries. Server packages: keep dependencies few, pinned, and
   audited; justify each in the PR.
3. **The server stores only what it cannot read.** No identity columns, no
   plaintext content, random UUID primary keys (never sequential), no
   `created_at` unless functionally required.
4. **Nothing financial.** No payments, wallets, tokens, billing code, or
   finance-adjacent features anywhere in this codebase. (Founder's standing
   rule.)
5. **No telemetry in any published package.** Adoption is measured
   externally (npm stats, GitHub traffic), never by phoning home.
6. **Honesty in claims.** PQC is described as "hybrid mode" until browsers
   ship native support. Docs state what each module does NOT protect against
   (traffic shape, a compromised device).
7. **Everything is designed to be read.** These packages will face security
   review and an NGI Zero-funded audit. Clarity beats cleverness; every
   non-obvious choice gets a comment pointing at the test vector, RFC, or
   threat it addresses.
8. **Publish gate.** Nothing is pushed to a public registry or public repo
   until the founder records in `DECISIONS.md` that the IP check (D-01) has
   passed. Until then, work is local or in the private GitHub repository.
9. **Self-contained.** The repository names no other product, nor any
   product's files, documents or versions.

## 1. What we are building (macro view)

One engine, packaged for two audiences: human developers and AI coding
agents. The engine supplies the four things AI-generated apps get wrong —
sign-in, key handling, access control, revocation — as drop-in packages. A
separate small CLI rides the UK NCSC post-quantum migration deadlines
(discovery by 2028).

**Monorepo:** GitHub org `microtoll`, repo `engine` (npm scope `@microtoll`).
Scanner lives in its own repo `pqc-scan`.

```
engine/
  packages/
    crypto-core/      M1  primitives wrapper, wire format, PQC hybrid
    identity/         M2  root key, unlock methods, sessions, restore
    access/           M3  capability links, sealing, rotation, revocation
    mailbox/          M3b pairwise unlinkable delivery
    blind-store/      M4  reference server (Node + Postgres, Docker)
    mcp/              M5  the docs and scaffold as an MCP server
  examples/
    notes-app/        M4  minimal E2EE notes app on the engine
    invite-app/       M5  minimal revocable-sharing demo
  docs/               M5  docs site source + llms.txt
  DECISIONS.md            founder decisions log
  THREATMODEL.md          per-package threat models, honest limits
```

## 2. Milestones

Work strictly in order. Each milestone ends with: green CI, updated docs, a
short written summary for the founder, and an explicit list of any format
changes. Do not start the next milestone until the founder approves.

### M0 — Audit and design (done, 2026-09-25)
- The existing security design was read in full and mapped to the planned
  packages, with its test coverage and every app-specific concept that had to
  be generalised or left out.
- `THREATMODEL.md` skeleton; every open design question listed as a founder
  decision with a recommendation (licensing, the product name, the v0.x
  stability promise, and the rest in `DECISIONS.md`).

### M1 — `@microtoll/crypto-core` (done, 2026-09-25)
- HKDF derivation with labelled purposes; Ed25519 seed derivation and the
  PKCS#8 wrapper; the stored P-256 sealing key; versioned AES-256-GCM wire
  format (leading version byte); the PQC hybrid mode; secure random helpers.
- Tests: every applicable published vector (RFC 5869, RFC 8032, RFC 5903,
  RFC 7914, NIST CAVP, the X-Wing draft) run through *this package's* public
  API, plus round-trip and tamper-detection property tests and frozen
  fixtures.
- Typed public API (hand-written declarations, D-08), README with a
  five-minute quickstart, threat-model section; zero runtime dependencies.

### M2 — `@microtoll/identity` (done, 2026-09-25)
- Account Root Key generation; HKDF-derived routing / identity / signing /
  symmetric keys; envelope encryption of the root key under passkey (WebAuthn
  PRF where available) and recovery code; add/remove unlock methods
  independently; 30-day sealed sessions; restore-on-new-device; account
  deletion order of operations.
- Nothing object-specific; the package exposes "an identity with unlinkable
  public routing and private recognition halves".
- Acceptance: a demo page can create, lock, restore and delete an identity
  using only this package and crypto-core.

### M3 — `@microtoll/access` (done, 2026-09-25)
- Sealed sharing of a symmetric object key to identity keys; capability
  derivation (read capabilities re-derived on rotation); one-time and N-use
  share links with hashed tokens and creator-held management capability;
  revocation (delete token) vs removal (full key rotation, re-seal for
  remaining members); signature verification and the "unverified" display
  rule; two-tier disclosure.
- The adversarial suite: a removed member's old key cannot read
  post-rotation writes; a revoked link cannot be redeemed and an
  already-redeemed link is unaffected; a forged signature is flagged
  unverified; holding an object never yields its second tier without the
  second key.

### M3b — `@microtoll/mailbox` (done, 2026-09-25, inside M5)
- Pairwise mailbox labels only the two parties can compute; signed,
  recipient-bound invitation bundles.

### M4 — `@microtoll/blind-store` + first example (done, 2026-09-25)
- The server: Node WebSocket service + Postgres schema (opaque blobs,
  pointer tables, unlock-method rows, hashed link tokens); Docker Compose
  deployment; Nginx sample config; a generic "collection + coarse public
  selector" abstraction, with the cover-traffic query pattern documented.
- `examples/notes-app`: E2EE notes with sharing and revocation, small enough
  to read in ten minutes.
- Tests: schema conformance (no forbidden columns), the server cannot
  decrypt fixtures, an integration test driving the example.

### M5 — Distribution kit (done, 2026-09-25)
- Docs site source (static, for microtoll.dev): the problem, quickstarts per
  package, the threat models, the honest-limits page.
- `llms.txt` and docs formatted for AI coding agents; `@microtoll/mcp`
  exposing docs search and project scaffolding.
- `examples/invite-app`; CONTRIBUTING, SECURITY.md, the (inert) release
  workflow with npm provenance, pinned CI.
- Launch checklist for the founder (`docs/LAUNCH.md`); nothing executed
  before the gate.

### M6 — `pqc-scan` (separate repo; built 2026-09-27, acceptance waits on the founder)
- CLI + GitHub Action: scan a JS/TS codebase and lockfile for cryptography
  usage — algorithms invoked (Web Crypto calls, node:crypto, common
  libraries), key sizes, classical-only signatures/KEMs, TLS configs where
  detectable — and emit an inventory report (JSON + Markdown) shaped like the
  NCSC discovery exercise: what you use, where, migration priority, suggested
  hybrid/PQC replacement.
- Honest output: "inventory and pointers, not a compliance certificate".
- Free forever at CLI level; leave a clean seam for a paid hosted report
  later (do not build the paid side now).
- Acceptance: running it on the engine and on a second real application
  produces a correct, readable report; false-positive rate reviewed by the
  founder on three public repos.

### M7 (later, optional) — Dogfood
- Move an existing application onto the published packages, deleting its
  private copies. Proves the packages are real. Only after v0 APIs settle.

## 3. Explicitly out of scope (do not build, even if it seems helpful)
- Hosted/managed service, billing, quotas, dashboards, accounts on
  microtoll.dev.
- The deepfake/known-person verification module.
- Support for runtimes beyond browser + Node in v0 (record requests as
  issues).
- Marketing pages beyond the docs site; no analytics beyond
  privacy-respecting aggregate page counts on the docs site (founder
  decision which, if any).

## 4. Working agreement with Claude Code
- Every session: read `DECISIONS.md` and the current milestone before coding.
- Anything ambiguous → write the question + a recommendation into the PR
  description; never resolve crypto or licensing ambiguity silently.
- Keep a running `CHANGELOG.md` per package from the first commit.
- Definition of done for any PR: tests, docs updated, threat model updated if
  the attack surface changed, format changes listed (or "none").

## 5. External timeline hooks (context, not tasks)
- NGI Zero Commons Fund: calls roughly every two months, fund runs to
  mid-2027; milestones M1–M5 are written to double as grant milestones
  (€5k–50k, paid in arrears, individual applicant, everything open source).
- NCSC PQC timeline (discovery/plan by 2028) is the demand driver for
  `pqc-scan`.
- Eight weeks after M5 launch: founder judges install/traffic signal before
  any Phase-2 (hosted tier) work begins.
