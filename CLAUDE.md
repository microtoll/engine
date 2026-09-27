# CLAUDE.md — Microtoll Engine

## Read first, every session

1. `microtoll-build-plan.md` §0 — the non-negotiables. They apply to every
   line of code.
2. `DECISIONS.md` — what the founder has decided, and what is still pending.
   Never resolve a crypto, licensing or IP question silently; write it up as a
   pending decision with a recommendation.
3. The current milestone in `microtoll-build-plan.md` §2.
4. `CLAUDE.local.md`, if it exists: local notes that are never committed.

## Rules of this repository

- **No new cryptography.** The formats are frozen by fixtures. Adding a
  published test vector, a fixture or a type declaration is fine; changing a
  label, a version byte, a parameter or a signed-byte layout is not, without
  a decision recorded in `DECISIONS.md`.
- **The repository is self-contained.** It names no other product: no
  application the engine came from, and none of its files, documents,
  versions or audit identifiers, in code, tests or documentation. Notes that
  need them live outside the repository (see `CLAUDE.local.md`).
- **Zero runtime dependencies** in the client packages. Server dependencies:
  few, pinned to exact versions, each justified in the PR.
- **No telemetry, nothing financial, no hosted-service code.**
- **Tests:** `node:test`, no framework. Every vector runs through the
  package's public API, never a re-implementation in the test file. The
  database-backed suites need `npm run db:up` (a throwaway Postgres in
  Docker) and skip otherwise; run them before calling a server change done.
- **Every package keeps `CHANGELOG.md`** from its first commit.
- **The publish gate is open** since 2026-09-27 (`DECISIONS.md`, D-01
  passed). Publishing follows `docs/LAUNCH.md` in order; nothing is
  published outside that list.
- **Never rewrite git history** (no amend, rebase, force-push or date
  changes). The history is part of the ownership record.
- **Commit and push straight away.** Every piece of work is committed and
  pushed to `origin` as soon as it is done and its tests pass, in this
  repository and in `pqc-scan` (founder, 2026-09-27). Before a commit,
  run the self-contained check in `CLAUDE.local.md`.

## Style

These rules apply to **all output**: replies, code comments, documentation,
commit messages and decision entries.

- **Plain language, clear and non-cryptic**, as if for someone IT-literate
  but not a deep specialist. Unwrap acronyms and highly specialist terms on
  first use, and name documents and references in full. Where a simpler word
  works, use it. Do not over-explain general IT concepts ("file", "folder",
  "terminal"): assume that baseline. Be brief.
- **Standard UK English only**, never US English (spelling, dates, usage).
- **No unfriendly colloquialisms** (for example "long pole", "barely costs
  you calendar time", "fail on usefulness"): use simpler, neutral language.
- Every non-obvious choice in code gets a comment naming the test vector,
  RFC, or threat it addresses. Clarity beats cleverness: this code will be
  audited.
- Ask the founder through `AskUserQuestion` with clickable options, and say
  which option is recommended.
