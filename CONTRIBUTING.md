# Contributing

Microtoll Engine will face security review and a funded audit, so the rules
below exist to keep it readable and its cryptography unchanged. They apply
to every contribution, the maintainer's included.

## The rules

1. **No new cryptography.** The constructions are fixed, verified by
   published test vectors and pinned by frozen fixtures. A change to a
   primitive, a mode, a label, a version byte, a key-derivation parameter
   or a signed-byte layout is not a pull request: it is a **pending decision**,
   written up in an issue with the reasoning and a recommendation, for the
   maintainer to decide first. Adding a test vector or a fixture is fine.
2. **Zero runtime dependencies** in the browser packages. The server package
   has exactly `ws` and `pg`, pinned; a new dependency anywhere needs a
   justification in the pull request and the maintainer's decision.
3. **The server stores only what it cannot read.** No identity column, no
   plaintext content, random UUID keys, no timestamp unless something
   functionally needs it. `packages/blind-store/test/schema.test.mjs`
   enforces the rules against a live database; a change that fails it is a
   design question, not a test to loosen.
4. **Nothing financial, no telemetry, no hosted-service code**, anywhere.
5. **Honest claims.** Post-quantum protection is "hybrid mode"; every
   package's README and `THREATMODEL.md` say what is *not* protected. A
   change to the attack surface updates the threat model in the same pull
   request.
6. **Written to be read.** Every non-obvious choice gets a comment naming
   the test vector, RFC or threat it addresses. Plain language, UK English.

## Sign-off (DCO)

Every commit carries a `Signed-off-by:` line with your real name and email
(`git commit -s`), certifying the [Developer Certificate of Origin](https://developercertificate.org/):
that you wrote the change or have the right to submit it under the file's
licence (Apache-2.0 for the browser packages and examples, AGPL-3.0-only for
`blind-store`, CC-BY-4.0 for documentation).

## Working on it

```
npm install                     # TypeScript for the declaration check; ws and pg for blind-store
npm run check                   # typecheck + every suite
npm run db:up                   # a throwaway Postgres 17 in Docker for the database-backed suites
npm run docs                    # builds the docs site and llms.txt into docs/site/
```

- Tests use Node's built-in `node:test`, no framework, and drive each
  package through its **public API** — never a re-implementation in the
  test file. A frozen fixture pins every format.
- Each package keeps a `CHANGELOG.md`.
- The repository is self-contained: it names no other product.

## What a pull request needs

Tests; docs updated (README, `CHANGELOG.md`, `FORMATS.md` where a format is
touched); the threat model updated if the attack surface changed; the
deviations section updated; `npm run check` green with the database-backed
suites running. A pull request that changes a format without a recorded
decision will be closed with a pointer to this page, kindly.

## Conduct

Be direct and be kind. Security findings are welcome and are handled
through `SECURITY.md`, never through a public issue.
