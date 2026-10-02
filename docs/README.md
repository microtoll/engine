# docs/

The source of microtoll.dev, of `llms.txt`, and of the snapshot
`@microtoll/mcp` ships.

- `pages/` — the hand-written pages: the pitch, start here, the honest
  limits, formats and stability, for agents.
- `build.mjs` — the build: the repository's own documents (package READMEs
  and formats, the threat model,
  CONTRIBUTING, SECURITY, the deploy and example READMEs) plus `pages/`,
  rendered with a zero-dependency Markdown renderer into `site/`
  (ignored by git), with `style.css`, `llms.txt` and `llms-full.txt`; and
  `packages/mcp/generated/` (committed: the pages as JSON for search, and
  the scaffold templates from `scaffold/notes/` and `examples/notes-app`).
- `scaffold/notes/` — the templates the MCP scaffold fills in.
- `test/build.test.mjs` — every page renders with no unknown construct,
  every internal link resolves, `llms.txt` lists every page, the committed
  snapshot is fresh.
- `DESIGN-M5.md` — the design note for the site, the MCP package and the
  release workflow.

```
npm run docs        # build
npm run check       # typecheck, build, every suite
```

The site is static: no script, one stylesheet, readable without either.
It is deployed to GitHub Pages on every push to `main`.
