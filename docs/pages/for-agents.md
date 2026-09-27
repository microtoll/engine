# For AI coding agents (and the people using them)

The engine exists for two audiences, and the second one writes most new
code now. Three things make it usable from inside a coding tool without a
browser tab open.

## llms.txt

<https://microtoll.dev/llms.txt> is the index: one line per page with what
it covers, following the llms.txt convention. <https://microtoll.dev/llms-full.txt>
is every page concatenated, as Markdown, for a tool that wants the whole
thing in context (about the size of a long article). Both are generated
from the same sources as this site, so they never drift from it.

## The MCP server

`@microtoll/mcp` speaks the Model Context Protocol over standard input and
output, so Claude Code, Cursor and any MCP host can call it. Zero
dependencies; no network; nothing runs but what you see in `src/`.

Add it to a host (Claude Code shown; the others take the same command):

```sh
claude mcp add microtoll -- npx -y @microtoll/mcp
```

Three tools:

- `microtoll_search_docs({ query })` — full-text search over these pages,
  returning the page, the section and an excerpt.
- `microtoll_read_doc({ path })` — one page as Markdown (the `path` from a
  search result, or from llms.txt).
- `microtoll_scaffold({ directory, namespace, origin })` — writes the notes
  starter into an **empty** directory: the client (`notes.js`, `page.js`,
  `index.html`), a Compose file that runs Postgres, the server and nginx
  from the published packages, and a README of next steps. It writes files
  and nothing else: no commands run, no network, and it refuses a directory
  that is not empty.

## What an agent should know before writing security code with this

- **Do not add cryptography.** Every construction needed is here, with its
  threat model. If a task seems to need a new primitive, mode or key
  derivation, the answer is a question to a person, not code.
- **The server stores only what it cannot read.** A column that could name
  a person, a plaintext timestamp, a sequential id: the schema test will
  fail, and it should.
- **The namespace is one string, used twice**: in `createCryptoCore` on the
  client and in `BLIND_STORE_NAMESPACE` on the server. Sign-in is bound to
  it and to the page's origin.
- **Say what is not protected.** Copy the [honest limits](honest-limits.html)
  into the app's own about page. That is not optional.
