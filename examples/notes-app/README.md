# Notes — the first example

End-to-end-encrypted notes with sharing and revocation, on the unchanged
blind-store reference server. Small enough to read in ten minutes:
`notes.js` is the whole model (about 200 lines), `page.js` wires it to
buttons, and nothing else is the app's.

## Run it

```sh
cd examples/notes-app
docker compose up
```

Then open <http://localhost:8088>. The first start builds the server image
and pulls Postgres and nginx (a few minutes on a clean machine); the notes
appear the moment nginx answers.

1. **Boot**, then **Sign up with a recovery code** (works in every browser;
   the passkey button needs a browser with PRF support). Keep the code: it
   is the only way back in.
2. **New note**, open it, write, **Save**.
3. **Share**: copy the link. Open a private window as a second person, paste
   the link's address into the browser, boot, sign up, press **Open link**.
   The second person reads the note.
4. As the second person, **join as member**. As the owner, **members**
   shows them (verified by their signature); **remove** rotates every key.
5. As the owner, edit and save. The second person's copy is now stale:
   **heal** finds no new key for them — they were removed, and the old key
   opens nothing written since.

`docker compose down -v` throws the database away.

## What the server learns, honestly

- **The shelf of every note** (one of 256, chosen at random when the note is
  made), and **which shelves each routing key asks for** — that is the
  cover-traffic trade: the server answers with every note on those shelves
  and cannot tell which are yours. With few users the crowd on a shelf is
  thin, and the server can guess well; with many it cannot. A real app picks
  a selector that is meaningful and coarse (a region and a day, say).
- **One note id per link opened** (`fetch-event`), because redeeming a link
  needs the note's current key epoch.
- **Sizes and timing**, the number of pointers an account holds, and that a
  routing key made a note today (the daily counter).

It does not learn a title, a body, a name, who owns what, who is a member of
what, or a link's secret. `THREATMODEL.md` §6 in the repository root is the
full list.

## Where things are

- `notes.js` — the model: list (the shelf query), create, update, share,
  open, join, members, remove (rotation), heal, delete, watch.
- `page.js` — the page, the identity session (`@microtoll/identity`) with
  prompts for the code and confirmations.
- `docker-compose.yml`, `nginx.conf` — the three containers: Postgres with
  the engine schema, the reference server with the `notes` collection
  (`{"notes":{"selectorLength":2}}`), nginx serving this page and the
  packages by import map and forwarding `/ws`.
- `test/notes.test.mjs` — the same model driven from Node against a real
  server and database (`node scripts/test-db.mjs up`, then `npm test`).

The packages load from `/packages/*/src` through an import map: no build
step, and exactly the files that will be published.
