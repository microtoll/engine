# Start here

One sitting, no questions: a working end-to-end-encrypted app in front of
you, then the packages in the order they build on each other.

## 1. Run the notes example (ten minutes)

```sh
git clone https://github.com/microtoll/engine
cd engine/examples/notes-app
docker compose up
```

Open <http://localhost:8088>. Sign up with a recovery code, write a note,
share it by link, open the link in a private window as a second person,
join, then remove that person and watch their copy go stale. The
[notes example](examples/notes-app.html) page walks through it and says,
honestly, what the server learned.

Then read [`notes.js`](https://github.com/microtoll/engine/blob/main/examples/notes-app/notes.js):
about two hundred lines, the whole model.

## 2. The packages, in order

1. **[crypto-core](packages/crypto-core.html)** — one call gives you a
   `cryptoCore` bound to your app's namespace. Everything else takes it.
2. **[identity](packages/identity.html)** — `createIdentitySession` with your
   screens as callbacks: boot, register, unlock, lock, delete.
3. **[access](packages/access.html)** — `createAccess` with your three choices
   (the fields in a pointer, what goes in the second tier, who is owed it),
   then objects, members, links and rotation.
4. **[blind-store](packages/blind-store.html)** — the server, as a library
   you mount handlers on or as the reference binary the examples run.

The [invite example](examples/invite-app.html) adds the fifth,
**[mailbox](packages/mailbox.html)**: inviting a known person with nothing
to forward.

## 3. Your own app

Either scaffold it from inside your editor with the
[MCP server](for-agents.html) (`microtoll_scaffold` writes the notes starter
into an empty directory), or copy `examples/notes-app` and change three
things: the collection (`BLIND_STORE_COLLECTIONS`), the namespace (the same
string in `createCryptoCore` and `BLIND_STORE_NAMESPACE`), and the origins
the server accepts.

## 4. Before you ship

- Read [the honest limits](honest-limits.html) and put its list in your own
  "about" page. Users are owed it.
- Deploy with [the kit](deploy.html): the database on the internal network,
  the server as its own database role, the proxy blanking the client's
  address, no access log.
- Run the schema-conformance test against your database
  (`packages/blind-store/test/schema.test.mjs`) whenever you add a table.
- Pin the versions. [Formats and stability](formats-and-stability.html)
  says what a version number promises.
