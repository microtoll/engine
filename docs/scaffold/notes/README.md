# __NAME__

An end-to-end-encrypted notes app on [Microtoll Engine](https://microtoll.dev),
scaffolded by `@microtoll/mcp`. It is the engine's notes example with your
namespace and origin filled in: read `notes.js` (the whole model, about two
hundred lines) before changing anything.

## Run it

```sh
npm install          # fetches the @microtoll packages this Compose file mounts
docker compose up
```

Then open __ORIGIN__. Sign up with a recovery code, write a note, share it
by link, open the link in a private window as a second person.

## What is where

- `notes.js` — the model: list (the shelf query), create, update, share,
  open, join, members, remove (rotation), heal, delete, live watch.
- `page.js`, `index.html` — the page. The packages load from `node_modules`
  through an import map: no build step.
- `docker-compose.yml`, `nginx.conf` — Postgres with the engine schema, the
  blind-store reference server (namespace `__NAMESPACE__`, collection
  `notes` with a two-character selector), nginx serving this directory and
  forwarding `/ws`.

## Before you change it

- **The namespace is one string used twice**: `__NAMESPACE__` in `page.js`
  (`createCryptoCore`) and in `docker-compose.yml`
  (`BLIND_STORE_NAMESPACE`). Sign-in is bound to it and to the page's origin.
- **Do not add cryptography.** Everything needed is in the packages, with
  its threat model. If something seems to need a new primitive, ask a person.
- **Say what is not protected.** Copy the engine's honest limits
  (<https://microtoll.dev/honest-limits.html>) into your own about page.
- **For a deployment**, use the engine's `deploy/` kit: secret files, TLS at
  the proxy, the server as its own database role, no access log.
