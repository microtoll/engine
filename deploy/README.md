# Deploying blind-store

The reference deployment: one Compose file, one Dockerfile, one Nginx
sample. The server never connects as the database superuser, never runs as
root, and never keeps an access log.

## Pieces

| File | What it is |
|---|---|
| `docker-compose.yml` | Postgres 17 on the internal network only, with the engine schema and the service role's login applied at first start; the server built from this repository, running as `node`, read-only, no capabilities, with passwords from secret files. |
| `Dockerfile` | `node:24-alpine`, the workspace's pinned `ws` and `pg`, the package, nothing else. |
| `../packages/blind-store/schema/900_app_login.sh` | Gives `blind_store_app` its login from the secret at first start. |
| `nginx.sample.conf` | TLS with the hybrid post-quantum group, the security headers, the WebSocket location with per-address limits and the client's address blanked, `/healthz`. |
| `.env.example` | The namespace, the allowed origins, the collections. |

## First start

```sh
cd deploy
cp .env.example .env                        # edit: namespace, origins, collections
mkdir -p secrets
openssl rand -base64 32 > secrets/postgres.password
openssl rand -base64 32 > secrets/blind_store_app.password
docker compose up -d
curl -s http://127.0.0.1:8020/healthz        # ok
```

Put the reverse proxy in front (`nginx.sample.conf`, with your certificate),
serving the app's static files and forwarding `/ws` to `127.0.0.1:8020`.

## What is deliberately not here

- No hosted service, no telemetry, no metrics endpoint: `/healthz` says `ok`
  or `unhealthy` and nothing else.
- No access log at the proxy, no request log at the server. The server logs
  counts and reasons (a sweep total, a lost LISTEN connection) and never a
  message body or a routing key.
- No client address reaches the server: the proxy blanks it, and the
  per-address limits live at the proxy.
- No schema migration tooling. The schema runs once, on an empty data
  directory; a change to a table is a new init file for a new deployment or
  a migration you write, and the schema-conformance test
  (`packages/blind-store/test/schema.test.mjs`) is there to run against it.

## Backups

A database copy holds what THREATMODEL.md §6 lists: sealed blobs, hashed
capabilities, the selectors and windows, the counters for the last two days,
and links and drops until the sweep removes them. It holds no key. Copy it
with the same care as the running database; there is nothing in it to
redact.
