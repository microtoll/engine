# Licences

Microtoll Engine is one repository under three licences, chosen per package.
Each package carries its own `LICENSE` file, which
is the one that applies to it.

| What | Licence |
|---|---|
| `@microtoll/crypto-core`, `@microtoll/identity`, `@microtoll/access`, `@microtoll/mailbox`, `@microtoll/mcp`, and the examples | Apache-2.0 |
| `@microtoll/blind-store` (the reference server library and its schema) | AGPL-3.0-only |
| The documentation (`docs/`, the site, `THREATMODEL.md`) | CC-BY-4.0 |

The AGPL applies to the server package only: a host server that embeds it
must be distributed under AGPL-compatible terms; an app that only uses the
browser packages is not affected. Outside contributions are accepted with a
Developer Certificate of Origin sign-off (`CONTRIBUTING.md`), not a
contributor licence agreement.
