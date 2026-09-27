# The locks, pre-built

Microtoll Engine is the security layer of an end-to-end-encrypted app,
packaged so the next app does not have to invent it: **sign-in without passwords, keys that
never reach the server, sharing by capability, and revocation that actually
takes access away.** Browser packages with zero dependencies, a server that
holds only what it cannot read, a threat model that says what is not
protected, and test vectors from the RFCs for every primitive.

## The problem it exists for

Most new code is now written with an AI coding agent, and the four things
those agents get wrong are the four things that cannot be got wrong: how a
person signs in, where the keys live, who may read what, and what happens
when someone is removed. The code they produce looks right — a bcrypt here,
an AES call there, a token in local storage — and passes review, because
security code that is wrong reads exactly like security code that is right.
The failures surface a year later, in someone else's inbox.

The engine's answer is not another library of primitives. It is the
**finished constructions**: an account with no password and no email; a
root key wrapped by a passkey and by a recovery code; a session that
survives a reload and dies on "sign out everywhere"; an object whose key is
sealed to each member and rotated when one is removed; a share link whose
secret never reaches the server; a mailbox two people can compute and the
server cannot. Each was built for a real app, fixed where an audit found it
wanting, and comes with the reasoning written down.

## What you get

- **`@microtoll/crypto-core`** — AES-256-GCM, HKDF, PBKDF2, Ed25519,
  P-256 sealing, the versioned wire formats, and an optional hybrid
  post-quantum seal. Web Crypto only; RFC and NIST vectors through the
  public API.
- **`@microtoll/identity`** — the account root key, passkeys as a PRF and
  recovery codes as the two ways in, the trusted-device session, the
  private settings blob, deletion. Your screens, as callbacks.
- **`@microtoll/access`** — an object with a key sealed per member, admin
  and read capabilities the server holds only hashes of, share links,
  removal that re-keys everything in one checked transaction, a second
  tier for the sensitive part.
- **`@microtoll/mailbox`** — direct invitations under labels only the two
  parties can compute.
- **`@microtoll/blind-store`** — the server: the handshake, the sealed
  tables, the coarse-selector query, live watches, the sweep, a hardened
  Docker deployment. It stores ciphertext, hashes and one coarse selector
  per object, and a test fails if a column that could identify anyone is
  ever added.
- **`@microtoll/mcp`** — the docs and a scaffold inside Claude Code, Cursor
  or any Model Context Protocol host, so an agent can wire the engine in
  without leaving the editor.

## What it is not

- **Not a hosted service.** You run the server; there is no account with us,
  no dashboard, no telemetry, and nothing financial anywhere in the code.
- **Not a compliance certificate.** It is a set of constructions with their
  threat model attached. [The honest limits](honest-limits.html) page says
  what is not protected: traffic shape, a compromised device, a script
  injected into your page.
- **Not "post-quantum secure".** The public-key seals are classical unless
  hybrid mode is on for every recipient; the docs say "hybrid mode" and mean
  it.
- **Not finished.** Pre-1.0: function names and options may change between
  minor versions; the bytes it writes never will
  ([formats and stability](formats-and-stability.html)).

## Start

[Start here](start-here.html): `docker compose up` the notes example, read
one file, and then the four packages in the order they build on each other.

## Where it lives

- Code and issues: [github.com/microtoll/engine](https://github.com/microtoll/engine); the scanner at [github.com/microtoll/pqc-scan](https://github.com/microtoll/pqc-scan).
- Packages: [npmjs.com/org/microtoll](https://www.npmjs.com/org/microtoll), every version published with provenance from the repository.
- Security reports: security@microtoll.dev (see `SECURITY.md`).
