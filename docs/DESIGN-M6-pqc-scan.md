# M6 — `pqc-scan`: design for decision

Status: **decided** 2026-09-27 (D-42 to D-45, each option (a)) and
**built** the same day. This is the design as proposed on 2026-09-25, kept
for the record. `pqc-scan` is its own repository (D-18); its `DESIGN.md` is
now the working copy, with §8 recording the details this version left open.
The publish gate (D-01) applies to it exactly as to the engine: built and
checked locally, nothing pushed.

## 1. What it is, in one paragraph

A command-line tool, and a GitHub Action around it, that reads a JavaScript
or TypeScript codebase and its lockfile and writes an **inventory of the
cryptography it uses**: which algorithms, through which interface (Web
Crypto, `node:crypto`, a library), with what key sizes where they are
written down, where in the code, and which of them a large enough quantum
computer would break. The report is shaped like the discovery exercise the
UK NCSC asks organisations to complete by 2028 in its post-quantum
migration timeline (discovery and a plan by 2028, the highest-priority
migrations by 2031, the rest by 2035): what you use, where, a migration
priority, and the hybrid or post-quantum replacement to consider. It says on
every page what it is: **an inventory and pointers, not a compliance
certificate.** It runs nothing it scans and sends nothing anywhere.

## 2. Decision D-42: repository, name, licence, runtime

- **Repository:** `D:\PROJECTS\pqc-scan`, its own git history, the same
  gate. On GitHub it becomes `microtoll/pqc-scan` when the gate opens.
- **Name:** npm `@microtoll/pqc-scan`, binary `pqc-scan` (the scoped name
  cannot be squatted; the binary is what people type).
- **Licence:** Apache-2.0 — a tool people run in their own CI; permissive
  maximises adoption, and there is nothing to protect by copyleft.
- **Runtime:** Node 20 or later (it runs in other people's CI, where 24 is
  not yet everywhere), tested on 24; `node:test`; **zero runtime
  dependencies** — the scanner reads files and writes files.
- **Free forever at the CLI level** (plan §2). The paid hosted report is
  not built (§5).

## 3. Decision D-43: what it detects, and how

### 3.1 How: a tokenizer, not a parser and not a grep

The scanner tokenizes each `.js`, `.mjs`, `.cjs`, `.ts`, `.tsx`, `.jsx`
file — strings, template literals and comments recognised so that a
mention in a comment or in a string is never mistaken for a call, and a
`'` inside a template never ends a string — and then matches **call
sites** and **object-literal fields** near them:

- `subtle.<method>(…)` and `crypto.subtle.<method>(…)` for `generateKey`,
  `importKey`, `deriveKey`, `deriveBits`, `encrypt`, `decrypt`, `sign`,
  `verify`, `digest`, `wrapKey`, `unwrapKey`, with the algorithm read from
  the nearest literal: `'AES-GCM'`, `{ name: 'ECDH', namedCurve: 'P-256' }`,
  `{ name: 'RSA-OAEP', modulusLength: 2048, hash: 'SHA-256' }`, `'Ed25519'`,
  `'X25519'`, `'HKDF'`, `'PBKDF2'`, `'SHA-256'`, and the hybrid names
  (`'X25519MLKEM768'`, `'MLKEM768-X25519'`, `'ML-KEM-768'`, `'ML-DSA-65'`).
- `node:crypto` (`crypto.` or a destructured import): `createHash`,
  `createHmac`, `createCipheriv`/`createDecipheriv`, `generateKeyPair`(`Sync`),
  `createSign`/`createVerify`, `sign`/`verify`, `createECDH`,
  `createDiffieHellman`, `diffieHellman`, `publicEncrypt`/`privateDecrypt`,
  `pbkdf2`, `scrypt`, `hkdf`, `randomBytes`, `randomUUID`, `getRandomValues`,
  `webcrypto`, `KeyObject`/`createPublicKey`, `X509Certificate`; the
  algorithm from the literal argument (`'sha1'`, `'aes-128-cbc'`, `'rsa'` with
  `modulusLength`, `'ec'` with `namedCurve`, `'ed25519'`).
- **Libraries**, from `package.json` and the lockfile (`package-lock.json`
  v1–v3, `yarn.lock` v1, `pnpm-lock.yaml` — package names and versions only),
  against a catalogue of about forty packages with what each provides
  (`tweetnacl`, `libsodium-wrappers`, `@noble/curves`, `@noble/hashes`,
  `@noble/ciphers`, `@noble/post-quantum`, `node-forge`, `elliptic`,
  `jsonwebtoken`, `jose`, `bcrypt`/`bcryptjs`, `argon2`, `crypto-js`,
  `openpgp`, `ssh2`, `@peculiar/webcrypto`, `mlkem`, `pqc-kyber`,
  `eth-crypto`, `web-push`, …), and
  the import sites of each (`from 'jose'`, `require('bcrypt')`) with the
  algorithm literals they are called with where the library takes one
  (`alg: 'RS256'`, `'ES256'`, `'EdDSA'`, `'HS256'`).
- **TLS configuration** where it is written down: nginx (`ssl_protocols`,
  `ssl_ciphers`, `ssl_ecdh_curve`), Apache (`SSLProtocol`,
  `SSLOpenSSLConfCmd Curves`), Caddy (`protocols`, `curves`), and Node's
  `tls.createServer` / `https.createServer` options (`minVersion`,
  `ciphers`, `ecdhCurve`). A configuration that lists no post-quantum
  hybrid group is reported as classical-only key exchange.

Each finding carries: the algorithm name as normalised, the **class**
(quantum-vulnerable public-key: RSA, DSA, DH, ECDH, ECDSA, EdDSA, X25519,
Ed25519, secp256k1; symmetric; hash; KDF or password hash; random;
post-quantum or hybrid; unknown), the key size or curve where it is
literal, the interface, `file:line`, and the evidence line. What cannot be
read statically (an algorithm name held in a variable) is reported as
"dynamic — check by hand", never guessed.

### 3.2 What it does not do

It runs nothing it scans, follows no `require` into `node_modules` beyond
the catalogue, reads no environment, sends nothing anywhere, and has no
telemetry. Frameworks' own cryptography (a session cookie signer inside a
web framework) is reported through the library catalogue when the
framework is on the list, and otherwise not at all — the report says so.

### 3.3 Alternatives

(b) A real parser (TypeScript's) as a dependency: exact scoping of
variables, at the cost of an eight-megabyte dependency and a much harder
audit of the tool. (c) Regular expressions over raw text: no dependency,
but comments and strings produce false positives the founder would reject
on the three public repositories.

## 4. Decision D-44: the report

Two outputs from one scan:

- **`pqc-scan.json`** — schema version 1, the machine-readable inventory:
  `{ schema, tool, scannedAt, root, summary, findings[], dependencies[],
  tls[], skipped[] }`. This JSON is the **seam** a hosted report would
  consume later (§5); it is documented in the repository and versioned.
- **`pqc-scan.md`** — the human report, in this order:
  1. **Summary**: counts by class; the one-line verdict ("N
     quantum-vulnerable public-key uses in M files; K libraries; TLS
     classical-only"); the fixed sentence *an inventory and pointers, not a
     compliance certificate*.
  2. **What you use, where**: the inventory table (algorithm, class,
     interface, key size, file:line).
  3. **Quantum-vulnerable public-key uses, with a priority**:
     - **High** — data at rest sealed with a classical public-key seal
       (ECDH/RSA key agreement or encryption): harvest-now-decrypt-later
       applies; a recorded ciphertext can be opened later. Replacement: a
       hybrid seal (X25519MLKEM768 / ML-KEM-768 with the classical curve)
       for everything sealed from now on; re-sealing old data where it must
       outlive the transition.
     - **Medium** — signatures and authentication (ECDSA, Ed25519, RSA
       signatures, JWT `RS256`/`ES256`/`EdDSA`): forgeable once a large
       quantum computer exists, not before, so the risk is to long-lived
       artefacts (software signatures, certificates, documents). Replacement:
       ML-DSA or SLH-DSA where the platform offers them; plan, do not rush.
     - **Low** — ephemeral session key exchange (TLS with a hybrid group
       available, Diffie–Hellman for a session): enable the hybrid group;
       the exposure is the session, not the archive.
     The priority is a **heuristic** from the interface used and the words
     around the call (`encrypt`, `seal`, `store`, `sign`, `verify`, `tls`,
     `session`); the report says so on the page and asks for a person's
     review of each High.
  4. **Symmetric and hash notes**: AES-128 → consider 256 for data that
     must outlive the transition (Grover halves the effective strength);
     SHA-1 and MD5 → replace regardless of quantum; 3DES/RC4/DES → replace
     now; PBKDF2 iterations under 100,000 flagged as weak on classical
     grounds.
  5. **Dependencies**: each catalogued library, its version, what it
     provides, whether it offers post-quantum algorithms.
  6. **TLS**: each configuration found and whether a hybrid group is
     enabled.
  7. **Next steps**, in the NCSC's three-milestone frame: finish discovery
     (the dynamic and unknown items), decide priorities, plan the High items
     for the 2031 milestone, the rest for 2035.
  8. **What this report cannot see** (§3.2), verbatim.

Options: (b) JSON only; (c) SARIF as well, for code-scanning tabs — deferred
(the JSON schema keeps the door open).

## 5. Decision D-45: the GitHub Action, and the paid seam

- **`action.yml`** in the same repository, a composite action: install the
  CLI from the checked-out repository (or, after publish, from npm at a
  pinned version), run it on the workspace, append `pqc-scan.md` to the
  job summary, upload `pqc-scan.json` as an artefact, and optionally fail
  the job when a threshold is crossed (`fail-on: high`). No marketplace
  listing until the gate opens (the launch checklist gains a line).
- **The paid seam is the JSON schema and nothing else.** A hosted report
  — trends over time, an organisation-wide view, the tracked plan — would
  read `pqc-scan.json`. Nothing of it is built: no upload, no account, no
  endpoint, no code path that could phone home. The README says the CLI is
  free forever and that a hosted report may exist later.

## 6. Acceptance (plan §2), how it will be shown

- Running it on **the engine** finds: AES-256-GCM, HKDF-SHA-256, PBKDF2
  (310,000 iterations), SHA-256, Ed25519 (medium), P-256 ECDH (high: the
  seal), the hybrid `MLKEM768-X25519` (post-quantum), and reports the
  server's `node:crypto` verify and hash as expected; the nginx sample as
  hybrid-enabled.
- Running it on **a second, real application** (read-only, chosen by the
  founder) finds the same constructions and whatever that application adds:
  a push-notification library (VAPID signatures and push-message
  encryption), a hybrid TLS group such as `X25519MLKEM768:X25519:prime256v1`
  in its nginx configuration, a composition in its test tooling. A library
  that is declared and imported only by a file the service never loads is
  still reported: a static scan cannot tell whether a file runs, and the
  report says so rather than guessing.
- Three public repositories chosen by the founder: the false-positive rate
  reviewed by hand; every false positive becomes a test case.
- Both reports read cleanly to someone IT-literate but not a specialist.

## 7. Shape of the repository

```
pqc-scan/
  bin/pqc-scan.mjs         the CLI: pqc-scan [dir] [--json out] [--md out] [--fail-on high|medium]
  src/tokenize.js          the JS/TS tokenizer
  src/detect/webcrypto.js  node-crypto.js  libraries.js  tls.js  lockfiles.js
  src/catalogue.js         the library catalogue and the algorithm classes
  src/report.js            JSON (schema v1) and Markdown
  action.yml               the composite GitHub Action
  test/                    node:test; fixtures of real code shapes, each false positive found becomes one
  README.md  DESIGN.md  CHANGELOG.md  LICENSE  SECURITY.md (pointing at the engine's)
```
