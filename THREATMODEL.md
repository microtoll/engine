# THREATMODEL.md — Microtoll Engine

**Status:** each package's section was completed before that package's API
was reviewed; the formats each claim rests on are in the
packages' `FORMATS.md` and `DESIGN.md`. A limit is stated as plainly as a
protection.

## 1. Adversaries

| ID | Adversary | Can do |
|---|---|---|
| A1 | **Server operator or database copy** | Reads every row, log and ciphertext; sees traffic timing and sizes; can drop, replay, reorder or roll back what it serves. It does not run the client. |
| A2 | **Network observer** | Sees TLS metadata and timing (TLS itself is assumed). |
| A3 | **Co-member** | Legitimately holds an object's key; sees other members' public keys and rows. |
| A4 | **Removed member** | Holds the *old* keys and everything they saw before removal. |
| A5 | **Link holder** | Holds a share link (and therefore the object key) without being a member. |
| A6 | **Stranger with an account** | Can authenticate and send any well-formed message. |
| A7 | **Harvest-now, decrypt-later** | A1's copy plus a future large quantum computer. |
| A8 | **Compromised device or page** | Malicious script in the origin, malware, or someone holding the unlocked device or a copy of the browser profile. |

## 2. Global limits (true of every package)

- **A8 wins.** Script injection into the page, or a compromised device, is
  total compromise. A trusted-device session is exactly as safe as the unlocked
  device it sits on.
- **Traffic shape is visible to A1 and A2.** This includes who connects and
  when, how many rows an account owns, ciphertext sizes (unpadded, in bands),
  and the plaintext coarse selector (area and date range) of every item. While
  few people use a deployment, one active account is easy to pick out.
  Hiding it would need mix-network routing, which is out of scope.
- **A link is as private as the channel it is sent through.** The secret is
  in the URL fragment, which servers and link previewers do not receive. The
  messaging app it travels through can read it unless that chat is
  end-to-end encrypted.
- **Nothing can be moderated in advance.** The server cannot read content, so
  abuse handling starts with a report from someone who can.
- **No server-side recovery.** Lose every unlock method and the data is lost
  to everyone, including the operator.
- **Quantum (A7).** Every public-key seal is classical (P-256) unless hybrid
  mode is on for every recipient. A copy of a database taken today could be
  opened by a large enough quantum computer, which does not yet exist. Hybrid
  mode protects only what is sealed after it is switched on, and an object is
  only as protected as its weakest member's copy of the key. Symmetric
  encryption (AES-256-GCM, HKDF, SHA-256) is not materially weakened.
- **Cooperative, not cryptographic:** session-generation "sign out
  everywhere" and link withdrawal are honoured by honest clients. Neither can
  take back a key that has already left.

## 3. `@microtoll/crypto-core`

- **Protects:**
  - Confidentiality and integrity of sealed bytes against A1, A2 and A6: AES-256-GCM with a leading version byte; recipient-bound, version-authenticated ECIES v3 (P-256) and v2 (X-Wing hybrid).
  - Domain separation of every derived key by label.
- **From whom:** A1, A2, A6. Against A7, only the v2 hybrid seal protects.
- **Does not protect:**
  - Anything once the caller mishandles keys.
  - Metadata such as sizes.
  - Anything against A8.
  - Recovery-code secrecy beyond its 128 bits of entropy. PBKDF2 at 310,000 iterations is not memory-hard; the entropy carries the security.
  - Hybrid mode is not "quantum-safe" until every recipient uses it (§2).
- **What each format refuses** (every row is a test in `packages/crypto-core/test/`):

  | Format | Refused, and how |
  |---|---|
  | AEAD v1 `[0x01][IV][ct‖tag]` | wrong key; any flipped bit in IV, ciphertext or tag; truncation; unknown version byte; additional data that differs or is missing — all fail at the GCM tag, before any plaintext is returned |
  | ECIES v3 `[0x03][ephemeral][AEAD]` | wrong recipient pair; the right private key with a swapped public half (the recipient is bound into the key); a relabelled version byte (authenticated as AAD); an ephemeral point off the curve; a blob from another namespace (the label is in the key); the retired v1 format, by name |
  | ECIES v2 `[0x02][KEM ct][AEAD]` | as v3, plus any flipped bit in the 1120-byte KEM ciphertext (the shared secret changes, then the tag fails); truncation; a v3 blob given to the v2 opener and the reverse |
  | Recovery code v3 | wrong length, an invalid character, a failed check character, non-zero padding bits — each with an error `code`; **every** single wrong character and **every** swap of two different characters fails the check; a random typo passes it with probability 1/32 and then fails lookup, never opens another account. A version-2 code is read only when asked for by name |

- **Misuse the API stops:** a bare private key where the pair is needed (`openWithPrivateKey`), a 32-byte "recipient key" (the retired X25519 length), a seed or key of the wrong length, a namespace missing or malformed, a retired label in any namespace, `hybridSealing` left off on a capable runtime (it stays classical; a capable browser never switches itself on).

- **Key material in memory:**
  - AES-GCM keys derived by HKDF or PBKDF2, the imported sealing private key and the session key are **non-extractable** `CryptoKey`s.
  - Ed25519: crypto-core's `importEd25519PrivateKeyFromSeed` returns an **extractable** key, because Web Crypto offers no other way to read the public half. The identity package, which owns the root key's lifetime, reads the public half once and holds its working routing and signing keys **non-extractable** (identity `FORMATS.md` §2.6). The raw root secret and the HKDF seeds still exist as bytes in JavaScript.
  - The hybrid KEM private key object is extractable as `raw-seed` (its seed is the HKDF output the identity package already holds).

- **Stability as a security property:** frozen fixtures (`test/fixtures/frozen-v1.json`, written once and never regenerated) must open and reproduce with every later version. A change that broke them would surface as a red test, not as silently unreadable data.

## 4. `@microtoll/identity`

- **Protects:**
  - The root key at rest against A1: wrapped only under a passkey PRF or a 128-bit recovery code; never stored in plaintext.
  - Unlinkability between the plaintext routing key and the person's identity keys against A1.
  - Independent unlock methods: removing one never locks out another, and the server refuses to remove the last.
  - Session key non-extractable by page script where the platform allows.
  - Step-up before sensitive changes.
- **From whom:** A1, A2, A6. A3 learns only public identity keys.
- **Does not protect:**
  - Against A8: the unlocked device, the browser profile, the root key and the HKDF seeds in page memory (the working Ed25519 keys are non-extractable, but the seed bytes they came from were in JavaScript).
  - The unauthenticated lookup, which returns the wrapped root key to anyone holding a credential id. That is safe only because the PRF output is secret.
  - The link between routing key and wrapped root key, which A1 can see (a locker number).
  - The existence and approximate age of accounts, and how often unlock methods changed (`session_generation`).
  - Step-up is client-side only.
- **What each stored item is bound to (formats version 2, and the label in version 3; every row is a test in `packages/identity/test/`):**

  | Item | Bound to | So that |
  |---|---|---|
  | Wrapped root key | method type + SHA-256(credential id) or the recovery lookup hash | a blob cannot be presented under another row or on the other unlock path |
  | Identity blob | the routing public key; carries a `revision` | it cannot be moved between accounts; a rollback is refused on a device that saw a later revision (cooperative) |
  | Unlock-method label | the method: its type, and SHA-256(credential id) for a passkey (version 3) | it cannot be shown against another method, even another passkey of the same account, so a person removing a method is not misled about which one; nor moved between accounts (another `K_master_symm`) |
  | Trusted-device session | routing key, expiry, session generation | an edited expiry or generation in a copied profile fails to open; a stored routing key that disagrees with the derived one is refused |
  | Handshake signature | `"<ns>/auth/v2"`, SHA-256(origin), the nonce | the signature is useless for another purpose, another deployment or another connection |

- **The recovery code: loss versus theft.** Loss of every unlock method loses the account for everyone; there is no server-side recovery, by design. Theft of the code opens the account from anywhere: it is 128 bits of entropy behind PBKDF2 (310,000 iterations, not memory-hard), so the entropy carries the security and the code must be kept like a key. Rotating it (a fresh proof first) cancels every old code in one server transaction and stales every other device's session.
- **Passkeys.** Used only as a PRF oracle; the server never sees or verifies an assertion, so a passkey's signature algorithm is irrelevant to the account's security. The "synced" flags an authenticator reports describe the kind of credential, not the live sync setting (measured on iOS), so the package reports `passkeyBackedUp` and the app must not claim more than "the phone reports a synced kind". A credential whose PRF is refused is disowned and never registered.
- **Step-up** proves the person, not the device, before adding or removing a method, rotating the code or deleting the account; a five-minute grace after a proof is bound to the account it proved, so switching to another account in the same tab inherits nothing. It is client-side: the server cannot ask for more than the connection already proves.
- **Deletion order and partial failure.** Confirm → prove → forget the session → the app's sweep of its own rows (while the capability secrets in its pointers still exist) → `delete-account` → the device's records. The sweep is the app's, best-effort step by step: a row it cannot reach is left, and the Privacy Notice must say what deletion does not reach (rows the account never held a secret for, sealed drops already in others' mailboxes, other members' decrypted copies). A failure before `delete-account` leaves the account intact and unlockable to finish the job.
- **Tested behaviours that close known failure modes:** an unreadable identity blob stops the unlock and nothing is written over it (a corrupt blob can never be silently replaced by a fresh one); the step-up grace is bound to the account it proved.
- **Still cooperative, stated plainly:** "sign out everywhere" (a generation counter honoured by honest clients), the blob revision (a device with no memory of a later revision accepts an older one), and the trusted session's expiry (enforced by the client that reads it, now with the expiry authenticated).

## 5. `@microtoll/access`

- **Protects:**
  - Object content against A1 and A6.
  - Second-tier payloads (two-tier disclosure) against anyone without a grant, including A3 and A5.
  - Authorship: a row whose signature fails is shown as unverified and never carries a name or identity.
  - A removed member cannot read writes made after rotation under the new key.
  - A revoked link cannot be redeemed again.
- **From whom:** A1, A5, A6, and A4 after rotation.
- **Does not protect:**
  - What A4 already saw, and anything written under the old key. Rotation protects the future only.
  - A5 holding the object key can read content and, by default, list named members through the derived read capability. **Where a link is posted is the real access control.**
  - Revoking a link does not remove access from anyone who already redeemed it; only removal (rotation) does.
  - Grant labels do not hide room membership from a link holder.
  - A1 can serve an older version of the same thing under the same key and epoch (an earlier edit): the additional authenticated data binds where a blob belongs, not which version it is.
- **Tested behaviours that close known failure modes:** the admin capability is replaced on every rotation and carried in padded seats, so a removed co-owner keeps no admin power; one grant rule serves both the sweep and rotation, so a rotation cannot hand the second tier to members the sweep would not; the server refuses a rotation at the wrong epoch or one that does not name every active row, and refuses content and row writes at the wrong epoch; a row that cannot have come from an honest client is set aside and never sealed to. Re-sealed invitations and withdrawn drops belong to the mailbox package (§7).

- **What each format binds (version 2; every row is a test in `packages/access/test/`):**

  | Item | Bound to | So that |
  |---|---|---|
  | Member-row signature | `"<ns>/sig/member-row/v2"`, object id, row id | a row cannot be lifted into another row or object and still verify |
  | Member-row seal | object id, row id (AAD) | a row's ciphertext cannot be presented under another row id, quiet and unsigned rows included |
  | Content, second tier | object id, epoch (AAD) | content cannot be moved between objects; a reader can assert the epoch it was told |
  | Pointer | the account's routing key (AAD) | a pointer cannot be moved to another account or confused with another blob under `K_master_symm`; the object it names is inside it, since the server returns pointers without an id |
  | Share-link payload | the token hash (AAD) and, when signed, `"<ns>/sig/share-link/v2"` + the token hash | a payload cannot be served under another link's hash; a signed payload cannot be re-wrapped in a fresh link as its creator's |
  | Admin box | object id, epoch (AAD) | a box from another object or epoch does not open |
  | Sealed copy of `K_object` per member | the recipient key and version (ECIES v3/v2) — **no additional data** | a server that moves it to another of the same member's rows gains nothing the member could not do; binding it would need an ECIES v4 |

- **The adversarial suite, mapped to its four requirements:**
  - *A removed member's old key cannot read post-rotation writes:* the new content, second tier and every re-sealed row and key are opened by remaining members and refused to the removed one; the server refuses the removed member's row write (`unauthorized`), a remaining member's write at the old epoch (`stale`), the old admin secret (`unauthorized`), a plan on the old epoch or missing a row (`stale`); a removed member's old signed row substituted under a remaining member's id is set aside, never sealed to.
  - *A revoked link cannot be redeemed:* `not-found` after revoke; `expired`; `exhausted` after N uses; stats only with the management secret; a recipient cannot revoke.
  - *An already-redeemed link is unaffected by revoke:* the holder still reads and lists the roster; and is cut off by a later rotation.
  - *A forged signature is flagged unverified:* a bit-flipped signature, a row lifted to another row id, a member signing with their own key while claiming another's; the display rule shows no name, status or keys for such a row; a quiet row carrying identity claims stays quiet, never verified.
  - *Holding the object never yields the second tier:* a `K_object`-only holder and a link holder get the preview only; the sweep grants "going" and admins, not "interested"; after a rotation only the owner, admins, `grantDue` rows and earlier grant holders open the new second tier; grant labels are object-scoped; a device holding only the preview cannot rotate a two-tier object.

- **Stated limits:** a link holder can list named members through the derived read capability unless the app's server enforces a responders-only roster; where a link is posted is the real access control. Rotation protects the future only. A quiet member's per-object key lives in their pointer; losing the pointer loses the object.

## 6. `@microtoll/blind-store`

- **Protects:**
  - The server holds only what it cannot read: opaque blobs, pointer rows with no object id, hashed capabilities, and hashed link tokens.
  - No identity columns, no creator columns, and no timestamps unless needed for expiry.
  - Random UUID keys.
  - Authorisation by capability, so writes do not reveal who made them.
- **From whom:** A1 (content), A6 (unauthorised writes).
- **Does not protect:**
  - The accepted trades, each to be listed exactly:
    - the coarse selector and window per item;
    - which selectors a connection queried;
    - the routing key × action × day in rate limits;
    - pointer counts per account;
    - timing and sizes;
    - push endpoints joining the subscriptions of one browser (if push is enabled).
  - Availability against A1.
  - Denial of service beyond the transport limits below.
- **The server's side** (`packages/blind-store/DESIGN.md`):
  - **What the server learns, exactly** (the trades above, spelled out). Per object: its collection, its selector and its window, its epoch, whether its roster is members-only, and the sizes of its sealed parts. Per connection: the routing key; the `Origin`; which selectors and windows it queried and watched, and when; one object id per `fetch-event` (a link redeemed, a pointer healed); which link hashes it redeemed, revoked or asked stats for; which mailbox labels it polled or watched. Per account: how many pointers and unlock methods it holds; its session generation and blob token (what changed, never when); and, in `rate_limit_counters`, that it made an object, a link or a drop today — the one table with a routing key beside an action, deleted after two days. Per link: uses, expiry, and its management hash. Everything else is ciphertext or a hash.
  - **What a database copy holds:** the above, plus sealed link payloads and drops until the sweep empties or deletes them (a used-up or expired link's payload at once; the link a week after expiry; a drop at expiry). Objects are never swept: what to keep is the app's decision. No key of any kind is in the database.
  - **The client obligations for cover traffic:** decrypt only what its pointers hold keys for; query the whole area it shows at a precision it fixes; never query by a list of ids; keep `fetch-event` for redeeming and healing. The engine cannot check these; the access package's `queryObjects` and the example app follow them.
  - **The schema rules as a test:** `test/schema.test.mjs` fails on a non-random primary key outside the whitelist, a sequence, a timestamp other than the two expiries, an identity-named column, a reference from objects, members, links or drops to `users`, or a hash column without a 32-byte check. A host runs it against its own tables.
  - **The database role:** the server connects as `blind_store_app`, which can read and write the eight tables and run the sweep, and can do no DDL, make no role and reach no other schema — so a compromise of the server process is a compromise of what the server can already read, and nothing more.
  - **The bound handshake (server half):** a signature made for another origin, another namespace or another nonce is refused; a non-browser client is verified against each allowed origin in turn; a browser's `Origin` is checked at upgrade and used for the verification.
  - **Transport limits:** frame 4 MiB, sign-in within 120 s, 300 messages per socket refilled 60 a second, 2,000 sockets, three unlock lookups per socket, per-field caps, a 5,000-row query answer. Each fails closed for one connection or request only. The per-address limits and the blanking of the client's address are the reverse proxy's (`deploy/nginx.sample.conf`): the server never holds an address beside a routing key.
  - **Live watches leak nothing new:** routing is by the selector a connection already sent; a member-row change is pushed content-free and debounced; the imminent watch carries no parameter at all.
  - **Availability** is not protected against A1 or against a determined flood: the limits are backstops, the daily counters fail open, and a lost LISTEN connection costs live updates (loudly logged, retried), not the service.

## 7. `@microtoll/mailbox`

- **Protects:**
  - A1 cannot compute a label (that needs one of the two private keys), attribute a row to an account, or read a bundle (sealed to the recipient, hybrid when the recipient's key is). Labels change monthly, so a stable polling fingerprint lasts at most two months.
  - A6 cannot forge an invitation from a named person: the bundle is signed, and (version 2, `packages/mailbox/FORMATS.md` §2) the signature binds the mailbox it is for and the recipient it is sealed to, so a bundle re-sealed into another mailbox or for another recipient verifies for nobody. The collection-side check — the signer must be the contact whose mailbox it arrived in — stays as a second lock.
  - Withdrawal: a consumed or withdrawn drop is served without its bundle and emptied in the row, so a client that ignores the flag still finds nothing to open.
- **From whom:** A1 (content and attribution), A6 (forgery), A3 (the mailbox needs the address, and the address needs a key only a co-member holds).
- **Does not protect:**
  - The routing graph: A1 sees that one anonymous label was written under and then read; with the connection's routing key, that this account polls these labels. It cannot pair the two ends without both private keys.
  - Linkage is classical (P-256 ECDH). Under A7, a former co-member could recover who invites whom. There is no standard post-quantum non-interactive key exchange; the bundle itself is hybrid where the recipient's key is.
  - Withdrawal reaches only a drop not yet collected; a collected key has left.
  - An unsigned drop is usable: the key in it either works or it does not. The engine attributes it to nobody; what the app does with it (a tray, a hold) is the app's.
  - Who is a contact, who is a favourite, who is blocked: the app's, in its identity blob.
- **Trades:** the labels a connection polls and watches (one per contact per month, two months deep); the daily count of drops per routing key; the row's expiry.

## 8. Review triggers

Update this document when any of these happen:
- a new format or label;
- a new plaintext column;
- a new pre-authentication message;
- a change to a default (selector precision, session length, iteration count);
- hybrid mode switched on;
- a browser shipping or withdrawing a primitive the engine relies on.
