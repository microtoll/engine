# @microtoll/identity — formats and the hardening design (M2, D-24)

**Status:** decided 2026-09-25 (DECISIONS.md D-28, D-29): the design below is
what M2 builds. Two items moved to version 3 on 2026-09-27 (D-46, D-47; §2.8):
the unlock-method label's binding and the recovery code's check character.
The package writes those in version 3 and everything else in version 2; it
reads a version-2 label or code only when a caller asks for it by name.

## 1. What version 1 left unbound

Version 1 is described here only to explain why version 2 exists and why a
version-1 record is not read.

| Item | Where it lives | How it is made | Bound to |
|---|---|---|---|
| Wrapped root key | `user_unlock_methods.wrapped_root_key` (one row per unlock method) | AEAD v1 of the 32-byte root key under the method's unwrap key: HKDF(PRF output, `<ns>/envelope/prf/v1`) or PBKDF2(recovery bytes, salt, 310,000) | **nothing** |
| Unlock-method label | `user_unlock_methods.encrypted_label` | AEAD v1 of the UTF-8 label under `K_master_symm` | nothing |
| Identity blob | `users.encrypted_identity_blob` | AEAD v1 of JSON under `K_master_symm`; compare-and-swap by a 16-byte random token | nothing |
| Trusted-device session | IndexedDB record `{v:1, sessionKey, wrappedRootKey, routingPublicKey, unlockedAt, expiresAt, sessionGeneration}` | AEAD v1 of the root key under a fresh non-extractable AES key kept beside it | nothing; the plaintext fields beside it are unauthenticated |
| Handshake | `auth {routingPublicKey, signature}` | Ed25519 by the routing key over the **bare 32-byte nonce** | nothing: no purpose label, no origin |
| Recovery lookup | `user_unlock_methods.recovery_lookup_hash` | HKDF(recovery bytes, `<ns>/recovery-lookup/v1`) | — (unchanged) |

Consequences, all within the threat model's A1 (the server or a database
copy) and A8 (a copied browser profile):

- A wrapped root key can be moved between unlock-method rows, or a passkey
  row's blob served in answer to a recovery lookup. It still needs the right
  unwrap secret to open, so this is a confusion, not a break.
- An identity blob or a label from account X could be served to account Y's
  device. It would fail to open (different `K_master_symm`), so again a
  confusion. But a **rolled-back** blob from the same account opens fine and
  is indistinguishable from current.
- A copied session record's plaintext `routingPublicKey`, `expiresAt` and
  `sessionGeneration` can be edited without the wrapped key noticing: an
  expiry pushed into the future, a generation raised to defeat "sign out
  everywhere". Cooperative checks, so the harm is bounded, but the record
  claims more than it proves.
- The handshake signature is over 32 random bytes with nothing else. If the
  routing key ever signed anything else in another context, or a nonce from
  another site's server were relayed, the signature would be replayable
  across contexts. Today the routing key signs nothing else, so this is the
  least urgent item, and the cheapest to fix.

## 2. The hardening (version 2), item by item

Every change below adds binding to an existing construction using
primitives crypto-core already has (`frameContext`, `sha256`, AEAD v1's
additional authenticated data). No primitive, mode or KDF changes. Version
numbers are carried in the profile label of each context, so a reader knows
what it is opening and a v1 blob can never be mistaken for v2.

### 2.1 AAD on the wrapped root key

```
context  = frameContext(profile.label('aad/unlock-method', 2), methodType, methodId)
methodType = 0x01 passkey-prf | 0x02 recovery-code                      (1 byte)
methodId   = SHA-256(credentialId)  for passkey-prf                    (32 bytes)
           = recovery lookup hash   for recovery-code                  (32 bytes)
wrapped    = sealSymmetric(unwrapKey, rootKey, context)
```

Both identifiers are known **before** unwrapping: the credential id comes
from the device's record or the discoverable assertion, and the lookup hash
from the entered code. The credential id is hashed because it is variable
length and `frameContext` takes fixed-length parts only.

Effect: a blob from one row cannot be presented as another, and a passkey
blob cannot be served on the recovery path or the reverse.

### 2.2 AAD on the identity blob

```
context = frameContext(profile.label('aad/identity-blob', 2), routingPublicKey)   (32 bytes)
```

The routing key is derived from the root key, so it is known when the blob
is opened. Effect: a blob cannot be moved between accounts.

**Rollback (optional, recommended):** the blob's plaintext gains a
`revision` integer that every writer increments. The device keeps the last
revision it saw beside its known-account record; a blob that opens with a
lower revision is refused with `identity-blob-rolled-back`. This is a
behaviour addition, not a format change, and it is cooperative (a wiped
device has no memory), but it turns a silent rollback into a loud one on
every device that was there. **It is not part of the format decision;** it is
listed so the decision is taken knowing AAD alone does not stop rollback.

### 2.3 AAD on the unlock-method label (version 3 since D-47)

Version 2, read only (`labelContextV2`, `openMethodLabelV2`):

```
context = frameContext(profile.label('aad/unlock-label', 2), routingPublicKey)
```

Effect: a label cannot be moved between accounts, which the account's own
key already ensured. It did **not** stop the server showing one passkey's
label against another passkey of the same account, the case that misleads a
person choosing which method to remove. Version 3, written since D-47
(`labelContext`, `sealMethodLabel`, `openMethodLabel`):

```
context = frameContext(profile.label('aad/unlock-label', 3), methodType, methodId)
methodType = 0x01 passkey-prf | 0x02 recovery-code                      (1 byte)
methodId   = SHA-256(credentialId)  for passkey-prf                    (32 bytes)
           = nothing                for recovery-code
```

The binding matches the wrapped root key's (§2.1), except that a recovery
code is bound by its type alone: the method listing carries no lookup hash
to bind to, and an account holds one recovery code at a time. Effect: a
label shown against any method but its own reads as null.

### 2.4 The trusted-device session record, version 2

```
context = frameContext(profile.label('aad/session', 2), routingPublicKey, u64be(expiresAt), u32be(sessionGeneration or 0))
record  = { v: 2, sessionKey, wrappedRootKey: sealSymmetric(sessionKey, rootKey, context),
            routingPublicKey, unlockedAt, expiresAt, sessionGeneration }
```

The three plaintext fields that decide whether the record may open are now
authenticated by the wrapped key. Editing `expiresAt` or `sessionGeneration`
in the profile makes the record fail to open (and be deleted). On restore the
package also derives the routing key from the recovered root key and refuses
a record whose stored key differs, so an edited routing key cannot pass the
record off as another account's. Needs one new crypto-core helper, `u64be`,
for the millisecond timestamp.

`unlockedAt` stays unauthenticated: nothing decides on it.

### 2.5 The handshake signature

```
message   = frameContext(profile.label('auth', 2), SHA-256(UTF-8(origin)), nonce)     (32 + 32 bytes)
signature = Ed25519(routingPrivateKey, message)
```

- `origin` is the web origin the client believes it is talking to
  (`location.origin` in a browser; passed explicitly in Node). The server
  verifies against its configured allowed origins, trying each.
- The label ties the signature to this purpose and this app; the origin ties
  it to this deployment; the nonce ties it to this connection.
- **Mirrored:** the client half ships in `@microtoll/identity` (M2); the
  server half in `@microtoll/blind-store` (M4), with a cross-implementation
  test that a browser-side signature verifies under Node. Until M4,
  identity's tests verify the message with crypto-core's own `verifyBytes`.

### 2.6 Non-extractable signing keys (D-24 item 4; already decided)

```
seed → import pkcs8 (extractable) → export JWK → public key
     → import pkcs8 again, extractable: false → the working key
```

The outputs do not change (the fixture signatures still match). The routing
and identity-signing working keys become non-extractable; the raw root key
and the HKDF seeds still exist as bytes in JavaScript, which the threat model
states. The seed bytes are zeroed after the second import (best effort; a
`Uint8Array.fill(0)` — JavaScript gives no stronger guarantee).

### 2.7 Unchanged

- The recovery lookup hash and its label (a version-3 code decodes to the
  same 16 bytes as before; only its check character differs, §2.8).
- PBKDF2 parameters and the PRF derivation label.
- The `register` message with both unlock methods in one transaction
  (already atomic in version 1).
- The open, pre-authentication `lookup-unlock-method` (D-20; the server
  caps its answers per connection, so one connection cannot harvest wrapped
  root keys in bulk).
- Session length (30 days), lock intervals, the step-up grace (5 minutes,
  bound to the account) and the deletion order.

### 2.8 Version 3 (2026-09-27, D-46 and D-47)

- **The unlock-method label** is bound to its own method (§2.3).
- **The recovery code** a person writes down is crypto-core's version 3
  (D-46): 16 bytes in Crockford base32 (26 characters) and a check
  character Σ aⁱ⁺¹·sᵢ over GF(32) = GF(2)[x]/(x⁵ + x² + 1), a = x. Every
  single wrong character and every swap of two different characters is
  caught before the lookup, and the two unused bits must be zero, so one
  string names one secret. Version 2's check (SHA-256-derived, D-26) caught
  each such error only 31 times in 32, and the rest failed later as "no such
  account".
- **Reading version 2.** A version-2 and a version-3 code have the same
  shape, and a label carries no version byte, so neither can be recognised
  by looking at it; trying version 2 after version 3 would give back what
  version 3 closes. Version 2 is therefore read only when a caller names it:
  `{ recoveryCodeVersion: 2 }` on `lookupHashForEnteredCode` and
  `unwrapRootKeyWithRecoveryCode`, and `openMethodLabelV2`. No version-2 code
  or label exists outside tests.
- Nothing else changes: the wrapped root key's binding (§2.1), the unwrap
  keys, PBKDF2 and the lookup hash are as in version 2.

## 3. Frozen fixtures

The crypto-core frozen fixtures (`crypto-core/test/fixtures/frozen-v1.json`)
pin the primitives and derivations underneath: their version-1 envelopes
still open, which proves the unwrap keys are unchanged and only the binding
is new. The identity package's tests pin every version-2 context byte for
byte, and `test/fixtures/frozen-v2.json` holds version-2 bytes this package
wrote (both wrapped root keys, the method labels, two identity-blob
revisions, two session records and the handshake message), which every
later version must open and reproduce. `test/fixtures/frozen-v3.json` holds
the version-3 bytes for the same account (labels bound to two passkeys and
the recovery code, and a root key wrapped for a version-3 code), and
crypto-core's `test/fixtures/frozen-recovery-v3.json` pins eight version-3
codes.

## 4. Package shape (for orientation; the API review is at M2 acceptance)

```js
import { createCryptoCore } from '@microtoll/crypto-core';
import { createIdentity } from '@microtoll/identity';

const cc = createCryptoCore({ namespace: 'myapp' });
const identity = createIdentity({
  cryptoCore: cc,
  origin: location.origin,                    // for the handshake binding
  transport,                                  // { connect(): ws } — the app's WebSocket factory
  storage: { session, knownAccount },         // adapters; browser defaults use IndexedDB + localStorage
  webauthn,                                   // the package's own, or a stub in tests
  ui: { askRecoveryCode, confirmDeletion, showRecoveryCode, status },
  hooks: { beforeDeleteAccount, afterUnlock, onLocked, registrationPolicy },
});
```

The package ends at "an authenticated connection, the `auth-ok` fields, the
opened blob, the adopted sealing key" (D-11). Everything after that is the
app's. Wire message names are fixed (D-27).
