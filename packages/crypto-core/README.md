# @microtoll/crypto-core

The primitives and wire formats of the Microtoll Engine. Web Crypto
(`SubtleCrypto`) only; no runtime dependencies; runs in current browsers and
Node ≥ 24.

**Status:** published as `@microtoll/crypto-core` on npm. Every format is pinned by frozen
fixtures (`test/fixtures/frozen-v1.json`) that each later version must open.

## Five-minute quickstart

```js
import { createCryptoCore } from '@microtoll/crypto-core';

// One instance per app. The namespace prefixes every derivation label, so no
// two apps ever share a key derivation by accident. It is required.
const cc = createCryptoCore({ namespace: 'myapp' });

// A 32-byte root secret, and keys derived from it under labelled purposes.
const root = cc.generateSymmetricKey();
const routingSeed = await cc.deriveBits(root, 'routing');          // HKDF, label "myapp/routing/v1"
const signingKey  = await cc.importEd25519PrivateKeyFromSeed(routingSeed);
const ownDataKey  = await cc.deriveAesKey(root, 'symm');           // AES-256-GCM, non-extractable

// Symmetric sealing: [0x01][12-byte IV][ciphertext ‖ tag], optional bound context.
const sealed = await cc.sealSymmetric(ownDataKey, new TextEncoder().encode('hello'));
const opened = await cc.openSymmetric(ownDataKey, sealed);

// Sealing to another person: they hold a P-256 key pair stored as a JWK.
const alice = await cc.generateSealingKeyPair();                    // { privateKey, publicKeyRaw, jwk }
const forAlice = await cc.sealToRecipient(alice.publicKeyRaw, opened);
const back = await cc.openWithPrivateKey(alice, forAlice);          // needs the pair, not a bare key

// A recovery code a person can write down: 128 bits, Crockford base32, checksum.
const { secretBytes, displayString } = await cc.generateRecoveryCode(); // "ABCD-EFGH-…-XYZ"
const unwrapKey = await cc.deriveAesKeyFromSecret(secretBytes, cc.randomBytes(16)); // PBKDF2, 310,000 iterations
```

Stateless primitives are also exported directly (`hkdfDeriveBits`,
`sealSymmetric`, `verifyBytes`, the encoders); everything derived under a
label lives on the instance.

## What is here

- **Encoding helpers:** hex, base64url, Crockford base32, and the
  fixed-length frame `context ‖ 0x00 ‖ parts` for bound contexts.
- **HKDF-SHA-256** (RFC 5869) in one shape: empty salt, the label as info.
- **Ed25519** from a 32-byte seed through the RFC 8410 PKCS#8 wrapper; sign
  and verify (verify returns `false`, never throws).
- **The stored P-256 sealing key**: generated once, kept as a private JWK,
  imported non-extractable. Stored rather than derived because Safari has no
  X25519 and Firefox cannot import a P-256 private key from a bare scalar.
- **AEAD v1:** `[0x01][12-byte IV][AES-256-GCM ciphertext ‖ tag]`, optional
  additional authenticated data.
- **ECIES v3:** `[0x03][65-byte ephemeral P-256 point][AEAD v1]`, key =
  HKDF(ECDH secret, `"<ns>/ecies/v3"` ‖ SHA-256(ephemeral ‖ recipient)),
  version byte authenticated. The retired X25519 v1 format is refused by name.
- **ECIES v2, hybrid post-quantum:** `[0x02][1120-byte MLKEM768-X25519
  ciphertext][AEAD v1]`, same binding. **Off by default** (`hybridSealing:
  false`): it needs a browser with native `MLKEM768-X25519` (Chrome 154+) and
  has not yet been cross-checked against one. In tests it runs through a
  test-only X-Wing composition verified against the draft's vectors.
- **PBKDF2-SHA-256** and the **recovery-code format, version 3** (D-46): 16
  bytes in Crockford base32 plus a weighted check character over GF(32)
  (`XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXX`). Every single wrong character and
  every swap of two characters is caught; a random typo, 31 times in 32.
  Version 2 (a SHA-256-derived check) is read only with `{ version: 2 }`.
- **The label profile:** `createProfile({ namespace })`, `<namespace>/<purpose>/v<n>`;
  retired labels are refused in every namespace. `DEFAULT_PBKDF2_ITERATIONS`
  is 310,000.

## Tests

`npm test` at the repository root. Published vectors run through this
package's own API: RFC 5869 (test cases 1 and 3), RFC 8032 (tests 1, 2, 3,
SHA(abc)), RFC 5903 §8.1, RFC 7914 §11, NIST CAVP AES-256-GCM, and X-Wing
draft-10 Appendix C plus the working-group `MLKEM768-X25519` vector. Then
property and tamper tests, and the frozen fixtures.

## Threat model

See `THREATMODEL.md` §3 at the repository root. In one line: this package
protects sealed bytes against the server, the network and strangers; it
protects nothing against a compromised device or page, and its classical seal
is not quantum-safe.

## Notes on the API

- **Labels come from a namespace profile** (DECISIONS.md D-05), never from
  constants an app could edit in place; retired labels are refused in every
  namespace.
- **The post-quantum switch is an instance option** (`hybridSealing`, off by
  default, D-07); the test seams are `_setHybridSealing` and
  `_resetHybridSupport`.
- **`pbkdf2DeriveBits`** is exposed so the RFC 7914 vectors run through the
  package; `deriveAesKeyFromSecret` takes its iteration count from the
  profile.
- **`randomBytes(length)`** is chunked past Web Crypto's 65,536-byte limit;
  `generateSymmetricKey` gives 32 random bytes, and the identity and access
  packages name its uses (root key, capability secret).
- **`fromHex` rejects non-hex characters** instead of decoding them as zero.
- **The recovery-code check character is version 3** (D-46): Σ aⁱ⁺¹·sᵢ over
  the 26 data characters in GF(32) = GF(2)[x]/(x⁵ + x² + 1), a = x, and the
  parser refuses non-zero padding bits, so one string names one secret. A
  version-2 code (D-26) looks the same, so it is never tried as a fallback:
  pass `{ version: 2 }` to read one. `formatRecoveryCode` and
  `parseRecoveryCode` stay asynchronous, because version 2 needs SHA-256.
  Errors carry a `code` (`recovery-code-checksum`, …) for the app to word.
- **Not in this package** (they live in identity, access or mailbox): the
  root-key envelopes, the recovery lookup hash, the URL-token and capability
  helpers, the handshake signature and the mailbox label. Their primitive-level
  fixtures are in `test/fixtures/frozen-v1.json` for those packages' tests.
