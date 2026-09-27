# Changelog — @microtoll/crypto-core

All notable changes are listed here. Until 1.0, the API may change in any
minor release and every such change is listed with a migration note; the bytes
the package writes never change meaning (DECISIONS.md D-04).

## 0.1.0 — 2026-09-27

The first release. The publish gate opened on 2026-09-27 (`DECISIONS.md`, D-01); every package is published in lockstep at 0.1.0 (D-41). The formats are frozen from this version (D-04).

### Recovery code, version 3 (2026-09-27, D-46)
- **Format change:** new recovery codes are version 3. The check character is
  Σ aⁱ⁺¹·sᵢ over the 26 data characters in GF(32) = GF(2)[x]/(x⁵ + x² + 1),
  a = x: every single wrong character and every swap of two different
  characters is caught (version 2 caught each 31 times in 32). The parser
  also refuses non-zero padding bits and a 27th data character, so one
  string names one secret. The 16 bytes, the 27 characters and the grouping
  are unchanged.
- **API change:** `RECOVERY_CODE_VERSION` is 3; `formatRecoveryCode` and
  `parseRecoveryCode` take `{ version: 2 | 3 }` (default 3); new
  `RECOVERY_CODE_VERSIONS`. A version-2 code has the same shape as a
  version-3 one, so it is never tried as a fallback. **Migration:** none for
  new codes; to read a code written before this release, pass
  `{ version: 2 }`. No version-2 code existed outside tests.
- An invalid check character is now `recovery-code-char` (it was
  `recovery-code-checksum`).
- Frozen: `test/fixtures/frozen-recovery-v3.json` (eight codes, written once
  by `test/tooling/generate-frozen-recovery-v3.mjs`); the version-2 code in
  `frozen-v1.json` still reads with `{ version: 2 }`.

### Self-contained documentation and frozen fixtures (2026-09-27)
- Documentation and comments made self-contained; no change to behaviour or
  formats.
- **API change:** the iteration-count constant is renamed
  `DEFAULT_PBKDF2_ITERATIONS` (same value, 310,000), and the preset profile
  export is removed. **Migration:** `createProfile({ namespace: '<yours>' })`.
- The frozen fixtures are now written by this package itself
  (`test/tooling/generate-frozen-fixtures.mjs` → `test/fixtures/frozen-v1.json`,
  namespace `example`) and refuse to be regenerated. They pin AEAD v1, ECIES
  v3 and v2, every labelled derivation from a fixed root, Ed25519 signatures,
  the recovery-code envelope, the URL-token key, the read capability, the
  detail-grant label (the NUL byte) and the mailbox label.
- README quickstart: `generateRecoveryCode()` is awaited (it returns a
  promise since the version-2 check character).

### Mailbox support (M3b, 2026-09-25)
- `deriveSealingSharedBits(privateKey, otherPublicKeyRaw)`: the 256-bit
  P-256 ECDH agreement between two long-term sealing keys, which the mailbox
  package feeds to HKDF for a pairwise mailbox label. The same agreement the
  ECIES seal already performs with an ephemeral key; no new construction.

### Recovery-code format v2 (2026-09-25)
- **Format change (D-26):** the recovery code's check character is now the
  Crockford digit of the low five bits of SHA-256(secret)[0], replacing the
  sum of the bytes mod 32, which missed an error confined to a byte's top
  three bits. Entropy, length and grouping unchanged. **Migration:**
  `generateRecoveryCode`, `formatRecoveryCode` and `parseRecoveryCode` return
  promises; `RECOVERY_CODE_VERSION` is exported as `2`.

### M1 (2026-09-25)
- The label profile (D-05), ECIES v3 and the hybrid ECIES v2 with the
  post-quantum master switch (off by default, D-07), `sealToRecipient`
  dispatch by key length, the recovery-code format,
  `generateNonExtractableSymmetricKey`.
- `createCryptoCore({ namespace, hybridSealing, pbkdf2Iterations })` returns
  a frozen instance carrying the primitives plus the label-bound functions.
- Test tooling (never in `src/`): an X-Wing composition and an
  `MLKEM768-X25519` platform shim, gated by the draft-10 and working-group
  vectors.
- 77 tests, all through the public API.

### Groundwork (M1, 2026-09-25)
- Package skeleton: zero runtime dependencies, `node:test` tests, hand-written
  type declarations checked with `tsc`.
- Format-independent primitives: byte and encoding helpers, HKDF-SHA-256,
  the Ed25519 PKCS#8 seed wrapper, the stored P-256 sealing key, AEAD v1
  (`[0x01][IV][ciphertext‖tag]`), PBKDF2-SHA-256.
- Published-vector tests through the public API: RFC 5869 (HKDF test cases 1
  and 3), RFC 8032 (Ed25519 tests 1, 2, 3 and SHA(abc)), RFC 5903 §8.1
  (P-256 ECDH), RFC 7914 §11 (PBKDF2-HMAC-SHA-256), NIST CAVP AES-256-GCM.
- Property tests: AEAD round trips, tamper detection, IV uniqueness.
