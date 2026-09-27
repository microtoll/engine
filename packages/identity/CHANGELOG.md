# Changelog — @microtoll/identity

Until 1.0, the API may change in any minor release and every such change is
listed with a migration note; the bytes the package writes never change
meaning (DECISIONS.md D-04).

## 0.1.2 — 2026-09-27

`repository` added to package.json: npm refuses a provenance publish without it. 0.1.1 was tagged but never published, because its release run failed on that check; nothing else changed.

## 0.1.1 — 2026-09-27 (tagged, never published)

No change to the code or the formats. Published through the release workflow with npm provenance (launch item 8); 0.1.0 had been published by hand.

## 0.1.0 — 2026-09-27

The first release. The publish gate opened on 2026-09-27 (`DECISIONS.md`, D-01); every package is published in lockstep at 0.1.0 (D-41). The formats are frozen from this version (D-04).

### Version 3: labels bound to their method, and version-3 recovery codes (2026-09-27, D-46, D-47)
- **Format change (D-47):** an unlock method's sealed label is bound to that
  method, `frameContext("<ns>/aad/unlock-label/v3", methodType,
  SHA-256(credentialId))` for a passkey and the type alone for the recovery
  code (FORMATS.md §2.3). A server can no longer show one passkey's name
  against another passkey of the same account.
- **API change:** `labelContext(cc, method)` (now asynchronous),
  `sealMethodLabel(cc, masterSymmKey, method, label)` and
  `openMethodLabel(cc, masterSymmKey, method, sealed)` take the method
  (`{ type, credentialId }`) instead of the routing key, and refuse a routing
  key loudly; the `sealLabel` and `openLabel` callbacks of `registerAccount`,
  `addUnlockMethod`, `rotateRecoveryCode` and `listUnlockMethods` receive the
  method as a second argument. New, read-only: `labelContextV2` and
  `openMethodLabelV2` for a label written before this release.
  **Migration:** pass the method where the routing key was:
  `sealLabel: (label, method) => sealMethodLabel(cc, key, method, label)`.
- **Recovery codes are crypto-core's version 3 (D-46).**
  `lookupHashForEnteredCode` and `unwrapRootKeyWithRecoveryCode` take
  `{ recoveryCodeVersion: 2 }` to read a code written before this release;
  it is never tried as a fallback. **Migration:** none for new codes.
- The wrapped root key's binding, the unwrap keys and the lookup hash are
  unchanged. No version-2 label or code existed outside tests.
- Frozen: `test/fixtures/frozen-v3.json` (labels for two passkeys and the
  recovery code, and a root key wrapped for a version-3 code, for the
  frozen-v2.json account), written once by
  `test/tooling/generate-frozen-fixtures-v3.mjs`; frozen-v2.json still opens.

- Documentation and comments made self-contained; no change to behaviour or
  formats.
- Frozen version-2 fixtures (`test/fixtures/frozen-v2.json`) and the generator that wrote them; no format change.

### M2 (2026-09-25)
- The identity layer: the key hierarchy, unlock methods (passkey PRF and
  recovery code), the trusted-device session, the identity blob, the passkey
  ceremonies, the device's known-account record, and the account half of the
  server protocol, with the app's screens as callbacks (D-25).
- **Formats, version 2** (D-28, D-29; `FORMATS.md`): the wrapped root key is
  bound to its method type and identifier; the identity blob and the
  unlock-method label to the routing public key; the trusted-device session
  record to the routing key, expiry and generation; the handshake signature
  covers `"<ns>/auth/v2" ‖ SHA-256(origin) ‖ nonce`. The blob carries a
  cooperative `revision`; a rolled-back blob is refused on a device that saw
  a later one.
- Working Ed25519 keys are non-extractable (D-24 item 4).
- `createIdentitySession` carries the flows: guest, registration (both
  methods in one message), the three unlock paths, the trusted-session boot
  with the offline and stale cases, step-up bound to the account, the
  blob's compare-and-swap retry, lock, unlock-method management, the
  device-account match, and the deletion order with the app's sweep as a hook.
- Test tooling: an in-process stand-in for the server's account
  protocol (the wire contract `blind-store` keeps) and a scripted WebAuthn.
