# @microtoll/identity

Sign-in and accounts without the server ever holding a key: one Account Root
Key per person, wrapped once per unlock method (a passkey, a recovery code),
a trusted-device session, a private settings blob, step-up for sensitive
actions, and a deletion order that leaves nothing behind. Web Crypto only;
depends only on `@microtoll/crypto-core`.

**Status:** published as `@microtoll/identity` on npm. Formats are version 2
(`FORMATS.md`); version 1 is not read.

## What the server learns

The routing public key (a locker number), one row per unlock method holding
ciphertext and a credential id or lookup hash, the sealed blob, a compare-and-
swap token and a generation counter. Never a key, a name, or when. The
server never verifies a passkey: WebAuthn is used only as a PRF oracle whose
32-byte output, through HKDF, unwraps the root key.

## Five-minute quickstart

```js
import { createCryptoCore } from '@microtoll/crypto-core';
import { createIdentitySession, createSessionStore, createKnownAccountStore, createWebAuthn } from '@microtoll/identity';

const cc = createCryptoCore({ namespace: 'myapp' });
const session = createIdentitySession({
  cryptoCore: cc,
  origin: location.origin,                                  // bound into the sign-in signature
  transport: { connect: () => openWebSocket('/ws') },       // your socket factory
  sessionStore: createSessionStore({ cryptoCore: cc }),     // IndexedDB "myapp-session"
  knownAccounts: createKnownAccountStore({ cryptoCore: cc }),
  webauthn: createWebAuthn({ rpName: 'My app' }),
  ui: {
    askRecoveryCode: async (reason) => promptUser(`Recovery code needed to ${reason}`),
    confirmDeletion: async () => confirmUser('Delete everything?'),
    passkeyName: (identity) => 'My app account',
  },
  hooks: {
    afterUnlock: (state) => showApp(state),
    onLocked: () => showGate(),
    beforeDeleteAccount: ({ ws, identity }) => deleteMyRows(ws, identity),   // while the keys still exist
  },
});

// First visit: browse as a guest, register when something is worth keeping.
if (!(await session.bootFromTrustedSession()).restored) await session.bootGuest();
const { recoveryCode } = await session.registerCurrentIdentity({ passkey: 'platform' });
showOnce(recoveryCode);                                      // the second way in; never stored

// Later, on the same device / a new browser / anywhere:
await session.unlockWithPasskey();
await session.unlockWithDiscoverablePasskey();
await session.unlockWithRecoveryCode(codeTyped);

// The private settings blob: read-modify-write under a compare-and-swap.
await session.saveIdentityBlob((blob) => ({ ...blob, theme: 'dark' }));

// Sensitive actions ask for a fresh proof of the person (5-minute grace).
await session.addPasskey({ label: 'laptop' });
const { recoveryCode: newCode } = await session.rotateRecoveryCode();
await session.signOutEverywhere();
await session.deleteAccount();
```

Lower layers are exported too (`wrapRootKeyWithPrf`, `openIdentityBlob`,
`createSessionStore`, `authenticateConnection`, …) for apps that need them.

The screens are the app's: the package asks through `ui` and `hooks`
and words nothing itself. Errors carry a `code` (`not-allowed`,
`prf-unsupported`, `identity-blob-unreadable`, `stale-session`,
`different-account`, …) and a `diagnostic` that never holds a secret.
Whatever the host's registration policy needs on the wire, such as terms or
age acceptance, comes from `hooks.registrationFields`; the package
stores no policy of its own. The `every-open` lock interval clears only the
session; clearing the app's own offline caches belongs in `hooks.onLocked`.

## The server side

The package speaks the account protocol of `@microtoll/blind-store`:
`challenge`/`auth`, `lookup-unlock-method` before sign-in, `register` with
every method in one transaction, the unlock-method messages,
`update-identity-blob` with a compare-and-swap, `bump-session-generation`,
`delete-account`. `test/tooling/fakeServer.mjs` is an in-process stand-in
that keeps the contract; the handshake signature verifies with
`verifyAuthSignature`.

## Threat model

`THREATMODEL.md` §4 at the repository root. In one line: the server and a
database copy learn nothing about the person; a compromised device or page
wins; a trusted-device session is as safe as the unlocked device it sits on;
"sign out everywhere" and the blob's revision are cooperative, not
cryptographic.
