# Identity demo

The M2 acceptance page: create, lock, restore and delete an identity using
only `@microtoll/crypto-core` and `@microtoll/identity`.

```
node examples/identity-demo/serve.mjs
```

Then open <http://localhost:8787/examples/identity-demo/>.

- The **server** is the identity package's in-process stand-in
  (`packages/identity/test/tooling/fakeServer.mjs`) running inside the page,
  until `@microtoll/blind-store` exists (M4). Reloading the page forgets every
  account on that "server"; the trusted-device session (IndexedDB) and the
  device record (localStorage) survive, so after a reload **Boot** restores
  the session and then reports `no-account`, which is the honest answer.
- **Passkeys** need a secure context (localhost counts) and an authenticator
  with the PRF extension: Windows Hello on Windows 11, Touch ID, Android, or
  Chrome's virtual authenticator (DevTools → WebAuthn, enable PRF). Where
  PRF is refused the page says `prf-unsupported`; use the recovery-code path.
- Nothing here is styled or worded for a product. It exists to show that the
  package's API is complete and that every flow works on a real browser.
