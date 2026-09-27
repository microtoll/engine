// Shared helpers: a crypto-core instance, identities with accounts on the
// fake server (extended with the object protocol), and an access instance
// with the choices an example app would make (an event with a hidden address).
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '@microtoll/identity';
import { createFakeServer } from '../../identity/test/tooling/fakeServer.mjs';
import { objectProtocol } from './tooling/objectServer.mjs';
import { createAccess, goingGrantDue, flag, oneOf } from '../src/index.js';

export const cc = createCryptoCore({ namespace: 'example' });
export const ORIGIN = 'https://example.test';
export const utf8 = (s) => new TextEncoder().encode(s);
export const text = (b) => new TextDecoder().decode(b);

/** Example app choices: a status mirror in the pointer, an address split, the package's example grant rule. */
export function makeAccess(extra = {}) {
  return createAccess({
    cryptoCore: cc,
    pointerFields: { myStatus: { wire: 'myStatus', ...oneOf(['going', 'interested', 'not going']) }, pushSubscribed: { wire: 'pushSubscribed', ...flag } },
    split: (content) => {
      const { address, ...preview } = content;
      return { preview: { ...preview, locationIsApproximate: true }, detail: { address } };
    },
    // The pair of the split above: the detail wins, and the preview's "approximate" mark goes.
    merge: (preview, detail) => { if (!detail) return preview; const m = { ...preview, ...detail }; delete m.locationIsApproximate; return m; },
    grantDue: goingGrantDue,
    ...extra,
  });
}

export function makeServer() {
  return createFakeServer({ cryptoCore: cc, allowedOrigins: [ORIGIN], extensions: [objectProtocol] });
}

/** An identity with an account on the server and an authenticated socket. */
export async function person(server, { account = true } = {}) {
  const identity = await id.createIdentity(cc);
  const ws = await server.connect();
  await id.authenticateConnection(cc, ws, identity.routing, ORIGIN);
  if (account) {
    const { method } = await id.wrapRootKeyWithNewRecoveryCode(cc, identity.rootKey);
    const blob = await id.sealIdentityBlob(cc, identity, id.buildIdentityBlobPlaintext(cc, identity, {}));
    await id.registerAccount(cc, ws, identity, blob, [method], { sealLabel: async () => new Uint8Array(0) });
  }
  return { identity, ws };
}

