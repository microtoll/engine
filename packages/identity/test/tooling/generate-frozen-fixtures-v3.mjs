// Writes test/fixtures/frozen-v3.json ONCE, and then never again.
//
//   node packages/identity/test/tooling/generate-frozen-fixtures-v3.mjs
//
// The version-3 bytes this package writes (DECISIONS.md D-46, D-47; FORMATS.md
// §2.3, §2.8), under the test namespace "example": the unlock-method labels
// bound to their own method, and a root key wrapped for a version-3 recovery
// code. Every later version must open them and reproduce every deterministic
// value in them. It refuses to overwrite the file. A NEW format gets a new
// entry beside the old ones (or a new file), never a regenerated one; the
// version-2 bytes stay in frozen-v2.json.
//
// The account is frozen-v2.json's (its root key and stored sealing key), so
// both files describe one person. Where a writer draws its own randomness
// (the recovery code and its salt), a stand-in for that one call supplies a
// fixed value; the construction around it is the package's. Random AEAD
// nonces stay random: those blobs are stored and must open.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '../../src/index.js';

const OUT = fileURLToPath(new URL('../fixtures/frozen-v3.json', import.meta.url));
if (existsSync(OUT)) {
  console.error(`${OUT} exists and is frozen. Nothing was written.`);
  process.exit(1);
}

const V2 = JSON.parse(readFileSync(new URL('../fixtures/frozen-v2.json', import.meta.url), 'utf8'));
const NAMESPACE = V2.namespace;
const cc = createCryptoCore({ namespace: NAMESPACE });
const hex = cc.toHex;

// Fixed inputs. Byte patterns rather than randomness, so a reader can see
// what went in. The first passkey is frozen-v2.json's credential.
const PASSKEY_A = cc.fromHex(V2.passkeyMethod.credentialId);                  // c0 … cf
const PASSKEY_B = Uint8Array.from({ length: 16 }, (_, i) => 0xd0 + i);        // d0 … df
const RECOVERY_CODE_BYTES = Uint8Array.from({ length: 16 }, (_, i) => (0x31 + i * 43) & 0xff);
const PBKDF2_SALT = Uint8Array.from({ length: 16 }, (_, i) => 0xf0 + i);      // f0 … ff

const me = await id.identityFromRootKey(cc, cc.fromHex(V2.identity.rootKey));
if (!await id.adoptSealingKey(cc, me, { sealingKey: V2.identity.sealingKeyJwk })) throw new Error('the frozen sealing key was not adopted');

const passkeyA = { type: id.METHOD_PASSKEY, credentialId: PASSKEY_A };
const passkeyB = { type: id.METHOD_PASSKEY, credentialId: PASSKEY_B };
const recoveryCode = { type: id.METHOD_RECOVERY, credentialId: null };

const out = {
  source: `Frozen by test/tooling/generate-frozen-fixtures-v3.mjs on 2026-09-27 under namespace "${NAMESPACE}". Never regenerated or edited.`,
  namespace: NAMESPACE,
  account: 'frozen-v2.json identity (root key and sealing key)',
  labels: {
    unlockLabel: cc.label('aad/unlock-label', 3),
  },
};

// --- §2.3 version 3: each label bound to its own method (D-47) -----------------
out.methodLabels = {
  passkeyA: { credentialId: hex(PASSKEY_A), context: hex(await id.labelContext(cc, passkeyA)), label: 'phone', sealed: hex(await id.sealMethodLabel(cc, me.masterSymmKey, passkeyA, 'phone')) },
  passkeyB: { credentialId: hex(PASSKEY_B), context: hex(await id.labelContext(cc, passkeyB)), label: 'laptop', sealed: hex(await id.sealMethodLabel(cc, me.masterSymmKey, passkeyB, 'laptop')) },
  recoveryCode: { context: hex(await id.labelContext(cc, recoveryCode)), label: 'paper in the drawer', sealed: hex(await id.sealMethodLabel(cc, me.masterSymmKey, recoveryCode, 'paper in the drawer')) },
};

// --- §2.1 with a version-3 recovery code (D-46) --------------------------------
// wrapRootKeyWithNewRecoveryCode draws the code and the salt itself; this
// stand-in answers those two draws with the fixed values above. The code is
// crypto-core's own formatting of the fixed bytes, in its current version.
if (cc.RECOVERY_CODE_VERSION !== 3) throw new Error('this file freezes recovery codes version 3');
const fixedDraws = {
  ...cc,
  generateRecoveryCode: async () => ({ secretBytes: RECOVERY_CODE_BYTES.slice(), displayString: await cc.formatRecoveryCode(RECOVERY_CODE_BYTES) }),
  randomBytes: (n) => {
    if (n !== PBKDF2_SALT.length) throw new Error(`unexpected draw of ${n} bytes`);
    return PBKDF2_SALT.slice();
  },
};
const { method: recovery, displayString } = await id.wrapRootKeyWithNewRecoveryCode(fixedDraws, me.rootKey, 'paper in the drawer');
out.recoveryMethod = {
  type: recovery.type,
  codeVersion: 3,
  codeBytes: hex(RECOVERY_CODE_BYTES),
  code: displayString,
  pbkdf2Salt: hex(recovery.salt),
  lookupHash: recovery.lookupHash,
  context: hex(await id.unlockMethodContext(cc, id.METHOD_RECOVERY, cc.fromHex(recovery.lookupHash))),
  wrappedRootKey: hex(recovery.wrappedRootKey),
};

writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log('wrote', OUT, Object.keys(out).join(', '));
