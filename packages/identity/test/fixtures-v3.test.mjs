// Frozen fixtures, version 3: the bytes this package wrote after D-46 and
// D-47 (test/tooling/generate-frozen-fixtures-v3.mjs, never regenerated),
// which every later version must open, and whose deterministic parts it must
// reproduce. The version-2 bytes are frozen-v2.json's, tested beside this in
// fixtures.test.mjs. Everything is checked through the package's public API.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '../src/index.js';

const fx = JSON.parse(readFileSync(new URL('./fixtures/frozen-v3.json', import.meta.url), 'utf8'));
const v2 = JSON.parse(readFileSync(new URL('./fixtures/frozen-v2.json', import.meta.url), 'utf8'));
const cc = createCryptoCore({ namespace: fx.namespace });
const H = cc.fromHex;
const flip = (hex, at) => { const b = H(hex); b[at] ^= 1; return b; };

/** The frozen account, the same person as frozen-v2.json's. */
async function frozenAccount() {
  const me = await id.identityFromRootKey(cc, H(v2.identity.rootKey));
  assert.equal(await id.adoptSealingKey(cc, me, { sealingKey: v2.identity.sealingKeyJwk }), true);
  return me;
}

const methods = {
  passkeyA: { type: id.METHOD_PASSKEY, credentialId: H(fx.methodLabels.passkeyA.credentialId) },
  passkeyB: { type: id.METHOD_PASSKEY, credentialId: H(fx.methodLabels.passkeyB.credentialId) },
  recoveryCode: { type: id.METHOD_RECOVERY, credentialId: null },
};

test('the label contexts, version 3, reproduce byte for byte: the label, the method type, SHA-256(credentialId) for a passkey (FORMATS.md §2.3)', async () => {
  assert.equal(fx.labels.unlockLabel, 'example/aad/unlock-label/v3');
  assert.equal(fx.methodLabels.passkeyA.credentialId, v2.passkeyMethod.credentialId, 'the same passkey as frozen-v2.json');
  const head = cc.toHex(new TextEncoder().encode(fx.labels.unlockLabel)) + '00';
  for (const [name, method] of Object.entries(methods)) {
    const frozen = fx.methodLabels[name].context;
    assert.equal(cc.toHex(await id.labelContext(cc, method)), frozen, name);
    assert.ok(frozen.startsWith(head), `${name}: the label heads the context`);
  }
  assert.equal(fx.methodLabels.passkeyA.context, head + '01' + cc.toHex(await cc.sha256(methods.passkeyA.credentialId)));
  assert.equal(fx.methodLabels.recoveryCode.context, head + '02', 'the type alone');
});

test('each frozen label opens against its own method only; moved to another method, another account or flipped, it reads as null (D-47)', async () => {
  const me = await frozenAccount();
  const other = await id.createIdentity(cc);
  for (const [name, entry] of Object.entries(fx.methodLabels)) {
    assert.equal(await id.openMethodLabel(cc, me.masterSymmKey, methods[name], H(entry.sealed)), entry.label, name);
    for (const [otherName, otherMethod] of Object.entries(methods)) {
      if (otherName !== name) assert.equal(await id.openMethodLabel(cc, me.masterSymmKey, otherMethod, H(entry.sealed)), null, `${name} shown as ${otherName}`);
    }
    assert.equal(await id.openMethodLabel(cc, other.masterSymmKey, methods[name], H(entry.sealed)), null, `${name}: another account`);
    assert.equal(await id.openMethodLabel(cc, me.masterSymmKey, methods[name], flip(entry.sealed, 20)), null, `${name}: a flipped byte`);
    // Never readable as a version-2 label either.
    assert.equal(await id.openMethodLabelV2(cc, me.masterSymmKey, me.routing.publicKeyRaw, H(entry.sealed)), null, `${name}: as version 2`);
  }
});

test('the root key wrapped for a version-3 recovery code opens with that code, typed as a person would (FORMATS.md §2.1, §2.8)', async () => {
  const r = fx.recoveryMethod;
  assert.equal(r.codeVersion, 3);
  assert.equal(await cc.formatRecoveryCode(H(r.codeBytes)), r.code);
  assert.equal(await id.lookupHashForEnteredCode(cc, r.code), r.lookupHash);
  assert.equal(await id.lookupHashForEnteredCode(cc, r.code.toLowerCase().replace(/-/g, ' ')), r.lookupHash, 'as a person might type it');
  assert.equal(r.context, cc.toHex(await id.unlockMethodContext(cc, id.METHOD_RECOVERY, H(r.lookupHash))), 'the wrap binding is version 2, unchanged');
  const method = { type: r.type, wrappedRootKey: H(r.wrappedRootKey), salt: H(r.pbkdf2Salt), lookupHash: r.lookupHash };
  assert.equal(cc.toHex(await id.unwrapRootKeyWithRecoveryCode(cc, method, r.code)), v2.identity.rootKey);
  await assert.rejects(id.unwrapRootKeyWithRecoveryCode(cc, { ...method, wrappedRootKey: flip(r.wrappedRootKey, 30) }, r.code), 'a flipped byte');
  // Every single mistyped character is refused before any lookup (D-46).
  const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const chars = r.code.replace(/-/g, '').split('');
  for (let i = 0; i < chars.length; i++) {
    const typo = chars.slice(); typo[i] = A[(A.indexOf(typo[i]) + 1) % 32];
    await assert.rejects(id.lookupHashForEnteredCode(cc, typo.join('')), (e) => e.code === 'recovery-code-checksum', `position ${i}`);
  }
  // Read as version 2 by name, the check character does not match (unless by one chance in 32).
  if (await cc.formatRecoveryCode(H(r.codeBytes), { version: 2 }) !== r.code) {
    await assert.rejects(id.lookupHashForEnteredCode(cc, r.code, { recoveryCodeVersion: 2 }), (e) => e.code === 'recovery-code-checksum');
  }
});
