// Unlock methods (v2, D-28): wrap and unwrap by PRF and by recovery code,
// independence of methods, the binding to method type and identifier.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createCryptoCore } from '@microtoll/crypto-core';
import * as id from '../src/index.js';

const fx = JSON.parse(readFileSync(new URL('../../crypto-core/test/fixtures/frozen-v1.json', import.meta.url), 'utf8'));
const cc = createCryptoCore({ namespace: fx.namespace });
const H = cc.fromHex;
const ROOT = cc.generateSymmetricKey();

test('the unwrap derivations are frozen: PRF via HKDF label, recovery via PBKDF2, lookup hash via its own label', async () => {
  // Proved against the version-1 fixture blobs, which carry no AAD: the keys are the same, only the binding is new.
  const prfKey = await id.deriveUnwrapKeyFromPrf(cc, H(fx.envelopes.prfOutput));
  assert.equal(cc.toHex(await cc.openSymmetric(prfKey, H(fx.envelopes.wrappedByPrf))), fx.envelopes.rootKey);
  const codeKey = await id.deriveUnwrapKeyFromRecoveryCode(cc, H(fx.envelopes.recoveryCodeBytes), H(fx.envelopes.pbkdf2Salt));
  assert.equal(cc.toHex(await cc.openSymmetric(codeKey, H(fx.envelopes.wrappedByRecoveryCode))), fx.envelopes.rootKey);
  assert.equal(await id.deriveRecoveryLookupHash(cc, H(fx.envelopes.recoveryCodeBytes)), fx.envelopes.recoveryLookupHash);
});

test('PRF path: wrap, unwrap, wrong PRF output refused, wrong credential id refused (the binding)', async () => {
  const prf = cc.randomBytes(32), credentialId = cc.randomBytes(20), salt = cc.randomBytes(32);
  const method = await id.wrapRootKeyWithPrf(cc, ROOT, prf, credentialId, salt, 'phone');
  assert.equal(method.type, 'passkey-prf');
  assert.equal(method.wrappedRootKey.length, 1 + 12 + 32 + 16);
  assert.deepEqual(await id.unwrapRootKeyWithPrf(cc, method, prf), ROOT);
  await assert.rejects(id.unwrapRootKeyWithPrf(cc, method, cc.randomBytes(32)), 'wrong PRF');
  await assert.rejects(id.unwrapRootKeyWithPrf(cc, { ...method, credentialId: cc.randomBytes(20) }, prf), 'moved to another credential');
  await assert.rejects(id.unwrapRootKeyWithPrf(cc, { ...method, type: 'recovery-code' }, prf), /called with/);
});

test('recovery path: a fresh code wraps, the display string unwraps, a wrong code and a moved blob are refused', async () => {
  const { method, displayString } = await id.wrapRootKeyWithNewRecoveryCode(cc, ROOT, 'code');
  assert.equal(method.type, 'recovery-code');
  assert.equal(method.salt.length, 16);
  assert.equal(method.lookupHash.length, 64);
  assert.equal(await id.lookupHashForEnteredCode(cc, displayString.toLowerCase()), method.lookupHash);
  assert.deepEqual(await id.unwrapRootKeyWithRecoveryCode(cc, method, displayString), ROOT);
  const other = await id.wrapRootKeyWithNewRecoveryCode(cc, ROOT, 'other');
  await assert.rejects(id.unwrapRootKeyWithRecoveryCode(cc, method, other.displayString), 'wrong code');
  // The same blob served under another code's lookup hash: the AAD refuses it even before the key is wrong.
  await assert.rejects(id.unwrapRootKeyWithRecoveryCode(cc, { ...method, lookupHash: other.method.lookupHash }, displayString));
  await assert.rejects(id.lookupHashForEnteredCode(cc, 'ABCD-EFGH'), (e) => e.code === 'recovery-code-length');
});

test('two methods wrap the SAME root key independently; each unwraps alone', async () => {
  const prf = cc.randomBytes(32);
  const a = await id.wrapRootKeyWithPrf(cc, ROOT, prf, cc.randomBytes(16), cc.randomBytes(32));
  const { method: b, displayString } = await id.wrapRootKeyWithNewRecoveryCode(cc, ROOT);
  assert.notEqual(cc.toHex(a.wrappedRootKey), cc.toHex(b.wrappedRootKey));
  assert.deepEqual(await id.unwrapRootKeyWithPrf(cc, a, prf), ROOT);
  assert.deepEqual(await id.unwrapRootKeyWithRecoveryCode(cc, b, displayString), ROOT);
});

test('the binding context is frozen: type byte and identifier under "<ns>/aad/unlock-method/v2"', async () => {
  const credentialId = new Uint8Array([1, 2, 3]);
  const ctx = await id.unlockMethodContext(cc, 'passkey-prf', credentialId);
  const expected = cc.concatBytes(new TextEncoder().encode('example/aad/unlock-method/v2'), new Uint8Array([0, 1]), await cc.sha256(credentialId));
  assert.equal(cc.toHex(ctx), cc.toHex(expected));
  const lookup = cc.randomBytes(32);
  const ctx2 = await id.unlockMethodContext(cc, 'recovery-code', lookup);
  assert.equal(cc.toHex(ctx2), cc.toHex(cc.concatBytes(new TextEncoder().encode('example/aad/unlock-method/v2'), new Uint8Array([0, 2]), lookup)));
  await assert.rejects(id.unlockMethodContext(cc, 'other', lookup), /unknown/);
  await assert.rejects(id.unlockMethodContext(cc, 'recovery-code', new Uint8Array(31)), /32 bytes/);
});

test('the label context, version 3 (D-47): the label, then the method type, then SHA-256(credentialId) for a passkey', async () => {
  const credentialId = cc.randomBytes(20);
  const head = new TextEncoder().encode('example/aad/unlock-label/v3');
  assert.equal(cc.toHex(await id.labelContext(cc, { type: 'passkey-prf', credentialId })),
    cc.toHex(cc.concatBytes(head, new Uint8Array([0, 1]), await cc.sha256(credentialId))));
  assert.equal(cc.toHex(await id.labelContext(cc, { type: 'recovery-code', credentialId: null })),
    cc.toHex(cc.concatBytes(head, new Uint8Array([0, 2]))));
  await assert.rejects(id.labelContext(cc, { type: 'other' }), /unknown/);
  await assert.rejects(id.labelContext(cc, { type: 'passkey-prf', credentialId: null }), /credential id/);
  // The version-2 call shape (a routing key) is refused loudly, not misread.
  await assert.rejects(id.labelContext(cc, cc.randomBytes(32)), /since version 3/);
  await assert.rejects(id.sealMethodLabel(cc, (await id.createIdentity(cc)).masterSymmKey, cc.randomBytes(32), 'x'), /since version 3/);
});

test('method labels are sealed under K_master_symm and bound to their own method; one moved to another method reads as null', async () => {
  const me = await id.createIdentity(cc);
  const other = await id.createIdentity(cc);
  const laptop = { type: 'passkey-prf', credentialId: cc.randomBytes(16) };
  const phone = { type: 'passkey-prf', credentialId: cc.randomBytes(16) };
  const code = { type: 'recovery-code', credentialId: null };
  const sealed = await id.sealMethodLabel(cc, me.masterSymmKey, laptop, 'my laptop');
  assert.equal(await id.openMethodLabel(cc, me.masterSymmKey, laptop, sealed), 'my laptop');
  assert.equal(await id.openMethodLabel(cc, me.masterSymmKey, phone, sealed), null, 'shown against another passkey of the same account');
  assert.equal(await id.openMethodLabel(cc, me.masterSymmKey, code, sealed), null, 'shown against the recovery code');
  assert.equal(await id.openMethodLabel(cc, other.masterSymmKey, laptop, sealed), null, 'another account\'s key');
  const codeLabel = await id.sealMethodLabel(cc, me.masterSymmKey, code, 'paper in the drawer');
  assert.equal(await id.openMethodLabel(cc, me.masterSymmKey, code, codeLabel), 'paper in the drawer');
  assert.equal(await id.openMethodLabel(cc, me.masterSymmKey, laptop, codeLabel), null);
  // A version-2 label is not read by the version-3 function, and the reverse.
  assert.equal(await id.openMethodLabelV2(cc, me.masterSymmKey, me.routing.publicKeyRaw, sealed), null);
});

test('assertSafeToRemove refuses the last method and bad indexes', () => {
  assert.throws(() => id.assertSafeToRemove([{}], 0), (e) => e.code === 'last-method');
  assert.throws(() => id.assertSafeToRemove([{}, {}], 2), /out of range/);
  assert.doesNotThrow(() => id.assertSafeToRemove([{}, {}], 1));
});
