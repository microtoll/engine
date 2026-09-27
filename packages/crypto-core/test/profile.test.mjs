// The label profile (D-05): labels are built exactly as frozen, a namespace
// is required, and retired labels stay reserved everywhere.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createProfile, createCryptoCore, DEFAULT_PBKDF2_ITERATIONS } from '../src/index.js';

const example = createProfile({ namespace: 'example' });

test('every label is <namespace>/<purpose>/v<version>, byte for byte (change-detector)', () => {
  const p = example;
  assert.equal(p.namespace, 'example');
  assert.equal(p.label('routing'), 'example/routing/v1');
  assert.equal(p.label('identity-sign'), 'example/identity-sign/v1');
  assert.equal(p.label('symm'), 'example/symm/v1');
  assert.equal(p.label('identity-kem'), 'example/identity-kem/v1');
  assert.equal(p.label('envelope/prf'), 'example/envelope/prf/v1');
  assert.equal(p.label('recovery-lookup'), 'example/recovery-lookup/v1');
  assert.equal(p.label('read'), 'example/read/v1');
  assert.equal(p.label('detail-grant'), 'example/detail-grant/v1');
  assert.equal(p.label('url-invite'), 'example/url-invite/v1');
  assert.equal(p.label('invite-mailbox', 2), 'example/invite-mailbox/v2');
  assert.equal(p.eciesV3, 'example/ecies/v3');
  assert.equal(p.eciesV2, 'example/ecies/v2');
  assert.equal(p.pbkdf2Iterations, 310000);
  assert.equal(DEFAULT_PBKDF2_ITERATIONS, 310000);
});

test('a namespace is required and validated; there is no default', () => {
  assert.throws(() => createProfile(), /namespace is required/);
  assert.throws(() => createProfile({}), /namespace is required/);
  assert.throws(() => createProfile({ namespace: '' }), /namespace is required/);
  assert.throws(() => createProfile({ namespace: 'Has Caps' }), /namespace is required/);
  assert.throws(() => createProfile({ namespace: 'a/b' }), /namespace is required/);
  assert.throws(() => createCryptoCore(), /namespace is required/);
  assert.equal(createProfile({ namespace: 'my-app2' }).label('routing'), 'my-app2/routing/v1');
});

test('two namespaces never share a label, and the same purpose gives different derivations', async () => {
  const a = createCryptoCore({ namespace: 'app-a' });
  const b = createCryptoCore({ namespace: 'app-b' });
  const ikm = new Uint8Array(32).fill(7);
  assert.notEqual(a.label('routing'), b.label('routing'));
  assert.notEqual(a.toHex(await a.deriveBits(ikm, 'routing')), b.toHex(await b.deriveBits(ikm, 'routing')));
});

test('retired labels are refused in every namespace', () => {
  for (const ns of ['example', 'other']) {
    const p = createProfile({ namespace: ns });
    assert.throws(() => p.label('identity', 1), /retired/);
    assert.throws(() => p.label('ecies', 1), /retired/);
    assert.throws(() => p.label('invite-mailbox', 1), /retired/);
    assert.equal(p.label('identity', 2), `${ns}/identity/v2`, 'a later version of a retired purpose is allowed');
  }
});

test('label purposes are lower-case words joined by "-" or "/"; versions are positive integers', () => {
  const p = example;
  for (const bad of ['', 'Routing', 'a b', 'a//b', '/a', 'a/', 'a\u0000b']) assert.throws(() => p.label(bad), /invalid label purpose/);
  for (const bad of [0, -1, 1.5, '1']) assert.throws(() => p.label('routing', bad), /version/);
});

test('deriveBits is exactly HKDF-SHA-256 with an empty salt and the label as info', async () => {
  const cc = createCryptoCore({ namespace: 'example' });
  const ikm = new Uint8Array(32).fill(1);
  const viaProfile = await cc.deriveBits(ikm, 'routing');
  const viaPrimitive = await cc.hkdfDeriveBits(ikm, new Uint8Array(0), new TextEncoder().encode('example/routing/v1'), 256);
  assert.equal(cc.toHex(viaProfile), cc.toHex(viaPrimitive));
  const key = await cc.deriveAesKey(ikm, 'symm');
  assert.equal(key.extractable, false);
});

test('the instance is frozen and carries the primitives, the sealer and the profile', () => {
  const cc = createCryptoCore({ namespace: 'example' });
  assert.equal(Object.isFrozen(cc), true);
  for (const name of ['sealSymmetric', 'openSymmetric', 'sealToRecipient', 'openWithPrivateKey', 'generateRecoveryCode', 'deriveAesKeyFromSecret']) {
    assert.equal(typeof cc[name], 'function', name);
  }
  assert.equal(cc.profile.namespace, 'example');
});
