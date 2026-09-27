// The passkey ceremonies against a scripted navigator.credentials: the
// request shapes, the PRF-at-create fast path, the fallback get(), the
// "no PRF" refusal, and error codes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createWebAuthn, backupStateFromAuthData, hintsForTransports } from '../src/index.js';

function scriptedCredentials({ prfAtCreate = true, prfOnGet = true, prfEnabled = true, backedUp = true } = {}) {
  const log = [];
  const id = new Uint8Array([9, 8, 7, 6]);
  const prf = (salt) => new Uint8Array(32).map((_, i) => salt[i] ^ 0x5a);
  const authData = new Uint8Array(37); authData[32] = backedUp ? 0x18 : 0x00;
  return {
    log,
    async create(opts) {
      log.push(['create', opts.publicKey]);
      const salt = opts.publicKey.extensions.prf.eval.first;
      return {
        rawId: id.buffer, response: { getTransports: () => ['internal'], getAuthenticatorData: () => authData },
        getClientExtensionResults: () => ({ prf: { enabled: prfEnabled, ...(prfAtCreate && prfEnabled ? { results: { first: prf(salt) } } : {}) } }),
      };
    },
    async get(opts) {
      log.push(['get', opts.publicKey]);
      const salt = opts.publicKey.extensions && opts.publicKey.extensions.prf ? opts.publicKey.extensions.prf.eval.first : null;
      return {
        rawId: id.buffer, response: { getTransports: () => ['internal'], userHandle: null },
        getClientExtensionResults: () => (prfOnGet && salt ? { prf: { results: { first: prf(salt) } } } : {}),
      };
    },
  };
}

test('createPasskeyWithPrf: platform shape, PRF answered at creation → one prompt', async () => {
  const creds = scriptedCredentials();
  const wa = createWebAuthn({ credentials: creds, rpName: 'example' });
  const r = await wa.createPasskeyWithPrf('Ada');
  assert.equal(creds.log.length, 1);
  const pk = creds.log[0][1];
  assert.deepEqual(pk.authenticatorSelection, { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' });
  assert.deepEqual(pk.hints, ['client-device']);
  assert.deepEqual(pk.pubKeyCredParams.map((p) => p.alg), [-8, -7, -257]);
  assert.equal(pk.rp.id, undefined, 'rp.id defaults to the host');
  assert.match(pk.user.name, /^Ada \(/);
  assert.equal(r.prfSalt.length, 32);
  assert.equal(r.prfOutput32.length, 32);
  assert.deepEqual(r.credentialId, new Uint8Array([9, 8, 7, 6]));
  assert.equal(r.backedUp, true);
});

test('cross-platform shape; PRF only on assertion → a fallback get() with the same salt', async () => {
  const creds = scriptedCredentials({ prfAtCreate: false });
  const wa = createWebAuthn({ credentials: creds, rpName: 'example' });
  const r = await wa.createPasskeyWithPrf('Ada', { attachment: 'cross-platform' });
  assert.equal(creds.log.length, 2);
  assert.deepEqual(creds.log[0][1].hints, ['hybrid', 'security-key']);
  assert.equal(creds.log[0][1].authenticatorSelection.residentKey, 'preferred');
  assert.deepEqual(creds.log[1][1].extensions.prf.eval.first, r.prfSalt);
  assert.deepEqual(creds.log[1][1].allowCredentials, [{ id: r.credentialId, type: 'public-key', transports: ['internal'] }]);
});

test('prf enabled:false at creation is the definitive no: refused before a second prompt', async () => {
  const creds = scriptedCredentials({ prfEnabled: false });
  const wa = createWebAuthn({ credentials: creds, rpName: 'example' });
  await assert.rejects(wa.createPasskeyWithPrf('Ada'), (e) => e.code === 'prf-unsupported' && /enabled:false/.test(e.diagnostic));
  assert.equal(creds.log.length, 1);
});

test('evaluatePrf: names the credential and its transports; no PRF result → prf-unsupported', async () => {
  const creds = scriptedCredentials({ prfOnGet: false });
  const wa = createWebAuthn({ credentials: creds, rpName: 'example' });
  await assert.rejects(wa.evaluatePrf(new Uint8Array([1]), new Uint8Array(32), ['internal']), (e) => e.code === 'prf-unsupported');
  const pk = creds.log[0][1];
  assert.deepEqual(pk.hints, ['client-device']);
  assert.equal(pk.userVerification, 'required');
  await assert.rejects(wa.evaluatePrf(new Uint8Array([1]), new Uint8Array(31)), (e) => e.code === 'invalid-state');
});

test('assertAnyCredential omits allowCredentials and asks for no PRF', async () => {
  const creds = scriptedCredentials();
  const wa = createWebAuthn({ credentials: creds, rpName: 'example' });
  const r = await wa.assertAnyCredential();
  const pk = creds.log[0][1];
  assert.equal('allowCredentials' in pk, false);
  assert.equal(pk.extensions, undefined);
  assert.deepEqual(r.credentialId, new Uint8Array([9, 8, 7, 6]));
});

test('browser errors map to codes; no WebAuthn at all is webauthn-unavailable', async () => {
  const boom = (name) => ({ async create() { throw Object.assign(new Error('x'), { name }); }, async get() { throw Object.assign(new Error('x'), { name }); } });
  for (const [name, code] of [['NotAllowedError', 'not-allowed'], ['InvalidStateError', 'already-exists'], ['NotSupportedError', 'webauthn-unavailable'], ['TypeError', 'invalid-state']]) {
    const wa = createWebAuthn({ credentials: boom(name), rpName: 'example' });
    await assert.rejects(wa.createPasskeyWithPrf('Ada'), (e) => e.code === code && e.stage === 'create (platform)');
  }
  const none = createWebAuthn({ credentials: null, rpName: 'example' });
  assert.equal(none.present(), false);
  await assert.rejects(none.evaluatePrf(new Uint8Array(1), new Uint8Array(32)), (e) => e.code === 'webauthn-unavailable');
  assert.throws(() => createWebAuthn({}), /rpName/);
});

test('backup flags and transport hints', () => {
  const a = new Uint8Array(37); a[32] = 0x18;
  assert.equal(backupStateFromAuthData(a), true);
  a[32] = 0x08; assert.equal(backupStateFromAuthData(a), false);
  assert.equal(backupStateFromAuthData(new Uint8Array(36)), null);
  assert.deepEqual(hintsForTransports(['internal', 'usb', 'hybrid', 'nfc', 'other']), ['client-device', 'security-key', 'hybrid']);
});
