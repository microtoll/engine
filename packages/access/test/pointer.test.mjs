import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createIdentity } from '@microtoll/identity';
import * as ac from '../src/index.js';
import { cc, makeAccess } from './helpers.mjs';

const objectId = '11111111-2222-4333-8444-555555555555';

test('a pointer round-trips its core and extension fields, and absent fields open as their defaults', async () => {
  const me = await createIdentity(cc);
  const access = makeAccess();
  const kObject = cc.generateSymmetricKey();
  const sealed = await access.pointerCodec.build(me, { objectId, kObject, keyEpoch: 3, rowCapabilitySecret: cc.randomBytes(32), myStatus: 'going', pushSubscribed: true, sharedLinks: [{ hashedToken: 'x' }] });
  const opened = await access.pointerCodec.open(me, sealed);
  assert.deepEqual(opened.kObject, kObject);
  assert.equal(opened.keyEpoch, 3);
  assert.equal(opened.myStatus, 'going');
  assert.equal(opened.pushSubscribed, true);
  assert.equal(opened.adminCapabilitySecret, null);
  assert.equal(opened.quietRotationKey, null);
  assert.deepEqual(opened.sharedLinks, [{ hashedToken: 'x' }]);
  assert.equal(opened.invitedBy, null);
  // A drifted vocabulary value opens as null; spreading and rewriting one field keeps the rest.
  const again = await access.pointerCodec.build(me, { ...opened, myStatus: 'maybe', pushSubscribed: false });
  const o2 = await access.pointerCodec.open(me, again);
  assert.equal(o2.myStatus, null); assert.equal(o2.pushSubscribed, false); assert.deepEqual(o2.rowCapabilitySecret, opened.rowCapabilitySecret);
});

test('a pointer is bound to its object: opened as another object it fails; another account cannot open it', async () => {
  const me = await createIdentity(cc); const other = await createIdentity(cc);
  const access = makeAccess();
  const sealed = await access.pointerCodec.build(me, { objectId, kObject: cc.generateSymmetricKey(), keyEpoch: 1 });
  await assert.rejects(access.pointerCodec.open({ masterSymmKey: me.masterSymmKey, routing: other.routing }, sealed), 'the same key under another account does not open it');
  await assert.rejects(access.pointerCodec.open(other, sealed));
});

test('required fields are checked; collisions with core fields and wire keys are refused', async () => {
  const me = await createIdentity(cc);
  const codec = ac.createPointerCodec(cc, {});
  await assert.rejects(codec.build(me, { objectId, keyEpoch: 1 }), /kObject/);
  await assert.rejects(codec.build(me, { objectId, kObject: cc.generateSymmetricKey(), keyEpoch: 0 }), /keyEpoch/);
  await assert.rejects(codec.build(me, 'string'), /values/);
  assert.throws(() => ac.createPointerCodec(cc, { keyEpoch: { wire: 'x', ...ac.flag } }), /core field/);
  assert.throws(() => ac.createPointerCodec(cc, { mine: { wire: 'kObject', ...ac.flag } }), /already used/);
  assert.throws(() => ac.createPointerCodec(cc, { mine: { wire: 'm' } }), /seal, open/);
});
