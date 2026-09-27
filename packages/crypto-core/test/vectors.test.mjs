// Published known-answer tests, every one run through the package's own
// public API rather than a re-implementation in this file. A red test here
// means the primitive moved: fix the code, never the number.
//
// Every vector was cross-checked against a second implementation (Node's
// node:crypto) before being trusted; see the comment on each block.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import * as cc from '../src/index.js';

const H = cc.fromHex;
const utf8 = (s) => new TextEncoder().encode(s);

// ---------------------------------------------------------------------
// RFC 5869 — HKDF-SHA-256. Appendix A test cases 1 (salt and info) and 3
// (empty salt and info — the shape the labelled derivation uses, so it
// is the one that matters most).
// ---------------------------------------------------------------------
test('RFC 5869 A.1 test case 1: HKDF-SHA-256 with salt and info', async () => {
  const okm = await cc.hkdfDeriveBits(
    H('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    H('000102030405060708090a0b0c'),
    H('f0f1f2f3f4f5f6f7f8f9'),
    42 * 8,
  );
  assert.equal(cc.toHex(okm), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
});

test('RFC 5869 A.3 test case 3: HKDF-SHA-256 with empty salt and empty info', async () => {
  const okm = await cc.hkdfDeriveBits(
    H('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b'),
    new Uint8Array(0),
    new Uint8Array(0),
    42 * 8,
  );
  assert.equal(cc.toHex(okm), '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8');
});

test('hkdfDeriveSeedBits is exactly HKDF with an empty salt and the UTF-8 label as info', async () => {
  const ikm = H('0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b');
  const viaLabel = await cc.hkdfDeriveSeedBits(ikm, 'example/label/v1', 256);
  const viaBits = await cc.hkdfDeriveBits(ikm, new Uint8Array(0), utf8('example/label/v1'), 256);
  assert.equal(cc.toHex(viaLabel), cc.toHex(viaBits));
});

// ---------------------------------------------------------------------
// RFC 8032 §7.1 — Ed25519. Tests 1, 2, 3 and SHA(abc), sign and verify,
// through the PKCS#8 seed wrapper the design depends on.
// ---------------------------------------------------------------------
const ED25519_VECTORS = [
  {
    name: 'TEST 1 (empty message)',
    seed: '9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60',
    pub: 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a',
    msg: '',
    sig: 'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b',
  },
  {
    name: 'TEST 2 (one byte)',
    seed: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
    pub: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
    msg: '72',
    sig: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
  },
  {
    name: 'TEST 3 (two bytes)',
    seed: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
    pub: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
    msg: 'af82',
    sig: '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
  },
  {
    name: 'TEST SHA(abc) (64-byte message)',
    seed: '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42',
    pub: 'ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf',
    msg: 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f',
    sig: 'dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704',
  },
];

for (const v of ED25519_VECTORS) {
  test(`RFC 8032 ${v.name}: public key, signature and verification`, async () => {
    const priv = await cc.importEd25519PrivateKeyFromSeed(H(v.seed));
    const pub = await cc.exportPublicKeyRawFromPrivate(priv);
    assert.equal(cc.toHex(pub), v.pub, 'public key');
    const sig = await cc.signBytes(priv, H(v.msg));
    assert.equal(cc.toHex(sig), v.sig, 'signature');
    assert.equal(await cc.verifyBytes(pub, H(v.msg), sig), true, 'verifies');
    // A single flipped bit in the signature, the message or the key is refused.
    const badSig = sig.slice(); badSig[63] ^= 0x01;
    assert.equal(await cc.verifyBytes(pub, H(v.msg), badSig), false, 'flipped signature bit');
    const badMsg = cc.concatBytes(H(v.msg), new Uint8Array([0]));
    assert.equal(await cc.verifyBytes(pub, badMsg, sig), false, 'extended message');
    const badPub = pub.slice(); badPub[0] ^= 0x01;
    assert.equal(await cc.verifyBytes(badPub, H(v.msg), sig), false, 'wrong public key');
  });
}

test('verifyBytes returns false, never throws, on a malformed key or signature', async () => {
  assert.equal(await cc.verifyBytes(new Uint8Array(31), new Uint8Array(0), new Uint8Array(64)), false);
  assert.equal(await cc.verifyBytes(new Uint8Array(32), new Uint8Array(0), new Uint8Array(3)), false);
});

test('a seed of the wrong length is refused before it reaches Web Crypto', async () => {
  await assert.rejects(cc.importEd25519PrivateKeyFromSeed(new Uint8Array(31)), /32 bytes/);
});

// ---------------------------------------------------------------------
// RFC 5903 §8.1 — P-256 ECDH, through the stored-key wrappers. The shared
// secret uses Web Crypto's deriveBits directly; the ECIES construction that
// wraps it is tested in seal.test.mjs.
// ---------------------------------------------------------------------
test('RFC 5903 §8.1 P-256: public point from the JWK and the ECDH shared secret', async () => {
  const i = H('c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433');
  const gix = 'dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180';
  const giy = '5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3';
  const grx = 'd12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63';
  const gry = '56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab';
  const girx = 'd6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de';
  const initiator = await cc.importSealingKeyPair({
    kty: 'EC', crv: 'P-256', d: cc.toBase64Url(i), x: cc.toBase64Url(H(gix)), y: cc.toBase64Url(H(giy)),
  });
  assert.equal(cc.toHex(initiator.publicKeyRaw), '04' + gix + giy, 'public point');
  const responderPub = await cc.importSealingPublicKey(H('04' + grx + gry));
  const shared = new Uint8Array(await globalThis.crypto.subtle.deriveBits(
    { name: 'ECDH', public: responderPub }, initiator.privateKey, 256,
  ));
  assert.equal(cc.toHex(shared), girx, 'shared secret');
  assert.equal(initiator.privateKey.extractable, false, 'the working private key is non-extractable');
});

test('a P-256 public key of the wrong length, or a point off the curve, is refused', async () => {
  await assert.rejects(cc.importSealingPublicKey(new Uint8Array(64)), /65 bytes/);
  const offCurve = cc.concatBytes(new Uint8Array([0x04]), new Uint8Array(32).fill(1), new Uint8Array(32).fill(2));
  await assert.rejects(cc.importSealingPublicKey(offCurve));
});

// ---------------------------------------------------------------------
// NIST CAVP AES-256-GCM (gcmEncryptExtIV256.rsp, Count 0 of the block with
// Keylen 256, IVlen 96, PTlen 128, AADlen 0, Taglen 128). Run through
// openSymmetric by framing the published ciphertext as AEAD v1, plus the
// tag-failure case the CAVP decrypt files test.
// ---------------------------------------------------------------------
test('NIST CAVP AES-256-GCM Count 0: openSymmetric recovers the plaintext and refuses a wrong tag', async () => {
  const key = await cc.importSymmetricKey(H('31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22'));
  const iv = H('0d18e06c7c725ac9e362e1ce');
  const ct = H('fa4362189661d163fcd6a56d8bf0405a');
  const tag = H('d636ac1bbedd5cc3ee727dc2ab4a9489');
  const framed = cc.concatBytes(new Uint8Array([cc.AEAD_VERSION_1]), iv, ct, tag);
  const pt = await cc.openSymmetric(key, framed);
  assert.equal(cc.toHex(pt), '2db5168e932556f8089a0622981d017d');
  const badTag = framed.slice(); badTag[badTag.length - 1] ^= 0x01;
  await assert.rejects(cc.openSymmetric(key, badTag), 'flipped tag bit must fail');
  const withAad = await cc.openSymmetric(key, framed, new Uint8Array([1])).catch(() => 'rejected');
  assert.equal(withAad, 'rejected', 'AAD that was not authenticated must fail');
});

// ---------------------------------------------------------------------
// RFC 7914 §11 — PBKDF2-HMAC-SHA-256 test vectors (the only published ones
// for SHA-256; RFC 6070 covers SHA-1 only). The second vector is 80,000
// iterations, so it also exercises a realistic count.
// ---------------------------------------------------------------------
test('RFC 7914 §11 vector 1: PBKDF2-HMAC-SHA-256("passwd", "salt", 1, 64)', async () => {
  const dk = await cc.pbkdf2DeriveBits(utf8('passwd'), utf8('salt'), 1, 64 * 8);
  assert.equal(cc.toHex(dk), '55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783');
});

test('RFC 7914 §11 vector 2: PBKDF2-HMAC-SHA-256("Password", "NaCl", 80000, 64)', async () => {
  const dk = await cc.pbkdf2DeriveBits(utf8('Password'), utf8('NaCl'), 80000, 64 * 8);
  assert.equal(cc.toHex(dk), '4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d');
});

test('deriveAesGcmKeyFromPbkdf2 derives the same 32 key bytes as the RFC 7914 vector', async () => {
  // The derived key is non-extractable, so prove it by opening a blob that
  // Node's own AES-256-GCM sealed under the first 32 bytes of the vector.
  const keyBytes = H('55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc');
  const iv = H('000102030405060708090a0b');
  const pt = utf8('the same key on both sides');
  const cipher = createCipheriv('aes-256-gcm', keyBytes, iv);
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const framed = cc.concatBytes(new Uint8Array([cc.AEAD_VERSION_1]), iv, new Uint8Array(ct), new Uint8Array(cipher.getAuthTag()));
  const key = await cc.deriveAesGcmKeyFromPbkdf2(utf8('passwd'), utf8('salt'), 1);
  assert.equal(key.extractable, false);
  assert.equal(new TextDecoder().decode(await cc.openSymmetric(key, framed)), 'the same key on both sides');
});
