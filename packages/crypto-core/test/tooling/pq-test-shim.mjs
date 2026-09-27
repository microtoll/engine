/**
 * TEST-ONLY platform shim.
 *
 * Teaches a Node `crypto.subtle` the hybrid KEM `MLKEM768-X25519` that Node
 * does not ship natively, so the client code in src/seal.js — which calls
 * only native `crypto.subtle` — can be exercised here. It lives under test/
 * and is never imported by src/.
 *
 * What a green run proves: the framing, the labels, the version bytes, the
 * dispatch and the call sequence, because the code under test is exactly
 * what a browser will run; only the platform underneath is stood in for. What
 * it does NOT prove: that a browser's implementation agrees with ours. That
 * cross-check on a real browser is a release gate (DECISIONS.md D-07).
 *
 * Deliberately strict: wrong key lengths, wrong usages and a private key
 * where a public one belongs are refused, as the real API would refuse them.
 */
import * as xw from './xwing.mjs';

const ALG = xw.WEBCRYPTO_ALGORITHM_NAME; // 'MLKEM768-X25519'
const MARK = Symbol('microtoll-pq-shim-key');

const nameOf = (algorithm) => (typeof algorithm === 'string' ? algorithm : algorithm?.name);
const isOurs = (algorithm) => nameOf(algorithm) === ALG;
const bytes = (b) => (b instanceof Uint8Array ? b : new Uint8Array(b.buffer ?? b, b.byteOffset ?? 0, b.byteLength ?? b.length));

/** Installs the shim; returns a function that removes it again. */
export function installPqShim(subtle = globalThis.crypto.subtle) {
  const original = {
    importKey: subtle.importKey.bind(subtle),
    exportKey: subtle.exportKey.bind(subtle),
    getPublicKey: subtle.getPublicKey ? subtle.getPublicKey.bind(subtle) : null,
    encapsulateBits: subtle.encapsulateBits ? subtle.encapsulateBits.bind(subtle) : undefined,
    decapsulateBits: subtle.decapsulateBits ? subtle.decapsulateBits.bind(subtle) : undefined,
  };

  subtle.importKey = async function (format, keyData, algorithm, extractable, usages) {
    if (!isOurs(algorithm)) return original.importKey(format, keyData, algorithm, extractable, usages);
    const raw = bytes(keyData);
    if (format === 'raw-seed') {
      if (raw.length !== xw.SK_BYTES) throw new Error(`seed must be ${xw.SK_BYTES} bytes, got ${raw.length}`);
      return { [MARK]: true, type: 'private', algorithm: { name: ALG }, extractable, usages, seed: Uint8Array.from(raw) };
    }
    if (format === 'raw-public') {
      if (raw.length !== xw.PK_BYTES) throw new Error(`public key must be ${xw.PK_BYTES} bytes, got ${raw.length}`);
      return { [MARK]: true, type: 'public', algorithm: { name: ALG }, extractable, usages, publicKeyRaw: Uint8Array.from(raw) };
    }
    throw new Error(`shim supports 'raw-seed' and 'raw-public' for ${ALG}, not '${format}'`);
  };

  subtle.getPublicKey = async function (key, usages) {
    if (!key?.[MARK]) return original.getPublicKey ? original.getPublicKey(key, usages) : Promise.reject(new Error('getPublicKey unsupported'));
    if (key.type !== 'private') throw new Error('getPublicKey needs a private key');
    return {
      [MARK]: true, type: 'public', algorithm: { name: ALG }, extractable: true, usages,
      publicKeyRaw: await xw.publicKeyFromSeed(key.seed),
    };
  };

  subtle.exportKey = async function (format, key) {
    if (!key?.[MARK]) return original.exportKey(format, key);
    if (format === 'raw-public') {
      if (key.type !== 'public') throw new Error("'raw-public' needs a public key");
      return key.publicKeyRaw.buffer.slice(key.publicKeyRaw.byteOffset, key.publicKeyRaw.byteOffset + key.publicKeyRaw.byteLength);
    }
    if (format === 'raw-seed') {
      if (key.type !== 'private') throw new Error("'raw-seed' needs a private key");
      if (!key.extractable) throw new Error('key is not extractable');
      return key.seed.buffer.slice(key.seed.byteOffset, key.seed.byteOffset + key.seed.byteLength);
    }
    throw new Error(`shim cannot export ${ALG} as '${format}'`);
  };

  subtle.encapsulateBits = async function (algorithm, encapsulationKey) {
    if (!isOurs(algorithm) || !encapsulationKey?.[MARK]) {
      if (original.encapsulateBits) return original.encapsulateBits(algorithm, encapsulationKey);
      throw new Error('encapsulateBits unsupported');
    }
    if (encapsulationKey.type !== 'public') throw new Error('encapsulateBits needs a public key');
    const { sharedSecret, ciphertext } = await xw.encapsulate(encapsulationKey.publicKeyRaw);
    return { sharedKey: sharedSecret.buffer.slice(0), ciphertext: ciphertext.buffer.slice(0) };
  };

  subtle.decapsulateBits = async function (algorithm, decapsulationKey, ciphertext) {
    if (!isOurs(algorithm) || !decapsulationKey?.[MARK]) {
      if (original.decapsulateBits) return original.decapsulateBits(algorithm, decapsulationKey, ciphertext);
      throw new Error('decapsulateBits unsupported');
    }
    if (decapsulationKey.type !== 'private') throw new Error('decapsulateBits needs a private key');
    const ss = await xw.decapsulate(bytes(ciphertext), decapsulationKey.seed);
    return ss.buffer.slice(0);
  };

  return function uninstallPqShim() {
    subtle.importKey = original.importKey;
    subtle.exportKey = original.exportKey;
    if (original.getPublicKey) subtle.getPublicKey = original.getPublicKey; else delete subtle.getPublicKey;
    if (original.encapsulateBits) subtle.encapsulateBits = original.encapsulateBits; else delete subtle.encapsulateBits;
    if (original.decapsulateBits) subtle.decapsulateBits = original.decapsulateBits; else delete subtle.decapsulateBits;
  };
}
