/**
 * The server half of the challenge-response handshake (DESIGN.md §3.1;
 * D-29, D-34). Deliberately narrow: the server only ever verifies a
 * routing-key signature, never signs or derives anything, so this uses
 * Node's own crypto and imports nothing from the client packages. The
 * message the client signs is built by @microtoll/identity's authMessage
 * with crypto-core's frameContext; test/auth.test.mjs proves the bytes
 * framed here are the same, and that a signature made with Web Crypto
 * verifies here -- the cross-implementation check D-29 asks for.
 *
 *   message   = UTF-8("<ns>/auth/v2") ‖ 0x00 ‖ SHA-256(UTF-8(origin)) ‖ nonce
 *   signature = Ed25519(routingPrivateKey, message)
 *
 * The label ties the signature to this purpose and this app, the origin to
 * this deployment, the nonce to this connection. The "v2" marks the step
 * from signing the bare nonce, which bound none of the three.
 */
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

export const NONCE_BYTES = 32;
const AUTH_LABEL_VERSION = 2;

export function generateNonce() {
  return randomBytes(NONCE_BYTES);
}

/** A namespace exactly as crypto-core's createProfile accepts it (its NAMESPACE_PATTERN): a-z, 0-9 and "-", 1 to 64 characters, starting with a letter or digit. */
export function assertNamespace(namespace) {
  if (typeof namespace !== 'string' || !/^[a-z0-9][a-z0-9-]{0,63}$/.test(namespace)) {
    throw new Error('namespace is required: 1-64 characters of a-z, 0-9 and "-", starting with a letter or digit (for example "example")');
  }
  return namespace;
}

/** The label crypto-core's profile.label('auth', 2) produces for this namespace. */
export function authLabel(namespace) {
  return `${assertNamespace(namespace)}/auth/v${AUTH_LABEL_VERSION}`;
}

/** frameContext(label, SHA-256(origin), nonce), framed with Buffer: label ‖ 0x00 ‖ parts. */
export function authMessage(namespace, origin, nonce) {
  if (typeof origin !== 'string' || !origin) throw new Error('authMessage: origin is required');
  if (!(nonce instanceof Uint8Array) || nonce.length !== NONCE_BYTES) throw new Error(`authMessage: a nonce is ${NONCE_BYTES} bytes`);
  const originHash = createHash('sha256').update(Buffer.from(origin, 'utf8')).digest();
  return Buffer.concat([Buffer.from(authLabel(namespace), 'utf8'), Buffer.from([0]), originHash, Buffer.from(nonce)]);
}

/**
 * rawBytes32: exactly 32 bytes. Node has no direct "import a raw Ed25519
 * public key" call; the portable route is the RFC 8037 JWK (kty OKP, crv
 * Ed25519, x = base64url of the raw key), the same encoding crypto-core
 * uses to export one.
 */
export function importEd25519PublicKeyRaw(rawBytes32) {
  if (!(rawBytes32 instanceof Uint8Array) || rawBytes32.length !== 32) {
    throw new Error(`Ed25519 public key must be 32 bytes, got ${rawBytes32 && rawBytes32.length}`);
  }
  return createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(rawBytes32).toString('base64url') }, format: 'jwk' });
}

/**
 * True when `signature` is a valid Ed25519 signature by `routingPublicKeyRaw32`
 * over the bound message for `origin` and `nonce`. A plain boolean for a bad
 * signature; throws only for structurally malformed input (a wrong-length
 * key), so a caller cannot treat a thrown error as "unverified" in a way
 * that skips the check.
 */
export function verifyAuthSignature(namespace, routingPublicKeyRaw32, origin, nonce, signature) {
  const publicKey = importEd25519PublicKeyRaw(routingPublicKeyRaw32);
  if (!(signature instanceof Uint8Array) || signature.length !== 64) return false;
  // algorithm null is correct (and required) for Ed25519 with crypto.verify.
  return verify(null, authMessage(namespace, origin, nonce), publicKey, signature);
}

/**
 * The connection's origin to verify against: the upgrade request's Origin
 * header when a browser sent one (server.js has already refused any that is
 * not allowed), otherwise each allowed origin in turn -- a non-browser
 * client sends none, and signs with the origin it was told.
 */
export function verifyAgainstOrigins(namespace, routingPublicKeyRaw32, origins, nonce, signature) {
  for (const origin of origins) {
    if (verifyAuthSignature(namespace, routingPublicKeyRaw32, origin, nonce, signature)) return origin;
  }
  return null;
}
