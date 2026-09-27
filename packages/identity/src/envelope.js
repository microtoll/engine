/**
 * Unlock methods: the root key wrapped once per method, one row each.
 * Version-2 binding (FORMATS.md §2.1, D-28): every wrapped root key carries
 * additional authenticated data naming its method type and its identifier,
 * both known before the open.
 *
 *   passkey-prf:   unwrap key = HKDF(PRF output, "<ns>/envelope/prf/v1")
 *                  context    = frameContext("<ns>/aad/unlock-method/v2", 0x01, SHA-256(credentialId))
 *   recovery-code: unwrap key = PBKDF2-SHA-256(16 code bytes, 16-byte salt, profile iterations)
 *                  lookup     = hex(HKDF(code bytes, "<ns>/recovery-lookup/v1"))
 *                  context    = frameContext("<ns>/aad/unlock-method/v2", 0x02, lookup bytes)
 *
 * A method record matches the server's user_unlock_methods columns:
 *   { type: 'passkey-prf',   label, wrappedRootKey, credentialId, prfSalt }
 *   { type: 'recovery-code', label, wrappedRootKey, salt, lookupHash }
 *
 * Any one method unwraps the same root key, so deleting one loses nothing;
 * there is no server-side recovery.
 */

export const METHOD_PASSKEY = 'passkey-prf';
export const METHOD_RECOVERY = 'recovery-code';
const TYPE_BYTE = { [METHOD_PASSKEY]: 0x01, [METHOD_RECOVERY]: 0x02 };
const PBKDF2_SALT_BYTES = 16;
const PURPOSE_PRF = 'envelope/prf';
const PURPOSE_LOOKUP = 'recovery-lookup';
const AAD_UNLOCK_METHOD = 'aad/unlock-method';
const AAD_UNLOCK_LABEL = 'aad/unlock-label';

/** The context a wrapped root key is bound to (FORMATS.md §2.1). */
export async function unlockMethodContext(cc, type, methodIdBytes) {
  if (!TYPE_BYTE[type]) throw new Error(`unknown unlock method type: ${type}`);
  let id;
  if (type === METHOD_PASSKEY) {
    if (!(methodIdBytes instanceof Uint8Array) || methodIdBytes.length === 0) throw new Error('a credential id is required');
    id = await cc.sha256(methodIdBytes);
  } else {
    if (!(methodIdBytes instanceof Uint8Array) || methodIdBytes.length !== 32) throw new Error('a recovery lookup hash is 32 bytes');
    id = methodIdBytes;
  }
  return cc.frameContext(cc.label(AAD_UNLOCK_METHOD, 2), new Uint8Array([TYPE_BYTE[type]]), id);
}

/** PRF output → unwrap key. Never used raw as a key. */
export function deriveUnwrapKeyFromPrf(cc, prfOutput32) {
  if (!(prfOutput32 instanceof Uint8Array) || prfOutput32.length !== 32) throw new Error('a PRF output is 32 bytes');
  return cc.deriveAesKey(prfOutput32, PURPOSE_PRF);
}

/** Recovery bytes + salt → unwrap key, with the profile's iteration count. */
export function deriveUnwrapKeyFromRecoveryCode(cc, secretBytes16, saltBytes) {
  if (!(secretBytes16 instanceof Uint8Array) || secretBytes16.length !== cc.RECOVERY_CODE_ENTROPY_BYTES) throw new Error('a recovery code is 16 bytes');
  if (!(saltBytes instanceof Uint8Array) || saltBytes.length !== PBKDF2_SALT_BYTES) throw new Error('a PBKDF2 salt is 16 bytes');
  return cc.deriveAesKeyFromSecret(secretBytes16, saltBytes);
}

/**
 * The server-safe lookup value for a recovery code: a different label from
 * the unwrap derivation, so knowing it never helps derive the root key. Hex.
 */
export async function deriveRecoveryLookupHash(cc, secretBytes16) {
  return cc.toHex(await cc.deriveBits(secretBytes16, PURPOSE_LOOKUP));
}

export async function wrapRootKeyWithPrf(cc, rootKey, prfOutput32, credentialId, prfSalt, label = null) {
  const unwrapKey = await deriveUnwrapKeyFromPrf(cc, prfOutput32);
  const context = await unlockMethodContext(cc, METHOD_PASSKEY, credentialId);
  const wrappedRootKey = await cc.sealSymmetric(unwrapKey, rootKey, context);
  return { type: METHOD_PASSKEY, label, wrappedRootKey, credentialId, prfSalt };
}

/** A fresh recovery code wrapping the root key. displayString is shown exactly once and never stored. */
export async function wrapRootKeyWithNewRecoveryCode(cc, rootKey, label = null) {
  const { secretBytes, displayString } = await cc.generateRecoveryCode();
  const salt = cc.randomBytes(PBKDF2_SALT_BYTES);
  const lookupHash = await deriveRecoveryLookupHash(cc, secretBytes);
  const unwrapKey = await deriveUnwrapKeyFromRecoveryCode(cc, secretBytes, salt);
  const context = await unlockMethodContext(cc, METHOD_RECOVERY, cc.fromHex(lookupHash));
  const wrappedRootKey = await cc.sealSymmetric(unwrapKey, rootKey, context);
  secretBytes.fill(0);
  return { method: { type: METHOD_RECOVERY, label, wrappedRootKey, salt, lookupHash }, displayString };
}

/**
 * The recovery-code version to parse: crypto-core's current one (3, D-46)
 * unless the caller names 2. The two cannot be told apart by shape, so
 * version 2 is never tried as a fallback.
 */
function recoveryCodeOptions(options) {
  return options && options.recoveryCodeVersion !== undefined ? { version: options.recoveryCodeVersion } : {};
}

/**
 * What a new device derives from an entered code to find its own row. Rejects
 * with the parser's `code` on a typo. `{ recoveryCodeVersion: 2 }` reads a
 * code written before D-46.
 */
export async function lookupHashForEnteredCode(cc, enteredCode, options = {}) {
  const secretBytes = await cc.parseRecoveryCode(enteredCode, recoveryCodeOptions(options));
  return deriveRecoveryLookupHash(cc, secretBytes);
}

export async function unwrapRootKeyWithPrf(cc, method, prfOutput32) {
  if (method.type !== METHOD_PASSKEY) throw new Error(`unwrapRootKeyWithPrf called with a ${method.type} method`);
  const unwrapKey = await deriveUnwrapKeyFromPrf(cc, prfOutput32);
  const context = await unlockMethodContext(cc, METHOD_PASSKEY, method.credentialId);
  return cc.openSymmetric(unwrapKey, method.wrappedRootKey, context);
}

/** `{ recoveryCodeVersion: 2 }` reads a code written before D-46. */
export async function unwrapRootKeyWithRecoveryCode(cc, method, enteredCode, options = {}) {
  if (method.type !== METHOD_RECOVERY) throw new Error(`unwrapRootKeyWithRecoveryCode called with a ${method.type} method`);
  const secretBytes = await cc.parseRecoveryCode(enteredCode, recoveryCodeOptions(options));
  const lookupHash = method.lookupHash || await deriveRecoveryLookupHash(cc, secretBytes);
  const unwrapKey = await deriveUnwrapKeyFromRecoveryCode(cc, secretBytes, method.salt);
  const context = await unlockMethodContext(cc, METHOD_RECOVERY, cc.fromHex(lookupHash));
  secretBytes.fill(0);
  return cc.openSymmetric(unwrapKey, method.wrappedRootKey, context);
}

/**
 * The label a device gives one of its methods ("Alice's phone"), sealed under
 * K_master_symm and bound to that method (FORMATS.md §2.3, version 3, D-47):
 *
 *   passkey-prf:   frameContext("<ns>/aad/unlock-label/v3", 0x01, SHA-256(credentialId))
 *   recovery-code: frameContext("<ns>/aad/unlock-label/v3", 0x02)
 *
 * The threat (D-47): with the version-2 binding to the account alone, the
 * server could show one passkey's name against another passkey of the same
 * account, and mislead a person choosing which method to remove. A recovery
 * code is bound by its type alone because the method list carries no lookup
 * hash to bind to, and an account has one recovery code at a time.
 * `method` is `{ type, credentialId }`, as a method record or a listing has it.
 */
export async function labelContext(cc, method) {
  if (method instanceof Uint8Array) throw new TypeError('labelContext takes the unlock method ({ type, credentialId }) since version 3 (D-47); labelContextV2 takes a routing key');
  const type = method && method.type;
  if (!TYPE_BYTE[type]) throw new Error(`unknown unlock method type: ${type}`);
  const parts = [new Uint8Array([TYPE_BYTE[type]])];
  if (type === METHOD_PASSKEY) {
    if (!(method.credentialId instanceof Uint8Array) || method.credentialId.length === 0) throw new Error('a credential id is required');
    parts.push(await cc.sha256(method.credentialId));
  }
  return cc.frameContext(cc.label(AAD_UNLOCK_LABEL, 3), ...parts);
}

export async function sealMethodLabel(cc, masterSymmKey, method, label) {
  return cc.sealSymmetric(masterSymmKey, new TextEncoder().encode(label), await labelContext(cc, method));
}

/** Null rather than a throw: a label is a nicety, never a reason to fail a listing. */
export async function openMethodLabel(cc, masterSymmKey, method, sealed) {
  const context = await labelContext(cc, method); // a wrong call throws; only an unopenable label is null
  try {
    return new TextDecoder().decode(await cc.openSymmetric(masterSymmKey, sealed, context));
  } catch {
    return null;
  }
}

/**
 * Version 2 of the label context (D-28): bound to the account's routing key
 * only. Read by openMethodLabelV2 for a label written before D-47; nothing
 * writes it.
 */
export function labelContextV2(cc, routingPublicKeyRaw) {
  return cc.frameContext(cc.label(AAD_UNLOCK_LABEL, 2), routingPublicKeyRaw);
}

/** A version-2 label (D-28); null when it does not open. */
export async function openMethodLabelV2(cc, masterSymmKey, routingPublicKeyRaw, sealed) {
  try {
    return new TextDecoder().decode(await cc.openSymmetric(masterSymmKey, sealed, labelContextV2(cc, routingPublicKeyRaw)));
  } catch {
    return null;
  }
}

/**
 * Throws if removing this method would leave zero unlock paths. "At least
 * two" is the app's policy, not a hard invariant; losing the LAST path is
 * the one thing that must be structurally impossible.
 */
export function assertSafeToRemove(methods, indexToRemove) {
  if (!Array.isArray(methods) || indexToRemove < 0 || indexToRemove >= methods.length) throw new Error('index out of range');
  if (methods.length <= 1) {
    throw Object.assign(new Error('cannot remove the only remaining unlock method'), { code: 'last-method' });
  }
}
