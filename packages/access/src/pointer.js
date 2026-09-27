/**
 * Pointers: a member's own private note about one object, sealed under their
 * K_master_symm, never under K_object. The only place capability secrets are
 * persisted anywhere recoverable. Format version 2: bound to the account
 * (FORMATS.md §3.2, D-37; see pointerContext below), with the app's fields
 * in an extension table rather than hard-coded.
 *
 * Every reader tolerates an absent field (a pointer sealed before it existed
 * opens with the field's default), and every writer builds from the opened
 * pointer by spreading it, so a field nobody else knows about survives every
 * rewrite. objectId, kObject and keyEpoch are required: a pointer without them
 * is corrupt, not degraded.
 */

const AAD_POINTER = 'aad/pointer';
const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

// Field codecs for the extension table.
export const asIs = { seal: (v) => (v === undefined ? null : v), open: (v) => (v === undefined ? null : v) };
export const flag = { seal: (v) => !!v, open: (v) => !!v };
export const list = { seal: (v) => (Array.isArray(v) ? v : []), open: (v) => (Array.isArray(v) ? v : []) };
export const objectOrNull = { seal: (v) => v || null, open: (v) => v || null };
export const instantOrNull = {
  seal: (v) => (typeof v === 'string' && Number.isFinite(Date.parse(v)) ? v : null),
  open: (v) => (typeof v === 'string' && Number.isFinite(Date.parse(v)) ? v : null),
};
/** One of a closed vocabulary, or null: a drifted value opens as "nothing recorded", never as a claim. */
export const oneOf = (values) => ({ seal: (v) => (values.includes(v) ? v : null), open: (v) => (values.includes(v) ? v : null) });

/**
 * The pointer's binding: the ACCOUNT it belongs to (its routing public key),
 * under the pointer label -- so a pointer cannot be moved to another account
 * or confused with any other blob sealed under K_master_symm (the identity
 * blob, a method label). The object id is NOT in the binding: the server
 * returns an account's pointers without one (by design, the pointer table
 * has no object column), so a fresh device could never open a pointer whose
 * binding needed the id. The id is inside the sealed pointer instead, and
 * a caller that expects one checks it (D-37; corrects the M3 design).
 */
export function pointerContext(cc, routingPublicKeyRaw) {
  if (!(routingPublicKeyRaw instanceof Uint8Array) || routingPublicKeyRaw.length !== 32) throw new Error('pointerContext: the routing public key (32 bytes) is required');
  return cc.frameContext(cc.label(AAD_POINTER, 2), routingPublicKeyRaw);
}

function accountOf(identity, what) {
  if (!identity || !identity.masterSymmKey || !identity.routing || !(identity.routing.publicKeyRaw instanceof Uint8Array)) {
    throw new Error(`${what}: the account identity (masterSymmKey and routing key) is required`);
  }
  return identity;
}

/** The package's own fields. Wire keys are frozen; the fixture suite pins them. */
export function coreFields(cc) {
  const bytesOrNull = { seal: (v) => (v ? cc.toBase64Url(v) : null), open: (v) => (v ? cc.fromBase64Url(v) : null) };
  return Object.freeze({
    objectId: { wire: 'objectId', ...asIs },
    kObject: { wire: 'kObject', seal: (v) => cc.toBase64Url(v), open: (v) => cc.fromBase64Url(v) },
    keyEpoch: { wire: 'keyEpoch', ...asIs },
    rowCapabilitySecret: { wire: 'rowCapabilitySecret', ...bytesOrNull },
    adminCapabilitySecret: { wire: 'adminCapabilitySecret', ...bytesOrNull },
    quietRotationKey: { wire: 'quietRotationKey', ...objectOrNull },
    quietRotationKemSeed: { wire: 'quietRotationKemSeed', ...bytesOrNull },
    sharedLinks: { wire: 'sharedLinks', ...list },
    invitedBy: { wire: 'invitedBy', ...objectOrNull },
  });
}

/**
 * createPointerCodec(cc, extension): the app's fields as { name: { wire, seal, open } }.
 * A name or wire key that collides with a core field is refused.
 */
export function createPointerCodec(cc, extension = {}) {
  const core = coreFields(cc);
  const wires = new Set(Object.values(core).map((f) => f.wire));
  const fields = { ...core };
  for (const [name, spec] of Object.entries(extension || {})) {
    if (core[name]) throw new Error(`pointer field "${name}" is a core field`);
    if (!spec || typeof spec.wire !== 'string' || typeof spec.seal !== 'function' || typeof spec.open !== 'function') throw new Error(`pointer field "${name}" needs { wire, seal, open }`);
    if (wires.has(spec.wire)) throw new Error(`pointer wire key "${spec.wire}" is already used`);
    wires.add(spec.wire);
    fields[name] = spec;
  }
  Object.freeze(fields);

  /** Seals a pointer for this account: `identity` is the account (masterSymmKey, routing). */
  async function build(identity, values) {
    accountOf(identity, 'buildPointer');
    if (!values || typeof values !== 'object') throw new Error('buildPointer: values must be an object built from the opened pointer');
    if (typeof values.objectId !== 'string' || !values.objectId) throw new Error('buildPointer: objectId is required');
    if (!(values.kObject instanceof Uint8Array) || values.kObject.length !== 32) throw new Error('buildPointer: kObject (32 bytes) is required');
    if (!Number.isInteger(values.keyEpoch) || values.keyEpoch < 1) throw new Error('buildPointer: keyEpoch must be an integer >= 1');
    const plaintext = {};
    for (const [name, spec] of Object.entries(fields)) plaintext[spec.wire] = spec.seal(values[name]);
    return cc.sealSymmetric(identity.masterSymmKey, utf8.encode(JSON.stringify(plaintext)), pointerContext(cc, identity.routing.publicKeyRaw));
  }

  /** Opens one of this account's pointers (as the server returns them, with no id); the object it names is `objectId` inside. */
  async function open(identity, sealed) {
    accountOf(identity, 'openPointer');
    const bytes = await cc.openSymmetric(identity.masterSymmKey, sealed, pointerContext(cc, identity.routing.publicKeyRaw));
    const parsed = JSON.parse(fromUtf8.decode(bytes));
    const opened = {};
    for (const [name, spec] of Object.entries(fields)) opened[name] = spec.open(parsed[spec.wire]);
    if (typeof opened.objectId !== 'string' || !opened.objectId) throw new Error('the pointer names no object');
    return opened;
  }

  return Object.freeze({ fields, build, open });
}
