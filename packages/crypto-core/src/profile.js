/**
 * The label profile (DECISIONS.md D-05).
 *
 * Every key is derived under a label such as `myapp/routing/v1`:
 * HKDF-SHA-256, empty salt, the label as `info`. The construction is fixed;
 * only the namespace prefix varies between apps, so two apps never share a
 * derivation by accident. A namespace is required — there is no silent
 * default.
 */

const NAMESPACE_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;

// Labels of retired formats, never reused in any namespace: a derived X25519
// identity key, the X25519 seal (ECIES v1), and the X25519 mailbox label.
// Reusing a retired label under a new meaning would let old bytes be read as
// new ones.
const RETIRED = new Set(['identity/v1', 'ecies/v1', 'invite-mailbox/v1']);

// The default PBKDF2-SHA-256 iteration count, part of the recovery-code
// format: changing it makes every existing envelope unreadable. Web Crypto has
// no memory-hard KDF, so the recovery code's 128 bits of entropy, not this
// count, carry the security.
export const DEFAULT_PBKDF2_ITERATIONS = 310000;

export function createProfile({ namespace, pbkdf2Iterations = DEFAULT_PBKDF2_ITERATIONS } = {}) {
  if (typeof namespace !== 'string' || !NAMESPACE_PATTERN.test(namespace)) {
    throw new Error('a namespace is required: 1–64 characters of a–z, 0–9 and "-", starting with a letter or digit (for example "myapp")');
  }
  if (!Number.isInteger(pbkdf2Iterations) || pbkdf2Iterations < 1) {
    throw new Error('pbkdf2Iterations must be a positive integer');
  }

  /**
   * `<namespace>/<purpose>/v<version>`. The purpose may contain "/" (for example
   * `envelope/prf`), never a NUL, a space or an empty segment.
   */
  function label(purpose, version = 1) {
    if (typeof purpose !== 'string' || !/^[a-z0-9]+(?:[-/][a-z0-9]+)*$/.test(purpose)) {
      throw new Error(`invalid label purpose "${purpose}": lower-case words joined by "-" or "/"`);
    }
    if (!Number.isInteger(version) || version < 1) throw new Error('label version must be a positive integer');
    const suffix = `${purpose}/v${version}`;
    if (RETIRED.has(suffix)) throw new Error(`label "${suffix}" is retired and never reused`);
    return `${namespace}/${suffix}`;
  }

  return Object.freeze({
    namespace,
    pbkdf2Iterations,
    label,
    // The two labels crypto-core itself derives under.
    eciesV3: label('ecies', 3),
    eciesV2: label('ecies', 2),
  });
}
