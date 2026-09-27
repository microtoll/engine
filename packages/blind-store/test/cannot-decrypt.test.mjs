// "The server cannot decrypt" as a fact about the package, not a
// discipline (DESIGN.md §5.4, D-34): its runtime dependencies are exactly
// ws and pg; nothing under src/ imports a @microtoll package; and the
// source contains no code that decrypts, unwraps, derives a key or holds a
// private key. The only cryptography here is SHA-256 of capability secrets,
// Ed25519 verification and random nonces. The runtime half -- sealed
// fixtures stored and read back byte-identical -- is in fixtures.test.mjs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const srcFiles = () => [...fs.readdirSync(path.join(pkgDir, 'src')).map((f) => path.join('src', f)), ...fs.readdirSync(path.join(pkgDir, 'bin')).map((f) => path.join('bin', f))]
  .filter((f) => /\.(m?js)$/.test(f));

test('runtime dependencies are exactly ws and pg, pinned to exact versions', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
  assert.deepEqual(Object.keys(pkg.dependencies).sort(), ['pg', 'ws']);
  for (const [name, version] of Object.entries(pkg.dependencies)) assert.match(version, /^\d+\.\d+\.\d+$/, `${name} is not pinned exactly`);
  assert.equal(pkg.license, 'AGPL-3.0-only');
});

test('nothing under src/ or bin/ imports a client package or anything but node:*, ws, pg and its own files', () => {
  for (const file of srcFiles()) {
    const text = fs.readFileSync(path.join(pkgDir, file), 'utf8');
    for (const m of text.matchAll(/^\s*import\s+(?:[^'"]+\s+from\s+)?['"]([^'"]+)['"]/gm)) {
      const spec = m[1];
      const ok = spec.startsWith('node:') || spec === 'ws' || spec === 'pg' || spec.startsWith('./') || spec.startsWith('../src/');
      assert.ok(ok, `${file} imports ${spec}`);
      assert.ok(!spec.startsWith('@microtoll/'), `${file} imports ${spec}`);
    }
    assert.doesNotMatch(text, /\bimport\s*\(/, `${file} has a dynamic import`);
    assert.doesNotMatch(text, /\brequire\s*\(/, `${file} uses require`);
  }
});

test('the source names no decryption, key derivation, unwrapping or private-key operation', () => {
  // Identifiers that would mean the server could open something. The
  // allowed cryptography is listed as exceptions: createHash (SHA-256 of a
  // capability secret), createPublicKey and verify (Ed25519), randomBytes.
  const forbidden = [
    // pbkdf2Salt / pbkdf2_salt is a stored salt, not a derivation; anything else named pbkdf2 is.
    /\bdecrypt\w*/i, /\bdecipher\w*/i, /\bunwrap\w*/i, /\bderiveKey\b/i, /\bderiveBits\b/i, /\bhkdf\w*/i, /\bpbkdf2(?!_?salt\b)\w*/i,
    /\baes[-_]?\w*/i, /\bgcm\b/i, /\bsubtle\b/, /\bcreatePrivateKey\b/, /\bprivateKey\b/, /\bsign\s*\(/, /\bcreateSign\b/,
    /\bdiffieHellman\b/i, /\becdh\b/i, /\bx25519\b/i, /\bkem\b/i, /\bopenSymmetric\b/, /\bopenWith\w*/, /\bsealSymmetric\b/, /\bsealTo\w*/,
  ];
  // Words that appear in comments describing what the CLIENT does (never in
  // code): stripped before the scan, so a comment cannot fail the test and
  // code cannot hide in one.
  const stripComments = (s) => s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\\])\/\/.*$/gm, '$1');
  for (const file of srcFiles()) {
    const code = stripComments(fs.readFileSync(path.join(pkgDir, file), 'utf8'));
    for (const re of forbidden) {
      const hit = code.match(re);
      assert.equal(hit, null, `${file} contains "${hit && hit[0]}"`);
    }
  }
});

test('the only node:crypto calls are createHash, createPublicKey, verify and randomBytes', () => {
  const allowed = new Set(['createHash', 'createPublicKey', 'verify', 'randomBytes']);
  for (const file of srcFiles()) {
    const text = fs.readFileSync(path.join(pkgDir, file), 'utf8');
    for (const m of text.matchAll(/import\s*\{([^}]+)\}\s*from\s*['"]node:crypto['"]/g)) {
      for (const name of m[1].split(',').map((s) => s.trim().split(/\s+as\s+/)[0]).filter(Boolean)) {
        assert.ok(allowed.has(name), `${file} imports ${name} from node:crypto`);
      }
    }
    assert.doesNotMatch(text, /from\s*['"]crypto['"]/, `${file} imports bare "crypto"`);
    // Comments stripped: a comment may say "crypto.verify"; code may not reach the global.
    const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:\\])\/\/.*$/gm, '$1');
    assert.doesNotMatch(code, /\bcrypto\.\w+/, `${file} uses the crypto global`);
  }
});

test('every ciphertext field the server stores has a registered cap, and every parser applies one', () => {
  // The static "every field capped" check, so no client can make the server
  // hold a ciphertext of any size it likes: any wire field whose name says
  // it carries ciphertext must be read through blobValue or blobField, never
  // through a bare typeof check followed by a decode.
  const code = srcFiles().map((f) => fs.readFileSync(path.join(pkgDir, f), 'utf8')).join('\n');
  const fields = new Set([...code.matchAll(/\b(encrypted[A-Z]\w+|wrappedRootKey|credentialId|prfSalt|pbkdf2Salt)\b/g)].map((m) => m[1]));
  const limits = JSON.parse(JSON.stringify(Object.fromEntries([...fs.readFileSync(path.join(pkgDir, 'src', 'limits.js'), 'utf8').matchAll(/^\s+(\w+):\s*(\d+)/gm)].map((m) => [m[1], m[2]]))));
  for (const field of fields) {
    assert.ok(field in limits, `${field} has no size limit registered`);
    assert.ok(new RegExp(`blob(?:Value|Field)\\([^)]*['"]${field}['"]`).test(code), `${field} is not read through blobValue/blobField`);
  }
  // No parser decodes a ciphertext field on its own.
  assert.doesNotMatch(code, /fromB64u\(\s*(?:msg|raw|cp|u|pointer)\.(encrypted\w+|wrappedRootKey)\)/, 'a ciphertext field decoded without its cap');
});
