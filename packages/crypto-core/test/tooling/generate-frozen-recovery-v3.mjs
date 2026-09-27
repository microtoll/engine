// Writes test/fixtures/frozen-recovery-v3.json ONCE, and then never again.
//
//   node packages/crypto-core/test/tooling/generate-frozen-recovery-v3.mjs
//
// Recovery codes in version 3 (DECISIONS.md D-46), under the test namespace
// "example" (the code itself does not depend on the namespace): every later
// version must parse each code to its bytes and format the bytes to the same
// code. It refuses to overwrite the file. A NEW format gets a new file, never
// a regenerated one. The version-2 code stays in frozen-v1.json.
//
// Byte patterns rather than randomness, so a reader can see what went in:
// the edges (all zero, all ones, one bit at each end) and a few spread
// patterns.
import { existsSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { createCryptoCore } from '../../src/index.js';

const OUT = fileURLToPath(new URL('../fixtures/frozen-recovery-v3.json', import.meta.url));
if (existsSync(OUT)) {
  console.error(`${OUT} exists and is frozen. Nothing was written.`);
  process.exit(1);
}

const NAMESPACE = 'example';
const cc = createCryptoCore({ namespace: NAMESPACE });
const pattern = (f) => Uint8Array.from({ length: 16 }, (_, i) => f(i) & 0xff);
const inputs = [
  ['all zero', pattern(() => 0x00)],
  ['all ones', pattern(() => 0xff)],
  ['first bit only', pattern((i) => (i === 0 ? 0x80 : 0))],
  ['last bit only', pattern((i) => (i === 15 ? 0x01 : 0))],
  ['counting', pattern((i) => i)],
  ['counting down', pattern((i) => 0xff - i)],
  ['alternating', pattern((i) => (i % 2 ? 0xaa : 0x55))],
  ['spread', pattern((i) => 0x0f + i * 29)],
];

const out = {
  source: `Frozen by test/tooling/generate-frozen-recovery-v3.mjs on 2026-09-27 under namespace "${NAMESPACE}". Never regenerated or edited.`,
  namespace: NAMESPACE,
  version: cc.RECOVERY_CODE_VERSION,
  codes: [],
};
if (out.version !== 3) throw new Error('this file freezes version 3');
for (const [name, bytes] of inputs) {
  out.codes.push({ name, bytes: cc.toHex(bytes), code: await cc.formatRecoveryCode(bytes) });
}

writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
console.log('wrote', OUT, out.codes.length, 'codes');
