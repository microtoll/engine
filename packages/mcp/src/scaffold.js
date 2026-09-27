/**
 * The scaffold: writes the notes starter (the engine's notes example with
 * the namespace and origin filled in) into an EMPTY directory the host
 * names, and does nothing else -- no command runs, nothing is fetched, no
 * telemetry. The templates are generated/scaffold/notes/, produced by the
 * repository's docs build from examples/notes-app and docs/scaffold/notes.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const NAMESPACE_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const NAME_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
export const TEMPLATES_DIR = fileURLToPath(new URL('../generated/scaffold/notes/', import.meta.url));

/** Everything the scaffold would write, without writing it: [{ name, text }]. */
export function renderScaffold({ namespace = 'myapp', origin = 'http://localhost:8088', name = null } = {}, templatesDir = TEMPLATES_DIR) {
  if (!NAMESPACE_RE.test(namespace)) throw new Error('namespace: 1-64 characters of a-z, 0-9 and "-", starting with a letter or digit (the same string createCryptoCore takes)');
  let url;
  try { url = new URL(origin); } catch { throw new Error('origin: a web origin such as http://localhost:8088 or https://app.example'); }
  if (!/^https?:$/.test(url.protocol) || url.pathname !== '/' || url.search || url.hash) throw new Error('origin: scheme and host only, no path');
  const appName = name || namespace;
  if (!NAME_RE.test(appName)) throw new Error('name: 1-64 characters of a-z, 0-9 and "-"');
  const port = url.port || (url.protocol === 'https:' ? '443' : '80');
  const wsOrigin = `${url.protocol === 'https:' ? 'wss' : 'ws'}://${url.host}`;
  const fill = (text) => text
    .replace(/__NAMESPACE__/g, namespace).replace(/__ORIGIN__/g, url.origin).replace(/__WS_ORIGIN__/g, wsOrigin)
    .replace(/__PORT__/g, port).replace(/__NAME__/g, appName);
  const out = [];
  for (const file of fs.readdirSync(templatesDir).sort()) {
    let text = fs.readFileSync(path.join(templatesDir, file), 'utf8');
    if (file === 'page.js') {
      // The example's own namespace and passkey name become the app's.
      text = text.replace("namespace: 'notes-example'", `namespace: '${namespace}'`).replace("rpName: 'Microtoll notes'", `rpName: '${appName}'`);
    }
    out.push({ name: file, text: fill(text) });
  }
  return { files: out, namespace, origin: url.origin, name: appName };
}

/** Writes the scaffold. Refuses a directory that exists and is not empty. Returns { directory, files, next }. */
export function scaffold(options = {}) {
  const directory = options.directory;
  if (typeof directory !== 'string' || !directory.trim()) throw new Error('directory: where to write the app (an absolute path, or one relative to the host\'s working directory)');
  const target = path.resolve(directory);
  if (fs.existsSync(target)) {
    if (!fs.statSync(target).isDirectory()) throw new Error(`${target} exists and is not a directory`);
    if (fs.readdirSync(target).length > 0) throw new Error(`${target} is not empty: the scaffold writes only into an empty directory, and never overwrites`);
  }
  const rendered = renderScaffold(options);
  fs.mkdirSync(target, { recursive: true });
  for (const f of rendered.files) fs.writeFileSync(path.join(target, f.name), f.text, { flag: 'wx' });
  return {
    directory: target,
    files: rendered.files.map((f) => f.name),
    namespace: rendered.namespace,
    origin: rendered.origin,
    next: [`cd ${target}`, 'npm install', 'docker compose up', `open ${rendered.origin}`, 'read notes.js, then README.md'],
  };
}
