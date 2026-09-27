/**
 * The Model Context Protocol over standard input and output, the subset a
 * tools-only server needs (D-39): JSON-RPC 2.0 messages, one per line, on
 * stdin and stdout; `initialize`, `ping`, `tools/list`, `tools/call`;
 * notifications acknowledged by silence; errors as JSON-RPC errors; logs on
 * stderr, never stdout (stdout is the protocol). Written in rather than
 * taken from the SDK so the whole package can be read in one sitting and
 * carries no dependency tree.
 *
 * Protocol version 2025-06-18. A host offers its version in `initialize`;
 * this server answers with the one it speaks, and a host that cannot speak
 * it disconnects -- the negotiation the specification describes.
 */
export const PROTOCOL_VERSION = '2025-06-18';

const PARSE_ERROR = -32700;
const INVALID_REQUEST = -32600;
const METHOD_NOT_FOUND = -32601;
const INVALID_PARAMS = -32602;

/**
 * createServer({ name, version, instructions, tools })
 *   tools: [{ name, description, inputSchema, handler(args) -> string | { text, isError } }]
 * Returns { handle(message) -> Promise<reply | null>, listen({ input, output, log }) }.
 * `handle` is the protocol; `listen` wires it to streams.
 */
export function createServer({ name, version, instructions = '', tools = [] }) {
  for (const t of tools) {
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(t.name)) throw new Error(`tool name not allowed: ${t.name}`);
    if (typeof t.handler !== 'function') throw new Error(`tool ${t.name} needs a handler`);
  }
  const byName = new Map(tools.map((t) => [t.name, t]));
  const ok = (id, result) => ({ jsonrpc: '2.0', id, result });
  const error = (id, code, message, data) => ({ jsonrpc: '2.0', id, error: { code, message, ...(data !== undefined ? { data } : {}) } });

  /** One message in, one reply out (or null for a notification). Never throws. */
  async function handle(msg) {
    if (!msg || typeof msg !== 'object' || Array.isArray(msg)) return error(null, INVALID_REQUEST, 'a JSON-RPC request object was expected');
    const { id, method, params } = msg;
    const isNotification = id === undefined || id === null;
    if (msg.jsonrpc !== '2.0' || typeof method !== 'string') return isNotification ? null : error(id, INVALID_REQUEST, 'invalid request');
    if (method.startsWith('notifications/')) return null;   // initialized, cancelled, progress: nothing to do
    if (isNotification) return null;                        // any other notification is ignored, as the specification allows
    switch (method) {
      case 'initialize':
        return ok(id, { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: { listChanged: false } }, serverInfo: { name, version }, ...(instructions ? { instructions } : {}) });
      case 'ping':
        return ok(id, {});
      case 'tools/list':
        return ok(id, { tools: tools.map(({ name: n, description, inputSchema }) => ({ name: n, description, inputSchema })) });
      case 'tools/call': {
        const wanted = params && typeof params === 'object' ? params.name : undefined;
        const tool = byName.get(wanted);
        if (!tool) return error(id, INVALID_PARAMS, `unknown tool: ${String(wanted)}`);
        const args = params && params.arguments && typeof params.arguments === 'object' ? params.arguments : {};
        try {
          const r = await tool.handler(args);
          const text = typeof r === 'string' ? r : String(r && r.text);
          return ok(id, { content: [{ type: 'text', text }], isError: Boolean(r && typeof r === 'object' && r.isError) });
        } catch (e) {
          // A tool's failure is a tool result, not a protocol error: the host shows it to the model.
          return ok(id, { content: [{ type: 'text', text: e.message }], isError: true });
        }
      }
      default:
        return error(id, METHOD_NOT_FOUND, `method not found: ${method}`);
    }
  }

  /** Reads newline-delimited JSON from `input`, answers on `output`, in order. */
  function listen({ input = process.stdin, output = process.stdout, log = (line) => process.stderr.write(`${line}\n`) } = {}) {
    let buffer = '';
    let queue = Promise.resolve();
    const write = (reply) => { if (reply) output.write(`${JSON.stringify(reply)}\n`); };
    input.setEncoding('utf8');
    input.on('data', (chunk) => {
      buffer += chunk;
      let nl;
      while ((nl = buffer.indexOf('\n')) >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { write(error(null, PARSE_ERROR, 'parse error')); continue; }
        queue = queue.then(() => handle(msg)).then(write).catch((e) => log(`microtoll-mcp: ${e.message}`));
      }
    });
    input.on('end', () => { queue.then(() => { if (typeof output.end === 'function' && output !== process.stdout) output.end(); }); });
    return { stop: () => input.removeAllListeners('data') };
  }

  return { handle, listen, tools };
}
