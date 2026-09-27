// Hand-written declarations for @microtoll/mcp (M5).
export const PROTOCOL_VERSION: '2025-06-18';
export const VERSION: string;
export const INSTRUCTIONS: string;

export interface ToolResult { text: string; isError?: boolean; }
export interface Tool {
  name: string;
  description: string;
  inputSchema: object;
  handler(args: Record<string, unknown>): string | ToolResult | Promise<string | ToolResult>;
}
export interface JsonRpcMessage { jsonrpc?: string; id?: string | number | null; method?: string; params?: unknown; }
export interface JsonRpcReply { jsonrpc: '2.0'; id: string | number | null; result?: unknown; error?: { code: number; message: string; data?: unknown }; }
export interface ReadableLike { setEncoding(enc: string): unknown; on(event: string, listener: (...args: any[]) => void): unknown; removeAllListeners(event: string): unknown; }
export interface WritableLike { write(text: string): unknown; end?(): unknown; }
export interface McpServer {
  handle(message: unknown): Promise<JsonRpcReply | null>;
  listen(options?: { input?: ReadableLike; output?: WritableLike; log?: (line: string) => void }): { stop(): void };
  tools: Tool[];
}
export function createServer(options: { name: string; version: string; instructions?: string; tools?: Tool[] }): McpServer;
export function createMicrotollServer(): McpServer;
export function tools(): Tool[];

export interface DocPage { path: string; url: string; title: string; description: string; section: string; markdown: string; sections: Array<{ heading: string | null; level: number; text: string }>; }
export function loadDocs(file?: URL): DocPage[];
export function readDoc(path: string, docs?: DocPage[]): { path: string; url: string; title: string; description: string; markdown: string } | null;
export interface SearchHit { path: string; url: string; title: string; heading: string; score: number; excerpt: string; }
export function searchDocs(query: string, options?: { limit?: number; docs?: DocPage[] }): SearchHit[];
export function formatSearch(query: string, hits: SearchHit[]): string;

export interface ScaffoldOptions { directory: string; namespace?: string; origin?: string; name?: string | null; }
export function renderScaffold(options?: Omit<ScaffoldOptions, 'directory'>, templatesDir?: string): { files: Array<{ name: string; text: string }>; namespace: string; origin: string; name: string };
export function scaffold(options: ScaffoldOptions): { directory: string; files: string[]; namespace: string; origin: string; next: string[] };
