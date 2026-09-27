#!/usr/bin/env node
// The Microtoll MCP server on standard input and output. Add it to a host:
//   claude mcp add microtoll -- npx -y @microtoll/mcp
// Stdout is the protocol; anything else goes to stderr.
import { createMicrotollServer } from '../src/index.js';

createMicrotollServer().listen();
