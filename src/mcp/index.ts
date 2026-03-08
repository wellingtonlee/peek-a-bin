#!/usr/bin/env npx tsx
/**
 * Peek-a-Bin MCP Server
 * Exposes PE analysis tools via Model Context Protocol (stdio transport).
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { initCapstone } from './disasm.js';
import { FileSession } from './session.js';
import { registerTools } from './tools.js';
import { registerResources } from './resources.js';

const server = new McpServer({
  name: 'peek-a-bin',
  version: '0.1.0',
});

const session = new FileSession();

registerTools(server, session);
registerResources(server, session);

async function main() {
  // Initialize Capstone WASM engine
  await initCapstone();

  // Connect via stdio
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
