#!/usr/bin/env npx tsx
/**
 * Peek-a-Bin MCP Server
 * Exposes PE analysis tools via Model Context Protocol (stdio transport).
 */

// CLI routing guard — handle `setup` subcommand before any heavy imports
if (process.argv[2] === 'setup') {
  const { runSetup } = await import('./cli.js');
  await runSetup(process.argv.slice(3));
  process.exit(0);
}

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { WebSocketServer } from 'ws';
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

  // Start WebSocket server for browser live sync
  const WS_PORT = Number(process.env.PEEK_A_BIN_WS_PORT) || 19283;
  const wss = new WebSocketServer({ port: WS_PORT });
  const clients = new Set<import('ws').WebSocket>();
  wss.on('connection', (ws) => {
    clients.add(ws);
    ws.on('close', () => clients.delete(ws));
  });

  session.onAnnotationChange = (_fileId, af) => {
    const msg = JSON.stringify({
      type: 'annotations',
      fileName: af.fileName,
      comments: af.comments,
      renames: af.renames,
      bookmarks: af.bookmarks,
    });
    for (const c of clients) c.send(msg);
  };

  process.stderr.write(`[peek-a-bin] WS sync on port ${WS_PORT}\n`);

  // Connect via stdio
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
