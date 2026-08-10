/**
 * Peek-a-Bin MCP Server
 * Exposes PE analysis tools via Model Context Protocol (stdio transport).
 *
 * Run via `npm run mcp` or `npx tsx src/mcp/index.ts` — this file is not directly
 * executable (a `#!/usr/bin/env npx tsx` shebang cannot work: env receives the
 * single argument "npx tsx"). All client configs in clients.ts invoke it via npx.
 */

// CLI routing guard — handle the `setup` subcommand and exit before the server starts.
// Note: this does NOT avoid loading the imports below — ESM static imports are hoisted
// and fully evaluated before any top-level statement runs. It only skips main().
if (process.argv[2] === 'setup') {
  const { runSetup } = await import('./cli.js');
  await runSetup(process.argv.slice(3));
  process.exit(0);
}

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { WebSocket, WebSocketServer } from 'ws';
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

  // Start WebSocket server for browser live sync.
  // The bridge is unauthenticated and unencrypted, so it binds to loopback only.
  // PEEK_A_BIN_WS_HOST can opt into a wider bind (e.g. 0.0.0.0) for users who
  // deliberately want remote access and provide their own network controls.
  const WS_PORT = Number(process.env.PEEK_A_BIN_WS_PORT) || 19283;
  const WS_HOST = process.env.PEEK_A_BIN_WS_HOST || '127.0.0.1';
  const wss = new WebSocketServer({ port: WS_PORT, host: WS_HOST });
  const clients = new Set<WebSocket>();
  wss.on('connection', (ws) => {
    clients.add(ws);
    ws.on('close', () => clients.delete(ws));
    // Without an 'error' listener, ws re-emits socket errors as uncaught exceptions.
    ws.on('error', () => clients.delete(ws));
  });

  wss.on('listening', () => {
    process.stderr.write(`[peek-a-bin] WS sync on ${WS_HOST}:${WS_PORT}\n`);
  });

  // EADDRINUSE (and friends) arrive as an 'error' event; unhandled, it kills the process.
  // Live sync is optional, so degrade instead of taking the MCP server down.
  wss.on('error', (err) => {
    process.stderr.write(`[peek-a-bin] WS sync disabled: ${err instanceof Error ? err.message : String(err)}\n`);
  });

  session.onAnnotationChange = (_fileId, af) => {
    const msg = JSON.stringify({
      type: 'annotations',
      fileName: af.fileName,
      comments: af.comments,
      renames: af.renames,
      bookmarks: af.bookmarks,
    });
    for (const c of clients) {
      if (c.readyState !== WebSocket.OPEN) continue;
      try {
        c.send(msg);
      } catch {
        // Socket raced into closing between the check and the send — drop it.
        clients.delete(c);
      }
    }
  };

  // Connect via stdio
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
