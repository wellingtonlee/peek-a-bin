/**
 * CLI for MCP setup: configures AI clients to use the Peek-a-Bin MCP server.
 *
 * Usage:
 *   peek-a-bin-mcp setup              # list available clients
 *   peek-a-bin-mcp setup --list       # same
 *   peek-a-bin-mcp setup <client>     # write config for client
 *   peek-a-bin-mcp setup <client> --dry-run  # preview without writing
 */

import { existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { clients } from './clients.js';

function findProjectDir(): string {
  const __filename = fileURLToPath(import.meta.url);
  let dir = dirname(__filename);
  // Walk up until we find package.json
  while (dir !== dirname(dir)) {
    if (existsSync(resolve(dir, 'package.json'))) return dir;
    dir = dirname(dir);
  }
  // Fallback: two levels up from src/mcp/
  return resolve(dirname(__filename), '..', '..');
}

function listClients(): void {
  process.stdout.write('\nAvailable clients:\n\n');
  for (const [slug, client] of clients) {
    process.stdout.write(`  ${slug.padEnd(14)} ${client.name} — ${client.description}\n`);
  }
  process.stdout.write('\nUsage: peek-a-bin-mcp setup <client> [--dry-run]\n\n');
}

export async function runSetup(args: string[]): Promise<void> {
  // No args or --list → show available clients
  if (args.length === 0 || args[0] === '--list') {
    listClients();
    return;
  }

  const slug = args[0];
  const dryRun = args.includes('--dry-run');

  const client = clients.get(slug);
  if (!client) {
    process.stderr.write(`Unknown client: ${slug}\n`);
    listClients();
    process.exitCode = 1;
    return;
  }

  const projectDir = findProjectDir();

  if (dryRun) {
    const { path, content, action } = client.generateConfig(projectDir);
    process.stdout.write(`\n[dry-run] ${action}\n`);
    if (path) {
      process.stdout.write(`File: ${path}\n`);
    }
    process.stdout.write(`\n${content}\n\n`);
    return;
  }

  const result = client.apply(projectDir);
  process.stdout.write(`\n✓ ${result}\n\n`);
}
