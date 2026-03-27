/**
 * MCP client config registry.
 * Each entry knows how to generate and write its config for a specific AI client.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { homedir } from 'node:os';

export interface ClientSetup {
  name: string;
  slug: string;
  description: string;
  /** Generate the action description and config content. */
  generateConfig(projectDir: string): { path: string | null; content: string; action: string };
  /** Write config to disk (merge into existing if needed). Returns description of what was done. */
  apply(projectDir: string): string;
  /** Optional detection: returns true if this client appears to be installed. */
  detect?(): boolean;
}

function readJsonFile(path: string): Record<string, unknown> {
  try {
    return JSON.parse(readFileSync(path, 'utf-8'));
  } catch {
    return {};
  }
}

function writeJsonFile(path: string, data: Record<string, unknown>): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(data, null, 2) + '\n', 'utf-8');
}

export const clients: Map<string, ClientSetup> = new Map();

// --- Claude Code ---
clients.set('claude-code', {
  name: 'Claude Code',
  slug: 'claude-code',
  description: 'Writes MCP server config to ~/.claude.json (global Claude Code settings)',

  generateConfig(projectDir: string) {
    const configPath = resolve(homedir(), '.claude.json');
    const entry = {
      command: 'npx',
      args: ['tsx', resolve(projectDir, 'src/mcp/index.ts')],
    };
    const config = readJsonFile(configPath);
    const servers = (config.mcpServers as Record<string, unknown>) ?? {};
    servers['peek-a-bin'] = entry;
    config.mcpServers = servers;
    return {
      path: configPath,
      content: JSON.stringify(config, null, 2),
      action: `Merge peek-a-bin entry into ${configPath}`,
    };
  },

  apply(projectDir: string) {
    const { path, action } = this.generateConfig(projectDir);
    const configPath = path!;
    const config = readJsonFile(configPath);
    const servers = (config.mcpServers as Record<string, unknown>) ?? {};
    servers['peek-a-bin'] = {
      command: 'npx',
      args: ['tsx', resolve(projectDir, 'src/mcp/index.ts')],
    };
    config.mcpServers = servers;
    writeJsonFile(configPath, config);
    return action;
  },
});

// --- OpenCode ---
clients.set('opencode', {
  name: 'OpenCode',
  slug: 'opencode',
  description: 'Writes MCP server config to ~/.config/opencode/config.json',

  generateConfig(projectDir: string) {
    const configPath = resolve(homedir(), '.config', 'opencode', 'config.json');
    const entry = {
      type: 'local',
      command: ['npx', 'tsx', resolve(projectDir, 'src/mcp/index.ts')],
      enabled: true,
    };
    const config = readJsonFile(configPath);
    const mcp = (config.mcp as Record<string, unknown>) ?? {};
    mcp['peek-a-bin'] = entry;
    config.mcp = mcp;
    return {
      path: configPath,
      content: JSON.stringify(config, null, 2),
      action: `Merge peek-a-bin entry into ${configPath}`,
    };
  },

  apply(projectDir: string) {
    const { path, action } = this.generateConfig(projectDir);
    const configPath = path!;
    const config = readJsonFile(configPath);
    const mcp = (config.mcp as Record<string, unknown>) ?? {};
    mcp['peek-a-bin'] = {
      type: 'local',
      command: ['npx', 'tsx', resolve(projectDir, 'src/mcp/index.ts')],
      enabled: true,
    };
    config.mcp = mcp;
    writeJsonFile(configPath, config);
    return action;
  },
});

// --- Continue.dev ---
clients.set('continue', {
  name: 'Continue.dev',
  slug: 'continue',
  description: 'Prints YAML snippet for ~/.continue/config.yaml (paste manually)',

  generateConfig(projectDir: string) {
    const absPath = resolve(projectDir, 'src/mcp/index.ts');
    const yaml = [
      'mcpServers:',
      '  - name: peek-a-bin',
      '    command: npx',
      '    args:',
      '      - tsx',
      `      - ${absPath}`,
    ].join('\n');
    return {
      path: null,
      content: yaml,
      action: 'Add the following to your ~/.continue/config.yaml:',
    };
  },

  apply(projectDir: string) {
    const { content, action } = this.generateConfig(projectDir);
    process.stdout.write(`\n${action}\n\n${content}\n\n`);
    return 'Printed YAML snippet to stdout';
  },
});
