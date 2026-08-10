/**
 * MCP client config registry (`src/mcp/clients.ts`).
 *
 * `generateConfig` reads (and `apply` writes) files under the user's home
 * directory, so every test redirects HOME to a temp dir — os.homedir() reads
 * process.env.HOME on POSIX, and both are resolved at call time.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { clients } from "../clients";

const PROJECT = "/home/example/peek-a-bin";
const SERVER_ENTRY = resolve(PROJECT, "src/mcp/index.ts");

let home: string;
const savedHome = process.env.HOME;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "peek-home-"));
  process.env.HOME = home;
});

afterEach(() => {
  if (savedHome === undefined) delete process.env.HOME;
  else process.env.HOME = savedHome;
  rmSync(home, { recursive: true, force: true });
});

describe("client registry", () => {
  it("registers exactly the three supported clients", () => {
    expect([...clients.keys()].sort()).toEqual(["claude-code", "continue", "opencode"]);
  });

  it("gives every client a slug matching its registry key", () => {
    for (const [key, client] of clients) {
      expect(client.slug).toBe(key);
      expect(client.name).toBeTruthy();
      expect(client.description).toBeTruthy();
    }
  });
});

describe("generateConfig — claude-code", () => {
  it("targets ~/.claude.json and registers the server under mcpServers", () => {
    const { path, content, action } = clients.get("claude-code")!.generateConfig(PROJECT);

    expect(path).toBe(join(home, ".claude.json"));
    expect(action).toContain(join(home, ".claude.json"));
    expect(JSON.parse(content).mcpServers["peek-a-bin"]).toEqual({
      command: "npx",
      args: ["tsx", SERVER_ENTRY],
    });
  });

  it("resolves a relative project dir against the cwd", () => {
    const { content } = clients.get("claude-code")!.generateConfig(".");
    const args = JSON.parse(content).mcpServers["peek-a-bin"].args as string[];

    expect(args[1]).toBe(resolve(".", "src/mcp/index.ts"));
    expect(args[1].startsWith("/")).toBe(true);
  });

  it("preserves unrelated keys and other servers in an existing config", () => {
    writeFileSync(
      join(home, ".claude.json"),
      JSON.stringify({ theme: "dark", mcpServers: { other: { command: "foo" } } }),
    );

    const { content } = clients.get("claude-code")!.generateConfig(PROJECT);
    const config = JSON.parse(content);

    expect(config.theme).toBe("dark");
    expect(config.mcpServers.other).toEqual({ command: "foo" });
    expect(config.mcpServers["peek-a-bin"]).toBeDefined();
  });

  it("replaces a stale peek-a-bin entry rather than duplicating it", () => {
    writeFileSync(
      join(home, ".claude.json"),
      JSON.stringify({ mcpServers: { "peek-a-bin": { command: "old", args: ["stale"] } } }),
    );

    const { content } = clients.get("claude-code")!.generateConfig(PROJECT);
    const entry = JSON.parse(content).mcpServers["peek-a-bin"];

    expect(entry.command).toBe("npx");
    expect(entry.args).toEqual(["tsx", SERVER_ENTRY]);
  });

  it("starts from an empty object when the config file is unreadable JSON", () => {
    writeFileSync(join(home, ".claude.json"), "not json at all");

    const { content } = clients.get("claude-code")!.generateConfig(PROJECT);
    expect(Object.keys(JSON.parse(content))).toEqual(["mcpServers"]);
  });

  it("does not write anything — generateConfig is a preview", () => {
    clients.get("claude-code")!.generateConfig(PROJECT);
    expect(existsSync(join(home, ".claude.json"))).toBe(false);
  });
});

describe("generateConfig — opencode", () => {
  it("targets ~/.config/opencode/config.json with a local command array", () => {
    const { path, content } = clients.get("opencode")!.generateConfig(PROJECT);

    expect(path).toBe(join(home, ".config", "opencode", "config.json"));
    expect(JSON.parse(content).mcp["peek-a-bin"]).toEqual({
      type: "local",
      command: ["npx", "tsx", SERVER_ENTRY],
      enabled: true,
    });
  });

  it("merges into an existing mcp block without dropping other servers", () => {
    const configDir = join(home, ".config", "opencode");
    mkdirSync(configDir, { recursive: true });
    writeFileSync(
      join(configDir, "config.json"),
      JSON.stringify({ model: "something", mcp: { other: { type: "remote" } } }),
    );

    const config = JSON.parse(clients.get("opencode")!.generateConfig(PROJECT).content);

    expect(config.model).toBe("something");
    expect(config.mcp.other).toEqual({ type: "remote" });
    expect(config.mcp["peek-a-bin"].enabled).toBe(true);
  });
});

describe("generateConfig — continue", () => {
  it("has no config path and emits a pasteable YAML snippet", () => {
    const { path, content, action } = clients.get("continue")!.generateConfig(PROJECT);

    expect(path).toBeNull();
    expect(action).toMatch(/config\.yaml/);
    expect(content).toBe(
      [
        "mcpServers:",
        "  - name: peek-a-bin",
        "    command: npx",
        "    args:",
        "      - tsx",
        `      - ${SERVER_ENTRY}`,
      ].join("\n"),
    );
  });

  it("is stable across calls (nothing on disk feeds into it)", () => {
    const a = clients.get("continue")!.generateConfig(PROJECT).content;
    const b = clients.get("continue")!.generateConfig(PROJECT).content;
    expect(a).toBe(b);
  });
});

describe("apply", () => {
  it("claude-code writes ~/.claude.json with a trailing newline", () => {
    const action = clients.get("claude-code")!.apply(PROJECT);

    const configPath = join(home, ".claude.json");
    expect(existsSync(configPath)).toBe(true);
    const raw = readFileSync(configPath, "utf-8");
    expect(raw.endsWith("\n")).toBe(true);
    expect(JSON.parse(raw).mcpServers["peek-a-bin"].args).toEqual(["tsx", SERVER_ENTRY]);
    expect(action).toContain(configPath);
  });

  it("claude-code apply keeps existing settings", () => {
    writeFileSync(join(home, ".claude.json"), JSON.stringify({ theme: "dark" }));
    clients.get("claude-code")!.apply(PROJECT);

    const config = JSON.parse(readFileSync(join(home, ".claude.json"), "utf-8"));
    expect(config.theme).toBe("dark");
    expect(config.mcpServers["peek-a-bin"]).toBeDefined();
  });

  it("opencode creates the nested config directory", () => {
    clients.get("opencode")!.apply(PROJECT);

    const configPath = join(home, ".config", "opencode", "config.json");
    expect(existsSync(configPath)).toBe(true);
    expect(JSON.parse(readFileSync(configPath, "utf-8")).mcp["peek-a-bin"].type).toBe("local");
  });

  it("opencode apply is idempotent", () => {
    clients.get("opencode")!.apply(PROJECT);
    const first = readFileSync(join(home, ".config", "opencode", "config.json"), "utf-8");
    clients.get("opencode")!.apply(PROJECT);
    const second = readFileSync(join(home, ".config", "opencode", "config.json"), "utf-8");

    expect(second).toBe(first);
  });

  it("continue prints to stdout and writes no file", () => {
    const written: string[] = [];
    const original = process.stdout.write.bind(process.stdout);
    process.stdout.write = ((chunk: string) => {
      written.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      const result = clients.get("continue")!.apply(PROJECT);
      expect(result).toMatch(/stdout/i);
    } finally {
      process.stdout.write = original;
    }

    expect(written.join("")).toContain("mcpServers:");
    expect(existsSync(join(home, ".continue"))).toBe(false);
  });
});
