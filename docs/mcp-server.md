# MCP Server

Peek-a-Bin includes an [MCP (Model Context Protocol)](https://modelcontextprotocol.io) server that lets AI agents programmatically analyze PE binaries. It uses the same parse, disassemble, and decompile pipeline as the browser UI, running in Node.js via stdio transport.

## Quick Setup

The setup CLI automatically configures supported AI clients:

```bash
npx tsx src/mcp/index.ts setup <client>
```

| Client | Command | What it does |
|--------|---------|-------------|
| `claude-code` | `npx tsx src/mcp/index.ts setup claude-code` | Merges into `~/.claude.json` |
| `opencode` | `npx tsx src/mcp/index.ts setup opencode` | Merges into `~/.config/opencode/config.json` |
| `continue` | `npx tsx src/mcp/index.ts setup continue` | Prints YAML snippet for `~/.continue/config.yaml` |

### CLI Flags

```bash
# List all available clients
npx tsx src/mcp/index.ts setup --list

# Preview config without writing (dry run)
npx tsx src/mcp/index.ts setup claude-code --dry-run
```

### Claude Code Auto-Discovery

When working inside the project directory, Claude Code automatically discovers the MCP server via the `.mcp.json` file at the project root — no manual setup needed.

## Starting Manually

```bash
npm run mcp
```

The server loads the Capstone WASM engine on startup and accepts MCP requests over stdin/stdout.

## Tools Reference

13 tools are available, defined in `src/mcp/tools.ts`:

### Analysis Tools

#### `load_pe`
Load a PE file from disk and run full analysis (parse, disassemble, detect functions, build xrefs, detect anomalies).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `filePath` | string | Yes | Absolute path to the PE file |
| `id` | string | No | Identifier (defaults to filename) |

Returns summary with header info, function count, anomalies, and driver detection.

#### `list_files`
List all currently loaded PE files with basic metadata (architecture, section count, function count). No parameters.

#### `list_functions`
List detected functions in a loaded file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |
| `filter` | string | No | Substring filter for function names |
| `offset` | number | No | Pagination offset (default 0) |
| `limit` | number | No | Max results (default 100) |

#### `decompile_function`
Decompile a function to C-like pseudocode. Runs the full pipeline: stack analysis, signature inference, CFG, IR lifting, SSA, optimization, structuring, type inference, struct synthesis, and emission.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |
| `address` | number or string | Yes | Function address (hex string or number) |

Returns `{ functionName, address, code, lineMap }`.

#### `disassemble_function`
Get formatted assembly listing for a function (address, raw bytes, mnemonic, operands, inline comments).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |
| `address` | number or string | Yes | Function address |

#### `get_xrefs`
Get cross-references to a given address — calls, jumps, branches, and data references.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |
| `address` | number or string | Yes | Target address |

#### `detect_anomalies`
Get security anomalies with severity, title, and detail for each finding.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |

### Annotation Tools

#### `add_comment`
Add or remove a comment at an address. Empty text removes the comment.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |
| `address` | number or string | Yes | Address to comment |
| `text` | string | Yes | Comment text (empty to remove) |

#### `rename_function`
Rename a function. Empty name removes the rename.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |
| `address` | number or string | Yes | Function address |
| `name` | string | Yes | New name (empty to remove) |

#### `add_bookmark`
Toggle a bookmark at an address (adds if absent, removes if present).

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |
| `address` | number or string | Yes | Address to bookmark |
| `label` | string | No | Bookmark label |

#### `list_comments`
List all annotations (comments, renames, bookmarks) for a file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |

### Import/Export Tools

#### `export_analysis`
Export annotations as ExportSchemaV1 JSON, optionally writing to a file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |
| `outputPath` | string | No | File path to write JSON to |

#### `import_analysis`
Import annotations from an ExportSchemaV1 JSON file, merging into the current session.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `fileId` | string | Yes | ID of the loaded PE file |
| `inputPath` | string | Yes | Path to ExportSchemaV1 JSON file |

## Resources Reference

PE file data is exposed as MCP resources using the URI template `pe://{fileId}/<resource>`:

| Resource | URI | Description |
|----------|-----|-------------|
| Headers | `pe://{fileId}/headers` | Image base, entry point, subsystem, DLL characteristics, machine type, timestamps |
| Sections | `pe://{fileId}/sections` | Section table with names, addresses, sizes, and characteristic flags |
| Imports | `pe://{fileId}/imports` | Import table — libraries and functions with IAT addresses |
| Exports | `pe://{fileId}/exports` | Export table — name, ordinal, and address for each export |
| Strings | `pe://{fileId}/strings` | Extracted strings with addresses and encoding (ascii/utf16le) |
| Functions | `pe://{fileId}/functions` | Detected function list with names, addresses, sizes, thunk status |
| Anomalies | `pe://{fileId}/anomalies` | Security anomalies with severity, title, and detail |
| Driver | `pe://{fileId}/driver` | Driver analysis — detection status, kernel modules, WDM flag |

## Live Browser Sync

When the MCP server runs alongside the browser app, annotations made via MCP tools are pushed to the browser in real-time over WebSocket.

- **Direction:** One-way (MCP → browser)
- **Requirement:** Same PE file must be loaded in both
- **Auto-reconnect:** Browser reconnects with 3-second backoff if the MCP server restarts
- **Status indicator:** Green "MCP" dot in the status bar when connected
- **Default port:** 19283
- **Override:** Set `PEEK_A_BIN_WS_PORT` environment variable:
  ```bash
  PEEK_A_BIN_WS_PORT=9999 npm run mcp
  ```

## Multi-File Sessions

The MCP server supports loading multiple PE files. Each file is identified by an `id` (auto-generated from filename or explicitly provided via `load_pe`). All tools and resources reference files by this ID, enabling side-by-side analysis.

## Adding New Clients

The client registry is in `src/mcp/clients.ts`. Each client implements the `ClientSetup` interface:

```typescript
interface ClientSetup {
  name: string;
  slug: string;
  description: string;
  generateConfig(projectDir: string): { path: string | null; content: string; action: string };
  apply(projectDir: string): string;
  detect?(): boolean;
}
```

To add a new client, insert a new entry in the `clients` Map. The setup CLI automatically picks it up.

## Example Prompts

Once configured, you can ask your AI agent:

- *"Load and analyze /path/to/notepad.exe"*
- *"Decompile the entry_point function"*
- *"List all functions containing 'Create'"*
- *"What security anomalies were detected?"*
- *"Show me the import table"*
- *"Get cross-references to 0x140001000"*
- *"Add a comment at 0x401000 saying 'main loop starts here'"*
- *"Export annotations to analysis.json"*
