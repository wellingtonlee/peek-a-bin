# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities via [GitHub Security Advisories](https://github.com/wellingtonlee/peek-a-bin/security/advisories/new) (private vulnerability reporting).

Do **not** open a public issue for security vulnerabilities.

## Scope

| Component | Attack Surface |
|-----------|---------------|
| **Browser app** | PE parser (malformed input), WASM engine, localStorage |
| **Ghidra server** | REST API, file uploads, bearer token auth |
| **MCP server** | Filesystem read access, WebSocket bridge |
| **AI features** | API key storage, LLM prompt injection |

## Security Model

- **All analysis is client-side** — PE files are never uploaded to any server (unless using the optional Ghidra server)
- **API keys** are stored in `localStorage` (not encrypted). They are sent only to the user-configured LLM endpoint.
- **Ghidra server CORS** allows all origins by default — restrict in production if exposing beyond localhost
- **MCP server** has filesystem read access for loading PE files from disk
- **MCP WebSocket** bridge is unencrypted and unauthenticated — intended for localhost use only

## Known Considerations

- localStorage is not encrypted — API keys are accessible to other scripts on the same origin
- Ghidra server CORS is permissive (`*`) — tighten for production deployments
- MCP server can read arbitrary files via `load_pe` — run in trusted environments
- PE parser has not been extensively fuzzed against adversarial inputs

## Supported Versions

Security fixes are applied to the latest release only.
