# Deployment

## Production Build

Requires **Node.js 20+** (`engines.node` in `package.json`). On Node 18 the build bundles
successfully and then fails with `ReferenceError: crypto is not defined`, raised by
`serialize-javascript` via `@rollup/plugin-terser` on the PWA/Workbox path; Node exposes the
global `crypto` unflagged only from 20 onward.

```bash
npm run build
npm run preview  # http://localhost:4173/peek-a-bin/
```

The build outputs to `dist/` with optimized, minified assets.

## Docker

Multi-stage build with Nginx:

```bash
docker build -t peek-a-bin .
docker run -p 8080:80 peek-a-bin
# http://localhost:8080/peek-a-bin/
```

The Dockerfile uses `node:20-alpine` for building and `nginx:alpine` for serving. Assets are served under the `/peek-a-bin/` path prefix.

## GitHub Pages

Deployment is triggered by version tags:

1. Push a `v*.*.*` tag (e.g., `v1.0.0`)
2. The `deploy.yml` workflow runs: type-check → test → build → deploy to GitHub Pages
3. Manual deployment is also available via `workflow_dispatch`

**Live demo:** [https://wellingtonlee.github.io/peek-a-bin/](https://wellingtonlee.github.io/peek-a-bin/)

## CI/CD

### CI (`ci.yml`)

Runs on every push and PR to `main`, on Node 20. Two jobs:

**`check`** — `npm run lint` (Biome) → `npm run typecheck` → `npm test` → `npm run build`.
The build step is deliberately included: it previously ran only on release tags, so a Vite or
PWA break could ship unnoticed.

**`audit`** — `npm audit --audit-level=high`. The threshold is `high` rather than `moderate`
because one moderate advisory (`@hono/node-server` path traversal) is pinned transitively by
`@modelcontextprotocol/sdk` with no upstream fix, and is unreachable here — the MCP server uses
stdio and `ws`, not Hono's static file serving.

### Deploy (`deploy.yml`)

Runs on `v*.*.*` tags and manual dispatch, on Node 20:
- `npx tsc --noEmit` → `npm test` → `npm run build`
- Upload to GitHub Pages

## Releasing

1. Bump `version` in `package.json`
2. Rename `[Unreleased]` to `[x.y.z] - YYYY-MM-DD` in `CHANGELOG.md`; add fresh `[Unreleased]` section
3. Commit, tag, and push:
   ```bash
   git tag v1.0.0
   git push --tags
   ```
4. The tag triggers the deploy workflow

## PWA / Offline

Peek-a-Bin is a Progressive Web App that works fully offline after the first visit.

1. **Visit the app** in Chrome, Edge, or another PWA-capable browser
2. **Install it** — click the install icon in the address bar, or use "Add to Home Screen" on mobile
3. **Use offline** — the service worker precaches all assets, including the Capstone WASM engine
4. **Updates** — auto-updates in the background; new version loads on next visit

> **Note:** The PWA caches the app itself. PE files are never uploaded — all processing is local.

### Precache contents

`vite.config.ts` configures `VitePWA` with `globPatterns: ["**/*.{js,css,html,wasm,png,svg}"]`
and `registerType: "autoUpdate"`. A production build reports **11 precache entries, ~4.85 MiB**,
and `dist/sw.js` lists the WASM engine explicitly:

```
{url:"assets/capstone.wasm",revision:null}
{url:"assets/capstone-DLaga0AD.wasm",revision:null}
```

Two points worth knowing:

- `capstone.wasm` is **1.70 MiB** (1,778,509 bytes), which is under Workbox's default
  `maximumFileSizeToCacheInBytes` of 2 MiB. The config sets no override, so the engine is
  precached only because it happens to fit. If capstone-wasm grows past 2 MiB, Workbox will
  silently drop it from the precache and offline disassembly will break with no build error.
- The engine ships **twice** — once hashed by Vite and once copied under its original name by
  the `copy-capstone-wasm` plugin (the pre-bundled `.mjs` references `capstone.wasm` by that
  literal name). Both copies are precached, so ~3.4 MiB of the 4.85 MiB total is one duplicated
  file.

## Self-Hosting Notes

### Base Path

The app is configured to serve under `/peek-a-bin/`. If you need a different base path, update `base` in `vite.config.ts` and rebuild.

### WASM MIME Type

Your web server must serve `.wasm` files with the `application/wasm` MIME type. Most modern servers (Nginx, Apache, Caddy) handle this by default. If the disassembly engine fails to load, check your server's MIME type configuration.

### CORS for Ghidra Proxy

If you're running the Ghidra server behind a reverse proxy alongside the app:
- Ensure the proxy forwards CORS headers, or configure its own CORS policy
- The Ghidra server allows all origins by default

### HTTPS

If serving over HTTPS, the Ghidra server connection must also use HTTPS (or be on `localhost`). Mixed-content requests (HTTPS app → HTTP server) are blocked by browsers.

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PEEK_A_BIN_WS_PORT` | `19283` | WebSocket port for MCP → browser sync |
| `PEEK_A_BIN_WS_HOST` | `127.0.0.1` | Bind address for the MCP → browser WebSocket bridge |
| `PEEK_A_BIN_EXPORT_DIR` | process working directory | Root that `export_analysis` writes are confined to |

> `PEEK_A_BIN_WS_HOST=0.0.0.0` exposes an unauthenticated annotation-injection channel to the
> network. See [SECURITY.md](../SECURITY.md) before changing it.

`.env.example` currently documents only `PEEK_A_BIN_WS_PORT` — the other two are described here
and in [mcp-server.md](mcp-server.md).
