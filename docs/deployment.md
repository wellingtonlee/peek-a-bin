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

`vite.config.ts` configures `VitePWA` with `registerType: "autoUpdate"` and:

- `globPatterns: ["**/*.{js,css,html,wasm,png,svg,json}"]` — `json` is there for
  `manifest.json`, the only JSON in `dist`, so the PWA manifest is available offline.
- `globIgnores: ["icons/icon-512.png"]` — that icon is 435 KB and is only read by the OS at
  install and splash time, which happens online. `icon-192.png` still ships.

A production build currently reports **10 precache entries, ~2.7 MiB**. The exact size tracks
the app bundle and moves with ordinary code changes; the entry count and the single WASM copy
are the parts worth watching.

Two points worth knowing:

- The engine is **1.70 MiB** (1,778,509 bytes), under Workbox's default
  `maximumFileSizeToCacheInBytes` of 2 MiB. The config sets no override, so it is precached only
  because it happens to fit. If capstone-wasm grows past 2 MiB, Workbox will silently drop it
  from the precache and offline disassembly will break with no build error.
- The engine ships **once**, as a hashed asset (`assets/capstone-<hash>.wasm`). It used to ship
  twice, and the fix is counterintuitive enough to be worth stating plainly: Rollup already
  recognises capstone-wasm's `new URL("capstone.wasm", import.meta.url)` and rewrites it to the
  hashed asset it emits, so the `copy-capstone-wasm` plugin that also copied the file under its
  literal name was itself the *sole* cause of the duplicate. Deleting the plugin removed
  1.7 MiB from every install. **Re-adding it will re-add that 1.7 MiB.**

In its place, `vite.config.ts` runs a `capstone-wasm-guard` plugin that fails the build if
`dist/assets` ever contains anything other than exactly one `.wasm` file, or if the emitted
`.wasm` is referenced by no chunk — the failure mode if Rollup ever stops rewriting that
`new URL(...)` pattern, which would otherwise ship an app that 404s on the disassembly engine.

## Content Security Policy

The policy itself is defined once, in **`build/csp.ts`**, and both deployment paths consume it
from there. The rationale for every directive lives in
[SECURITY.md](../SECURITY.md#content-security-policy); what follows is only how it is delivered.

| Path | Mechanism |
|------|-----------|
| GitHub Pages | Pages cannot set response headers, so the `inject-csp-meta` Vite plugin (`vite.config.ts`) injects `<meta http-equiv="Content-Security-Policy">` into `dist/index.html` |
| Docker / nginx | `nginx.conf` carries the generated `add_header` line verbatim, in both the server block and the static-asset location block |

The plugin is **build-only** (`apply: "build"`, `transformIndexHtml` with `order: "pre"`).
`index.html` doubles as the dev entry point, and Vite injects an inline React Refresh preamble
in dev that a source-level meta CSP would block — so committing the tag into `index.html` would
break `npm run dev`. Running at `"pre"` puts the policy in the document before the built
`<script>`/`<link>` tags it governs, and the plugin throws rather than shipping a build if it
cannot find the `<meta charset>` it anchors to.

The header policy carries one directive the meta tag does not: `frame-ancestors`, which browsers
ignore when it arrives via `<meta http-equiv>`. Clickjacking protection therefore exists only on
the nginx deployment.

**To change the policy:** edit `build/csp.ts`, then regenerate the nginx line and paste it into
both places in `nginx.conf`:

```bash
npx tsx -e 'import("./build/csp.ts").then(m => console.log(m.nginxCspHeaderLine()))'
```

`build/csp.test.ts` fails the test suite if `nginx.conf` stops matching what `build/csp.ts`
generates, so the two delivery paths cannot drift apart silently.

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
