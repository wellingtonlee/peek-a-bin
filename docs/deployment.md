# Deployment

## Production Build

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

Runs on every push and PR to `main`:
- `npx tsc --noEmit` (type checking)
- `npm test` (unit tests)

### Deploy (`deploy.yml`)

Runs on `v*.*.*` tags and manual dispatch:
- Type-check + test + build
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
3. **Use offline** — the service worker precaches all assets, including the ~2 MB Capstone WASM engine
4. **Updates** — auto-updates in the background; new version loads on next visit

> **Note:** The PWA caches the app itself. PE files are never uploaded — all processing is local.

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

See `.env.example` for documented configuration options.
