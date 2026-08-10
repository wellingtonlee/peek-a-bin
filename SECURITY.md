# Security Policy

## Reporting Vulnerabilities

Please report security vulnerabilities via [GitHub Security Advisories](https://github.com/wellingtonlee/peek-a-bin/security/advisories/new) (private vulnerability reporting).

Do **not** open a public issue for security vulnerabilities.

## Scope

| Component | Attack Surface |
|-----------|---------------|
| **Browser app** | PE parser (malformed input), WASM engine, localStorage |
| **Ghidra server** | REST API, file uploads, bearer token auth |
| **MCP server** | Filesystem read access, confined filesystem write, WebSocket bridge |
| **AI features** | API key storage, LLM prompt injection |

## Security Model

- **All analysis is client-side** — PE files are never uploaded to any server (unless using the optional Ghidra server)
- **API keys** are stored in `localStorage` (not encrypted). They are sent only to the user-configured LLM endpoint.
- **Ghidra server CORS** allows all origins by default — restrict in production if exposing beyond localhost
- **MCP server** has filesystem read access for loading PE files from disk
- **MCP WebSocket** bridge is unencrypted and unauthenticated. It binds to `127.0.0.1` only.

### MCP filesystem surface

The MCP server runs locally with the privileges of the user who starts it.

**Reads (unconfined, by design):**

- `load_pe` reads any path the user can read. Files larger than 256 MB are rejected.
- `import_analysis` reads any JSON path the user can read.

**Writes (confined):**

- `export_analysis` is the only tool that writes to disk, and only when `outputPath` is
  supplied. The path must end in `.json` and must resolve inside the export root —
  `PEEK_A_BIN_EXPORT_DIR` if set, otherwise the server's working directory. Relative
  paths resolve against that root; the parent directory is resolved with `realpath`, so
  `..` traversal and symlinked directories cannot escape it. Rejected paths return an
  MCP error and write nothing. With no `outputPath`, the JSON is returned in the
  response body and nothing touches the filesystem.

**WebSocket bridge:**

- Binds to `127.0.0.1:19283` by default. Port via `PEEK_A_BIN_WS_PORT`, bind address via
  `PEEK_A_BIN_WS_HOST`. Setting `PEEK_A_BIN_WS_HOST=0.0.0.0` exposes an unauthenticated
  annotation-injection channel to the whole network — only do this behind your own
  network controls.
- The bridge is one-way (MCP → browser) and carries annotations only.

## Content Security Policy

The Docker/nginx deployment (`nginx.conf`) sets `X-Content-Type-Options`,
`X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy` and the full
`Content-Security-Policy` below.

**The policy is defined once, in `build/csp.ts`**, and consumed by both deployment paths:

- **GitHub Pages** — cannot set response headers, so a build-only Vite plugin
  (`inject-csp-meta`, `apply: "build"` in `vite.config.ts`) injects it as a
  `<meta http-equiv="Content-Security-Policy">` into `dist/index.html`.
- **Docker/nginx** — `nginx.conf` carries the generated `add_header` line verbatim, in
  both the server block and the static-asset location block (nginx `add_header` does not
  inherit into a block that declares its own headers).

`build/csp.test.ts` fails if `nginx.conf` drifts from `build/csp.ts`. To change the
policy: edit `build/csp.ts`, run `npx tsx -e 'import("./build/csp.ts").then(m =>
console.log(m.nginxCspHeaderLine()))'`, paste the line into both places in `nginx.conf`.

The directives:

```
default-src 'self';
script-src  'self' 'wasm-unsafe-eval';
style-src   'self' 'unsafe-inline';
img-src     'self' data: blob:;
font-src    'self';
worker-src  'self' blob:;
manifest-src 'self';
connect-src 'self' data: blob: https: http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*;
object-src  'none';
base-uri    'self';
form-action 'none';
frame-ancestors 'none';   /* header only — see below */
```

Why each awkward part is required:

- **`'wasm-unsafe-eval'`** — the Capstone engine calls `WebAssembly.instantiate`. (The
  `capstone-wasm` glue itself uses no `eval`/`new Function`, so plain `'unsafe-eval'` is
  not needed.)
- **`'unsafe-inline'` in `style-src`** — React `style={{...}}` attributes (virtual
  scrolling, CFG layout) and the runtime `--mono-font-size` variable.
- **`worker-src`** — the disassembly Web Worker and the PWA service worker.
- **`blob:` in `img-src`** — `ResourcesView` reconstructs embedded `RT_ICON` resources
  into a `Blob` and renders them through an object URL.
- **`connect-src` is effectively unrestrictable** — the LLM base URL is user-configured
  and may be any origin, the Ghidra server defaults to `http://localhost:8765`, and the
  MCP bridge is `ws://localhost:19283`. Any policy that does not break user-configured
  endpoints ends up allowing `https:` wholesale, so `connect-src` provides little value
  here; the real gain is from `script-src`/`object-src`/`base-uri`. Non-localhost
  plain `http:` is deliberately omitted: the hosted demo is served over HTTPS, so mixed
  content blocking would reject those requests regardless of CSP. On the **HTTP** nginx
  deployment this does bite — a Ghidra server on a LAN address such as
  `http://192.168.1.5:8765` will be blocked. Add that origin to `connect-src` in
  `build/csp.ts` if you need it.

**Why the meta tag is injected at build time rather than committed into `index.html`:**
`index.html` is also the dev entry point, and Vite injects an **inline**
`<script type="module">` React Refresh preamble in dev, which a source-level meta CSP
would block. The build-only plugin keeps `npm run dev` working.

**`frame-ancestors` is header-only.** Browsers ignore `frame-ancestors` (along with
`report-uri` and `sandbox`) when the policy arrives via `<meta http-equiv>`, so the
injected meta tag omits it to avoid a console warning on every page load. Clickjacking
protection therefore exists only on the nginx deployment (which also sends
`X-Frame-Options: DENY`); the GitHub Pages demo has none, because Pages cannot send
either header.

**Not verified in a browser.** The directive list was derived by reading the source and
the build output — it has never been exercised in a real browser session. Treat a CSP
violation report as a policy bug, not an app bug, until proven otherwise.

## Known Considerations

- localStorage is not encrypted — API keys are accessible to other scripts on the same origin
- Ghidra server CORS is permissive (`*`) — tighten for production deployments
- MCP server can read arbitrary files via `load_pe` — run in trusted environments
- PE parser has not been extensively fuzzed against adversarial inputs
- The CSP has not been validated in a browser, and `frame-ancestors` cannot be enforced
  on the GitHub Pages demo (see above)

## Supported Versions

Security fixes are applied to the latest release only.
