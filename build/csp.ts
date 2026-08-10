/**
 * Single source of truth for the Content-Security-Policy.
 *
 * Two deployment paths consume this:
 *   1. GitHub Pages — cannot set response headers, so `vite.config.ts` injects
 *      `cspMetaTag()` into `dist/index.html` with a build-only plugin.
 *   2. Docker/nginx — `nginx.conf` carries `nginxCspHeaderLine()` verbatim.
 *
 * `build/csp.test.ts` asserts that nginx.conf still matches what this module
 * generates, so the two paths cannot drift apart silently.
 *
 * Rationale for each directive lives in SECURITY.md ("Content Security Policy").
 */

/**
 * Directives shared by both delivery mechanisms, in emission order.
 */
const BASE_DIRECTIVES: ReadonlyArray<readonly [string, string]> = [
  ["default-src", "'self'"],
  // 'wasm-unsafe-eval': Capstone calls WebAssembly.instantiate. The capstone-wasm
  // glue uses no eval/new Function, so full 'unsafe-eval' is not needed.
  ["script-src", "'self' 'wasm-unsafe-eval'"],
  // 'unsafe-inline': React style={{...}} props (virtual scrolling, CFG layout)
  // and the runtime --mono-font-size variable.
  ["style-src", "'self' 'unsafe-inline'"],
  // blob:: reconstructed RT_ICON previews in ResourcesView are rendered from a
  // blob: URL in an <img>.
  ["img-src", "'self' data: blob:"],
  ["font-src", "'self'"],
  // The disassembly Web Worker and the Workbox service worker.
  ["worker-src", "'self' blob:"],
  ["manifest-src", "'self'"],
  // Effectively unrestrictable: the LLM base URL is user-configured (any origin),
  // Ghidra defaults to http://localhost:8765 and the MCP bridge to
  // ws://localhost:19283. Non-localhost http: is omitted because the hosted demo
  // is https and mixed-content blocking would reject it anyway.
  [
    "connect-src",
    "'self' data: blob: https: http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:*",
  ],
  ["object-src", "'none'"],
  ["base-uri", "'self'"],
  ["form-action", "'none'"],
];

/**
 * Header-only directives. `frame-ancestors` is ignored when delivered via
 * `<meta http-equiv>` (browsers drop it and log a console warning), so it must
 * not appear in the meta tag.
 */
const HEADER_ONLY_DIRECTIVES: ReadonlyArray<readonly [string, string]> = [
  ["frame-ancestors", "'none'"],
];

function serialize(directives: ReadonlyArray<readonly [string, string]>): string {
  return directives.map(([name, value]) => `${name} ${value}`).join("; ");
}

/** Policy for `<meta http-equiv="Content-Security-Policy">` (no frame-ancestors). */
export const CSP_META_POLICY = serialize(BASE_DIRECTIVES);

/** Policy for the `Content-Security-Policy` response header. */
export const CSP_HEADER_POLICY = serialize([...BASE_DIRECTIVES, ...HEADER_ONLY_DIRECTIVES]);

/** The exact `<meta>` tag injected into dist/index.html at build time. */
export function cspMetaTag(): string {
  return `<meta http-equiv="Content-Security-Policy" content="${CSP_META_POLICY}" />`;
}

/** The exact nginx directive that must appear in nginx.conf. */
export function nginxCspHeaderLine(): string {
  return `add_header Content-Security-Policy "${CSP_HEADER_POLICY}" always;`;
}
