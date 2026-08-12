import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { readdirSync, readFileSync } from "fs";
import { resolve } from "path";
import { defineConfig } from "vite";
import { VitePWA } from "vite-plugin-pwa";
import { cspMetaTag } from "./build/csp";

/**
 * Injects the CSP as a <meta http-equiv> into dist/index.html.
 *
 * Build-only (`apply: "build"`): index.html doubles as the dev entry point and
 * Vite injects an *inline* React Refresh preamble in dev, which a source-level
 * meta CSP would block. GitHub Pages cannot set response headers, so the meta
 * tag is the only way to get a policy onto the hosted demo; the Docker/nginx
 * deployment gets the same policy as a real header (see build/csp.ts).
 */
function cspPlugin() {
  return {
    name: "inject-csp-meta",
    apply: "build" as const,
    transformIndexHtml: {
      // "pre" runs before Vite injects the built <script>/<link> tags, so the
      // policy is guaranteed to be parsed before anything it governs.
      order: "pre" as const,
      handler(html: string) {
        // Insert directly after <meta charset> so the charset declaration stays
        // inside the first 1024 bytes of the document.
        const charset = /<meta\s+charset=[^>]*>/i.exec(html);
        if (!charset) {
          throw new Error(
            "inject-csp-meta: no <meta charset> found in index.html — refusing to " +
              "ship a build without a CSP. Update the insertion point in vite.config.ts.",
          );
        }
        const at = charset.index + charset[0].length;
        return `${html.slice(0, at)}\n    ${cspMetaTag()}${html.slice(at)}`;
      },
    },
  };
}

/**
 * Guards the assumption that exactly one Capstone WASM binary ships.
 *
 * capstone-wasm's .mjs references the binary via
 * `new URL("capstone.wasm", import.meta.url)`. Rollup *does* recognise that
 * pattern and rewrites it to the hashed asset it emits, so no manual copy is
 * needed — an earlier `copy-capstone-wasm` plugin duplicated the 1.7 MiB file
 * under its original name, and both copies ended up in the PWA precache.
 *
 * This plugin fails the build if that ever stops being true (0 or >1 wasm
 * assets, or an emitted wasm nothing references), rather than silently shipping
 * an app that 404s on the disassembly engine.
 */
function capstoneWasmGuardPlugin() {
  return {
    name: "capstone-wasm-guard",
    apply: "build" as const,
    writeBundle(options: { dir?: string }) {
      const outDir = options.dir || resolve("dist");
      const assetsDir = resolve(outDir, "assets");
      const files = readdirSync(assetsDir);
      const wasm = files.filter((f) => f.endsWith(".wasm"));
      if (wasm.length !== 1) {
        throw new Error(
          `capstone-wasm-guard: expected exactly 1 .wasm asset in ${assetsDir}, found ` +
            `${wasm.length} (${wasm.join(", ")}). Duplicate copies are precached by the ` +
            `service worker; a missing copy breaks disassembly.`,
        );
      }
      const referenced = files
        .filter((f) => f.endsWith(".js"))
        .some((f) => readFileSync(resolve(assetsDir, f), "utf8").includes(wasm[0]));
      if (!referenced) {
        throw new Error(
          `capstone-wasm-guard: ${wasm[0]} is not referenced by any emitted chunk. ` +
            `Rollup probably stopped rewriting new URL("capstone.wasm", import.meta.url); ` +
            `the runtime will request an unhashed path that is never emitted.`,
        );
      }
    },
  };
}

export default defineConfig({
  base: "/peek-a-bin/",
  plugins: [
    react(),
    tailwindcss(),
    cspPlugin(),
    capstoneWasmGuardPlugin(),
    VitePWA({
      registerType: "autoUpdate",
      workbox: {
        // "json" picks up manifest.json (the only JSON in dist) so the PWA
        // manifest is available offline.
        globPatterns: ["**/*.{js,css,html,wasm,png,svg,json}"],
        // icon-512.png is 435 KB and is only read by the OS/browser at install
        // and splash time, which happens online. Keeping it out of the precache
        // saves every visitor that download; icon-192.png still ships.
        globIgnores: ["icons/icon-512.png"],
      },
      manifest: false,
    }),
  ],
  optimizeDeps: {
    exclude: ["capstone-wasm"],
  },
});
