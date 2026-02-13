import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";
import { copyFileSync, mkdirSync } from "fs";

// capstone-wasm's .mjs references "capstone.wasm" via `new URL("capstone.wasm", import.meta.url)`.
// Vite hashes the wasm filename in dist but doesn't rewrite the reference inside the pre-bundled .mjs,
// so we copy the wasm with its original name next to the built assets.
function capstoneWasmPlugin() {
  return {
    name: "copy-capstone-wasm",
    writeBundle(options: any) {
      const outDir = options.dir || resolve("dist");
      const src = resolve("node_modules/capstone-wasm/dist/capstone.wasm");
      const assetsDir = resolve(outDir, "assets");
      mkdirSync(assetsDir, { recursive: true });
      copyFileSync(src, resolve(assetsDir, "capstone.wasm"));
    },
  };
}

export default defineConfig({
  base: "/peek-a-bin/",
  plugins: [react(), tailwindcss(), capstoneWasmPlugin()],
  optimizeDeps: {
    exclude: ["capstone-wasm"],
  },
});
