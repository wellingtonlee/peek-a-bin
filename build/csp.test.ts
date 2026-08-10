import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { CSP_HEADER_POLICY, CSP_META_POLICY, cspMetaTag, nginxCspHeaderLine } from "./csp";

const nginxConf = readFileSync(fileURLToPath(new URL("../nginx.conf", import.meta.url)), "utf8");

describe("CSP policy", () => {
  it("keeps nginx.conf in sync with build/csp.ts", () => {
    const line = nginxCspHeaderLine();
    const occurrences = nginxConf.split(line).length - 1;
    // nginx `add_header` does not inherit into a location block that declares its
    // own headers, so the policy appears in both the server block and the
    // static-asset location block.
    expect(
      occurrences,
      `nginx.conf is out of sync with build/csp.ts. Expected this line twice:\n${line}`,
    ).toBe(2);
  });

  it("has no Content-Security-Policy line in nginx.conf other than the generated one", () => {
    const lines = nginxConf
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => l.startsWith("add_header Content-Security-Policy"));
    expect(lines).toEqual([nginxCspHeaderLine(), nginxCspHeaderLine()]);
  });

  it("omits frame-ancestors from the meta policy", () => {
    // <meta http-equiv> delivery ignores frame-ancestors (and report-uri/sandbox);
    // including it only produces a console warning on every page load.
    expect(CSP_META_POLICY).not.toContain("frame-ancestors");
    expect(CSP_HEADER_POLICY).toContain("frame-ancestors 'none'");
  });

  it("keeps the directives the app is known to need", () => {
    // Regression guards for the non-obvious ones — see SECURITY.md for why.
    expect(CSP_META_POLICY).toContain("'wasm-unsafe-eval'"); // Capstone
    expect(CSP_META_POLICY).toContain("style-src 'self' 'unsafe-inline'"); // React style props
    expect(CSP_META_POLICY).toContain("worker-src 'self' blob:"); // disasm + service worker
    expect(CSP_META_POLICY).toContain("object-src 'none'");
    expect(CSP_META_POLICY).toContain("base-uri 'self'");
  });

  it("emits a well-formed meta tag", () => {
    expect(cspMetaTag()).toBe(
      `<meta http-equiv="Content-Security-Policy" content="${CSP_META_POLICY}" />`,
    );
    // A double quote in a directive value would break out of the attribute.
    expect(CSP_META_POLICY).not.toContain('"');
  });
});
