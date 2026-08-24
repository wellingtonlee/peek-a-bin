// @vitest-environment jsdom

import "../../test/domSetup";
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CSP_META_POLICY } from "../../../build/csp";
import { MarkdownRenderer } from "../MarkdownRenderer";

/**
 * The one place LLM output reaches `innerHTML`.
 *
 * `MarkdownRenderer` is 32 lines and every AI feature's output goes through it —
 * the chat panel, the AI report, and anything added later. It runs `marked`
 * (which has not sanitized by default since v5) and then `DOMPurify.sanitize`,
 * and hands the result to `dangerouslySetInnerHTML`.
 *
 * WHY THAT IS THE INTERESTING PROPERTY. `content` is a model response, and the
 * prompts this app builds quote the analysed binary: `useAIChat`'s
 * `buildSystemPrompt` embeds section names read out of the PE header and up to
 * 6000 characters of decompiled pseudocode, which carries identifiers derived
 * from the file's own strings and imports. So the text is attacker-INFLUENCEABLE
 * — a crafted binary can put a chosen byte string in front of the model and the
 * model may echo it. Nothing here is a *proof* of injection (the model is not a
 * transparent pipe), which is exactly why the sanitize call is the load-bearing
 * line rather than the prompt.
 *
 * It was reached before this suite existed — `AIDialogs.dom.test.tsx` renders
 * `AIReportPanel`, which renders this — but only for two benign markdown
 * fixtures. Nothing had ever asked it a hostile question, and the sanitize call
 * could have been deleted with the whole tree green.
 *
 * THE HONEST BOUND. Every row below is a specific vector against
 * `dompurify@3.4.13` under jsdom 28. It is a regression pin on this
 * configuration — `USE_PROFILES: { html: true }`, and the fact that the call is
 * made at all — and it is NOT an audit of DOMPurify, not a claim about a real
 * browser's parser, and not a bypass hunt. jsdom's HTML parser is not Blink's,
 * and mutation-XSS is precisely a parser-differential class.
 *
 * The two things DOMPurify's html profile lets through on purpose are pinned at
 * the bottom, against the CSP directives that contain them.
 */

function html(content: string, className?: string): string {
  const { container } = render(<MarkdownRenderer content={content} className={className} />);
  const root = container.firstElementChild as HTMLElement;
  return root.innerHTML;
}

/**
 * The CSP as a directive map. Asserting on a SUBSTRING of the serialized policy
 * is how a relaxation gets past a green test: `toContain("img-src 'self' data:
 * blob:")` is satisfied by `img-src 'self' data: blob: https:`, which is exactly
 * the change the row exists to catch — measured, it left the row INERT. So the
 * value is compared whole.
 */
const cspDirectives: Record<string, string> = Object.fromEntries(
  CSP_META_POLICY.split("; ").map((d) => {
    const i = d.indexOf(" ");
    return [d.slice(0, i), d.slice(i + 1)];
  }),
);

function root(content: string): HTMLElement {
  const { container } = render(<MarkdownRenderer content={content} />);
  return container.firstElementChild as HTMLElement;
}

describe("MarkdownRenderer renders markdown", () => {
  it("turns headings, lists, inline code and fences into elements", () => {
    const el = root("## Findings\n\n- one\n- two\n\n`CreateFileW`\n\n```c\nint x;\n```");
    expect(el.querySelector("h2")?.textContent).toBe("Findings");
    expect([...el.querySelectorAll("li")].map((n) => n.textContent)).toEqual(["one", "two"]);
    expect(el.querySelector("p > code")?.textContent).toBe("CreateFileW");
    // `gfm: true` — the fence's language reaches the class, which is what any
    // later syntax highlighter would key on.
    expect(el.querySelector("pre > code")?.className).toBe("language-c");
  });

  it("honours `breaks: true`, so a single newline is a line break", () => {
    // Model output is written as prose, not as markdown source: without this a
    // reply typed with single newlines would render as one run-together
    // paragraph.
    expect(html("a\nb")).toContain("<br>");
  });

  it("renders nothing for empty content, rather than an empty paragraph", () => {
    // Reached on every render of a streaming reply before its first token
    // arrives. NOTE ON WHAT THIS DOES NOT COVER: the `if (!content) return ""`
    // early return is UNOBSERVABLE from here and that is measured — deleting it
    // leaves this row green, because `marked.parse("")` is `""` and
    // `DOMPurify.sanitize("")` is `""`. So the branch is an optimisation, not
    // behaviour; what is pinned is the output.
    expect(root("").innerHTML).toBe("");
  });

  it("composes its class with the caller's, and tolerates no caller class", () => {
    const { container } = render(<MarkdownRenderer content="x" className="text-xs" />);
    expect((container.firstElementChild as HTMLElement).className).toBe("markdown-content text-xs");
    const { container: bare } = render(<MarkdownRenderer content="x" />);
    // The `?? ""` leaves a trailing space; asserted as-is so a tidy-up is a
    // deliberate change rather than a surprise.
    expect((bare.firstElementChild as HTMLElement).className).toBe("markdown-content ");
  });

  it("does not throw on markdown cut mid-construct", () => {
    // A stream is severed at an arbitrary byte, so `marked` is routinely handed
    // an unterminated fence, table or emphasis run. A throw inside the `useMemo`
    // tears the whole panel down mid-answer.
    for (const partial of ["```c\nint x = ", "| a | b\n|---", "**bold", "[link](", "> quote\n> "]) {
      expect(() => html(partial)).not.toThrow();
    }
  });
});

describe("MarkdownRenderer sanitizes", () => {
  it("removes a script element and keeps the surrounding text", () => {
    const el = root("<script>alert(1)</script>after");
    expect(el.querySelector("script")).toBeNull();
    expect(el.innerHTML).not.toContain("alert(1)");
    expect(el.textContent).toContain("after");
  });

  it("removes inline event handlers while keeping the element", () => {
    const img = root("<img src=x onerror=alert(1)>").querySelector("img");
    expect(img).not.toBeNull();
    expect(img?.getAttribute("onerror")).toBeNull();
    expect(img?.getAttribute("src")).toBe("x");

    const div = root('<div onclick="alert(1)" data-x="1">d</div>').querySelector("div");
    expect(div?.getAttribute("onclick")).toBeNull();
    // Data attributes survive — DOMPurify's `ALLOW_DATA_ATTR` default.
    expect(div?.getAttribute("data-x")).toBe("1");
  });

  it("strips a javascript: or data: URI off a link, leaving the text", () => {
    for (const src of ["[click](javascript:alert(1))", '<a href="data:text/html,<b>x">d</a>']) {
      const a = root(src).querySelector("a");
      expect(a).not.toBeNull();
      expect(a?.getAttribute("href")).toBeNull();
    }
  });

  it("keeps an ordinary https link", () => {
    // The negative rows above are only meaningful beside this one: a sanitizer
    // that dropped every href would pass them and be useless.
    expect(
      root('<a href="https://example.test/x">x</a>').querySelector("a")?.getAttribute("href"),
    ).toBe("https://example.test/x");
  });

  it("removes frames, styles, and the SVG and MathML namespaces", () => {
    // `USE_PROFILES: { html: true }` is what excludes the last two — the svg and
    // mathml profiles are opt-in, and both are mXSS surface.
    for (const [src, tag] of [
      ['<iframe src="https://evil.test"></iframe>ok', "iframe"],
      ["<style>body{display:none}</style>z", "style"],
      ["<svg onload=alert(1)><circle/></svg>tail", "svg"],
      ["<math><mtext></mtext></math>m", "math"],
    ] as const) {
      const el = root(src);
      expect(el.querySelector(tag)).toBeNull();
      expect(el.innerHTML).not.toContain("alert(1)");
    }
  });

  it("drops target, so a link cannot open a new context", () => {
    // CURRENT BEHAVIOUR, PINNED RATHER THAN ENDORSED: `target` is not in
    // DOMPurify's html attribute profile, so a link in a model reply navigates
    // the SPA away in place — losing the loaded image and the worker's
    // disassembly (annotations are in localStorage and survive; the analysis is
    // not). Allowing `target="_blank"` would need a `rel="noopener"` to come
    // with it, which is a design decision and not a fix to make from a test.
    expect(
      root('<a href="https://ok.test" target="_blank">x</a>')
        .querySelector("a")
        ?.getAttribute("target"),
    ).toBeNull();
  });
});

describe("what the sanitizer lets through, and what contains it", () => {
  /**
   * Two things survive `USE_PROFILES: { html: true }` and are worth knowing
   * about precisely because they are NOT sanitizer failures — DOMPurify's job is
   * to remove script execution, and it does. The containment is the CSP, which
   * exists for unrelated reasons and is being relied on here; pinned so a CSP
   * relaxation has to walk past this.
   */

  it("keeps a remote image — contained by img-src", () => {
    const img = root("![alt](https://evil.test/pixel.png)").querySelector("img");
    expect(img?.getAttribute("src")).toBe("https://evil.test/pixel.png");
    // Would otherwise be a read receipt: a chosen URL fetched when a reply is
    // displayed. `img-src` names no remote scheme, so the browser never loads it.
    expect(cspDirectives["img-src"]).toBe("'self' data: blob:");
  });

  it("keeps a form and its inputs — contained by form-action", () => {
    const el = root('<form action="https://evil.test/"><input name="key"></form>q');
    expect(el.querySelector("form")).not.toBeNull();
    expect(el.querySelector("input")).not.toBeNull();
    // So a reply can *draw* a credential prompt. It cannot submit one:
    // `form-action 'none'` blocks every destination, including 'self'.
    expect(cspDirectives["form-action"]).toBe("'none'");
  });

  it("relies on script-src carrying no 'unsafe-inline', as a second layer", () => {
    // Defence in depth for the two rows above it, not a substitute for the
    // sanitize call: an injected `onerror=` or inline `<script>` would be
    // refused by the policy even if DOMPurify were removed. Stated so nobody
    // reads that as permission to remove it — an `unsafe-inline` added for some
    // future need would take the layer away silently.
    expect(cspDirectives["script-src"]).toBe("'self' 'wasm-unsafe-eval'");
  });
});
