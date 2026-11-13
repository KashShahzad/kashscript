// ============================================================================
// The evaluator in a browser bundle. Bun builds `src` for `target: "browser"`
// as one IIFE, inlined into a page beside the hiring fixture's signed vectors,
// and headless Chromium runs the checklist, the desk's check and the routing.
// The bundle's size is printed, minified and gzipped. Without a Chromium the
// test says so by name and the browser run is NOT claimed.
// ============================================================================

import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";
import { buildPacket, type PacketEntry } from "../src/packet";
import { ruleRequest } from "../src/rule";
import { AS_OF, englishCert, hiringWorld, party, T0 } from "./world";

function findChromium(): string | null {
  const candidates = [
    process.env.CHROME_PATH,
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
  ];
  return candidates.find((c): c is string => typeof c === "string" && existsSync(c)) ?? null;
}
const CHROMIUM = findChromium();
const SRC = join(import.meta.dir, "..", "src");

async function build(entry: string, format: "iife" | "esm"): Promise<string> {
  const built = await Bun.build({ entrypoints: [entry], target: "browser", format, minify: true });
  if (!built.success) throw new Error(built.logs.map(String).join("\n"));
  return built.outputs[0]!.text();
}

/**
 * Sizes come from the `bun build` CLI in a child process: Bun 1.2.5 on Windows
 * panics when one test process runs several in-process builds, so this test
 * makes exactly one (the page's) and measures through the CLI.
 */
function cliBundle(entry: string): string {
  const r = spawnSync(process.execPath, ["build", entry, "--target=browser", "--format=esm", "--minify"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`bun build failed: ${r.stderr}`);
  return r.stdout;
}

export function bundleSizes(): { readonly whole: { readonly min: number; readonly gzip: number }; readonly feel: { readonly min: number; readonly gzip: number } } {
  const size = (s: string) => ({ min: Buffer.byteLength(s), gzip: gzipSync(Buffer.from(s)).length });
  return { whole: size(cliBundle(join(SRC, "index.ts"))), feel: size(cliBundle(join(SRC, "feel", "index.ts"))) };
}

describe("the evaluator in a browser bundle", () => {
  it("states its size", () => {
    const s = bundleSizes();
    console.log(`[size] @kashscript/predicate, browser, minified: ${(s.whole.min / 1024).toFixed(1)} KiB (${(s.whole.gzip / 1024).toFixed(1)} KiB gzipped) — with attest's SD-JWT, DSSE and holder verification inside`);
    console.log(`[size] @kashscript/predicate/feel alone: ${(s.feel.min / 1024).toFixed(1)} KiB (${(s.feel.gzip / 1024).toFixed(1)} KiB gzipped)`);
    expect(s.whole.min).toBeGreaterThan(0);
  }, 60_000);

  if (CHROMIUM === null) {
    it.skip("SKIPPED — no Chromium on this machine (set CHROME_PATH): the browser run was NOT checked", () => {});
    return;
  }
  const chromium = CHROMIUM;

  it("runs the hiring checklist and routes the packet to an automatic yes in headless Chromium", async () => {
    const w = await hiringWorld();
    const copy = await party();
    const cert = await englishCert(w.assessor, copy);
    const req = ruleRequest(w.rule, { nonce: "browser-nonce-0123456789", responseUri: "https://door.practice.invalid/answer" });
    const entries: PacketEntry[] = [
      ...w.projects.map((a): PacketEntry => ({ kind: "artifact", queryId: "projects", artifact: a as unknown as Record<string, unknown>, signer: w.doer })),
      { kind: "sd-jwt", queryId: "english", held: cert, signer: copy },
      { kind: "own-word", queryId: "availability_word", fields: { availableFrom: "2026-11-15" }, signer: await party() },
    ];
    const packet = await buildPacket({ rule: w.rule, request: req, entries, iatUnix: T0 });
    const vectors = JSON.stringify({
      rule: w.rule.envelope,
      held: [...w.projects.map((v, i) => ({ ref: `p${i}`, value: v })), { ref: "cert", value: cert }],
      ownWord: { availability: { availableFrom: "2026-11-15" } },
      trustLists: [w.list],
      request: { client_id: req.client_id, nonce: req.nonce },
      vp_token: packet.vp_token,
      asOf: AS_OF,
    }).replace(/<\//g, "<\\/");
    const script = (await build(join(import.meta.dir, "browser", "entry.ts"), "iife")).replace(/<\/script/gi, "<\\/script");
    const dir = mkdtempSync(join(tmpdir(), "predicate-browser-"));
    try {
      const page = join(dir, "door.html");
      writeFileSync(page, `<!doctype html><html><head><meta charset="utf-8"></head><body><pre id="out">pending</pre><script type="application/json" id="vectors">${vectors}</script><script>${script}</script></body></html>`);
      const r = spawnSync(
        chromium,
        ["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", `--user-data-dir=${join(dir, "profile")}`, "--virtual-time-budget=30000", "--dump-dom", pathToFileURL(page).href],
        { encoding: "utf8", timeout: 120_000, maxBuffer: 64 * 1024 * 1024 },
      );
      const m = /<pre id="out">([\s\S]*?)<\/pre>/.exec(r.stdout ?? "");
      if (m === null) throw new Error(`no output from Chromium (status ${r.status}): ${r.stderr}`);
      const text = m[1]!.replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
      expect(text).not.toBe("pending");
      const o = JSON.parse(text);
      expect(o.crashed).toBeUndefined();
      expect(o.userAgent).toMatch(/Chrome|Edg/);
      expect(o.rows).toEqual([["projects", "answered"], ["react", "answered"], ["english", "answered"], ["availability", "own-word"]]);
      expect(o.ready).toBe(true);
      expect(o.problems).toEqual([]);
      expect(o.route).toBe("automatic-yes");
      expect(o.fired).toEqual(["availability", "english", "projects", "react"]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);
});
