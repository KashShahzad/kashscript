// ============================================================================
// The verifier in a browser build (PL-2). Ed25519 reached browsers late
// (Chrome 137, Firefox 129, Safari 17) and some WebViews still lack it; P-256
// is everywhere. So the same bundle runs twice in headless Chromium: once as
// the browser is, and once with WebCrypto refusing Ed25519. ES256 must verify
// both times; Ed25519 must come back "not checked here", never "invalid".
//
// The bundle is built by Bun for `target: "browser"` as one IIFE and inlined
// into a page with the vectors, so nothing is fetched. Chromium is found on
// this machine (or via CHROME_PATH); without one the test says so by name.
// ============================================================================

import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const PKG = join(import.meta.dir, "..");
const V = join(PKG, "test", "vectors");
const read = (...p: string[]): string => readFileSync(join(V, ...p), "utf8");

function findChromium(): string | null {
  const candidates = [
    process.env.CHROME_PATH,
    "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ];
  return candidates.find((c): c is string => typeof c === "string" && existsSync(c)) ?? null;
}

const CHROMIUM = findChromium();

async function bundle(): Promise<string> {
  const built = await Bun.build({ entrypoints: [join(import.meta.dir, "browser", "entry.ts")], target: "browser", format: "iife", minify: true });
  if (!built.success) throw new Error(built.logs.map(String).join("\n"));
  return built.outputs[0]!.text();
}

function vectors(): string {
  return JSON.stringify({
    context: JSON.parse(read("es256", "context.v1.json")),
    trustList: JSON.parse(read("es256", "trust-list-es256.v1.json")),
    presentation: read("es256", "predicate-presentation-es256.v1.txt"),
    succession: JSON.parse(read("es256", "succession-helpers.v1.json")),
    es256Export: read("es256", "holder-export-es256.v1.json"),
    countersign: JSON.parse(read("es256", "countersign-es256.v1.json")),
    negative: JSON.parse(read("es256", "negative.v1.json")),
    pl1Export: read("holder", "holder-export.v1.json"),
    au3: { context: JSON.parse(read("au3", "context.v1.json")), kidNotIss: read("au3", "sdjwt-kid-not-iss.v1.txt").trim() },
    ed25519: {
      wycheproof: JSON.parse(read("ed25519", "wycheproof-ed25519_test.json")),
      speccheck: JSON.parse(read("ed25519", "speccheck-cases.json")),
      generated: JSON.parse(read("ed25519", "generated.v1.json")),
    },
  });
}

const ED25519_EXPECTED = JSON.parse(read("ed25519", "expected.v1.json")) as { wycheproof: Record<string, boolean>; speccheck: boolean[]; generated: Record<string, boolean> };

/** Run the page in headless Chromium and return what it wrote into #out. */
function runInChromium(chromium: string, script: string, noEd25519: boolean): Record<string, any> {
  const dir = mkdtempSync(join(tmpdir(), "attest-browser-"));
  try {
    const page = join(dir, "verify.html");
    // `</` never appears in JSON we wrote, but escape it anyway so the data cannot close its tag.
    const data = vectors().replace(/<\//g, "<\\/");
    const js = script.replace(/<\/script/gi, "<\\/script");
    writeFileSync(
      page,
      `<!doctype html><html><head><meta charset="utf-8"></head><body><pre id="out">pending</pre>` +
        `<script type="application/json" id="vectors">${data}</script>` +
        `<script>window.__NO_ED25519__ = ${noEd25519};</script><script>${js}</script></body></html>`,
    );
    const r = spawnSync(
      chromium,
      ["--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check", `--user-data-dir=${join(dir, "profile")}`, "--virtual-time-budget=30000", "--dump-dom", pathToFileURL(page).href],
      { encoding: "utf8", timeout: 120_000, maxBuffer: 64 * 1024 * 1024 },
    );
    const m = /<pre id="out">([\s\S]*?)<\/pre>/.exec(r.stdout ?? "");
    if (m === null) throw new Error(`no output from Chromium (status ${r.status}): ${r.stderr}`);
    const text = m[1]!.replace(/&quot;/g, '"').replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");
    if (text === "pending") throw new Error("the page never finished — raise --virtual-time-budget");
    return JSON.parse(text) as Record<string, any>;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

describe("the verifier in a browser build (headless Chromium)", () => {
  if (CHROMIUM === null) {
    it.skip("SKIPPED — no Chromium on this machine (set CHROME_PATH): the browser build was NOT checked", () => {});
    return;
  }
  const chromium = CHROMIUM;
  let script: Promise<string> | null = null;
  const built = () => (script ??= bundle());

  it("as the browser is: Ed25519 and ES256 both verify; confusion and high-S fail", async () => {
    const o = runInChromium(chromium, await built(), false);
    expect(o.crashed).toBeUndefined();
    expect(o.userAgent).toContain("Chrome");
    expect(o.ed25519Available).toBe(true);
    expect(o.es256TrustList).toBe(true);
    expect(o.es256Presentation).toBe("ok");
    expect(o.helperClaim).toBe("ok");
    expect(o.es256Export).toEqual([]);
    expect(o.countersignEs256).toBe("ok");
    expect(o.ed25519Export).toEqual([]);
    expect(o.es256UnderEd25519Did).toBe(false);
    expect(o.ed25519UnderP256Did).toBe("TRUST_LIST_SIGNATURE_INVALID");
    expect(o.dsseHighS).toBe("TRUST_LIST_SIGNATURE_INVALID");
    expect(o.kbJwtHighS).toBe("KEY_BINDING_INVALID");
    // AU-3: the forgery in another organisation's name, and the Ed25519 edge cases, answer as they do under bun and node.
    expect(o.kidNotIssuer).toBe("KID_NOT_ISSUER");
    expect(o.ed25519.wycheproof).toEqual(ED25519_EXPECTED.wycheproof);
    expect(o.ed25519.speccheck).toEqual(ED25519_EXPECTED.speccheck);
    expect(o.ed25519.generated).toEqual(ED25519_EXPECTED.generated);
  }, 180_000);

  it("with no Ed25519: ES256 still verifies; everything needing Ed25519 is 'not checked', never 'invalid'", async () => {
    const o = runInChromium(chromium, await built(), true);
    expect(o.crashed).toBeUndefined();
    expect(o.ed25519Available).toBe(false);
    expect(o.es256TrustList).toBe(true);
    expect(o.es256Presentation).toBe("ok");
    expect(o.helperClaim).toBe("RUNTIME_CANNOT_CHECK"); // its lost key and two helpers are Ed25519
    expect(o.countersignEs256).toBe("RUNTIME_CANNOT_CHECK"); // its requester is Ed25519
    expect(o.ed25519Export).toEqual(["RUNTIME_CANNOT_CHECK"]);
    expect(o.dsseHighS).toBe("TRUST_LIST_SIGNATURE_INVALID"); // P-256 checks still bite
  }, 180_000);
});
