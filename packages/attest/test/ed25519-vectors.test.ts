/**
 * Ed25519 edge cases — one verdict, pinned, under every runtime (AU-3, A7-07).
 *
 * test/vectors/ed25519 holds Wycheproof's EdDSA set (210 cases), ed25519-speccheck's
 * twelve, and attest's own; expected.v1.json says what each must do under the
 * acceptance rule in identity-core/src/ed25519-strict.ts. This file runs them
 * under bun, and again under plain node through a bundle built by the `bun build`
 * command (a subprocess: an in-process Bun.build beside other builds has crashed
 * this Bun). test/browser-smoke.test.ts runs the same verdicts in Chromium.
 */

import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ed25519Precheck } from "@kashscript/identity-core";
import { ed25519Verdicts, hexBytes, type Ed25519Verdicts, type GeneratedFile, type SpeccheckCase, type WycheproofFile } from "./ed25519/verdicts";

const PKG = join(import.meta.dir, "..");
const V = join(PKG, "test", "vectors", "ed25519");
const WIN = process.platform === "win32";
const file = (name: string): string => join(V, name);
/** Relative to the package root: the Windows shell splits an absolute path on the space in this repository's name. */
const rel = (name: string): string => `test/vectors/ed25519/${name}`;
/** A path handed through the Windows shell keeps its spaces only when quoted. */
const q = (p: string): string => (WIN && /\s/.test(p) ? `"${p}"` : p);
const wycheproof = JSON.parse(readFileSync(file("wycheproof-ed25519_test.json"), "utf8")) as WycheproofFile;
const speccheck = JSON.parse(readFileSync(file("speccheck-cases.json"), "utf8")) as SpeccheckCase[];
const generated = JSON.parse(readFileSync(file("generated.v1.json"), "utf8")) as GeneratedFile & { cases: readonly { name: string; pk: string; sig: string; precheck: string }[] };
const expected = JSON.parse(readFileSync(file("expected.v1.json"), "utf8")) as Ed25519Verdicts;

describe("Ed25519 edge cases — the pinned verdicts under bun", () => {
  it("Wycheproof: every valid case verifies, every invalid one fails, and acceptable ones split by the order of the key", async () => {
    const v = await ed25519Verdicts({ wycheproof, speccheck, generated });
    const wrong = Object.entries(expected.wycheproof).filter(([id, want]) => v.wycheproof[id] !== want);
    expect(wrong).toEqual([]);
    expect(Object.keys(v.wycheproof)).toHaveLength(210);
  });

  it("ed25519-speccheck: only case 3 verifies — small-order and non-canonical A or R, and S ≥ L, never do", async () => {
    const v = await ed25519Verdicts({ wycheproof: { testGroups: [] }, speccheck, generated: { cases: [] } });
    expect(v.speccheck).toEqual(expected.speccheck);
    expect(expected.speccheck).toEqual([false, false, false, true, false, false, false, false, false, false, false, false]);
  });

  it("attest's own cases: each as the rule names it, and the pre-check gives the recorded reason", async () => {
    const v = await ed25519Verdicts({ wycheproof: { testGroups: [] }, speccheck: [], generated });
    expect(v.generated).toEqual(expected.generated);
    for (const c of generated.cases) expect(ed25519Precheck(hexBytes(c.pk), hexBytes(c.sig))).toBe(c.precheck as never);
    expect(expected.generated.honest).toBe(true);
    expect(Object.values(expected.generated).filter((x) => x)).toHaveLength(1);
  });
});

describe("Ed25519 edge cases — the same verdicts under plain node (OpenSSL's WebCrypto)", () => {
  it("node answers exactly as bun does, case by case", () => {
    const dir = mkdtempSync(join(tmpdir(), "attest-ed25519-node-"));
    try {
      const out = join(dir, "entry.mjs");
      // The bundle is made by the `bun build` command in a subprocess, never in-process.
      const build = spawnSync("bun", ["build", "test/ed25519/node-entry.ts", "--target", "node", "--outfile", q(out)], { cwd: PKG, encoding: "utf8", shell: WIN });
      expect(build.stderr).not.toContain("error");
      expect(build.status).toBe(0);
      const r = spawnSync("node", [q(out), rel("wycheproof-ed25519_test.json"), rel("speccheck-cases.json"), rel("generated.v1.json")], { cwd: PKG, encoding: "utf8", shell: WIN, maxBuffer: 16 * 1024 * 1024 });
      expect(r.stderr).toBe("");
      expect(r.status).toBe(0);
      const v = JSON.parse(r.stdout) as Ed25519Verdicts;
      expect(v.wycheproof).toEqual(expected.wycheproof);
      expect(v.speccheck).toEqual(expected.speccheck);
      expect(v.generated).toEqual(expected.generated);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 120_000);
});
