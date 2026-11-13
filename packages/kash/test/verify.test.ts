/**
 * `kash verify` is attest's verifier with attest's exit codes, and it never
 * touches the network (d28). Run from the bundled single file under the offline
 * guard, so a verify that tried to reach out would throw, not pass.
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { bunSrc, buildBundles, issueArgs, makeStationZero, nodeDist, offlineGuardPath, removeDir, tempDir } from "./helpers";

let work = "";
beforeAll(() => {
  buildBundles();
  work = tempDir("verify");
}, 180_000);
afterAll(() => removeDir(work));

describe("the offline guard itself", () => {
  it("makes any attempt to reach the network throw — so passing under it means something", () => {
    const r = spawnSync("node", ["--require", offlineGuardPath(), "-e", "fetch('http://example.invalid/').catch(e=>{console.log(e.message);process.exit(0)})"], { encoding: "utf8" });
    // fetch itself throws synchronously under the guard
    expect(`${r.stdout}${r.stderr}`).toContain("offline-guard");
  });
});

for (const [label, run] of [["bun-src", bunSrc], ["node-dist", nodeDist]] as const) {
  describe(`verify exit codes — ${label}`, () => {
    it("0 for a finished record, 1 for a failed one, 2 for a file it cannot read or recognise", () => {
      const z = makeStationZero(run);
      try {
        const pending = join(z.work, "p.json");
        const finished = join(z.work, "f.json");
        expect(run(issueArgs(z, pending)).status).toBe(0);
        expect(run(["verify", pending]).status).toBe(1);
        expect(run(["countersign", pending, "--keystore", z.keystore, "--yes", "--out", finished]).status).toBe(0);
        expect(run(["verify", finished]).status).toBe(0);

        expect(run(["verify", join(work, "does-not-exist.json")]).status).toBe(2);
        const junk = join(work, "junk.json");
        writeFileSync(junk, JSON.stringify({ not: "an artifact" }));
        expect(run(["verify", junk]).status).toBe(2);
        const notJson = join(work, "not.json");
        writeFileSync(notJson, "{{{");
        expect(run(["verify", notJson]).status).toBe(2);
      } finally {
        removeDir(z.keystore);
        removeDir(z.work);
      }
    }, 180_000);

    it("exits 2 on a usage error, and cannot be asked to check the network", () => {
      const nothing = run(["verify"]);
      expect(nothing.status).toBe(2);
      const status = run(["verify", "--check-status", join(work, "x.json")]);
      expect(status.status).toBe(2);
      expect(status.stderr).toContain("--check-status");
    });
  });
}

describe("where the verifier comes from", () => {
  it("is attest's own binary, built, next to the attest package kash resolves", () => {
    expect(existsSync(join(import.meta.dir, "..", "..", "attest", "dist", "bin", "attest.js"))).toBe(true);
  });
});
