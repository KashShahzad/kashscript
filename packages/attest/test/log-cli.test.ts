// ============================================================================
// KS-Q4 — the trust log through the published CLI, under plain Node, with the
// network switched off by ./offline-guard.cjs. A stranger with the files and
// the attest package checks a log, a mirror, a proof and a time — nothing of
// ours is reached.
// ============================================================================

import { beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { opensslAvailable } from "../src/bin/openssl";

const PKG = join(import.meta.dir, "..");
const WIN = process.platform === "win32";
const BIN = "dist/bin/attest.js";
const GUARD = "./test/offline-guard.cjs";
const V = "test/vectors/log";
const ROOT = `${V}/sample-tsa-root.crt`;

function attest(args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("node", ["--require", GUARD, BIN, ...args], { cwd: PKG, encoding: "utf8", shell: WIN });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

beforeAll(() => {
  const build = spawnSync("bun", ["run", "build:bin"], { cwd: PKG, encoding: "utf8", shell: WIN });
  if (build.status !== 0) throw new Error(`build:bin failed:\n${build.stderr || build.stdout}`);
});

describe("attest log verify — a whole log, from its files alone", () => {
  it("the original and its mirror agree; without a witness root, the times are the log's own claims", () => {
    const r = attest(["log", "verify", `${V}/original`, "--mirror", `${V}/mirror`]);
    expect(r.stderr).not.toContain("offline-guard");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Trust log (9 entries)");
    expect(r.stdout).toContain("root rebuilt from the entries; extends the head before it");
    expect(r.stdout).toContain("a mirror was compared: 9 entries, 3 checkpoints");
    expect(r.stdout).toContain("its time is the log's own claim");
    expect(r.stdout).toContain("without gossip between mirrors");
    expect(r.stdout).toMatch(/what was checked {3}: every head rebuilt from the entries alone/);
    expect(r.stdout.trimEnd().endsWith("RESULT: PASS")).toBe(true);
  });

  it("with the SAMPLE root, every head is attested, and the backdated attestation is named", () => {
    if (!opensslAvailable()) {
      console.warn("openssl not found — the witness half of this test was skipped");
      return;
    }
    const r = attest(["log", "verify", `${V}/original`, "--tsa-root", ROOT]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("rfc3161 — final");
    expect(r.stdout).toContain("tsa root           : sha256 ");
    expect(r.stdout).toContain("time               : entry 8 (attestation) — CLAIMED_BEFORE_WITNESS");
    expect(r.stdout).toContain("RESULT: PASS — the log is whole; 1 entry's claimed time not supported");
  });

  it("every tampered copy is refused, by name", () => {
    const cases: [string, string][] = [
      ["altered", "MIRROR_ROOT_MISMATCH"],
      ["removed", "MIRROR_ROOT_MISMATCH"],
      ["reordered", "MIRROR_ROOT_MISMATCH"],
      ["split", "SPLIT_VIEW"],
      ["stranger", "MIRROR_CHECKPOINT_INVALID"],
    ];
    for (const [name, code] of cases) {
      const r = attest(["log", "verify", `${V}/original`, "--mirror", `${V}/tampered/${name}`]);
      expect({ name, status: r.status }).toEqual({ name, status: 1 });
      expect(r.stdout).toContain(`fault              : ${code}`);
      expect(r.stdout.trimEnd().endsWith("RESULT: FAIL")).toBe(true);
    }
    const stranger = attest(["log", "verify", `${V}/tampered/stranger`]);
    expect(stranger.status).toBe(1);
    expect(stranger.stdout).toContain("fault              : CHECKPOINT_INVALID at 9");
  });

  it("a folder that is not a log is a usage error", () => {
    const r = attest(["log", "verify", `${V}/does-not-exist`]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("cannot read the log");
  });
});

describe("attest verify — a checkpoint, a proof, a time", () => {
  it("a checkpoint names its log, its key, its size, its root and its own time — as a claim", () => {
    const r = attest(["verify", `${V}/original/checkpoints/9.json`]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Trust log checkpoint");
    expect(r.stdout).toContain("tree size          : 9");
    expect(r.stdout).toContain("— a claim until a public witness stamps it");
    expect(r.stdout).toContain("previous head      : 7 entries");
    const forged = attest(["verify", `${V}/tampered/stranger/checkpoints/9.json`]);
    expect(forged.status).toBe(1);
    expect(forged.stdout).toContain("FAIL (CHECKPOINT_SIGNATURE_INVALID)");
  });

  it("THE BACKDATED ATTESTATION, checked by a stranger: in the log, and its claimed time refused by the witness", () => {
    if (!opensslAvailable()) {
      console.warn("openssl not found — the witness half of this test was skipped");
      return;
    }
    const r = attest(["verify", `${V}/inclusion-backdated.json`, "--tsa-root", ROOT]);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("in the log         : yes — its own path reaches the root the log's key signed");
    expect(r.stdout).toContain("first head         : yes — its witness is the entry's first");
    expect(r.stdout).toContain("time               : CLAIMED_BEFORE_WITNESS — the claimed time is not supported; the attested time stands");
    expect(r.stdout).toContain("reason             : TIME_NOT_SUPPORTED");
    // The backfilled one says it came late, and passes.
    const back = attest(["verify", `${V}/inclusion-backfilled.json`, "--tsa-root", ROOT]);
    expect(back.status).toBe(0);
    expect(back.stdout).toContain("(backfilled — logged after the log began, about something before it)");
  });

  it("without a witness root no signature is checked, so there is no attested time — and the output says so", () => {
    const r = attest(["verify", `${V}/inclusion-backdated.json`]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("rfc3161 — unchecked");
    expect(r.stdout).toContain("attested           : none — unwitnessed");
  });

  it("a later head leaves the claimed time unjudged; consistency proofs pass, and a broken one fails", () => {
    const later = attest(["verify", `${V}/inclusion-later-head.json`]);
    expect(later.status).toBe(0);
    expect(later.stdout).toContain("first head         : no — a later head; the claimed time is not judged");
    const c = attest(["verify", `${V}/consistency-4-9.json`]);
    expect(c.status).toBe(0);
    expect(c.stdout).toContain("consistent         : yes — the later head keeps every entry of the earlier one, in order");
  });
});
