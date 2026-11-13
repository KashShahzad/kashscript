// ============================================================================
// PL-3's artifacts through the published CLI, under plain Node, with the
// network switched off by ./offline-guard.cjs (fetch, net, tls, dns, http,
// https, http2, dgram all throw). Every PASS here is a PASS from the file alone.
// ============================================================================

import { describe, it, expect, beforeAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PKG = join(import.meta.dir, "..");
const WIN = process.platform === "win32";
const BIN = "dist/bin/attest.js";
const GUARD = "./test/offline-guard.cjs";
const V = "test/vectors/exchange";
const ctx = JSON.parse(readFileSync(join(PKG, V, "context.v1.json"), "utf8"));

function run(args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("node", ["--require", GUARD, BIN, "verify", ...args], { cwd: PKG, encoding: "utf8", shell: WIN });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

beforeAll(() => {
  const build = spawnSync("bun", ["run", "build:bin"], { cwd: PKG, encoding: "utf8", shell: WIN });
  if (build.status !== 0) throw new Error(`build:bin failed:\n${build.stderr || build.stdout}`);
});

describe("attest bin — presentations, sessions and thank-yous, with the network disabled", () => {
  it("a predicate presentation passes against the audience and nonce its verifier sent", () => {
    const r = run([`${V}/predicate-presentation-a.v1.txt`, "--audience", ctx.verifiers.a.did, "--nonce", ctx.verifiers.a.nonce, "--status-list", `${V}/predicate-status-list.v1.json`]);
    expect(r.stderr).not.toContain("offline-guard");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("judged against     : rule rule-demo-1 version 3");
    expect(r.stdout).toContain("record hashes      : none disclosed");
    expect(r.stdout).toContain("valid unless revoked, as of 2026-09-24T00:00:00Z");
    expect(r.stdout).toContain("RESULT: PASS");
  });

  it("the same presentation fails for another verifier (exit 1)", () => {
    const r = run([`${V}/predicate-presentation-a.v1.txt`, "--audience", ctx.verifiers.b.did, "--nonce", ctx.verifiers.a.nonce]);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("DOES NOT MATCH");
  });

  it("a complete session is proof; a pending one passes as a file but says it is not proof", () => {
    const c = run([`${V}/session-receipt-complete.v1.json`]);
    expect(c.status).toBe(0);
    expect(c.stdout).toContain("complete — every line signed by both");
    expect(c.stdout).toContain("4500.00 PKR over 2 hashed line item(s)");
    const p = run([`${V}/session-receipt-pending.v1.json`]);
    expect(p.status).toBe(0);
    expect(p.stdout).toContain("PENDING — not proof");
    expect(p.stdout).toContain("RESULT: PASS (pending — not proof)");
  });

  it("a second-version anchor shows its place in its batch; a first-version one says that is not checked; a broken path fails (GP-6)", () => {
    const v2 = run(["test/vectors/anchor/session-anchored-2.v2.json"]);
    expect(v2.stderr).not.toContain("offline-guard");
    expect(v2.status).toBe(0);
    expect(v2.stdout).toContain(
      "batch              : leaf index 2 in a batch of 5 — its own path reaches the root this anchor names; no public log witnessed that root; this file holds no other session's id, head or lines",
    );
    expect(v2.stdout).toContain("RESULT: PASS");
    // The plain layer names the batch check only where there was one, and says no log saw a practice anchor.
    expect(v2.stdout).toMatch(/what was checked {3}: .*and its place in its batch by its own path to the root the anchor names/);
    expect(v2.stdout).toContain("does not prove     : what was bought (the line items are hashes); that the goods or service arrived; that any public log saw the anchor — it is recorded only");
    const v1 = run([`${V}/session-receipt-complete.v1.json`]);
    expect(v1.status).toBe(0);
    expect(v1.stdout).toContain("batch              : not checked — the anchor carries no inclusion proof this verifier reads");
    expect(v1.stdout).not.toMatch(/what was checked {3}: .*its place in its batch/);
    expect(v1.stdout).toContain("RESULT: PASS");
    const broken = JSON.parse(readFileSync(join(PKG, "test/vectors/anchor/session-anchored-2.v2.json"), "utf8"));
    broken.anchor.inclusion.path[1] = "0".repeat(64);
    const path = join(tmpdir(), `attest-anchor-broken-${process.pid}.json`);
    writeFileSync(path, JSON.stringify(broken));
    try {
      const bad = run([path]);
      expect(bad.stderr).not.toContain("offline-guard");
      expect(bad.status).toBe(1);
      expect(bad.stdout).toContain("claims leaf index 2 in a batch of 5 — its path DOES NOT reach the root this anchor names");
      // The anchor line agrees with the verdict: a consumer reading only that line is not told "matches".
      expect(bad.stdout).toContain("anchor             : none, covers lines 0–5 — DOES NOT MATCH");
      expect(bad.stdout).toContain("fault              : ANCHOR_MISMATCH");
    } finally {
      rmSync(path, { force: true });
    }
  });

  it("a thank-you redeems with its own issuer, and is refused once the issuer marks it used", () => {
    const ok = run([`${V}/thank-you-redemption.v1.txt`, "--nonce", ctx.redemptionNonce, "--status-list", `${V}/thank-you-status-before.v1.json`]);
    expect(ok.stdout).toContain("presented to       :");
    expect(ok.stdout).toContain("its own issuer");
    expect(ok.stdout).toContain("never the answer");
    const used = run([`${V}/thank-you-redemption.v1.txt`, "--nonce", ctx.redemptionNonce, "--status-list", `${V}/thank-you-status-after.v1.json`]);
    expect(used.status).toBe(1);
    expect(used.stdout).toContain("USED_OR_WITHDRAWN");
  });

  it("an ask passes the eight rules, and an ask about caste fails", () => {
    expect(run([`${V}/asks/valid.json`]).status).toBe(0);
    const bad = run([`${V}/asks/invalid-forbidden-caste.json`]);
    expect(bad.status).toBe(1);
    expect(bad.stdout).toContain("FORBIDDEN-NEED");
  });

  it("--check-status is the only path that reaches for the network", () => {
    const quiet = run([`${V}/predicate-presentation-a.v1.txt`, "--audience", ctx.verifiers.a.did, "--nonce", ctx.verifiers.a.nonce]);
    expect(quiet.status).toBe(0);
    expect(quiet.stdout).not.toContain("offline-guard");
    expect(quiet.stdout).toContain("status not checked");
    const asked = run([`${V}/predicate-presentation-a.v1.txt`, "--audience", ctx.verifiers.a.did, "--nonce", ctx.verifiers.a.nonce, "--check-status"]);
    expect(asked.stdout).toContain("offline-guard: fetch is disabled");
  });
});
