// ============================================================================
// The attest CLI must run under PLAIN NODE, not just Bun (ROADMAP M7.1 / Duedale ADR-0018).
// ----------------------------------------------------------------------------
// Regression guard for the one real bug Duedale logged: the bin shipped
// extensionless relative ESM imports (`from "../chain"`) that Node's native ESM
// loader rejects (ERR_MODULE_NOT_FOUND) at LOAD time — the bin ran only under
// Bun. These tests bundle the bin (self-contained) and drive it through the
// system `node` binary, so the failure mode is exercised by the real runtime.
// ============================================================================

import { describe, it, expect, beforeAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PKG = join(import.meta.dir, "..");
const WIN = process.platform === "win32";
const REL_BIN = "dist/bin/attest.js";
const REL_REPORT = "test/fixtures/duedale-report.json";
const REL_COUNTERSIGN = "test/fixtures/countersign-bundle.json";
const REL_AUDIT = "test/fixtures/oreoasis-audit-bundle.dsse.json";
const REL_HOST_KEY = "test/fixtures/oreoasis-host-public-key.txt";
/** The operator key the report carries — handed to the CLI out of band, as a reader who trusts it would. */
const OPERATOR_HEX = (JSON.parse(readFileSync(join(PKG, REL_REPORT), "utf8")) as { operatorPublicKeyHex: string }).operatorPublicKeyHex;

/** Run the bundled bin under the real `node` binary, from the package root
 *  (relative paths avoid the space in the repo path breaking shell parsing). */
function runNode(args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("node", args, { cwd: PKG, encoding: "utf8", shell: WIN });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

beforeAll(() => {
  const build = spawnSync("bun", ["run", "build:bin"], { cwd: PKG, encoding: "utf8", shell: WIN });
  if (build.status !== 0) {
    throw new Error(`build:bin failed (status ${build.status}):\n${build.stderr || build.stdout}`);
  }
});

describe("attest bin — runs under plain Node, not just Bun", () => {
  it("bundles to a self-contained dist/bin/attest.js", () => {
    expect(existsSync(join(PKG, REL_BIN))).toBe(true);
  });

  it("loads the whole module graph under `node` without an ESM-resolution crash", () => {
    // No args → usage, exit 2. The OLD bug threw ERR_MODULE_NOT_FOUND at LOAD,
    // before any usage text could print. A clean load reaches the usage path.
    const r = runNode([REL_BIN]);
    expect(r.stderr).not.toContain("ERR_MODULE_NOT_FOUND");
    expect(r.stderr).not.toContain("Cannot find module");
    expect(r.stderr).not.toContain("Cannot find package");
    expect(r.status).toBe(2);
    expect(`${r.stdout}${r.stderr}`).toContain("attest — the KashScript evidence-commons verifier");
  });

  it("verifies a real signed artifact end-to-end under `node`, against a key given out of band (exit 0 = PASS)", () => {
    const r = runNode([REL_BIN, "verify", REL_REPORT, "--key", OPERATOR_HEX]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("RESULT: PASS");
  });
});

// ============================================================================
// AU-3, A7-06 (AUDIT-2026-11-11): a file whose only key came from inside itself
// proves that it is consistent with itself, and nothing about who signed it.
// The printed lines always said so; the exit code said PASS. Now the exit code
// says INTEGRITY ONLY (3) until a key is given out of band.
// ============================================================================

describe("attest bin — a key from inside the file is integrity only, exit 3 (A7-06)", () => {
  it("the Every-Rupee report without --key: INTEGRITY ONLY, exit 3; with the operator's key: PASS, exit 0", () => {
    const self = runNode([REL_BIN, "verify", REL_REPORT]);
    expect(self.status).toBe(3);
    expect(self.stdout).toContain("RESULT: INTEGRITY ONLY");
    expect(self.stdout).not.toContain("RESULT: PASS");
    const keyed = runNode([REL_BIN, "verify", REL_REPORT, "--key", OPERATOR_HEX]);
    expect(keyed.status).toBe(0);
    expect(keyed.stdout).toContain("RESULT: PASS");
  });

  it("the Oreoasis audit bundle without --key: INTEGRITY ONLY, exit 3; with the host's key: PASS, exit 0; --signer-did alone lifts nothing", () => {
    const self = runNode([REL_BIN, "verify", REL_AUDIT]);
    expect(self.status).toBe(3);
    expect(self.stdout).toContain("RESULT: INTEGRITY ONLY");
    const keyid = (JSON.parse(readFileSync(join(PKG, REL_AUDIT), "utf8")) as { signatures: { keyid: string }[] }).signatures[0]!.keyid;
    const named = runNode([REL_BIN, "verify", REL_AUDIT, "--signer-did", keyid]);
    expect(named.status).toBe(3);
    const keyed = runNode([REL_BIN, "verify", REL_AUDIT, "--key", REL_HOST_KEY]);
    expect(keyed.status).toBe(0);
    expect(keyed.stdout).toContain("RESULT: PASS");
  });

  it("a tampered bundle still fails with exit 1 — integrity only is never a pass of a broken file", () => {
    const original = JSON.parse(readFileSync(join(PKG, REL_AUDIT), "utf8")) as { payload: string };
    const tampered = { ...original, payload: `${original.payload.slice(0, -4)}AAAA` };
    const tamperedPath = join(tmpdir(), `attest-audit-tampered-${process.pid}.json`);
    writeFileSync(tamperedPath, JSON.stringify(tampered));
    try {
      const r = runNode([REL_BIN, "verify", tamperedPath]);
      expect(r.status).not.toBe(0);
      expect(r.status).not.toBe(3);
    } finally {
      rmSync(tamperedPath, { force: true });
    }
  });
});

// ============================================================================
// The stranger path (ADR-0018 / ECOSYSTEM d26, d28).
// ----------------------------------------------------------------------------
// Someone who has never heard of us, holding nothing but the published verifier
// and a file, must be able to check that two independent parties signed the same
// bytes. No key material is passed on the command line, no service is running,
// and nothing is fetched: both public keys are inside the did:kash identifiers
// the artifact already carries. If this test ever needs a --key, an endpoint or
// a second package, decision 28's "never build anything whose verification
// requires us" has been broken.
// ============================================================================

describe("attest bin — the stranger path: a two-signature bundle, offline, no keys", () => {
  it("verifies with NO --key at all (exit 0 = PASS)", () => {
    const r = runNode([REL_BIN, "verify", REL_COUNTERSIGN]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("RESULT: PASS");
  });

  it("reports two distinct keys over the same bytes, and calls it proof", () => {
    const r = runNode([REL_BIN, "verify", REL_COUNTERSIGN]);
    expect(r.stdout).toContain("2 distinct key(s) over the same bytes");
    expect(r.stdout).toContain("two-signature proof: yes");
    expect(r.stdout).toContain("key custody      : subject-generated");
  });

  it("prints what it cannot know rather than implying it checked", () => {
    const r = runNode([REL_BIN, "verify", REL_COUNTERSIGN]);
    expect(r.stdout).toContain("none presented");
    expect(r.stdout).toContain("not evidence that none exists");
    expect(r.stdout).toContain("signers' own claims");
  });

  it("fails a tampered bundle (exit 1), without a network round-trip to tell it so", () => {
    const original = readFileSync(join(PKG, REL_COUNTERSIGN), "utf8");
    const bundle = JSON.parse(original) as {
      request: { body: { statement: string } };
    };
    bundle.request.body.statement = "Confirm you received a used car.";
    const tamperedPath = join(tmpdir(), `attest-countersign-tampered-${process.pid}.json`);
    writeFileSync(tamperedPath, JSON.stringify(bundle));
    try {
      const r = runNode([REL_BIN, "verify", tamperedPath]);
      expect(r.status).toBe(1);
      expect(r.stdout).toContain("RESULT: FAIL");
    } finally {
      rmSync(tamperedPath, { force: true });
    }
  });
});

// ============================================================================
// KS-D1 — the checker's plain layer (design language §5.6, law 9: "a tick is never alone").
// ----------------------------------------------------------------------------
// Every verdict is followed by who signed, what was checked, and what it does not prove — new
// lines, immediately before RESULT, so every line printed before still prints and RESULT stays
// last (scripts and the simulation read this text). Nothing here is JSON: the CLI has no JSON mode.
// ============================================================================

describe("attest bin — the plain layer: who signed, what was checked, what this does not prove (law 9)", () => {
  const ES = "test/vectors/es256";
  const GUARD = "./test/offline-guard.cjs";
  const SIGNED = /^ {2}(who signed|claims signed by) {1,}: /;
  const CHECKED = /^ {2}what was checked {3}: /;
  const NOT_PROVEN = /^ {2}does not prove {5}: /;

  const linesOf = (stdout: string): string[] => stdout.split("\n").filter((l) => l.length > 0);
  const plainOf = (stdout: string): string[] => linesOf(stdout).filter((l) => SIGNED.test(l) || CHECKED.test(l) || NOT_PROVEN.test(l));

  /** The three lines exist, in order, directly before RESULT, and RESULT is the last line. */
  function expectPlainLayerBeforeResult(stdout: string): void {
    const lines = linesOf(stdout);
    const last = lines.length - 1;
    expect(lines[last]).toMatch(/^RESULT: /);
    expect(lines[last - 3]).toMatch(SIGNED);
    expect(lines[last - 2]).toMatch(CHECKED);
    expect(lines[last - 1]).toMatch(NOT_PROVEN);
    expect(plainOf(stdout)).toHaveLength(3);
  }

  it("a passing countersign bundle names both keys and says what it does not show", () => {
    const r = runNode([REL_BIN, "verify", REL_COUNTERSIGN]);
    expect(r.status).toBe(0);
    expectPlainLayerBeforeResult(r.stdout);
    const [signed, , notProven] = plainOf(r.stdout) as [string, string, string];
    expect(signed).toMatch(/^ {2}who signed {9}: did:kash:/);
    expect(notProven).toContain("who holds a key");
    expect(notProven).toContain("that nobody has withdrawn");
  });

  it("a tampered bundle still gets the layer, and says the names are claims", () => {
    const bundle = JSON.parse(readFileSync(join(PKG, REL_COUNTERSIGN), "utf8")) as { request: { body: { statement: string } } };
    bundle.request.body.statement = "Confirm you received a used car.";
    const tamperedPath = join(tmpdir(), `attest-plain-tampered-${process.pid}.json`);
    writeFileSync(tamperedPath, JSON.stringify(bundle));
    try {
      const r = runNode([REL_BIN, "verify", tamperedPath]);
      expect(r.status).toBe(1);
      expectPlainLayerBeforeResult(r.stdout);
      expect(plainOf(r.stdout)[0]).toMatch(/^ {2}claims signed by {3}: /);
      expect(plainOf(r.stdout)[0]).not.toMatch(/^ {2}who signed/);
    } finally {
      rmSync(tamperedPath, { force: true });
    }
  });

  it("every artifact kind the CLI reads gets the layer, and the layer's wording stays inside the rules other tools rely on", () => {
    const ctx = JSON.parse(readFileSync(join(PKG, ES, "context.v1.json"), "utf8")) as { trustPublisher: string; audience: string; nonce: string };
    const runs: readonly (readonly string[])[] = [
      [REL_BIN, "verify", REL_REPORT, "--key", OPERATOR_HEX],
      [REL_BIN, "verify", REL_AUDIT, "--key", REL_HOST_KEY],
      [REL_BIN, "verify", REL_COUNTERSIGN],
      [REL_BIN, "verify", `${ES}/holder-export-es256.v1.json`, "--trust-publisher", ctx.trustPublisher],
      [REL_BIN, "verify", `${ES}/trust-list-es256.v1.json`, "--trust-publisher", ctx.trustPublisher],
      [REL_BIN, "verify", `${ES}/status-list-es256.v1.json`],
      [REL_BIN, "verify", `${ES}/predicate-presentation-es256.v1.txt`, "--audience", ctx.audience, "--nonce", ctx.nonce, "--status-list", `${ES}/status-list-es256.v1.json`],
      [REL_BIN, "verify", "test/vectors/exchange/session-receipt-complete.v1.json"],
      [REL_BIN, "verify", "test/vectors/exchange/session-receipt-pending.v1.json"],
      [REL_BIN, "verify", "test/vectors/anchor/session-anchored-2.v2.json"],
      [REL_BIN, "verify", "test/vectors/exchange/thank-you.v1.txt"],
    ];
    for (const args of runs) {
      const r = runNode(["--require", GUARD, ...args]);
      expect(r.status).toBe(0);
      expectPlainLayerBeforeResult(r.stdout);
      // holder-cli.test.ts asserts no "trusted" anywhere; the simulation filters stdout on reason|fault|FAIL.
      for (const l of plainOf(r.stdout)) {
        expect(l).not.toMatch(/trusted/i);
        expect(l).not.toMatch(/reason|fault|FAIL/);
      }
    }
  }, 120_000);

  it("never claims a did:kash is a person, wherever it names a signer", () => {
    const r = runNode([REL_BIN, "verify", REL_COUNTERSIGN]);
    expect(plainOf(r.stdout)[2]).toContain("who holds a key");
  });
});

// ============================================================================
// PL-2 — ES256 and recovery under Node 22, with the network switched off.
// The verifier must work in Node 22 and in a browser build, where Ed25519
// availability differs; this half is Node (test/browser-smoke.test.ts is the
// other). Every check below runs with ./offline-guard.cjs loaded.
// ============================================================================

describe("attest bin — ES256 and helper recovery under Node 22, offline (PL-2)", () => {
  const ES = "test/vectors/es256";
  const GUARD = "./test/offline-guard.cjs";
  const ctx = JSON.parse(readFileSync(join(PKG, ES, "context.v1.json"), "utf8")) as { trustPublisher: string; audience: string; nonce: string };

  it("runs on Node 22 or newer", () => {
    const v = spawnSync("node", ["--version"], { encoding: "utf8", shell: WIN }).stdout.trim();
    expect(Number(v.replace(/^v/, "").split(".")[0])).toBeGreaterThanOrEqual(22);
  });

  it("verifies the ES256 export: a helper-quorum claim, a cross-algorithm claim, the new key's helper set", () => {
    const r = runNode(["--require", GUARD, REL_BIN, "verify", `${ES}/holder-export-es256.v1.json`, "--trust-publisher", ctx.trustPublisher]);
    expect(r.stderr).not.toContain("offline-guard");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("network            : none");
    expect(r.stdout).toContain("helpers, 2 of 3 signed (need 2) · Ed25519 → P-256");
    expect(r.stdout).toContain("the prior key · P-256 → Ed25519");
    expect(r.stdout).toContain("recovery helpers");
    expect(r.stdout).toContain("RESULT: PASS");
  });

  it("verifies a countersign bundle with a P-256 countersigner and claims both ways", () => {
    const r = runNode(["--require", GUARD, REL_BIN, "verify", `${ES}/countersign-es256.v1.json`]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("the prior key · Ed25519 → P-256");
    expect(r.stdout).toContain("the prior key · P-256 → Ed25519");
  });

  it("verifies an ES256 presentation, its ES256 key binding and its ES256 status list", () => {
    const r = runNode(["--require", GUARD, REL_BIN, "verify", `${ES}/predicate-presentation-es256.v1.txt`, "--audience", ctx.audience, "--nonce", ctx.nonce, "--status-list", `${ES}/status-list-es256.v1.json`]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("holder binding     : ok");
    expect(r.stdout).toContain("RESULT: PASS");
  });

  it("fails an export carrying a fork — two successors for one lost key (exit 1)", () => {
    const exp = JSON.parse(readFileSync(join(PKG, ES, "holder-export-es256.v1.json"), "utf8")) as { keySuccession: unknown[] };
    const neg = JSON.parse(readFileSync(join(PKG, ES, "negative.v1.json"), "utf8")) as { fork: { claims: unknown[] } };
    exp.keySuccession = [...exp.keySuccession, neg.fork.claims[1]];
    const forked = join(tmpdir(), `attest-es256-fork-${process.pid}.json`);
    writeFileSync(forked, JSON.stringify(exp));
    try {
      const r = runNode(["--require", GUARD, REL_BIN, "verify", forked]);
      expect(r.status).toBe(1);
      expect(r.stdout).toContain("CONFLICT");
      expect(r.stdout).toContain("RESULT: FAIL");
    } finally {
      rmSync(forked, { force: true });
    }
  });
});
