// ============================================================================
// PY-5 — `attest verify` on an attestation record, under plain Node with the
// network switched off: a census checks whole, with every item against the
// seal's root; a sampled batch on a synthetic chain prints its draw, recomputed,
// and fails the work floor; the real worked example passes once its draw block
// is mined (specs/attestation/batch.md §6).
// ============================================================================

import { beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { batchOf, party, receiptOf, sampledBatch, signRecord } from "./helpers/batch";

const PKG = join(import.meta.dir, "..");
const WIN = process.platform === "win32";
const BIN = "dist/bin/attest.js";
const GUARD = "./test/offline-guard.cjs";
const CENSUS = "../../specs/attestation/examples/receipt-batch-all";
const SAMPLED = "../../specs/attestation/examples/receipt-batch-sampled";

function runNode(args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("node", ["--require", GUARD, BIN, ...args], { cwd: PKG, encoding: "utf8", shell: WIN });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

let dir: string;
beforeAll(async () => {
  const build = spawnSync("bun", ["run", "build:bin"], { cwd: PKG, encoding: "utf8", shell: WIN });
  if (build.status !== 0) throw new Error(`build:bin failed:\n${build.stderr || build.stdout}`);
  dir = mkdtempSync(join(tmpdir(), "attest-batch-"));
  const sb = await sampledBatch();
  const asker = await party();
  const approver = await party();
  writeFileSync(join(dir, "sampled.json"), JSON.stringify(await signRecord(receiptOf(asker, approver, batchOf(sb, []), sb.sealDigest), asker, approver)));
  writeFileSync(join(dir, "sampled-items.json"), JSON.stringify({ format: "kashscript-batch-items/1", salt: sb.salt, digests: sb.digests }));
  const items = JSON.parse(readFileSync(join(PKG, CENSUS, "items.json"), "utf8")) as { digests: string[] };
  items.digests[5] = "ab".repeat(32);
  writeFileSync(join(dir, "census-items-changed.json"), JSON.stringify(items));
  return () => rmSync(dir, { recursive: true, force: true });
}, 120_000);

describe("attest verify — a batch accepted on a sample (PY-5)", () => {
  it("a census checks whole: both signatures, the plan, the count found, every item against the root, and its words (exit 0)", () => {
    const r = runNode(["verify", `${CENSUS}/record.dsse.json`, "--batch", `${CENSUS}/items.json`]);
    expect(r.stderr).not.toContain("offline-guard");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Attestation record (application/vnd.kash.attestation+json)");
    expect(r.stdout).toContain("attests            : receipt — accepted, client-signoff/1, grade 1 (practice)");
    expect(r.stdout).toContain("every item checked (a census)");
    expect(r.stdout).toContain("found short        : 17");
    expect(r.stdout).toContain("bound              : 1 of 40");
    expect(r.stdout).toContain("items              : all 40 make the seal's root");
    expect(r.stdout).toContain("in words           : The approver checked every one of the 40 items in the asker's batch.");
    expect(r.stdout).toContain("in words           : The acceptance does not cover that one.");
    expect(r.stdout).toContain("what was checked   : the issuer's and the other side's signatures over one canonical body, and its rules; the seal against the receipt's reference; the plan and the count found, exactly; every item against the seal's root");
    expect(r.stdout.trim().endsWith("RESULT: PASS")).toBe(true);
  }, 60_000);

  it("an items file with one item changed does not make the root (exit 1)", () => {
    const r = runNode(["verify", `${CENSUS}/record.dsse.json`, "--batch", join(dir, "census-items-changed.json")]);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("items              : DO NOT MATCH — these items, under this salt, do not make the seal's root");
    expect(r.stdout).toContain("RESULT: FAIL");
  }, 60_000);

  it("a sampled batch on a synthetic chain: the draw is recomputed and shown, and the work floor refuses it (exit 1)", () => {
    const r = runNode(["verify", join(dir, "sampled.json"), "--batch", join(dir, "sampled-items.json")]);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("plan               : 30 drawn; accepted with up to 0 short; chance 1 in 20");
    expect(r.stdout).toContain("draw block         : 900003 — ");
    expect(r.stdout).toContain("drawn              : 30 positions, recomputed from the seal and the draw block:");
    expect(r.stdout).toContain("problem            : BATCH_DRAW — block 900000: the header claims less than 76 bits of work");
    expect(r.stdout).toContain("items              : all 200 make the seal's root");
    expect(r.stdout).toContain("not checked        : that these headers are Bitcoin's own chain");
    expect(r.stdout).toContain("RESULT: FAIL");
  }, 60_000);

  it("--batch is refused for a record that accepts no batch (exit 2)", () => {
    const r = runNode(["verify", "../../specs/attestation/examples/receipt-booking/record.dsse.json", "--batch", `${CENSUS}/items.json`]);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain("--batch is for a record that accepts a batch on a sample");
  }, 60_000);

  it("a 1.0.0 record of truth now prints as an attestation record, not an audit bundle", () => {
    const r = runNode(["verify", "../../specs/attestation/examples/receipt-booking/record.dsse.json"]);
    expect(r.stdout).toContain("Attestation record (application/vnd.kash.attestation+json)");
    expect(r.stdout).not.toContain("DSSE audit bundle");
    expect(r.status).toBe(0);
  }, 60_000);

  it("the real worked example: once its draw block is mined, it passes at the default floor; until then the seal waits, stamped", () => {
    if (existsSync(join(PKG, SAMPLED, "record.dsse.json"))) {
      const r = runNode(["verify", `${SAMPLED}/record.dsse.json`, "--batch", `${SAMPLED}/items.json`]);
      expect(r.status).toBe(0);
      expect(r.stdout).toContain("stamp              : reaches block");
      expect(r.stdout).toContain("items              : all 2000 make the seal's root");
      expect(r.stdout.trim().endsWith("RESULT: PASS")).toBe(true);
    } else {
      // Not a pass by silence: the pending state is what the folder must hold until `batch-example.ts finish` runs.
      const pending = JSON.parse(readFileSync(join(PKG, SAMPLED, "pending.json"), "utf8")) as { drawHeight: number };
      expect(pending.drawHeight).toBeGreaterThan(977_689);
      expect(existsSync(join(PKG, SAMPLED, "stamp.ots.b64"))).toBe(true);
    }
  }, 60_000);
});
