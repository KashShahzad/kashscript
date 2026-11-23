// ============================================================================
// RW-15 — `attest verify` on an attestation copy, under plain Node with the
// network switched off: a presentation checks at its verifier; a page's stored
// copy shows no artefact; the viewer's copy — stored plus fragment — shows it
// with --artifact; another artefact DOES NOT MATCH (specs/attestation/README.md
// §2.4b). The files are the worked example, generated once.
// ============================================================================

import { beforeAll, describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const PKG = join(import.meta.dir, "..");
const WIN = process.platform === "win32";
const BIN = "dist/bin/attest.js";
const GUARD = "./test/offline-guard.cjs";
const EXAMPLE = "../../specs/attestation/examples/receipt-booking-countersigned";
const OTHER_RECORD = "../../specs/attestation/examples/receipt-booking/record.dsse.json";

interface Context {
  readonly record: string;
  readonly presentations: { readonly a: { readonly audience: string; readonly nonce: string; readonly iatUnix: number } };
  readonly checkAt: number;
}
const ctx = JSON.parse(readFileSync(join(PKG, EXAMPLE, "context.json"), "utf8")) as Context;

function runNode(args: readonly string[]): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync("node", args, { cwd: PKG, encoding: "utf8", shell: WIN });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

beforeAll(() => {
  const build = spawnSync("bun", ["run", "build:bin"], { cwd: PKG, encoding: "utf8", shell: WIN });
  if (build.status !== 0) throw new Error(`build:bin failed:\n${build.stderr || build.stdout}`);
}, 120_000);

describe("attest verify — an attestation copy, and the page's rule (RW-15)", () => {
  it("a presentation checks at its verifier: the class, nothing disclosed, PASS", () => {
    const p = ctx.presentations.a;
    const r = runNode(["--require", GUARD, BIN, "verify", `${EXAMPLE}/presentation-a.sd-jwt.txt`, "--audience", p.audience, "--nonce", p.nonce, "--at", String(p.iatUnix + 60)]);
    expect(r.stderr).not.toContain("offline-guard");
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("Attestation copy (https://kashscript.com/vct/attestation/1)");
    expect(r.stdout).toContain("attests            : receipt — accepted, booking.delivered/1, grade 1 (practice)");
    expect(r.stdout).toContain("disclosed          : nothing beyond the class");
    expect(r.stdout).toContain("record             : not disclosed");
    expect(r.stdout).toContain("audience           : https://review-door.example/verifier — matches");
    expect(r.stdout).toContain("RESULT: PASS");
  }, 60_000);

  it("the page's stored copy with --artifact: the artefact is not shown, because the record was not disclosed (exit 0)", () => {
    const r = runNode(["--require", GUARD, BIN, "verify", `${EXAMPLE}/page/copy.sd-jwt.txt`, "--artifact", `${EXAMPLE}/record.countersign.json`, "--at", String(ctx.checkAt)]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("holder binding     : none");
    expect(r.stdout).toContain("artefact           : not shown — the record was not disclosed — a page shows the artefact only to the holder of the disclosure");
    expect(r.stdout).toContain("RESULT: PASS");
  }, 60_000);

  it("the viewer's copy — the stored copy with the fragment — with --artifact: shown (exit 0); against another artefact: DOES NOT MATCH (exit 1)", () => {
    const dir = mkdtempSync(join(tmpdir(), "attest-copy-"));
    try {
      const viewer = join(dir, "viewer.sd-jwt.txt");
      writeFileSync(viewer, `${readFileSync(join(PKG, EXAMPLE, "page", "copy.sd-jwt.txt"), "utf8").trim()}${readFileSync(join(PKG, EXAMPLE, "page", "fragment.txt"), "utf8").trim()}\n`);
      const shown = runNode(["--require", GUARD, BIN, "verify", viewer, "--artifact", `${EXAMPLE}/record.countersign.json`, "--at", String(ctx.checkAt)]);
      expect(shown.status).toBe(0);
      expect(shown.stdout).toContain(`record             : ${ctx.record.slice(0, 12)}… (disclosed by the holder)`);
      expect(shown.stdout).toContain("artefact           : shown — the disclosed record names this artefact, and it checks");
      expect(shown.stdout).toContain("RESULT: PASS");
      const other = runNode(["--require", GUARD, BIN, "verify", viewer, "--artifact", OTHER_RECORD, "--at", String(ctx.checkAt)]);
      expect(other.status).toBe(1);
      expect(other.stdout).toContain("artefact           : DOES NOT MATCH — the disclosed record names no artefact here");
      expect(other.stdout).toContain("RESULT: FAIL");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 60_000);
});
