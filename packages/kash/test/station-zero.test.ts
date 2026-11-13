/**
 * Station zero's loop through the real CLI, twice: from the workspace source (bun)
 * and from the bundled single file that `npx` would run (node, with the offline
 * guard on — every way a Node process reaches the network throws, and the child
 * `attest` that `kash verify` spawns inherits it).
 *
 *   init ×3 → issue (teacher) → verify the pending file (1) → countersign (station)
 *   → verify (0) → a tampered copy (1)
 *
 * Everything is a simulation (d11): no real learner, station or teacher.
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalizeBytes } from "@kashscript/identity-core";
import { base64ToBytes, bytesToBase64 } from "@kashscript/attest";

import { bunSrc, buildBundles, linkFrom, makeStationZero, nodeDist, issueArgs, removeDir, type Runner } from "./helpers";

const RUNNERS: ReadonlyArray<readonly [string, Runner]> = [
  ["bun-src", bunSrc],
  ["node-dist", nodeDist],
];

beforeAll(() => buildBundles(), 180_000);

for (const [label, run] of RUNNERS) {
  describe(`station zero's loop — ${label}`, () => {
    const dirs: string[] = [];
    afterAll(() => dirs.forEach(removeDir));

    it("init → issue → verify pending (1) → countersign → verify (0) → tamper (1)", () => {
      const z = makeStationZero(run);
      dirs.push(z.keystore, z.work);
      const pending = join(z.work, "cohort-record.pending.json");
      const finished = join(z.work, "cohort-record.json");

      // issue: the teacher's organisation signs; the file is not a record yet.
      const issued = run(issueArgs(z, pending));
      expect(issued.stderr).not.toContain("offline-guard");
      expect(issued.status).toBe(0);
      expect(existsSync(pending)).toBe(true);
      expect(issued.stdout).toContain("Carried link");
      // paper is the floor: a file and a carried link — never a wallet offer
      expect(issued.stdout).not.toMatch(/openid-credential-offer|openid4vci:|haip:|https?:\/\//i);
      const link = linkFrom(issued.stdout);

      // verify the pending file: one signature is not proof
      const early = run(["verify", pending]);
      expect(early.stderr).not.toContain("offline-guard");
      expect(early.stdout).toContain("two-signature proof: NO");
      expect(early.stdout).toContain("MISSING_COUNTERSIGNATURE");
      expect(early.stdout).toContain("RESULT: FAIL");
      expect(early.status).toBe(1);

      // countersign: the station, from the carried link plus the pending file, with its own key
      const signed = run(["countersign", link, "--record", pending, "--keystore", z.keystore, "--yes", "--out", finished]);
      expect(signed.stderr).not.toContain("offline-guard");
      expect(signed.status).toBe(0);
      expect(existsSync(finished)).toBe(true);

      // verify: exit 0, and the plain layer says what it checked and what it does not prove
      const pass = run(["verify", finished]);
      expect(pass.stderr).not.toContain("offline-guard");
      expect(pass.stdout).toContain("two-signature proof: yes");
      expect(pass.stdout).toContain("Cohort record (kashscript-cohort/1)");
      expect(pass.stdout).toContain(`teacher's org      : ${z.teacher} — countersigned`);
      expect(pass.stdout).toContain(`station            : ${z.station} — countersigned`);
      expect(pass.stdout).toContain("profile            : every rule holds");
      expect(pass.stdout).toContain("RESULT: PASS");
      expect(pass.status).toBe(0);

      // tamper: the syllabus version changes after both organisations signed
      const bundle = JSON.parse(readFileSync(finished, "utf8"));
      const claim = JSON.parse(new TextDecoder().decode(base64ToBytes(bundle.subject.payload)));
      claim.rule.version = "2.0";
      bundle.subject.payload = bytesToBase64(canonicalizeBytes(claim));
      const tampered = join(z.work, "cohort-record-tampered.json");
      writeFileSync(tampered, JSON.stringify(bundle, null, 2));
      const fail = run(["verify", tampered]);
      expect(fail.stderr).not.toContain("offline-guard");
      expect(fail.stdout).toContain("RESULT: FAIL");
      expect(fail.status).toBe(1);
    }, 180_000);
  });
}
