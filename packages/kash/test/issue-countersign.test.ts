/**
 * What `issue cohort` and `countersign` refuse, and what a "no" leaves behind.
 * Through the real CLI where the behaviour is the CLI's; in-process where a test
 * needs a clock in the past or a person saying no.
 *
 * Everything is a simulation (d11): no real learner, station or teacher.
 */

import { describe, it, expect, beforeAll, afterAll } from "bun:test";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { base64ToBytes, buildCohortClaim, cohortSubject, sha256HexOf } from "@kashscript/attest";
import {
  acceptCountersignRequest,
  assembleCountersignBundle,
  createCountersignRequest,
} from "@kashscript/identity-server";

import { runCountersign } from "../src/commands/countersign";
import { loadKey } from "../src/keystore/store";
import { bunSrc, issueArgs, linkFrom, makeStationZero, removeDir, type StationZero } from "./helpers";

const run = bunSrc;

describe("issue cohort", () => {
  let z: StationZero;
  beforeAll(() => {
    z = makeStationZero(run);
  });
  afterAll(() => {
    removeDir(z.keystore);
    removeDir(z.work);
  });

  it("records the SHA-256 of the syllabus file's exact bytes, and the profile's pinned shape", () => {
    const out = join(z.work, "hash.pending.json");
    const r = run(issueArgs(z, out));
    expect(r.status).toBe(0);
    const bundle = JSON.parse(readFileSync(out, "utf8"));
    const claim = JSON.parse(new TextDecoder().decode(base64ToBytes(bundle.subject.payload)));
    expect(claim.rule.hash).toBe(createHash("sha256").update(readFileSync(z.syllabusFile)).digest("hex"));
    expect(claim.actor).toEqual({ class: "person", id: z.holder });
    expect(claim.status).toBe("completed");
    expect(claim.meta).toEqual({
      profile: "kashscript-cohort/1",
      teacherOrg: z.teacher,
      station: z.station,
      expiresAt: "2029-09-25T12:00:00.000Z",
    });
    // exactly one of the two signatures, and it is the teacher's organisation's
    expect(bundle.subject.signatures.map((s: { keyid: string }) => s.keyid)).toEqual([z.teacher]);
    expect(bundle.acceptances.length).toBe(1);
  });

  it("will not choose an expiry for you", () => {
    const args = issueArgs(z, join(z.work, "noexp.json"));
    const at = args.indexOf("--expires");
    args.splice(at, 2);
    const r = run(args);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain("--expires");
    expect(existsSync(join(z.work, "noexp.json"))).toBe(false);
  });

  it("refuses a cohort that has not finished", () => {
    const out = join(z.work, "future.json");
    const args = issueArgs(z, out);
    args[args.indexOf("--finished") + 1] = "2999-01-01T00:00:00.000Z";
    const r = run(args);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("future");
    expect(existsSync(out)).toBe(false);
  });

  it("refuses an expiry that is not after the finish, or already past", () => {
    for (const [expires, said] of [
      ["2026-09-25T12:00:00.000Z", "after --finished"], // equal to the finish
      ["2026-01-01T00:00:00.000Z", "after --finished"], // before it
      ["2026-10-01T00:00:00.000Z", "already in the past"], // after the finish, but over
    ] as const) {
      const out = join(z.work, `expiry-${expires.slice(0, 10)}.json`);
      const args = issueArgs(z, out);
      args[args.indexOf("--expires") + 1] = expires;
      const r = run(args);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain(said);
      expect(existsSync(out)).toBe(false);
    }
  });

  it("takes only the exact time format the profile signs — not whatever Date.parse tolerates", () => {
    for (const [flag, bad] of [
      ["--finished", "Sept 25 2026"],
      ["--finished", "2026-09-25"],
      ["--finished", "2026-09-25T12:00:00+05:00"],
      ["--finished", "2026-02-31T12:00:00.000Z"], // Date.parse would roll this into March
      ["--expires", "next year"],
    ] as const) {
      const out = join(z.work, "fmt.json");
      const args = issueArgs(z, out);
      args[args.indexOf(flag) + 1] = bad;
      const r = run(args);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("ISO-8601 UTC");
      expect(existsSync(out)).toBe(false);
    }
  });

  it("reads --ttl-days as a number, fractions included, and refuses what is not one", () => {
    const window = (out: string): number => {
      const body = JSON.parse(readFileSync(out, "utf8")).request.body;
      return body.expiresAtUnix - body.issuedAtUnix;
    };
    const half = join(z.work, "ttl-half.json");
    expect(run(issueArgs(z, half, ["--ttl-days", "0.5"])).status).toBe(0);
    expect(window(half)).toBe(43_200);
    const one = join(z.work, "ttl-one.json");
    expect(run(issueArgs(z, one, ["--ttl-days", "1.5"])).status).toBe(0);
    expect(window(one)).toBe(129_600); // not silently 1 day
    for (const bad of ["0", "-3", "abc", "91", ""]) {
      const out = join(z.work, `ttl-bad.json`);
      const r = run(issueArgs(z, out, ["--ttl-days", bad]));
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("--ttl-days");
      expect(existsSync(out)).toBe(false);
    }
  });

  it("refuses a holder that is not a did:kash, and one that is the station itself", () => {
    for (const holder of ["not-a-did", z.station, z.teacher]) {
      const out = join(z.work, `holder-${holder.slice(-6)}.json`);
      const args = issueArgs(z, out);
      args[args.indexOf("--holder") + 1] = holder;
      const r = run(args);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("RECORD_INVALID");
      expect(existsSync(out)).toBe(false);
    }
  });

  it("refuses a missing syllabus file and a missing key, and never overwrites a record", () => {
    const missingFile = issueArgs(z, join(z.work, "m1.json"));
    missingFile[missingFile.indexOf("--syllabus-file") + 1] = join(z.work, "no-such-syllabus.txt");
    expect(run(missingFile).status).toBe(1);

    const noKey = run(issueArgs(z, join(z.work, "m2.json"), ["--key", "nobody"]));
    expect(noKey.status).toBe(1);
    expect(noKey.stderr).toContain("KEY_NOT_FOUND");

    const out = join(z.work, "once.json");
    expect(run(issueArgs(z, out)).status).toBe(0);
    const before = readFileSync(out, "utf8");
    const again = run(issueArgs(z, out));
    expect(again.status).toBe(1);
    expect(again.stderr).toContain("UNSAFE_WRITE");
    expect(readFileSync(out, "utf8")).toBe(before);
  });
});

describe("countersign", () => {
  let z: StationZero;
  let pending = "";
  let link = "";
  beforeAll(() => {
    z = makeStationZero(run);
    pending = join(z.work, "pending.json");
    const issued = run(issueArgs(z, pending));
    if (issued.status !== 0) throw new Error(issued.stdout + issued.stderr);
    link = linkFrom(issued.stdout);
  });
  afterAll(() => {
    removeDir(z.keystore);
    removeDir(z.work);
  });

  it("takes the pending file itself in place of the link", () => {
    const out = join(z.work, "by-file.json");
    const r = run(["countersign", pending, "--keystore", z.keystore, "--yes", "--out", out]);
    expect(r.status).toBe(0);
    expect(run(["verify", out]).status).toBe(0);
  });

  it("will not sign with a key that is not the station the record names — and writes nothing", () => {
    const out = join(z.work, "wrong-key.json");
    const r = run(["countersign", link, "--record", pending, "--key", "teacher", "--keystore", z.keystore, "--yes", "--out", out]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("WRONG_STATION");
    expect(r.stderr).toContain(z.station); // names the station the record wants
    expect(existsSync(out)).toBe(false);
  });

  it("will not sign a link that is not the request inside the record", () => {
    const other = join(z.work, "other.json");
    const second = run(issueArgs(z, other));
    expect(second.status).toBe(0);
    const out = join(z.work, "mismatch.json");
    const r = run(["countersign", linkFrom(second.stdout), "--record", pending, "--keystore", z.keystore, "--yes", "--out", out]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("LINK_INVALID");
    expect(existsSync(out)).toBe(false);
  });

  it("does not guess its mode: a file plus --record is refused, and a mistyped path is a missing file, not a bad link", () => {
    const other = join(z.work, "other-pending.json");
    expect(run(issueArgs(z, other)).status).toBe(0);
    const out = join(z.work, "both.json");
    const both = run(["countersign", pending, "--record", other, "--keystore", z.keystore, "--yes", "--out", out]);
    expect(both.status).toBe(1);
    expect(both.stderr).toContain("--record");
    expect(both.stderr).toContain("ignored");
    expect(existsSync(out)).toBe(false); // neither record was signed

    const typo = run(["countersign", join(z.work, "pendign.json"), "--keystore", z.keystore, "--yes", "--out", out]);
    expect(typo.status).toBe(1);
    expect(typo.stderr).toContain("No file at");
    expect(typo.stderr).not.toContain("LINK_INVALID");
    expect(existsSync(out)).toBe(false);
  });

  it("needs the record when it is given only a link, and refuses a link that is not one", () => {
    const noRecord = run(["countersign", link, "--keystore", z.keystore, "--yes"]);
    expect(noRecord.status).toBe(1);
    expect(noRecord.stderr).toContain("--record");
    const junk = run(["countersign", "bm90LWEtbGluaw", "--record", pending, "--keystore", z.keystore, "--yes"]);
    expect(junk.status).toBe(1);
    expect(junk.stderr).toContain("LINK_INVALID");
  });

  it("will not sign a file that is not a cohort record", () => {
    const notRecord = join(z.work, "not-a-record.json");
    writeFileSync(notRecord, JSON.stringify({ hello: "world" }));
    const r = run(["countersign", notRecord, "--keystore", z.keystore, "--yes"]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("RECORD_INVALID");
  });

  it("does not sign without a person to ask: no terminal and no --yes writes nothing", () => {
    const out = join(z.work, "no-yes.json");
    const r = run(["countersign", pending, "--keystore", z.keystore, "--out", out]);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain("--yes");
    expect(existsSync(out)).toBe(false);
  });

  it("a no leaves nothing behind (d49)", async () => {
    const out = join(z.work, "declined.json");
    await runCountersign({ link: pending, keystore: z.keystore, out, prompt: async () => "n" });
    expect(existsSync(out)).toBe(false);
    // and a yes, through the same door, does sign
    await runCountersign({ link: pending, keystore: z.keystore, out, prompt: async () => "y" });
    expect(existsSync(out)).toBe(true);
  });

  it("refuses a request that has expired", async () => {
    // A request issued 30 days ago with a one-day window, built with the real ceremony and a clock in the past.
    const teacher = await loadKey("teacher", z.keystore);
    const claim = buildCohortClaim({
      holderDid: z.holder,
      teacherOrgDid: teacher.did,
      stationDid: z.station,
      syllabus: { id: `${teacher.did}/syllabus/old`, version: "1.0", hash: await sha256HexOf("old syllabus (simulation)") },
      finishedAt: "2026-01-01T00:00:00.000Z",
      expiresAt: "2029-01-01T00:00:00.000Z",
    });
    const subject = cohortSubject(claim);
    const long = Math.floor(Date.now() / 1000) - 30 * 86_400;
    const signingKey = { did: teacher.did, publicKey: teacher.publicKey, privateKey: teacher.privateKey, custody: "subject-generated" } as const;
    const created = await createCountersignRequest({
      subject,
      requesterDid: teacher.did,
      requesterPrivateKey: teacher.privateKey,
      statement: "Countersign that the holder finished the cohort.",
      ttlSeconds: 86_400,
      nowSec: long,
    });
    const byTeacher = await acceptCountersignRequest({ request: created.request, subject, signingKey, nowSec: long + 60 });
    if (!byTeacher.ok) throw new Error(byTeacher.reason);
    const stale = join(z.work, "stale.json");
    writeFileSync(stale, JSON.stringify(assembleCountersignBundle({ subject: byTeacher.envelope, request: created.request, acceptances: [byTeacher.acceptance] })));

    const out = join(z.work, "stale-out.json");
    await expect(runCountersign({ link: stale, keystore: z.keystore, out, yes: true })).rejects.toThrow(/expired/i);
    expect(existsSync(out)).toBe(false);
  });
});
