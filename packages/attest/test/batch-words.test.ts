/**
 * PY-5 — a batch's words (`specs/attestation/batch.md` §7), against the content standard
 * (CONTENT-AND-FLOW-STANDARD-2026-11-09 §1): a first line a person would say; the parties named; counts, never
 * percentages; what it does not prove, in the body; the bound never a guarantee; nothing about who made the items.
 */

import { beforeAll, describe, expect, test } from "bun:test";
import type { AttestationBody } from "../src/attestation";
import { OVER_PLAN_REASON, batchWords, boundOf, chanceWords, grouped, limitOf, type Batch, type BatchSeal } from "../src/batch";
import { batchOf, party, receiptOf, sampledBatch, type Party, type SampledBatch } from "./helpers/batch";

let asker: Party;
let approver: Party;
let sb: SampledBatch;
beforeAll(async () => {
  asker = await party();
  approver = await party();
  sb = await sampledBatch();
}, 60_000);

/** The plan's own example: 10,000 items, 300 drawn, none allowed short, 1 in 20. */
function bigBatch(found: readonly number[], accept = 0): Batch {
  const alpha = { num: 1, den: 20 };
  const seal: BatchSeal = {
    format: "kash-batch-seal/1",
    root: "ab".repeat(32),
    size: 10_000,
    plan: { sample: 300, accept, alpha, limit: limitOf({ size: 10_000, sample: 300, accept, alpha }) },
    draw: { source: "bitcoin/1", height: 977_713 },
  };
  return { seal, stamp: "AA==", blocks: ["00".repeat(80), "00".repeat(80)], found, bound: boundOf({ size: 10_000, sample: 300, found: found.length, alpha }) };
}

const FORBIDDEN = [/%/, /percent/i, /\bverified\b/i, /\bsecure\b/i, /\bscore/i, /\brating/i, /\btrusted\b/i, /\breminder/i, /\burgent/i, /\bcertif/i, /\bguarantee(?!d)/i, /\bdid:/i];

function standard(lines: readonly string[], doesNotProve: readonly string[]): void {
  expect(lines.length).toBeGreaterThan(0);
  expect(lines[0]).toMatch(/^[A-Z].*\.$/);
  const all = [...lines, ...doesNotProve].join(" ");
  for (const re of FORBIDDEN) {
    if (re.source.includes("guarantee")) expect(all.replace(/not a guarantee/g, "")).not.toMatch(re);
    else expect(all).not.toMatch(re);
  }
  expect(doesNotProve).toContain("It says nothing about who made the items.");
  expect(doesNotProve.some((l) => l.startsWith("It does not show that the items are good"))).toBe(true);
}

describe("the words, in both voices", () => {
  test("the plan's example, for the approver before signing: checked, drawn, all meet, the plan, the bound, not a guarantee", () => {
    const b = receiptOf(asker, approver, bigBatch([]), "ab".repeat(32));
    const w = batchWords(b, { asker: "Acme", voice: "approver" });
    standard(w.lines, w.doesNotProve);
    expect(w.lines[0]).toBe("You checked 300 of the 10,000 items in Acme's batch.");
    expect(w.lines[1]).toBe("They were chosen by Bitcoin block 977713, mined after the batch was fixed, so neither you nor Acme picked them.");
    expect(w.lines[2]).toBe("All 300 meet the agreed words.");
    const limit = limitOf({ size: 10_000, sample: 300, accept: 0, alpha: { num: 1, den: 20 } });
    expect(w.lines).toContain(`The plan: check 300, and accept the batch only if none fall short. If more than ${grouped(limit)} of the 10,000 fell short, this plan would pass the batch at most 1 time in 20.`);
    expect(w.lines).toContain(`If more than ${grouped(limit)} of the 10,000 fell short, a draw of 300 as clean as this one would come up at most 1 time in 20.`);
    expect(w.lines).toContain("This is not a guarantee: the other 9,700 items were not seen.");
  });

  test("for anyone reading the record: the approver, named as a role; the asker unnamed unless given", () => {
    const w = batchWords(receiptOf(asker, approver, bigBatch([]), "ab".repeat(32)));
    standard(w.lines, w.doesNotProve);
    expect(w.lines[0]).toBe("The approver checked 300 of the 10,000 items in the asker's batch.");
    expect(w.lines[1]).toContain("so neither side picked them");
  });

  test("short items within the plan: counted, and the acceptance does not cover them", () => {
    const b = receiptOf(asker, approver, bigBatch([4, 9], 3), "ab".repeat(32));
    const w = batchWords(b, { asker: "Acme", voice: "approver" });
    standard(w.lines, w.doesNotProve);
    expect(w.lines).toContain("2 of the 300 fall short of the agreed words; the plan accepts up to 3.");
    expect(w.lines).toContain("Your acceptance does not cover those 2.");
    expect(w.lines.some((l) => l.includes("with 2 or fewer short would come up at most 1 time in 20"))).toBe(true);
  });

  test("over the plan: only not yet, the reason only to the asker, and a new draw needs a new batch", () => {
    const b: AttestationBody = { ...receiptOf(asker, approver, bigBatch([1, 2, 3]), "ab".repeat(32)), outcome: "not-yet", reasons: [OVER_PLAN_REASON] };
    const w = batchWords(b, { asker: "Acme", voice: "approver" });
    standard(w.lines, w.doesNotProve);
    expect(w.lines).toContain("3 of the 300 fall short of the agreed words; the plan accepts none, so the batch can only be answered not yet.");
    expect(w.lines).toContain("Tell Acme what to change — only Acme will see it. A new draw needs a new batch.");
  });

  test("a not yet within the plan is the approver's own answer", () => {
    const b: AttestationBody = { ...receiptOf(asker, approver, bigBatch([]), "ab".repeat(32)), outcome: "not-yet", reasons: ["wrong-dialect"] };
    expect(batchWords(b).lines).toContain("The approver answered not yet.");
  });

  test("a census: every one, and nothing more than what was seen", async () => {
    const seal: BatchSeal = { format: "kash-batch-seal/1", root: sb.seal.root, size: 40, plan: { sample: 40, accept: 0, alpha: { num: 1, den: 20 }, limit: 0 } };
    const w = batchWords(receiptOf(asker, approver, { seal, found: [], bound: 0 }, "ab".repeat(32)), { asker: "Acme", voice: "approver" });
    standard(w.lines, w.doesNotProve);
    expect(w.lines[0]).toBe("You checked every one of the 40 items in Acme's batch.");
    expect(w.lines).toContain("All 40 meet the agreed words.");
    expect(w.lines).toContain("This says what was seen in these 40 items, and nothing more.");
    expect(w.lines.join(" ")).not.toMatch(/Bitcoin|times? in/);
  });

  test("a new draw says so", async () => {
    const again = await sampledBatch({ previous: "fe".repeat(32) });
    const w = batchWords(receiptOf(asker, approver, batchOf(again, []), again.sealDigest));
    expect(w.lines).toContain("This is a new draw: these items were sealed once before (seal fefefefefefe…).");
  });

  test("numbers group the same in every locale; a chance reads as times in so many", () => {
    expect(grouped(0)).toBe("0");
    expect(grouped(999)).toBe("999");
    expect(grouped(1000)).toBe("1,000");
    expect(grouped(1_000_000)).toBe("1,000,000");
    expect(chanceWords({ num: 1, den: 20 })).toBe("1 time in 20");
    expect(chanceWords({ num: 3, den: 1000 })).toBe("3 times in 1,000");
  });

  test("the words name no person and no key — the asker only as the screen names them", () => {
    const w = batchWords(receiptOf(asker, approver, bigBatch([]), "ab".repeat(32)), { asker: "Acme" });
    const all = [...w.lines, ...w.doesNotProve].join(" ");
    expect(all).not.toContain(asker.did);
    expect(all).not.toContain(approver.did);
  });
});
