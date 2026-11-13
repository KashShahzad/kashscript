/**
 * subscription-thread.test.ts — variable-amount subscriptions as linked OTDCs.
 */

import { expect, test } from "bun:test";

import { deriveDid, generateKeyPair } from "@kashscript/identity-core";

import { TermsError } from "../src/errors";
import type { ManifestId } from "../src/types";
import {
  THREAD_META_KEY,
  cycleLink,
  cycleMetadata,
  deriveThreadId,
  isThreadComplete,
  nextCycleDueAt,
  parseCycleLink,
  validateThreadSequence,
  type CycleLink,
  type SubscriptionThreadConfig,
  type ThreadId,
} from "../src/subscription-thread";

const sub = deriveDid((await generateKeyPair()).publicKey);
const prov = deriveDid((await generateKeyPair()).publicKey);

const CONFIG: SubscriptionThreadConfig = {
  subscriber: sub,
  provider: prov,
  cadenceSeconds: 86_400, // 1 day
  startAt: 1_000,
  maxCycles: 12,
  label: "gym-monthly",
};

const MID = (h: string) => (`kash-trade:0x${h.repeat(32)}`) as ManifestId;

/* ── thread id ── */

test("threadId is deterministic and content-addressed", async () => {
  const a = await deriveThreadId(CONFIG);
  const b = await deriveThreadId({ ...CONFIG });
  expect(a).toBe(b);
  expect(a.startsWith("kash-thread:0x")).toBe(true);
  expect(await deriveThreadId({ ...CONFIG, cadenceSeconds: 99 })).not.toBe(a);
});

test("thread config is validated", async () => {
  await expect(deriveThreadId({ ...CONFIG, cadenceSeconds: 0 })).rejects.toThrow(TermsError);
  await expect(deriveThreadId({ ...CONFIG, subscriber: "nope" as never })).rejects.toThrow(TermsError);
});

/* ── cadence ── */

test("cadence + completion helpers", () => {
  expect(nextCycleDueAt(CONFIG, 0)).toBe(1_000);
  expect(nextCycleDueAt(CONFIG, 3)).toBe(1_000 + 3 * 86_400);
  expect(isThreadComplete(CONFIG, 11)).toBe(false);
  expect(isThreadComplete(CONFIG, 12)).toBe(true);
});

/* ── cycle links (variable amount per cycle) ── */

test("cycle links carry a per-cycle amount and chain to the prior cycle", async () => {
  const threadId = await deriveThreadId(CONFIG);
  const c0 = cycleLink({ threadId, cycleIndex: 0, amount: "1000", dueAt: 1_000 });
  const c1 = cycleLink({ threadId, cycleIndex: 1, amount: "1500", dueAt: 87_400, prevCycleManifestId: MID("a") });
  expect(c0.amount).toBe("1000");
  expect(c1.amount).toBe("1500"); // different price next cycle
  expect(c1.prevCycleManifestId).toBe(MID("a"));
});

test("cycle-link validation: cycle 0 has no predecessor; later cycles must chain", async () => {
  const threadId = await deriveThreadId(CONFIG);
  expect(() => cycleLink({ threadId, cycleIndex: 0, amount: "1000", dueAt: 1_000, prevCycleManifestId: MID("a") })).toThrow(TermsError);
  expect(() => cycleLink({ threadId, cycleIndex: 1, amount: "1000", dueAt: 1_000 })).toThrow(TermsError); // missing prev
  expect(() => cycleLink({ threadId, cycleIndex: 1, amount: "-5", dueAt: 1_000, prevCycleManifestId: MID("a") })).toThrow(TermsError);
  expect(() => cycleLink({ threadId, cycleIndex: -1, amount: "1000", dueAt: 1_000 })).toThrow(TermsError);
});

/* ── metadata round-trip ── */

test("cycle link round-trips through manifest metadata", async () => {
  const threadId = await deriveThreadId(CONFIG);
  const link = cycleLink({ threadId, cycleIndex: 0, amount: "1000", dueAt: 1_000 });
  const meta = cycleMetadata(link);
  expect(meta[THREAD_META_KEY]).toEqual(link);
  expect(parseCycleLink(meta)).toEqual(link);
  expect(parseCycleLink({})).toBeNull();
  expect(parseCycleLink({ [THREAD_META_KEY]: { kind: "x" } })).toBeNull();
});

/* ── sequence coherence ── */

test("validateThreadSequence accepts a contiguous chained thread", async () => {
  const threadId = await deriveThreadId(CONFIG);
  const links: CycleLink[] = [
    cycleLink({ threadId, cycleIndex: 0, amount: "1000", dueAt: 1_000 }),
    cycleLink({ threadId, cycleIndex: 1, amount: "1500", dueAt: 87_400, prevCycleManifestId: MID("a") }),
    cycleLink({ threadId, cycleIndex: 2, amount: "1200", dueAt: 173_800, prevCycleManifestId: MID("b") }),
  ];
  expect(() => validateThreadSequence(threadId, links, CONFIG)).not.toThrow();
});

test("validateThreadSequence rejects gaps, duplicates, foreign threads, and regressing due times", async () => {
  const threadId = await deriveThreadId(CONFIG);
  const other = "kash-thread:0x" + "ff".repeat(32) as ThreadId;
  const c0 = cycleLink({ threadId, cycleIndex: 0, amount: "1000", dueAt: 1_000 });
  const c2 = cycleLink({ threadId, cycleIndex: 2, amount: "1000", dueAt: 9_000, prevCycleManifestId: MID("b") });
  expect(() => validateThreadSequence(threadId, [c0, c2])).toThrow(TermsError); // gap (missing 1)
  expect(() => validateThreadSequence(threadId, [c0, c0])).toThrow(TermsError); // duplicate index 0
  const foreign = cycleLink({ threadId: other, cycleIndex: 1, amount: "1000", dueAt: 2_000, prevCycleManifestId: MID("a") });
  expect(() => validateThreadSequence(threadId, [c0, foreign])).toThrow(TermsError); // foreign thread
  const regress = cycleLink({ threadId, cycleIndex: 1, amount: "1000", dueAt: 500, prevCycleManifestId: MID("a") });
  expect(() => validateThreadSequence(threadId, [c0, regress])).toThrow(TermsError); // dueAt regresses
});

test("validateThreadSequence enforces maxCycles", async () => {
  const threadId = await deriveThreadId({ ...CONFIG, maxCycles: 2 });
  const links: CycleLink[] = [
    cycleLink({ threadId, cycleIndex: 0, amount: "1", dueAt: 1 }),
    cycleLink({ threadId, cycleIndex: 1, amount: "1", dueAt: 2, prevCycleManifestId: MID("a") }),
    cycleLink({ threadId, cycleIndex: 2, amount: "1", dueAt: 3, prevCycleManifestId: MID("b") }),
  ];
  expect(() => validateThreadSequence(threadId, links, { ...CONFIG, maxCycles: 2 })).toThrow(TermsError);
});

/* ── time is Unix seconds ── */

test("instants must be Unix seconds — a millisecond value is refused", async () => {
  const ms = 1_760_000_000_000;
  await expect(deriveThreadId({ ...CONFIG, startAt: ms })).rejects.toThrow(TermsError);
  const threadId = await deriveThreadId(CONFIG);
  expect(() => cycleLink({ threadId, cycleIndex: 0, amount: "1", dueAt: ms })).toThrow(TermsError);
});

test("a calendar-month pass uses explicit due times, not the fixed cadence", async () => {
  const threadId = await deriveThreadId(CONFIG);
  // 1 Jan, 1 Feb and 1 Mar 2026 (UTC). Months differ in length, so no fixed cadence fits them.
  const jan = 1_767_225_600;
  const feb = 1_769_904_000;
  const mar = 1_772_323_200;
  expect(feb - jan).not.toBe(mar - feb);
  const links: CycleLink[] = [
    cycleLink({ threadId, cycleIndex: 0, amount: "1000", dueAt: jan }),
    cycleLink({ threadId, cycleIndex: 1, amount: "1000", dueAt: feb, prevCycleManifestId: MID("a") }),
    cycleLink({ threadId, cycleIndex: 2, amount: "1000", dueAt: mar, prevCycleManifestId: MID("b") }),
  ];
  expect(() => validateThreadSequence(threadId, links)).not.toThrow();
});
