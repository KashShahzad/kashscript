/**
 * vocabulary.test.ts — the package's rules, kept true by a test.
 *
 *   1. src/ never uses the vocabulary of held money, scoring or chains, and
 *      never counts time in blocks.
 *   2. No state names a person.
 *   3. No state holds a balance: nothing the machine takes or returns is an amount.
 *
 * (This file lives in test/, outside the src/ the first rule reads.)
 */

import { expect, test } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { transition, type FsmContext, type FsmEvent } from "../src/fsm";
import { STATES, type BlueprintType } from "../src/types";

/* ── 1. the words ── */

const SRC = join(import.meta.dir, "..", "src");
const BANNED = /trust|reputation|escrow|refund|onchain|oracle/i;

test("src/ contains none of: trust, reputation, escrow, refund, onchain, oracle", () => {
  const files = readdirSync(SRC).filter((f) => f.endsWith(".ts"));
  expect(files.length).toBeGreaterThan(0);
  const hits: string[] = [];
  for (const f of files) {
    readFileSync(join(SRC, f), "utf-8").split("\n").forEach((line, i) => {
      if (BANNED.test(line)) hits.push(`${f}:${i + 1}: ${line.trim()}`);
    });
  }
  expect(hits).toEqual([]);
});

test("src/ speaks of time in Unix seconds, never of blocks", () => {
  const hits: string[] = [];
  for (const f of readdirSync(SRC).filter((f) => f.endsWith(".ts"))) {
    readFileSync(join(SRC, f), "utf-8").split("\n").forEach((line, i) => {
      if (/block/i.test(line)) hits.push(`${f}:${i + 1}: ${line.trim()}`);
    });
  }
  expect(hits).toEqual([]);
});

/* ── 2. states describe the agreement, never the person ── */

const PERSON_LABELS = /default|delinquen|deadbeat|fraud|scam|bad|blacklist|offender|debtor|cheat|unreliable|risky|score|rank/i;

test("no state labels a person", () => {
  expect(STATES.length).toBeGreaterThan(0);
  for (const s of STATES) expect(PERSON_LABELS.test(s)).toBe(false);
});

/* ── 3. no state holds a balance ── */

const CLAIM = "0x00" as const;
const COMMITMENT = ("0x" + "a1".repeat(32)) as `0x${string}`;

/** One sample of every event kind; the Record type makes this exhaustive. */
const SAMPLE: Record<FsmEvent["t"], FsmEvent> = {
  commit:                  { t: "commit" },
  cancelDraft:             { t: "cancelDraft" },
  commitDelivery:          { t: "commitDelivery", deliveryClaim: CLAIM },
  submitTruthSignal:       { t: "submitTruthSignal", priorityClass: 1, verdict: "accept", didCommitment: COMMITMENT, period: 0 },
  openDispute:             { t: "openDispute" },
  arbitratorSettle:        { t: "arbitratorSettle" },
  arbitratorVoid:          { t: "arbitratorVoid" },
  arbitratorSplit:         { t: "arbitratorSplit", providerBps: 6_000 },
  revertOnTimeout:         { t: "revertOnTimeout" },
  revertOnDisputeTimeout:  { t: "revertOnDisputeTimeout" },
  periodTick:              { t: "periodTick" },
  periodRevertOnTimeout:   { t: "periodRevertOnTimeout" },
  cancelSubscription:      { t: "cancelSubscription" },
  releaseMilestone:        { t: "releaseMilestone", index: 0, deliveryClaim: CLAIM },
  disputeMilestone:        { t: "disputeMilestone", index: 0 },
  resolveMilestoneDispute: { t: "resolveMilestoneDispute", index: 0, favorConsumer: false },
  finalizeMilestone:       { t: "finalizeMilestone" },
};

const BLUEPRINTS: readonly BlueprintType[] = ["otdc", "subscription", "milestone"];

const ctxFor = (blueprint: BlueprintType): FsmContext => ({
  blueprint,
  now: 5_000,                       // past every timeout, so timeout events fire too
  softTimeoutAt: 1_000,
  hardTimeoutAt: 2_000,
  disputeTimeoutAt: 3_000,
  validation: { classThresholds: { 1: 1, 2: 0, 3: 0 }, priorityClasses: [1], threshold: 1 },
  acceptCount: { 1: 0, 2: 0, 3: 0 },
  rejectCount: { 1: 0, 2: 0, 3: 0 },
  currentPeriod: 0,
  maxPeriods: 3,
  totalSteps: 2,
  disputedSteps: new Set([0]),
  resolvedSteps: new Set([0, 1]),
});

const holdsBigint = (v: unknown): boolean => {
  if (typeof v === "bigint") return true;
  if (v && typeof v === "object") return Object.values(v).some(holdsBigint);
  return false;
};

test("no event carries an amount, and no transition result holds one", () => {
  let fired = 0;
  for (const event of Object.values(SAMPLE)) expect(holdsBigint(event)).toBe(false);
  for (const blueprint of BLUEPRINTS) {
    const ctx = ctxFor(blueprint);
    for (const state of STATES) {
      for (const event of Object.values(SAMPLE)) {
        let result;
        try { result = transition(state, event, ctx); } catch { continue; } // illegal here — fine
        fired++;
        expect(holdsBigint(result)).toBe(false);
        expect(STATES).toContain(result.nextState);
      }
    }
  }
  expect(fired).toBeGreaterThan(20); // the sweep reached real transitions, not just errors
});
