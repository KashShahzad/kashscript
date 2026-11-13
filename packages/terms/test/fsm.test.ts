/**
 * fsm.test.ts — the core lifecycle: commit, deliver, confirm, time out,
 * dispute, and a subscription cycle.
 */

import { expect, test } from "bun:test";

import { TermsError } from "../src/errors";
import { isSignalAccepting, stateGroup, transition, type FsmContext, type FsmEvent } from "../src/fsm";
import { STATES } from "../src/types";

const base: FsmContext = {
  blueprint: "otdc",
  now: 100,
  softTimeoutAt: 1_000,
  hardTimeoutAt: 2_000,
  disputeTimeoutAt: 3_000,
  validation: { classThresholds: { 1: 1, 2: 0, 3: 0 }, priorityClasses: [1], threshold: 1 },
  acceptCount: { 1: 0, 2: 0, 3: 0 },
  rejectCount: { 1: 0, 2: 0, 3: 0 },
};

const DID_A = ("0x" + "a1".repeat(32)) as `0x${string}`;
const accept = (period = 0): FsmEvent => ({ t: "submitTruthSignal", priorityClass: 1, verdict: "accept", didCommitment: DID_A, period });
const reject = (period = 0): FsmEvent => ({ t: "submitTruthSignal", priorityClass: 1, verdict: "reject", didCommitment: DID_A, period });

/* ── otdc: the happy path ── */

test("otdc: Drafted → Committed → Active → Resolved, declaring the shares", () => {
  const committed = transition("Drafted", { t: "commit" }, base);
  expect(committed.nextState).toBe("Committed");
  expect(committed.effects).toEqual([{ kind: "committed", at: 100 }]);

  const active = transition("Committed", { t: "commitDelivery", deliveryClaim: "0x00" }, base);
  expect(active.nextState).toBe("Active");

  const resolved = transition("Active", accept(), base);
  expect(resolved.nextState).toBe("Resolved");
  expect(resolved.effects).toEqual([{ kind: "sharesDeclared" }]);
});

test("otdc: a rejecting confirmation opens a dispute", () => {
  const r = transition("Active", reject(), base);
  expect(r.nextState).toBe("Disputed");
  expect(r.effects).toEqual([{ kind: "disputeOpened", at: 100 }]);
});

test("otdc: commitDelivery needs Committed; commit needs Drafted", () => {
  expect(() => transition("Drafted", { t: "commitDelivery", deliveryClaim: "0x00" }, base)).toThrow(TermsError);
  expect(() => transition("Committed", { t: "commit" }, base)).toThrow(TermsError);
});

/* ── cancel, timeout, lockout ── */

test("cancelDraft voids the shares", () => {
  const r = transition("Drafted", { t: "cancelDraft" }, base);
  expect(r.nextState).toBe("Reverted");
  expect(r.effects).toEqual([{ kind: "sharesVoided" }]);
});

test("timeout: Committed → Lockout after the soft timeout, → Reverted after the hard one", () => {
  expect(() => transition("Committed", { t: "revertOnTimeout" }, base)).toThrow(TermsError); // too early
  const lock = transition("Committed", { t: "revertOnTimeout" }, { ...base, now: 1_001 });
  expect(lock.nextState).toBe("Lockout");
  expect(() => transition("Lockout", { t: "revertOnTimeout" }, { ...base, now: 1_500 })).toThrow(TermsError);
  const reverted = transition("Lockout", { t: "revertOnTimeout" }, { ...base, now: 2_000 });
  expect(reverted.nextState).toBe("Reverted");
  expect(reverted.effects).toEqual([{ kind: "sharesVoided" }]);
});

test("Lockout permits only revertOnTimeout; terminal states permit nothing", () => {
  expect(() => transition("Lockout", accept(), { ...base, now: 1_500 })).toThrow(TermsError);
  for (const s of ["Resolved", "Reverted", "Cancelled"] as const) {
    expect(() => transition(s, { t: "commit" }, base)).toThrow(TermsError);
  }
});

/* ── confirmation guards ── */

test("a signal after the soft timeout, or a replayed attestor, is rejected", () => {
  expect(() => transition("Active", accept(), { ...base, now: 1_001 })).toThrow(TermsError);
  const seen = new Map([[0, new Set([DID_A])]]);
  expect(() => transition("Active", accept(), { ...base, seenAttestorsByPeriod: seen })).toThrow(TermsError);
});

test("two-of-three: one accept lingers in Resolving, the second resolves", () => {
  const ctx: FsmContext = { ...base, validation: { classThresholds: { 1: 2, 2: 0, 3: 0 }, priorityClasses: [1, 1, 1], threshold: 2 } };
  const first = transition("Active", accept(), ctx);
  expect(first.nextState).toBe("Resolving");
  const second = transition("Resolving", accept(), { ...ctx, acceptCount: { 1: 1, 2: 0, 3: 0 }, seenAttestorsByPeriod: new Map([[0, new Set([("0x" + "b2".repeat(32)) as `0x${string}`])]]) });
  expect(second.nextState).toBe("Resolved");
});

/* ── disputes ── */

test("openDispute: Resolving → Disputed, once", () => {
  const r = transition("Resolving", { t: "openDispute" }, base);
  expect(r.nextState).toBe("Disputed");
  expect(() => transition("Resolving", { t: "openDispute" }, { ...base, openDisputeAt: 90 })).toThrow(TermsError);
  expect(() => transition("Active", { t: "openDispute" }, base)).toThrow(TermsError);
});

test("an arbitrator can declare the shares, or void them; a dispute can time out", () => {
  expect(transition("Disputed", { t: "arbitratorSettle" }, base).effects).toEqual([{ kind: "sharesDeclared" }]);
  const voided = transition("Disputed", { t: "arbitratorVoid" }, base);
  expect(voided.nextState).toBe("Reverted");
  expect(voided.effects).toEqual([{ kind: "sharesVoided" }]);
  expect(() => transition("Disputed", { t: "revertOnDisputeTimeout" }, base)).toThrow(TermsError);
  expect(transition("Disputed", { t: "revertOnDisputeTimeout" }, { ...base, now: 3_000 }).nextState).toBe("Reverted");
});

/* ── subscription: a pass ── */

const sub: FsmContext = { ...base, blueprint: "subscription", currentPeriod: 0, maxPeriods: 3 };

test("subscription: a cycle runs Committed → Period_Active → Period_Resolved → Period_Active", () => {
  const tick = transition("Committed", { t: "periodTick" }, sub);
  expect(tick.nextState).toBe("Period_Active");
  expect(tick.periodAdvance).toBe(true);

  const done = transition("Period_Active", accept(0), sub);
  expect(done.nextState).toBe("Period_Resolved");
  expect(done.effects).toEqual([{ kind: "sharesDeclared" }]);

  const next = transition("Period_Resolved", { t: "periodTick" }, { ...sub, currentPeriod: 1 });
  expect(next.nextState).toBe("Period_Active");
});

test("subscription: the last tick resolves the pass; a wrong-period signal is rejected", () => {
  expect(transition("Period_Resolved", { t: "periodTick" }, { ...sub, currentPeriod: 2 }).nextState).toBe("Resolved");
  expect(() => transition("Period_Active", accept(1), sub)).toThrow(TermsError);
});

test("subscription: a timed-out period is voided and skipped, or cascades per policy", () => {
  const ctx: FsmContext = { ...sub, now: 2_000 };
  const skip = transition("Period_Active", { t: "periodRevertOnTimeout" }, ctx);
  expect(skip.nextState).toBe("Period_Active");
  expect(skip.effects).toEqual([{ kind: "sharesVoided" }]);
  const cascade = transition("Period_Active", { t: "periodRevertOnTimeout" }, { ...ctx, periodRevertPolicy: "cascade-revert" });
  expect(cascade.nextState).toBe("Cancelled");
  const nth = transition("Period_Active", { t: "periodRevertOnTimeout" }, { ...ctx, periodRevertPolicy: "cascade-on-N-failures", sequentialFailedPeriods: 1, maxSequentialFailedPeriods: 2 });
  expect(nth.nextState).toBe("Cancelled");
});

test("subscription: cancelling voids the shares; it is subscription-only", () => {
  const r = transition("Period_Active", { t: "cancelSubscription" }, sub);
  expect(r.nextState).toBe("Cancelled");
  expect(r.effects).toEqual([{ kind: "sharesVoided" }]);
  expect(() => transition("Active", { t: "cancelSubscription" }, base)).toThrow(TermsError);
});

/* ── helpers ── */

test("stateGroup is total over STATES; isSignalAccepting covers the signalling states", () => {
  for (const s of STATES) expect(typeof stateGroup(s)).toBe("string");
  expect(stateGroup("Committed")).toBe("committed");
  expect(stateGroup("Cancelled")).toBe("reverted");
  expect(STATES.filter(isSignalAccepting)).toEqual(["Active", "Period_Active", "Resolving", "Period_Resolving"]);
});
