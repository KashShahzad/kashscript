/**
 * fsm.milestone.test.ts — milestone lifecycle + per-step dispute isolation.
 */

import { expect, test } from "bun:test";

import { TermsError } from "../src/errors";
import { transition, type FsmContext } from "../src/fsm";

const base: FsmContext = {
  blueprint: "milestone",
  now: 100,
  softTimeoutAt: 1_000,
  hardTimeoutAt: 2_000,
  disputeTimeoutAt: 3_000,
  validation: { classThresholds: { 1: 1, 2: 0, 3: 0 }, priorityClasses: [1], threshold: 1 },
  acceptCount: { 1: 0, 2: 0, 3: 0 },
  rejectCount: { 1: 0, 2: 0, 3: 0 },
  totalSteps: 3,
};

const CLAIM = "0x00" as const;

test("milestone: commit moves a draft to Committed", () => {
  expect(transition("Drafted", { t: "commit" }, base).nextState).toBe("Committed");
});

test("milestone: releasing steps keeps it Active until finalize", () => {
  expect(
    transition("Committed", { t: "releaseMilestone", index: 0, deliveryClaim: CLAIM }, base).nextState,
  ).toBe("Active");
  expect(
    transition(
      "Active",
      { t: "releaseMilestone", index: 1, deliveryClaim: CLAIM },
      { ...base, resolvedSteps: new Set([0]) },
    ).nextState,
  ).toBe("Active");
});

test("milestone: a release declares the shares", () => {
  const r = transition("Committed", { t: "releaseMilestone", index: 0, deliveryClaim: CLAIM }, base);
  expect(r.effects.some((e) => e.kind === "sharesDeclared")).toBe(true);
});

test("milestone: double-resolving a step is rejected", () => {
  expect(() =>
    transition(
      "Active",
      { t: "releaseMilestone", index: 0, deliveryClaim: CLAIM },
      { ...base, resolvedSteps: new Set([0]) },
    ),
  ).toThrow(TermsError);
});

test("milestone: out-of-range step index is rejected", () => {
  expect(() =>
    transition("Committed", { t: "releaseMilestone", index: 5, deliveryClaim: CLAIM }, base),
  ).toThrow(TermsError);
});

test("milestone: per-step dispute does not change the global state", () => {
  const r = transition("Active", { t: "disputeMilestone", index: 1 }, { ...base, resolvedSteps: new Set([0]) });
  expect(r.nextState).toBe("Active");
});

test("milestone: releasing a disputed step is blocked until resolved", () => {
  expect(() =>
    transition(
      "Active",
      { t: "releaseMilestone", index: 1, deliveryClaim: CLAIM },
      { ...base, disputedSteps: new Set([1]) },
    ),
  ).toThrow(TermsError);
});

test("milestone: resolving a disputed step (favor consumer) voids its shares and stays Active", () => {
  const r = transition(
    "Active",
    { t: "resolveMilestoneDispute", index: 1, favorConsumer: true },
    { ...base, disputedSteps: new Set([1]) },
  );
  expect(r.nextState).toBe("Active");
  expect(r.effects.some((e) => e.kind === "sharesVoided")).toBe(true);
});

test("milestone: finalize requires every step resolved", () => {
  expect(() =>
    transition("Active", { t: "finalizeMilestone" }, { ...base, resolvedSteps: new Set([0, 1]) }),
  ).toThrow(TermsError);
  const r = transition("Active", { t: "finalizeMilestone" }, { ...base, resolvedSteps: new Set([0, 1, 2]) });
  expect(r.nextState).toBe("Resolved");
});

test("milestone: milestone events are rejected for non-milestone blueprints", () => {
  expect(() =>
    transition("Committed", { t: "releaseMilestone", index: 0, deliveryClaim: CLAIM }, { ...base, blueprint: "otdc" }),
  ).toThrow(TermsError);
});
