/**
 * graded-dispute.test.ts — a partly upheld dispute: dust-free graded splits,
 * the binary-generalisation property, and the FSM transition.
 */

import { expect, test } from "bun:test";

import { deriveDid, generateKeyPair } from "@kashscript/identity-core";

import { TermsError } from "../src/errors";
import { transition, type FsmContext } from "../src/fsm";
import { declaredGradedSplit, declaredSplit } from "../src/splitter";
import type { ShareLeg } from "../src/types";

const did = async () => deriveDid((await generateKeyPair()).publicKey);
const [A, B, BUYER] = [await did(), await did(), await did()];

const SPLITS: ShareLeg[] = [
  { did: A, bps: 7000 },
  { did: B, bps: 3000, sweepFinal: true },
];

/* ── dust-free closure ── */

test("graded splits are dust-free across 2000 random (bps, amount) pairs", () => {
  let seed = 0x1234_5678;
  const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  for (let i = 0; i < 2000; i++) {
    const providerBps = Math.floor(rnd() * 10_001); // 0..10000 inclusive
    const amount = BigInt(Math.floor(rnd() * 1e12)) + BigInt(Math.floor(rnd() * 7)); // include 1-unit residues
    const g = declaredGradedSplit(SPLITS, amount, providerBps, BUYER);
    const sum = g.providerLegs.reduce((s, l) => s + l.amount, 0n) + g.remainderAmount;
    expect(sum).toBe(amount);
    expect(g.total).toBe(amount);
    expect(g.providerAmount + g.remainderAmount).toBe(amount);
    expect(g.remainderLeg.amount).toBe(g.remainderAmount);
  }
});

/* ── generalises the binary outcomes ── */

test("providerBps = 10000 ≡ every share declared in full", () => {
  const amount = 1_000_003n;
  const g = declaredGradedSplit(SPLITS, amount, 10_000, BUYER);
  expect(g.remainderAmount).toBe(0n);
  const full = declaredSplit(SPLITS, amount);
  expect(g.providerLegs.map((l) => l.amount)).toEqual(full.legs.map((l) => l.amount));
});

test("providerBps = 0 ≡ every share void; the whole amount is the remainder", () => {
  const amount = 1_000_003n;
  const g = declaredGradedSplit(SPLITS, amount, 0, BUYER);
  expect(g.remainderAmount).toBe(amount);
  expect(g.providerLegs.every((l) => l.amount === 0n)).toBe(true);
});

test("a 70/30 split upholds 70% for the provider side and leaves 30% as the remainder", () => {
  const g = declaredGradedSplit(SPLITS, 1_000_000n, 7_000, BUYER);
  expect(g.providerAmount).toBe(700_000n);
  expect(g.remainderAmount).toBe(300_000n);
  expect(g.remainderLeg.did).toBe(BUYER);
});

test("declaredGradedSplit validates providerBps, the amount and the buyer", () => {
  expect(() => declaredGradedSplit(SPLITS, 100n, 10_001, BUYER)).toThrow(TermsError);
  expect(() => declaredGradedSplit(SPLITS, 100n, -1, BUYER)).toThrow(TermsError);
  expect(() => declaredGradedSplit(SPLITS, 100n, 50.5, BUYER)).toThrow(TermsError);
  expect(() => declaredGradedSplit(SPLITS, -1n, 5_000, BUYER)).toThrow(TermsError);
  expect(() => declaredGradedSplit(SPLITS, 100n, 5_000, "nope" as never)).toThrow(TermsError);
});

/* ── FSM transition ── */

const ctx: FsmContext = {
  blueprint: "otdc",
  now: 100,
  softTimeoutAt: 1_000,
  hardTimeoutAt: 2_000,
  disputeTimeoutAt: 3_000,
  validation: { classThresholds: { 1: 1, 2: 0, 3: 0 }, priorityClasses: [1], threshold: 1 },
  acceptCount: { 1: 0, 2: 0, 3: 0 },
  rejectCount: { 1: 0, 2: 0, 3: 0 },
};

test("graded arbitration: Disputed → Resolved, part declared and part void", () => {
  const r = transition("Disputed", { t: "arbitratorSplit", providerBps: 7_000 }, ctx);
  expect(r.nextState).toBe("Resolved");
  expect(r.effects.some((e) => e.kind === "sharesDeclared")).toBe(true);
  expect(r.effects.some((e) => e.kind === "sharesVoided")).toBe(true);
});

test("graded FSM generalises binary: 10000 → declared only, 0 → void only", () => {
  const full = transition("Disputed", { t: "arbitratorSplit", providerBps: 10_000 }, ctx);
  expect(full.effects.some((e) => e.kind === "sharesDeclared")).toBe(true);
  expect(full.effects.some((e) => e.kind === "sharesVoided")).toBe(false);
  const none = transition("Disputed", { t: "arbitratorSplit", providerBps: 0 }, ctx);
  expect(none.effects.some((e) => e.kind === "sharesVoided")).toBe(true);
  expect(none.effects.some((e) => e.kind === "sharesDeclared")).toBe(false);
});

test("graded arbitration requires Disputed and a valid providerBps", () => {
  expect(() => transition("Resolving", { t: "arbitratorSplit", providerBps: 5_000 }, ctx)).toThrow(TermsError);
  expect(() => transition("Disputed", { t: "arbitratorSplit", providerBps: 10_001 }, ctx)).toThrow(TermsError);
});
