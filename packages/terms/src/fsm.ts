/**
 * The agreement state machine — a pure function from (state, event, context)
 * to the next state. NO I/O. NO side effects. Deterministic.
 *
 * A state is a stage of the AGREEMENT. It never labels a person, and it never
 * holds a balance: no event, context field or result carries an amount.
 * Effects are declarations for the caller to act on — `sharesDeclared` means
 * "declare the split in the book", `sharesVoided` means "nothing is owed". The
 * machine moves nothing.
 *
 * Every blueprint walks a subgraph of the same transition table. The blueprint
 * discriminator and the current state determine which events are legal next:
 *
 *   otdc          : Drafted → Committed → Active → Resolving → Resolved | Reverted | Disputed
 *   subscription  : Drafted → Committed → Period_Active → Period_Resolving →
 *                   Period_Resolved → Period_Active (cycle) | Cancelled
 *   milestone     : Drafted → Committed → Active (steps released or voided one
 *                   by one) → Resolved
 */

import { fail } from "./errors";
import {
  BPS_TOTAL,
  TERMINAL_STATES,
  type BlueprintType,
  type PriorityClass,
  type UniversalState,
  type ValidationPolicy,
  type Verdict,
} from "./types";

/* ─────────────────────────────────────────────────────────────────
 *  Event vocabulary
 * ───────────────────────────────────────────────────────────────── */

export type FsmEvent =
  | { readonly t: "commit" }
  | { readonly t: "cancelDraft" }
  | { readonly t: "commitDelivery";         readonly deliveryClaim: `0x${string}` }
  | { readonly t: "submitTruthSignal";      readonly priorityClass: PriorityClass; readonly verdict: Verdict; readonly didCommitment: `0x${string}`; readonly period: number }
  | { readonly t: "openDispute" }
  | { readonly t: "arbitratorSettle" }
  | { readonly t: "arbitratorVoid" }
  | { readonly t: "arbitratorSplit";        readonly providerBps: number }  // graded resolution
  | { readonly t: "revertOnTimeout" }
  | { readonly t: "revertOnDisputeTimeout" }
  | { readonly t: "periodTick" }                                           // Subscription cycle
  | { readonly t: "periodRevertOnTimeout" }                                // per-period revert
  | { readonly t: "cancelSubscription" }                                   // Subscription
  | { readonly t: "releaseMilestone";        readonly index: number; readonly deliveryClaim: `0x${string}` }  // Milestone
  | { readonly t: "disputeMilestone";        readonly index: number }                                         // Milestone (per-step)
  | { readonly t: "resolveMilestoneDispute"; readonly index: number; readonly favorConsumer: boolean }        // Milestone (per-step)
  | { readonly t: "finalizeMilestone" };                                   // Milestone

/* ─────────────────────────────────────────────────────────────────
 *  Per-instance context the transition function reads.
 * ───────────────────────────────────────────────────────────────── */

export interface FsmContext {
  readonly blueprint: BlueprintType;
  /** The caller's current time, in Unix seconds. Nothing in this package reads a clock. */
  readonly now: number;
  readonly softTimeoutAt: number;
  readonly hardTimeoutAt: number;
  readonly disputeTimeoutAt: number;
  /** Set ONCE when a dispute opens. Drives the dispute timeout. */
  readonly openDisputeAt?: number | null;
  readonly validation: ValidationPolicy;
  /** Running tallies. Maps class → count. */
  readonly acceptCount: Readonly<Record<PriorityClass, number>>;
  readonly rejectCount: Readonly<Record<PriorityClass, number>>;
  /** For Subscription instances: which period are we in (0-indexed). */
  readonly currentPeriod?: number;
  readonly maxPeriods?: number;
  /**
   * Per-period replay key. The outer Map's key is the period index; the inner
   * Set holds attestor `didCommitment`s already seen FOR THAT PERIOD. For
   * non-recurring blueprints, the period is always `0` and the Map has at most
   * one entry.
   */
  readonly seenAttestorsByPeriod?: ReadonlyMap<number, ReadonlySet<`0x${string}`>>;
  /**
   * How many CONSECUTIVE periods have failed quorum + timed out.
   * Subscription-only. Drives the `cascade-on-N-failures` policy.
   */
  readonly sequentialFailedPeriods?: number;
  readonly maxSequentialFailedPeriods?: number;
  readonly periodRevertPolicy?: SubscriptionPeriodRevertPolicy;
  /* ── Milestone-only ── */
  /** Total number of milestone steps in the schedule. */
  readonly totalSteps?: number;
  /** Step indices already released OR voided (terminal per-step). */
  readonly resolvedSteps?: ReadonlySet<number>;
  /** Step indices with an open dispute (not yet resolved). */
  readonly disputedSteps?: ReadonlySet<number>;
}

export type SubscriptionPeriodRevertPolicy =
  | "skip-and-continue"
  | "cascade-revert"
  | "cascade-on-N-failures";

export interface FsmTransitionResult {
  readonly nextState: UniversalState;
  /** Declarations for the caller to act on. */
  readonly effects: readonly FsmEffect[];
  /** Updated tally / counter deltas. Empty when transition does not touch tallies. */
  readonly tallyDelta?: { readonly class: PriorityClass; readonly verdict: Verdict };
  readonly periodAdvance?: boolean;
}

export type FsmEffect =
  /** The parties committed at this instant (Unix seconds). */
  | { readonly kind: "committed";      readonly at: number }
  /** A dispute opened at this instant (Unix seconds). */
  | { readonly kind: "disputeOpened";  readonly at: number }
  /** Declare the split in the book. */
  | { readonly kind: "sharesDeclared" }
  /** The split does not apply; nothing is owed. */
  | { readonly kind: "sharesVoided" };

/* ─────────────────────────────────────────────────────────────────
 *  The transition function.
 * ─────────────────────────────────────────────────────────────────
 *
 * Pure: (state, event, ctx) → result | TermsError.
 */

export function transition(
  state: UniversalState,
  event: FsmEvent,
  ctx: FsmContext,
): FsmTransitionResult {
  // Terminal states never transition.
  if (TERMINAL_STATES.has(state)) {
    fail("WRONG_STATE", `State ${state} is terminal; no transitions out.`);
  }

  // Lockout-deadband guard.
  if (state === "Lockout") {
    if (event.t !== "revertOnTimeout") {
      fail("STALE_AFTER_SOFT_TIMEOUT", `Inside Lockout, only revertOnTimeout is permitted (got "${event.t}").`);
    }
    return revertOnTimeoutFromLockout(ctx);
  }

  switch (event.t) {
    case "commit":                  return T1_commit(state, ctx);
    case "cancelDraft":             return T2_cancelDraft(state);
    case "commitDelivery":          return T3_commitDelivery(state);
    case "submitTruthSignal":       return T5_or_T11_submitTruthSignal(state, event, ctx);
    case "openDispute":             return T7_openDispute(state, ctx);
    case "arbitratorSettle":        return T8_arbitratorSettle(state);
    case "arbitratorSplit":         return T8b_arbitratorSplit(state, event);
    case "arbitratorVoid":          return T9_arbitratorVoid(state);
    case "revertOnTimeout":         return T6_revertOnTimeout(state, ctx);
    case "revertOnDisputeTimeout":  return T10_revertOnDisputeTimeout(state, ctx);
    case "periodTick":              return Subscription_periodTick(state, ctx);
    case "periodRevertOnTimeout":   return Subscription_periodRevertOnTimeout(state, ctx);
    case "cancelSubscription":      return Subscription_cancel(state, ctx);
    case "releaseMilestone":        return Milestone_release(state, event, ctx);
    case "disputeMilestone":        return Milestone_dispute(state, event, ctx);
    case "resolveMilestoneDispute": return Milestone_resolveDispute(state, event, ctx);
    case "finalizeMilestone":       return Milestone_finalize(state, ctx);
  }
}

/* ─────────────────────────────────────────────────────────────────
 *  T1 — Drafted → Committed
 * ───────────────────────────────────────────────────────────────── */

function T1_commit(state: UniversalState, ctx: FsmContext): FsmTransitionResult {
  if (state !== "Drafted") {
    fail("WRONG_STATE", `T1 requires state=Drafted, got ${state}.`);
  }
  return {
    nextState: "Committed",
    effects: [{ kind: "committed", at: ctx.now }],
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  T2 — Drafted → Reverted (the buyer's cancelDraft)
 * ───────────────────────────────────────────────────────────────── */

function T2_cancelDraft(state: UniversalState): FsmTransitionResult {
  if (state !== "Drafted") {
    fail("WRONG_STATE", `T2 requires state=Drafted, got ${state}.`);
  }
  return {
    nextState: "Reverted",
    effects: [{ kind: "sharesVoided" }],
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  T3 — Committed → Active (the seller's commitDelivery)
 * ───────────────────────────────────────────────────────────────── */

function T3_commitDelivery(state: UniversalState): FsmTransitionResult {
  if (state !== "Committed") {
    fail("WRONG_STATE", `T3 requires state=Committed, got ${state}.`);
  }
  return { nextState: "Active", effects: [] };
}

/* ─────────────────────────────────────────────────────────────────
 *  T5 / T11 — Resolving → Resolved | Disputed by the resolution algebra
 * ───────────────────────────────────────────────────────────────── */

function T5_or_T11_submitTruthSignal(
  state: UniversalState,
  event: Extract<FsmEvent, { t: "submitTruthSignal" }>,
  ctx: FsmContext,
): FsmTransitionResult {
  // The FIRST signal advances Active → Resolving (T4 implicit).
  let workingState: UniversalState = state;
  if (state === "Active" || state === "Period_Active") workingState = "Resolving";
  if (workingState !== "Resolving" && workingState !== "Period_Resolving") {
    fail("SIGNAL_TOO_EARLY", `Truth signals are only accepted in Active/Resolving, got ${state}.`);
  }
  if (ctx.now > ctx.softTimeoutAt) {
    fail("STALE_AFTER_SOFT_TIMEOUT", `Signal at ${ctx.now} > softTimeoutAt ${ctx.softTimeoutAt}.`);
  }
  // Per-period guards.
  const expectedPeriod = ctx.blueprint === "subscription" ? (ctx.currentPeriod ?? 0) : 0;
  if (event.period !== expectedPeriod) {
    fail("WRONG_PERIOD", `signal.period=${event.period} != currentPeriod=${expectedPeriod}.`);
  }
  // Per-period replay key.
  const seenForPeriod = ctx.seenAttestorsByPeriod?.get(expectedPeriod);
  if (seenForPeriod?.has(event.didCommitment)) {
    fail("REPLAY", `Attestor ${event.didCommitment} already signed period ${expectedPeriod}.`);
  }

  // Project tallies AFTER this signal lands.
  const accept = { ...ctx.acceptCount };
  const reject = { ...ctx.rejectCount };
  if (event.verdict === "accept") accept[event.priorityClass] += 1;
  else                            reject[event.priorityClass] += 1;

  // Resolution algebra — first matching rule fires.
  const isSub = ctx.blueprint === "subscription";
  const resolvedState: UniversalState = isSub ? "Period_Resolved" : "Resolved";
  const lingerState:   UniversalState = isSub ? "Period_Resolving" : "Resolving";
  for (const k of [1, 2, 3] as const) {
    const T = ctx.validation.classThresholds[k];
    if (T === 0) continue;
    const A = accept[k];
    const R = reject[k];
    if (A >= T && A > R) {
      return {
        nextState: resolvedState,
        effects: [{ kind: "sharesDeclared" }],
        tallyDelta: { class: event.priorityClass, verdict: event.verdict },
      };
    }
    if (R >= T && R > A) {
      return {
        nextState: "Disputed",
        effects: [{ kind: "disputeOpened", at: ctx.now }],
        tallyDelta: { class: event.priorityClass, verdict: event.verdict },
      };
    }
    if (A >= T || R >= T) {
      return { nextState: lingerState, effects: [], tallyDelta: { class: event.priorityClass, verdict: event.verdict } };
    }
  }

  // No resolution; signal accepted, FSM lingers.
  return { nextState: lingerState, effects: [], tallyDelta: { class: event.priorityClass, verdict: event.verdict } };
}

/* ─────────────────────────────────────────────────────────────────
 *  T6 — Committed/Active/Resolving → Lockout → Reverted
 * ───────────────────────────────────────────────────────────────── */

function T6_revertOnTimeout(state: UniversalState, ctx: FsmContext): FsmTransitionResult {
  // T6a: Committed/Active/Resolving → Lockout when softTimeoutAt passed.
  if (state === "Committed" || state === "Active" || state === "Resolving" || state === "Period_Active" || state === "Period_Resolving") {
    if (ctx.now <= ctx.softTimeoutAt) {
      fail("PRE_SOFT_TIMEOUT", `Soft timeout not reached (now ${ctx.now} ≤ ${ctx.softTimeoutAt}).`);
    }
    return {
      nextState: "Lockout",
      effects: [],
    };
  }
  // T6b: Lockout → Reverted handled by revertOnTimeoutFromLockout (entry point above).
  fail("WRONG_STATE", `revertOnTimeout requires an active state, got ${state}.`);
}

function revertOnTimeoutFromLockout(ctx: FsmContext): FsmTransitionResult {
  if (ctx.now < ctx.hardTimeoutAt) {
    fail("PRE_HARD_TIMEOUT", `Hard timeout not reached (now ${ctx.now} < ${ctx.hardTimeoutAt}).`);
  }
  return {
    nextState: "Reverted",
    effects: [{ kind: "sharesVoided" }],
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  T7 — Resolving → Disputed
 * ───────────────────────────────────────────────────────────────── */

function T7_openDispute(state: UniversalState, ctx: FsmContext): FsmTransitionResult {
  if (state !== "Resolving") {
    fail("WRONG_STATE", `T7 requires state=Resolving, got ${state}.`);
  }
  if (ctx.openDisputeAt !== null && ctx.openDisputeAt !== undefined) {
    fail("ALREADY_DISPUTED", `Dispute already open since ${ctx.openDisputeAt}.`);
  }
  return {
    nextState: "Disputed",
    effects: [{ kind: "disputeOpened", at: ctx.now }],
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  T8 / T9 — Disputed → Resolved | Reverted
 * ───────────────────────────────────────────────────────────────── */

function T8_arbitratorSettle(state: UniversalState): FsmTransitionResult {
  if (state !== "Disputed") fail("WRONG_STATE", `T8 requires state=Disputed, got ${state}.`);
  return {
    nextState: "Resolved",
    effects: [{ kind: "sharesDeclared" }],
  };
}

function T9_arbitratorVoid(state: UniversalState): FsmTransitionResult {
  if (state !== "Disputed") fail("WRONG_STATE", `T9 requires state=Disputed, got ${state}.`);
  return {
    nextState: "Reverted",
    effects: [{ kind: "sharesVoided" }],
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  T8b — Disputed → Resolved (graded: part upheld, part not owed)
 * ─────────────────────────────────────────────────────────────────
 *
 * The arbitrator upholds `providerBps` of the price for the provider side; the
 * rest is not owed (see the splitter's `declaredGradedSplit`). It generalises
 * T8/T9: providerBps=10_000 ≡ every share declared (T8), providerBps=0 ≡ every
 * share void. The terminal state is Resolved — the dispute is concluded.
 */
function T8b_arbitratorSplit(
  state: UniversalState,
  event: Extract<FsmEvent, { t: "arbitratorSplit" }>,
): FsmTransitionResult {
  if (state !== "Disputed") fail("WRONG_STATE", `T8b requires state=Disputed, got ${state}.`);
  if (!Number.isInteger(event.providerBps) || event.providerBps < 0 || event.providerBps > BPS_TOTAL) {
    fail("INVALID_MANIFEST", `arbitratorSplit providerBps must be an integer in [0, ${BPS_TOTAL}], got ${event.providerBps}.`);
  }
  const effects: FsmEffect[] = [];
  if (event.providerBps > 0) effects.push({ kind: "sharesDeclared" });
  if (event.providerBps < BPS_TOTAL) effects.push({ kind: "sharesVoided" });
  return { nextState: "Resolved", effects };
}

/* ─────────────────────────────────────────────────────────────────
 *  T10 — Disputed → Reverted (timeout)
 * ───────────────────────────────────────────────────────────────── */

function T10_revertOnDisputeTimeout(state: UniversalState, ctx: FsmContext): FsmTransitionResult {
  if (state !== "Disputed") fail("WRONG_STATE", `T10 requires state=Disputed, got ${state}.`);
  if (ctx.now < ctx.disputeTimeoutAt) {
    fail("PRE_DISPUTE_TIMEOUT", `Dispute timeout not reached (now ${ctx.now} < ${ctx.disputeTimeoutAt}).`);
  }
  return {
    nextState: "Reverted",
    effects: [{ kind: "sharesVoided" }],
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  Subscription-only transitions
 * ───────────────────────────────────────────────────────────────── */

function Subscription_periodTick(state: UniversalState, ctx: FsmContext): FsmTransitionResult {
  if (ctx.blueprint !== "subscription") fail("WRONG_STATE", `periodTick is subscription-only.`);
  if (ctx.maxPeriods === undefined || ctx.currentPeriod === undefined) {
    fail("INVALID_BLUEPRINT_PAYLOAD", `Subscription FSM context missing currentPeriod / maxPeriods.`);
  }
  if (state !== "Period_Resolved" && state !== "Committed") {
    fail("WRONG_STATE", `periodTick requires Committed or Period_Resolved, got ${state}.`);
  }
  const nextPeriod = ctx.currentPeriod + 1;
  if (nextPeriod >= ctx.maxPeriods) {
    return { nextState: "Resolved", effects: [{ kind: "sharesDeclared" }] };
  }
  return { nextState: "Period_Active", effects: [], periodAdvance: true };
}

function Subscription_cancel(state: UniversalState, ctx: FsmContext): FsmTransitionResult {
  if (ctx.blueprint !== "subscription") fail("WRONG_STATE", `cancelSubscription is subscription-only.`);
  if (state === "Resolved" || state === "Reverted" || state === "Cancelled") {
    fail("WRONG_STATE", `Cannot cancel a terminal subscription (${state}).`);
  }
  return {
    nextState: "Cancelled",
    effects: [{ kind: "sharesVoided" }],
  };
}

/**
 * Per-period timeout. Drives the three `periodRevertPolicy` values.
 * Voids the CURRENT period's shares; advances or cascades per policy.
 */
function Subscription_periodRevertOnTimeout(state: UniversalState, ctx: FsmContext): FsmTransitionResult {
  if (ctx.blueprint !== "subscription") fail("WRONG_STATE", `periodRevertOnTimeout is subscription-only.`);
  if (state !== "Period_Active" && state !== "Period_Resolving") {
    fail("WRONG_STATE", `periodRevertOnTimeout requires Period_Active/Period_Resolving, got ${state}.`);
  }
  if (ctx.now < ctx.hardTimeoutAt) {
    fail("PRE_HARD_TIMEOUT", `Period hard timeout not reached (now ${ctx.now} < ${ctx.hardTimeoutAt}).`);
  }
  const policy = ctx.periodRevertPolicy ?? "skip-and-continue";
  const sequential = (ctx.sequentialFailedPeriods ?? 0) + 1;
  const cap = ctx.maxSequentialFailedPeriods ?? 2;

  // Cascade — terminal Cancelled, every remaining period's shares void.
  if (policy === "cascade-revert" || (policy === "cascade-on-N-failures" && sequential >= cap)) {
    return {
      nextState: "Cancelled",
      effects: [{ kind: "sharesVoided" }],
    };
  }

  // Skip-and-continue — this period's shares are void; advance.
  if (ctx.currentPeriod === undefined || ctx.maxPeriods === undefined) {
    fail("INVALID_BLUEPRINT_PAYLOAD", `Subscription FSM context missing currentPeriod / maxPeriods.`);
  }
  const nextPeriod = ctx.currentPeriod + 1;
  if (nextPeriod >= ctx.maxPeriods) {
    return { nextState: "Resolved", effects: [{ kind: "sharesVoided" }] };
  }
  return {
    nextState: "Period_Active",
    effects: [{ kind: "sharesVoided" }],
    periodAdvance: true,
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  Milestone-only transitions
 * ─────────────────────────────────────────────────────────────────
 *
 * Per-step dispute isolation: disputing or resolving an individual step does
 * NOT move the global state. The agreement lingers in Active while steps are
 * released or voided one by one, and only `finalizeMilestone` — once every
 * step is resolved — drives it to the Resolved terminal.
 */

function milestoneGuards(index: number, ctx: FsmContext): void {
  if (ctx.blueprint !== "milestone") fail("WRONG_STATE", "milestone events are milestone-only.");
  if (ctx.totalSteps === undefined) fail("INVALID_BLUEPRINT_PAYLOAD", "Milestone context missing totalSteps.");
  if (!Number.isInteger(index) || index < 0 || index >= ctx.totalSteps) {
    fail("INVALID_MANIFEST", `Milestone step index ${index} out of range [0, ${ctx.totalSteps}).`);
  }
}

function Milestone_release(
  state: UniversalState,
  event: Extract<FsmEvent, { t: "releaseMilestone" }>,
  ctx: FsmContext,
): FsmTransitionResult {
  milestoneGuards(event.index, ctx);
  if (state !== "Committed" && state !== "Active") {
    fail("WRONG_STATE", `releaseMilestone requires Committed/Active, got ${state}.`);
  }
  if (ctx.now > ctx.softTimeoutAt) {
    fail("STALE_AFTER_SOFT_TIMEOUT", `Milestone release at ${ctx.now} > softTimeoutAt ${ctx.softTimeoutAt}.`);
  }
  if (ctx.resolvedSteps?.has(event.index)) fail("ALREADY_CLAIMED", `Milestone step ${event.index} already resolved.`);
  if (ctx.disputedSteps?.has(event.index)) fail("WRONG_STATE", `Milestone step ${event.index} is in dispute; resolve it first.`);
  return { nextState: "Active", effects: [{ kind: "sharesDeclared" }] };
}

function Milestone_dispute(
  state: UniversalState,
  event: Extract<FsmEvent, { t: "disputeMilestone" }>,
  ctx: FsmContext,
): FsmTransitionResult {
  milestoneGuards(event.index, ctx);
  if (state !== "Committed" && state !== "Active") {
    fail("WRONG_STATE", `disputeMilestone requires Committed/Active, got ${state}.`);
  }
  if (ctx.resolvedSteps?.has(event.index)) fail("WRONG_STATE", `Milestone step ${event.index} already resolved.`);
  if (ctx.disputedSteps?.has(event.index)) fail("ALREADY_DISPUTED", `Milestone step ${event.index} already disputed.`);
  // Global state unchanged (per-step isolation); a Committed agreement promotes to Active.
  return { nextState: "Active", effects: [{ kind: "disputeOpened", at: ctx.now }] };
}

function Milestone_resolveDispute(
  state: UniversalState,
  event: Extract<FsmEvent, { t: "resolveMilestoneDispute" }>,
  ctx: FsmContext,
): FsmTransitionResult {
  milestoneGuards(event.index, ctx);
  if (state !== "Active") fail("WRONG_STATE", `resolveMilestoneDispute requires Active, got ${state}.`);
  if (!ctx.disputedSteps?.has(event.index)) fail("WRONG_STATE", `Milestone step ${event.index} is not in dispute.`);
  if (ctx.resolvedSteps?.has(event.index)) fail("ALREADY_CLAIMED", `Milestone step ${event.index} already resolved.`);
  return {
    nextState: "Active",
    effects: [event.favorConsumer ? { kind: "sharesVoided" } : { kind: "sharesDeclared" }],
  };
}

function Milestone_finalize(state: UniversalState, ctx: FsmContext): FsmTransitionResult {
  if (ctx.blueprint !== "milestone") fail("WRONG_STATE", "finalizeMilestone is milestone-only.");
  if (ctx.totalSteps === undefined) fail("INVALID_BLUEPRINT_PAYLOAD", "Milestone context missing totalSteps.");
  if (state !== "Active" && state !== "Committed") {
    fail("WRONG_STATE", `finalizeMilestone requires Committed/Active, got ${state}.`);
  }
  const resolved = ctx.resolvedSteps?.size ?? 0;
  if (resolved < ctx.totalSteps) {
    fail("WRONG_STATE", `finalizeMilestone requires all ${ctx.totalSteps} steps resolved; ${resolved} done.`);
  }
  return { nextState: "Resolved", effects: [{ kind: "sharesDeclared" }] };
}

/* ─────────────────────────────────────────────────────────────────
 *  Helpers
 * ───────────────────────────────────────────────────────────────── */

/** True iff the state permits truth-signal submissions. */
export function isSignalAccepting(state: UniversalState): boolean {
  return state === "Active" || state === "Resolving"
      || state === "Period_Active" || state === "Period_Resolving";
}

/** Tier the FSM by agreement-level stage (for UI / analytics). */
export function stateGroup(state: UniversalState): "draft" | "committed" | "active" | "lockout" | "disputed" | "resolved" | "reverted" {
  if (state === "Drafted") return "draft";
  if (state === "Committed") return "committed";
  if (state === "Active" || state === "Resolving" || state === "Period_Active" || state === "Period_Resolving" || state === "Period_Resolved") return "active";
  if (state === "Lockout") return "lockout";
  if (state === "Disputed") return "disputed";
  if (state === "Resolved") return "resolved";
  return "reverted";
}
