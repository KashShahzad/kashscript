/**
 * Type bundle for @kashscript/terms.
 *
 * An agreement is a sealed manifest, a state that describes the agreement's
 * stage, and a declared split — the shares a Duedale book declares. Nothing
 * here holds a balance, and nothing here moves value: payment happens on the
 * payer's own rails, and Duedale confirms arrival.
 */

import type { KashDid, SignedKashEvent } from "@kashscript/identity-core";

/* ─────────────────────────────────────────────────────────────────
 *  Branded identifiers
 * ───────────────────────────────────────────────────────────────── */

/** `kash-trade:<keccak256(JCS(manifestBody))>` — the deterministic id. */
export type ManifestId = `kash-trade:${string}`;

/* ─────────────────────────────────────────────────────────────────
 *  Blueprints — the agreement kinds this package models.
 *  A booking, a ticket or a bounty is an `otdc`; a pass is a
 *  `subscription`; a cohort is a `milestone` schedule.
 * ───────────────────────────────────────────────────────────────── */

export type BlueprintType = "otdc" | "subscription" | "milestone";

export type BlueprintPayload =
  | { readonly kind: "otdc";         readonly otdc:         OTDCPayload }
  | { readonly kind: "subscription"; readonly subscription: SubscriptionPayload }
  | { readonly kind: "milestone";    readonly milestone:    MilestonePayload };

/* ─────────────────────────────────────────────────────────────────
 *  States
 * ─────────────────────────────────────────────────────────────────
 *
 * A state is a stage of the AGREEMENT. It never labels a person and it never
 * holds a balance. The list is exported so a test can check it stays that way.
 */

export const STATES = [
  "Drafted",
  "Committed",
  "Active",
  "Period_Active",        // Subscription-only
  "Resolving",
  "Period_Resolving",     // Subscription-only
  "Lockout",
  "Disputed",
  "Resolved",
  "Period_Resolved",      // Subscription mid-cycle
  "Reverted",
  "Cancelled",            // Subscription-level revert
] as const;

export type UniversalState = (typeof STATES)[number];

/** Terminal states. Once entered, no transitions out. */
export const TERMINAL_STATES = new Set<UniversalState>(["Resolved", "Reverted", "Cancelled"]);

/* ─────────────────────────────────────────────────────────────────
 *  Party, price and share shapes
 * ───────────────────────────────────────────────────────────────── */

export interface PartyRef {
  readonly did: KashDid;
  /** keccak256 of the did (32 bytes) — the replay key for signals. */
  readonly didCommitment: `0x${string}`;
  /** Verification-method id pinned in the manifest. */
  readonly kid: `${KashDid}#${string}`;
  readonly label?: string;
}

/** What the parties agreed. A statement of the agreement, not a held amount. */
export interface Price {
  /** Decimal-stringified non-negative integer, in the currency's smallest unit. */
  readonly amount: string;
  /** Currency code, e.g. an ISO-4217 code. Display and declaration only. */
  readonly currency: string;
}

/** One share of the declared split. */
export interface ShareLeg {
  /** Who the payer declares this share is for. Duedale names the party the same way. */
  readonly did: KashDid;
  /** 1..10_000 inclusive. */
  readonly bps: number;
  /**
   * Exactly one leg per manifest MUST set this (Strategy A) OR
   * `roundingHolder` at manifest level MUST be set (Strategy B).
   * It makes the shares add up to the declared amount with no dust.
   */
  readonly sweepFinal?: boolean;
  readonly label?: string;
}

/* ─────────────────────────────────────────────────────────────────
 *  Validation policy — who confirms, and how many must
 * ───────────────────────────────────────────────────────────────── */

export type PriorityClass = 1 | 2 | 3;

export interface ValidationPolicy {
  /** Per-class M-of-N thresholds. `0` = class unused. */
  readonly classThresholds: Readonly<Record<PriorityClass, number>>;
  /** Priority-class assignment, per attestor index. */
  readonly priorityClasses: readonly PriorityClass[];
  /** Aggregate threshold (sum of class thresholds). Used for the strict-majority guard. */
  readonly threshold: number;
  /** Optional separate arbitrator set for dispute resolution. */
  readonly disputeArbitrators?: readonly PartyRef[];
  /** Quorum threshold for the dispute arbitrator set. Strict majority enforced. */
  readonly disputeThreshold?: number;
}

/* ─────────────────────────────────────────────────────────────────
 *  Per-blueprint payloads
 * ───────────────────────────────────────────────────────────────── */

/** One-time agreement — a booking, a ticket, a bounty. */
export interface OTDCPayload {
  /** keccak256 over the expected delivery body. */
  readonly deliveryClaim: `0x${string}`;
  /** Human-readable, ≤ 280 chars. */
  readonly description: string;
  /** Free-form clause signed into the manifest. */
  readonly buyerExpectation: string;
}

/** Recurring agreement — a pass. */
export interface SubscriptionPayload {
  /** Length of each period, in seconds. */
  readonly periodSeconds: number;
  /** Maximum number of periods before automatic Resolved. */
  readonly maxPeriods: number;
  /** Per-period BPS shares. Σ bps == 10_000. */
  readonly perPeriodSplits: readonly ShareLeg[];
  /** Per-period price amount (decimal-stringified integer). */
  readonly perPeriodAmount: string;
  /** Mid-subscription cancellation policy. */
  readonly cancellation: {
    /** Lead time, in seconds, required before the next period for a cancellation to take effect. */
    readonly leadTimeSeconds: number;
    /** What is owed for the current period when the subscriber cancels. */
    readonly owedPolicy: "pro-rata" | "none" | "current-period";
  };
  /** When true, a fresh agreement starts at maxPeriods. */
  readonly autoRenew: boolean;

  /**
   * What happens when a single period times out without reaching quorum.
   *
   *   • `"skip-and-continue"`     — this period's shares are void; advance to next.
   *   • `"cascade-revert"`        — one failed period → terminal `Cancelled`.
   *   • `"cascade-on-N-failures"` — cascade only after `maxSequentialFailedPeriods`
   *                                 consecutive timeouts.
   */
  readonly periodRevertPolicy: "skip-and-continue" | "cascade-revert" | "cascade-on-N-failures";
  /** Required when `periodRevertPolicy === "cascade-on-N-failures"`. */
  readonly maxSequentialFailedPeriods?: number;
}

/** A schedule of steps, each released or voided on its own — a cohort. */
export interface MilestoneStepSpec {
  /** Stable id for indexing / log correlation. */
  readonly stepId: `0x${string}`;
  /** Share of the total price for this step. Σ over steps == 10_000. */
  readonly bps: number;
  /** keccak256 over the expected delivery body for this step. */
  readonly triggerClaim: `0x${string}`;
  /** Per-step shares — dust-free in their own right (Σ bps == 10_000). */
  readonly recipients: readonly ShareLeg[];
  /** Human-readable, ≤ 280 chars. */
  readonly description?: string;
}

export interface MilestonePayload {
  /** Ordered steps. Released independently; the agreement resolves once every
   *  step is released or voided. */
  readonly steps: readonly MilestoneStepSpec[];
}

/* ─────────────────────────────────────────────────────────────────
 *  The manifest
 * ───────────────────────────────────────────────────────────────── */

export interface TermsManifest {
  readonly v: 3;
  readonly manifestId: ManifestId;
  readonly blueprint: BlueprintType;
  readonly state: UniversalState;
  readonly parties: {
    readonly buyer:  PartyRef;
    readonly seller: PartyRef;
    readonly attestors: readonly PartyRef[];
  };
  readonly price: Price;
  readonly splits: readonly ShareLeg[];
  /** Strategy B: the party who holds the rounding remainder, instead of a `sweepFinal` leg. */
  readonly roundingHolder?: KashDid;
  readonly validation: ValidationPolicy;
  /** Timeouts, as Unix seconds. After `softTimeoutAt` confirmations stop; at `hardTimeoutAt`
   *  (at least {@link MIN_LOCKOUT_SECONDS} later) an unconfirmed agreement reverts. */
  readonly softTimeoutAt: number;
  readonly hardTimeoutAt: number;
  readonly disputeTimeoutAt: number;
  /** When the parties committed (Unix seconds). Null until then. */
  readonly committedAt: number | null;
  readonly openDisputeAt?: number | null;
  readonly witnesses: {
    readonly set: readonly PartyRef[];
    readonly threshold: number;
  };
  readonly payload: BlueprintPayload;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly signature: SignedKashEvent["signature"];
}

/* ─────────────────────────────────────────────────────────────────
 *  Confirmation signals
 * ───────────────────────────────────────────────────────────────── */

export type Verdict = "accept" | "reject";

/* ─────────────────────────────────────────────────────────────────
 *  Constants
 * ───────────────────────────────────────────────────────────────── */

/**
 * Floor, in seconds, on the gap between an agreement's soft and hard timeouts.
 * It is a race guard (a late confirmation must not collide with the revert), not
 * a business term: the manifest declares the real gap, and it can be as long as
 * the agreement needs. 60 s is what the old kernel's 30-unit deadband came to on a
 * two-second chain, restated in time. The founder may raise it.
 */
export const MIN_LOCKOUT_SECONDS = 60;
export const BPS_TOTAL           = 10_000;

/**
 * Every instant in this package is a Unix timestamp in SECONDS (UTC), the unit
 * attest's `…Unix` fields use. Nothing here reads a clock: the caller passes
 * `now`. Largest accepted value ≈ the year 5138 — anything above it is almost
 * certainly milliseconds, and is refused rather than silently misread.
 */
export const MAX_UNIX_SECONDS = 99_999_999_999;

/** True iff `n` is a plausible Unix timestamp in seconds. */
export function isUnixSeconds(n: unknown): n is number {
  return typeof n === "number" && Number.isInteger(n) && n >= 0 && n <= MAX_UNIX_SECONDS;
}
