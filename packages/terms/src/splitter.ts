/**
 * The declared split — the shares an agreement declares in a Duedale book.
 *
 * It computes numbers and moves nothing. Payment happens on the payer's own
 * rails; Duedale confirms arrival. All this module does is divide an amount
 * into shares that add up to it exactly, with no dust.
 *
 * For each leg i ∈ [1, n] with bps_i ∈ [1, 10_000]:
 *
 *     Share_i = amount − Σ_{j ≠ i_sweep} Share_j        if i == i_sweep
 *             = ⌊amount × bps_i / 10_000⌋                otherwise
 *
 * Constraints (enforced when a manifest compiles AND when a split is declared):
 *
 *     Σ bps_i = 10_000
 *     Σ Share_i ≡ amount                 (no dust)
 *     ∃! i* with sweepFinal_i* = true    OR  roundingHolder ≠ ∅
 */

import { isKashDid, type KashDid } from "@kashscript/identity-core";

import { fail } from "./errors";
import { BPS_TOTAL, type ShareLeg } from "./types";

/* ─────────────────────────────────────────────────────────────────
 *  Manifest-level validation (compile time, idempotent)
 * ───────────────────────────────────────────────────────────────── */

export interface SplitValidationResult {
  readonly ok: true;
  readonly sweepIndex: number;          // -1 when roundingHolder is used
  readonly usesRoundingHolder: boolean;
}

/**
 * Validates a set of shares. Pure function; declares nothing — see
 * {@link declaredSplit} for that.
 *
 * Strategy A: exactly one leg has `sweepFinal: true`. Returns its index.
 * Strategy B: `roundingHolder` was supplied at the manifest level.
 *             Returns `sweepIndex: -1, usesRoundingHolder: true`.
 *
 * Throws on any of: empty splits, bps out of range, a leg that does not name a
 * did:kash, Σ bps ≠ 10_000, zero sweep legs and no `roundingHolder`, multiple
 * sweep legs.
 */
export function validateSplits(
  splits: readonly ShareLeg[],
  roundingHolder?: KashDid,
): SplitValidationResult {
  if (!Array.isArray(splits) || splits.length === 0) {
    fail("INVALID_MANIFEST", "splits MUST be a non-empty array.");
  }

  let bpsSum = 0;
  let sweepIndex = -1;

  for (let i = 0; i < splits.length; i++) {
    const leg = splits[i]!;
    if (!Number.isInteger(leg.bps) || leg.bps < 1 || leg.bps > BPS_TOTAL) {
      fail("INVALID_MANIFEST", `splits[${i}].bps must be an integer in [1, ${BPS_TOTAL}], got ${leg.bps}.`);
    }
    if (!isKashDid(leg.did)) {
      fail("WRONG_DID", `splits[${i}].did must be a did:kash.`);
    }
    bpsSum += leg.bps;
    if (leg.sweepFinal === true) {
      if (sweepIndex !== -1) {
        fail("DUPLICATE_SWEEP", `Multiple splits set sweepFinal=true (indices ${sweepIndex} and ${i}).`);
      }
      sweepIndex = i;
    }
  }

  if (bpsSum !== BPS_TOTAL) {
    fail("BPS_SUM", `Σ bps = ${bpsSum}, expected ${BPS_TOTAL}.`);
  }

  if (roundingHolder !== undefined && !isKashDid(roundingHolder)) {
    fail("WRONG_DID", "roundingHolder must be a did:kash.");
  }
  const usesRoundingHolder = sweepIndex === -1 && roundingHolder !== undefined;
  if (sweepIndex === -1 && !usesRoundingHolder) {
    fail("NO_SWEEP_LEG", "Exactly one leg MUST set sweepFinal=true OR roundingHolder MUST be provided.");
  }

  return { ok: true, sweepIndex, usesRoundingHolder };
}

/* ─────────────────────────────────────────────────────────────────
 *  Declaring a split
 * ───────────────────────────────────────────────────────────────── */

/** One share, with the amount it declares. */
export interface ShareDeclaration {
  readonly did: KashDid;
  readonly amount: bigint;
  readonly bps: number;
  readonly label?: string;
}

export interface DeclaredSplit {
  /** Per-leg shares; same length and order as the input splits. */
  readonly legs: readonly ShareDeclaration[];
  /** The sweep leg, or — for a `roundingHolder` — a synthetic leg holding the rounding remainder. */
  readonly sweepLeg: ShareDeclaration;
  /** Σ amount across the legs. MUST equal the declared amount. */
  readonly total: bigint;
}

/**
 * Divide `amount` into shares with no dust.
 *
 * **Closed-form guarantee:** the shares add up to `amount` exactly. The
 * runtime assertion at the bottom is that guarantee, checked.
 */
export function declaredSplit(
  splits: readonly ShareLeg[],
  amount: bigint,
  roundingHolder?: KashDid,
): DeclaredSplit {
  if (typeof amount !== "bigint" || amount < 0n) {
    fail("INVALID_MANIFEST", `amount must be a non-negative bigint, got ${String(amount)}.`);
  }

  const v = validateSplits(splits, roundingHolder);

  // Every non-sweep leg gets floor((amount * bps) / 10_000).
  const legs: ShareDeclaration[] = [];
  let declaredSoFar = 0n;
  let sweepLeg: ShareDeclaration;

  for (let i = 0; i < splits.length; i++) {
    const leg = splits[i]!;
    const label = leg.label !== undefined ? { label: leg.label } : {};
    if (i === v.sweepIndex) {
      // Placeholder; final amount computed AFTER the loop.
      legs.push({ did: leg.did, amount: 0n, bps: leg.bps, ...label });
      continue;
    }
    const cut = (amount * BigInt(leg.bps)) / BigInt(BPS_TOTAL);
    declaredSoFar += cut;
    legs.push({ did: leg.did, amount: cut, bps: leg.bps, ...label });
  }

  if (v.sweepIndex !== -1) {
    const sweep = legs[v.sweepIndex]!;
    const sweepAmount = amount - declaredSoFar;
    if (sweepAmount < 0n) {
      // Cannot happen given Σ bps = 10_000 and integer floor, but assert for safety.
      fail("INVARIANT_DRIFT", `Computed sweep amount is negative (${String(sweepAmount)}). Σ bps math is wrong.`);
    }
    legs[v.sweepIndex] = { ...sweep, amount: sweepAmount };
    declaredSoFar = amount;
    sweepLeg = legs[v.sweepIndex]!;
  } else {
    // Strategy B — a synthetic leg outside the splits array holds the rounding remainder.
    sweepLeg = {
      did: roundingHolder as KashDid,
      amount: amount - declaredSoFar,
      bps: 0,                       // synthetic; not counted in the 10_000 sum
      label: "roundingHolder",
    };
    declaredSoFar = amount;
  }

  // Post-condition.
  if (declaredSoFar !== amount) {
    fail("INVARIANT_DRIFT", `declared (${String(declaredSoFar)}) != amount (${String(amount)}).`);
  }

  return { legs, sweepLeg, total: declaredSoFar };
}

/* ─────────────────────────────────────────────────────────────────
 *  Graded outcomes (a partly upheld dispute)
 * ─────────────────────────────────────────────────────────────────
 *
 * A graded outcome upholds `providerBps` of the amount for the provider side
 * (split dust-free among the manifest's shares). The remainder is the part the
 * payer does not owe; it is named to the buyer so the split still sums to the
 * whole. It GENERALISES the binary outcomes:
 *   • providerBps = 10_000  ≡  every share declared in full
 *   • providerBps = 0        ≡  every share void; the whole amount is the remainder
 *
 * Closed-form guarantee: Σ providerLegs.amount + remainderAmount === amount.
 */

export interface GradedSplit {
  /** Provider-side legs (the manifest split applied to the upheld portion). */
  readonly providerLegs: readonly ShareDeclaration[];
  /** The part the payer does not owe, named to the buyer. */
  readonly remainderLeg: ShareDeclaration;
  readonly providerAmount: bigint;
  readonly remainderAmount: bigint;
  /** Σ providerLegs.amount + remainderAmount. MUST equal the amount. */
  readonly total: bigint;
}

/**
 * The primitive: declare an ABSOLUTE `providerAmount` to the provider side
 * (split dust-free among the manifest shares) and name the exact remainder
 * (`amount - providerAmount`) to the buyer.
 */
export function declaredPartialSplit(
  splits: readonly ShareLeg[],
  amount: bigint,
  providerAmount: bigint,
  buyer: KashDid,
  roundingHolder?: KashDid,
): GradedSplit {
  if (typeof amount !== "bigint" || amount < 0n) {
    fail("INVALID_MANIFEST", `amount must be a non-negative bigint, got ${String(amount)}.`);
  }
  if (typeof providerAmount !== "bigint" || providerAmount < 0n || providerAmount > amount) {
    fail("INVALID_MANIFEST", `providerAmount must be a bigint in [0, amount], got ${String(providerAmount)}.`);
  }
  if (!isKashDid(buyer)) {
    fail("WRONG_DID", "buyer must be a did:kash.");
  }

  const remainderAmount = amount - providerAmount;

  // The upheld portion is split dust-free among the manifest shares. At
  // providerAmount === 0 every leg is 0; the whole amount is the remainder.
  const providerLegs = declaredSplit(splits, providerAmount, roundingHolder).legs;

  const remainderLeg: ShareDeclaration = {
    did: buyer,
    amount: remainderAmount,
    bps: 0,
    label: "remainder",
  };

  const total = providerLegs.reduce((s, l) => s + l.amount, 0n) + remainderAmount;
  if (total !== amount) {
    fail("INVARIANT_DRIFT", `partial total (${String(total)}) != amount (${String(amount)}).`);
  }

  return { providerLegs, remainderLeg, providerAmount, remainderAmount, total };
}

/** Graded outcome by basis points: `providerBps` of `amount` is upheld for the
 *  provider side. A thin bps-wrapper over {@link declaredPartialSplit}. */
export function declaredGradedSplit(
  splits: readonly ShareLeg[],
  amount: bigint,
  providerBps: number,
  buyer: KashDid,
  roundingHolder?: KashDid,
): GradedSplit {
  if (typeof amount !== "bigint" || amount < 0n) {
    fail("INVALID_MANIFEST", `amount must be a non-negative bigint, got ${String(amount)}.`);
  }
  if (!Number.isInteger(providerBps) || providerBps < 0 || providerBps > BPS_TOTAL) {
    fail("INVALID_MANIFEST", `providerBps must be an integer in [0, ${BPS_TOTAL}], got ${providerBps}.`);
  }
  const providerAmount = (amount * BigInt(providerBps)) / BigInt(BPS_TOTAL);
  return declaredPartialSplit(splits, amount, providerAmount, buyer, roundingHolder);
}
