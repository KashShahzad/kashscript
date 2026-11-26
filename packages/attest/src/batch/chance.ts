/**
 * The arithmetic of a batch accepted on a sample (PY-5; `specs/attestation/batch.md` §4) — exact, in
 * integers, with no floating point anywhere.
 *
 * A batch holds `size` items, of which some number `short` fall short of the agreed words; nobody knows it.
 * A draw takes `sample` of them — every set of that many equally likely, without replacement — and `found` is
 * how many of the drawn fell short. The number found follows the hypergeometric distribution:
 *
 *     P(X = k) = C(short, k) · C(size − short, sample − k) / C(size, sample)
 *
 * **The bound.** For a chance α, the bound after finding `found` is the largest `short` for which a draw as
 * clean as this one — `found` or fewer short — would still come up more often than α:
 *
 *     bound = max { D : P(X ≤ found; size, D, sample) > α }
 *
 * so for every D above the bound, a draw this clean comes up at most α of the time. It is the exact one-sided
 * upper confidence bound on a count — Clopper and Pearson's construction, for drawing without replacement. It
 * counts items in this batch; it is never a rate of anyone's work (d43).
 *
 * **The plan.** Check `sample` items; accept if at most `accept` fall short. Its `limit` is the bound at
 * `found = accept`: if more than `limit` items fell short, the plan would pass the batch at most α of the time
 * (ISO 2859-2 calls the same figure, as a fraction, the limiting quality). Accepting with `found ≤ accept`
 * keeps `bound ≤ limit`, because the chance of `x` or fewer only grows with `x`.
 *
 * **A checker never searches.** `isExactBound` certifies a stated bound with two evaluations — above α at D,
 * at most α at D + 1 — because the chance only falls as D grows; `boundVerdict` says which way a wrong figure is
 * off from the same two. Searching (`boundOf`, `planFor`) is the maker's, and no fault's words call it. Every
 * count is a BigInt; α is a fraction of two small whole numbers; comparisons cross-multiply.
 *
 * **What an evaluation costs** (PY-5r). The sum's terms follow one another by one multiplication and one exact
 * division by numbers below 10^11, so a term never meets another big number until it is added; the evaluation at
 * D + 1 follows from the one at D by one more such step. The cost grows with the count found: at both caps the
 * costliest figure certifies in about 150 ms, and the maker's search for it takes about 5 seconds (measured
 * 2026-11-26, under Bun, on a laptop).
 */

import { AttestError } from "../errors";

/** The chance a plan accepts as its risk, as a fraction of whole numbers: `{num: 1, den: 20}` is 1 time in 20. */
export interface Alpha {
  readonly num: number;
  readonly den: number;
}

/**
 * The most items one batch holds. Rebuilding the root of a full batch from its items file takes about 40 seconds
 * on a laptop (measured 2026-11-26; 100,000 items about 4); certifying a record's plan and bound never builds the
 * tree. At both caps a figure certifies in about 150 ms at worst, whatever was found (PY-5r, measured 2026-11-26;
 * before it, about 8 seconds with half the draw found short, and 140 ms only with almost none found).
 */
export const BATCH_MAX_SIZE = 1_000_000;
/** The most items one draw takes — and so the largest census. A person checks each one. */
export const BATCH_MAX_SAMPLE = 10_000;
/** The largest denominator a chance may have. */
export const ALPHA_MAX_DEN = 1_000_000;

/** Why a chance is not one this format reads, in words, or null. */
export function alphaProblem(a: Alpha): string | null {
  if (a === null || typeof a !== "object" || !Number.isSafeInteger(a.num) || !Number.isSafeInteger(a.den)) return "a chance is two whole numbers, num and den";
  if (a.num < 1 || a.den < 2 || a.den > ALPHA_MAX_DEN) return `a chance is at least 1 in ${ALPHA_MAX_DEN}, written with a denominator of at most ${ALPHA_MAX_DEN}`;
  if (2 * a.num > a.den) return "a chance above 1 in 2 bounds nothing";
  return null;
}

function whole(name: string, v: number, min: number, max: number): void {
  if (!Number.isSafeInteger(v) || v < min || v > max) throw new AttestError("INVALID_INPUT", `${name} is a whole number from ${min} to ${max}`);
}

function checkAlpha(a: Alpha): void {
  const p = alphaProblem(a);
  if (p !== null) throw new AttestError("INVALID_INPUT", p);
}

/** a · (a+1) · … · b, by halves so the large multiplications are few; 1 when a > b. */
function productRange(a: bigint, b: bigint): bigint {
  if (a > b) return 1n;
  if (b - a < 16n) {
    let p = 1n;
    for (let i = a; i <= b; i++) p *= i;
    return p;
  }
  const m = (a + b) / 2n;
  return productRange(a, m) * productRange(m + 1n, b);
}

/** C(n, k), exactly: 0 outside 0 ≤ k ≤ n. */
export function binomial(n: number, k: number): bigint {
  if (!Number.isSafeInteger(n) || !Number.isSafeInteger(k)) throw new AttestError("INVALID_INPUT", "a binomial coefficient takes whole numbers");
  if (n < 0 || k < 0 || k > n) return 0n;
  const j = Math.min(k, n - k);
  if (j === 0) return 1n;
  return productRange(BigInt(n - j + 1), BigInt(n)) / productRange(1n, BigInt(j));
}

/**
 * The sum below, and its term at k = found — the draws that hold exactly `found` short items (0 when none can).
 * The term t_k = C(short, k) · C(good, sample − k) gives the next by one multiplication and one exact division by
 * small numbers: t_{k+1} = t_k · (short − k)(sample − k) / ((k + 1)(good − sample + k + 1)). Exact, because t_{k+1}
 * is a whole number and the two sides are equal as fractions. Inputs are checked by the callers.
 */
function sumAndLast(size: number, short: number, sample: number, found: number): { readonly sum: bigint; readonly last: bigint } {
  const good = size - short;
  const kLow = Math.max(0, sample - good);
  const kHigh = Math.min(found, short, sample);
  if (kLow > kHigh) return { sum: 0n, last: 0n };
  let t = binomial(short, kLow) * binomial(good, sample - kLow);
  let sum = t;
  for (let k = kLow; k < kHigh; k++) {
    t = (t * (BigInt(short - k) * BigInt(sample - k))) / (BigInt(k + 1) * BigInt(good - sample + k + 1));
    sum += t;
  }
  return { sum, last: kHigh === found ? t : 0n };
}

/**
 * Of the C(size, sample) equally likely draws, how many hold at most `found` short items, when `short` of the
 * `size` items fall short: Σ C(short, k) · C(size − short, sample − k) over the k that can happen, k ≤ found.
 * Each term follows from the one before by one multiplication and one exact division, by small numbers.
 */
export function drawsWithAtMost(size: number, short: number, sample: number, found: number): bigint {
  whole("size", size, 1, Number.MAX_SAFE_INTEGER);
  whole("short", short, 0, size);
  whole("sample", sample, 0, size);
  whole("found", found, 0, Number.MAX_SAFE_INTEGER);
  return sumAndLast(size, short, sample, found).sum;
}

/**
 * The same count with one more short item, from the count and its last term: making one of the `size − short`
 * good items short removes exactly the draws that held `found` short items and that item — a share
 * (sample − found)/(size − short) of them. So
 *
 *     drawsWithAtMost(short + 1) = drawsWithAtMost(short) − last · (sample − found) / (size − short)
 *
 * and the division is exact, because both counts are whole numbers. Needs short < size and found ≤ sample.
 */
function oneMoreShort(size: number, short: number, sample: number, found: number, at: { readonly sum: bigint; readonly last: bigint }): bigint {
  return at.sum - (at.last * BigInt(sample - found)) / BigInt(size - short);
}

/** P(X ≤ found) as an exact fraction of draws: `{num, den}` with `den = C(size, sample)`, not reduced. */
export function chanceAtMost(size: number, short: number, sample: number, found: number): { readonly num: bigint; readonly den: bigint } {
  return { num: drawsWithAtMost(size, short, sample, found), den: binomial(size, sample) };
}

/** count / total > α, by cross-multiplying. */
const aboveAlpha = (count: bigint, total: bigint, alpha: Alpha): boolean => count * BigInt(alpha.den) > BigInt(alpha.num) * total;

export interface BoundInput {
  readonly size: number;
  readonly sample: number;
  /** How many of the drawn fell short. */
  readonly found: number;
  readonly alpha: Alpha;
}

function checkBoundInput(i: BoundInput): void {
  whole("size", i.size, 1, BATCH_MAX_SIZE);
  whole("sample", i.sample, 1, Math.min(i.size, BATCH_MAX_SAMPLE));
  whole("found", i.found, 0, i.sample);
  checkAlpha(i.alpha);
}

/** The most short items a draw that found `found` allows: every item not drawn could be one. */
export const boundCeiling = (i: Pick<BoundInput, "size" | "sample" | "found">): number => i.size - i.sample + i.found;

/**
 * The bound after a draw, searched: the largest count of short items for which a draw as clean as this one
 * still comes up more often than α. A census (`sample = size`) gives `found` exactly.
 */
export function boundOf(i: BoundInput): number {
  checkBoundInput(i);
  const total = binomial(i.size, i.sample);
  const top = boundCeiling(i);
  const above = (d: number): boolean => aboveAlpha(drawsWithAtMost(i.size, d, i.sample, i.found), total, i.alpha);
  // above(found) always holds: every draw holds at most `found` of `found` short items, and α ≤ 1/2.
  let lo = i.found;
  if (lo === top) return top;
  let hi = -1;
  for (let step = 1; ; step *= 2) {
    const d = Math.min(top, lo + step);
    if (above(d)) {
      lo = d;
      if (d === top) return top;
    } else {
      hi = d;
      break;
    }
  }
  while (hi - lo > 1) {
    const mid = lo + Math.floor((hi - lo) / 2);
    if (above(mid)) lo = mid;
    else hi = mid;
  }
  return lo;
}

/** What two evaluations say of a stated figure: exact, or which way it is off. */
export type BoundVerdict = "exact" | "too high" | "too low";

/**
 * Whether `bound` is exactly the bound for this draw, and if not which way it is off — two evaluations, no
 * search: the chance of a draw this clean is above α with `bound` short items (else the figure is too high), and
 * at most α with one more, or no more can exist (else it is too low). The second evaluation follows from the
 * first by one step (`oneMoreShort`).
 */
export function boundVerdict(i: BoundInput & { readonly bound: number }): BoundVerdict {
  checkBoundInput(i);
  if (!Number.isSafeInteger(i.bound)) throw new AttestError("INVALID_INPUT", "a bound is a whole number");
  if (i.bound < i.found) return "too low";
  const ceiling = boundCeiling(i);
  if (i.bound > ceiling) return "too high";
  const total = binomial(i.size, i.sample);
  const at = sumAndLast(i.size, i.bound, i.sample, i.found);
  if (!aboveAlpha(at.sum, total, i.alpha)) return "too high";
  if (i.bound === ceiling) return "exact";
  return aboveAlpha(oneMoreShort(i.size, i.bound, i.sample, i.found, at), total, i.alpha) ? "too low" : "exact";
}

/**
 * Whether `bound` is exactly the bound for this draw — two evaluations, no search: the chance of a draw this
 * clean is above α with `bound` short items, and at most α with one more (or no more can exist).
 */
export const isExactBound = (i: BoundInput & { readonly bound: number }): boolean => Number.isSafeInteger(i.bound) && boundVerdict(i) === "exact";

export interface PlanInput {
  readonly size: number;
  readonly sample: number;
  /** The most short items among the drawn with which the batch may still be accepted. */
  readonly accept: number;
  readonly alpha: Alpha;
}

/** A plan's limit: the bound it gives when exactly `accept` are found. If more than this fell short, the plan passes the batch at most α of the time. */
export const limitOf = (p: PlanInput): number => boundOf({ size: p.size, sample: p.sample, found: p.accept, alpha: p.alpha });

/** Whether `limit` is exactly this plan's limit, and if not which way it is off — two evaluations. */
export const limitVerdict = (p: PlanInput & { readonly limit: number }): BoundVerdict =>
  boundVerdict({ size: p.size, sample: p.sample, found: p.accept, alpha: p.alpha, bound: p.limit });

/** Whether `limit` is exactly this plan's limit — two evaluations. */
export const isExactLimit = (p: PlanInput & { readonly limit: number }): boolean => Number.isSafeInteger(p.limit) && limitVerdict(p) === "exact";

export interface PlanWanted {
  readonly size: number;
  /** The most short items the acceptor can live with. */
  readonly limit: number;
  readonly accept: number;
  readonly alpha: Alpha;
}

/**
 * The smallest draw for a wanted limit: the least `sample` with which a batch holding `limit + 1` short items
 * would show `accept` or fewer at most α of the time — so the plan's own limit is at most the one wanted. With
 * `accept = 0` it is a plan for no defects; with more, for a stated number of them. Throws when the plan would
 * need more than {@link BATCH_MAX_SAMPLE} items checked.
 */
export function planFor(w: PlanWanted): { readonly sample: number; readonly limit: number } {
  whole("size", w.size, 1, BATCH_MAX_SIZE);
  whole("limit", w.limit, 0, w.size - 1);
  whole("accept", w.accept, 0, w.limit);
  checkAlpha(w.alpha);
  const ok = (n: number): boolean => !aboveAlpha(drawsWithAtMost(w.size, w.limit + 1, n, w.accept), binomial(w.size, n), w.alpha);
  // A draw of `accept` or fewer items can never find more than `accept`: lo never passes. A census finds all
  // `limit + 1 > accept` short items: the full size always passes. A larger draw finds more, so `ok` only turns on.
  const cap = Math.min(w.size, BATCH_MAX_SAMPLE);
  if (!ok(cap)) throw new AttestError("INVALID_INPUT", `this plan needs more than ${cap} items checked — accept a wider limit, a larger chance or more found`);
  let lo = w.accept;
  let hi = cap;
  while (hi - lo > 1) {
    const mid = lo + Math.floor((hi - lo) / 2);
    if (ok(mid)) hi = mid;
    else lo = mid;
  }
  return { sample: hi, limit: limitOf({ size: w.size, sample: hi, accept: w.accept, alpha: w.alpha }) };
}
