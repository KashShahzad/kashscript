/**
 * PY-5 — the arithmetic of a batch accepted on a sample (`specs/attestation/batch.md` §4). Exact, in integers:
 * checked against an independent count over every subset for small batches, then by properties over seeded
 * cases — the exact coverage of the bound, monotonicity, the plan's minimality, accept-implies-bound-within-limit
 * — and against the conformance file `batch-chance@1`.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
  ALPHA_MAX_DEN,
  BATCH_MAX_SAMPLE,
  BATCH_MAX_SIZE,
  alphaProblem,
  binomial,
  boundOf,
  boundVerdict,
  chanceAtMost,
  drawsWithAtMost,
  isExactBound,
  isExactLimit,
  limitOf,
  limitVerdict,
  planFor,
  type Alpha,
} from "../src/batch";
import { intIn, seeded } from "./helpers/batch";

const ALPHAS: readonly Alpha[] = [{ num: 1, den: 2 }, { num: 1, den: 10 }, { num: 1, den: 20 }, { num: 3, den: 100 }, { num: 1, den: 1000 }];

/** For a batch of N, every draw of every size, counted by how many of the first D items it holds — by enumerating every subset. Nothing shared with the code under test. */
function subsetCounts(N: number, D: number): number[][] {
  const table = Array.from({ length: N + 1 }, () => new Array<number>(N + 1).fill(0));
  const low = (1 << D) - 1;
  const pop = (m: number): number => {
    let c = 0;
    for (let x = m; x !== 0; x &= x - 1) c++;
    return c;
  };
  for (let mask = 0; mask < 1 << N; mask++) table[pop(mask)]![pop(mask & low)]!++;
  return table;
}

/** Pascal's triangle, a second independent source for larger batches. */
function pascal(max: number): bigint[][] {
  const rows: bigint[][] = [[1n]];
  for (let n = 1; n <= max; n++) {
    const r: bigint[] = [1n];
    for (let k = 1; k < n; k++) r.push(rows[n - 1]![k - 1]! + rows[n - 1]![k]!);
    r.push(1n);
    rows.push(r);
  }
  return rows;
}
const P = pascal(60);
const C = (n: number, k: number): bigint => (k < 0 || k > n ? 0n : P[n]![k]!);
const refAtMost = (N: number, D: number, n: number, x: number): bigint => {
  let s = 0n;
  for (let k = 0; k <= x; k++) s += C(D, k) * C(N - D, n - k);
  return s;
};
/** P(X ≤ x) > α, from the reference counts. */
const refAbove = (N: number, D: number, n: number, x: number, a: Alpha): boolean => refAtMost(N, D, n, x) * BigInt(a.den) > BigInt(a.num) * C(N, n);
const refBound = (N: number, n: number, x: number, a: Alpha): number => {
  let b = x;
  for (let D = x; D <= N - n + x; D++) if (refAbove(N, D, n, x, a)) b = D;
  return b;
};

describe("counts, exactly", () => {
  test("binomials match Pascal's triangle to 60, and are 0 outside the triangle", () => {
    for (let n = 0; n <= 60; n++) for (let k = -1; k <= n + 1; k++) expect(binomial(n, k)).toBe(C(n, k));
  });

  test("for every batch of up to 12 items, every short count, draw size and found count: the count of draws equals one made by enumerating every subset", () => {
    for (let N = 1; N <= 12; N++) {
      for (let D = 0; D <= N; D++) {
        const t = subsetCounts(N, D);
        for (let n = 0; n <= N; n++) {
          let atMost = 0;
          for (let x = 0; x <= n; x++) {
            atMost += t[n]![x]!;
            expect(drawsWithAtMost(N, D, n, x)).toBe(BigInt(atMost));
          }
        }
      }
    }
  });

  test("for batches to 60, every case agrees with the sum over Pascal's triangle; the fraction's denominator is C(size, sample)", () => {
    const rand = seeded(5);
    for (let i = 0; i < 3000; i++) {
      const N = intIn(rand, 1, 60);
      const D = intIn(rand, 0, N);
      const n = intIn(rand, 0, N);
      const x = intIn(rand, 0, n);
      const c = chanceAtMost(N, D, n, x);
      expect(c.num).toBe(refAtMost(N, D, n, x));
      expect(c.den).toBe(C(N, n));
    }
  });
});

describe("the bound", () => {
  test("for every batch of up to 30 items, every draw and every chance: the bound equals a linear search, and certifies exactly — not one more, not one less", () => {
    for (let N = 1; N <= 30; N++) {
      for (let n = 1; n <= N; n++) {
        for (const a of ALPHAS) {
          for (let x = 0; x <= Math.min(n, 3); x++) {
            const b = boundOf({ size: N, sample: n, found: x, alpha: a });
            expect(b).toBe(refBound(N, n, x, a));
            expect(isExactBound({ size: N, sample: n, found: x, alpha: a, bound: b })).toBe(true);
            if (b > x) expect(isExactBound({ size: N, sample: n, found: x, alpha: a, bound: b - 1 })).toBe(false);
            if (b < N - n + x) expect(isExactBound({ size: N, sample: n, found: x, alpha: a, bound: b + 1 })).toBe(false);
          }
        }
      }
    }
  });

  test("its exact coverage: for every true count of short items, the chance the bound falls below it is at most α — summed over the exact distribution", () => {
    for (const N of [8, 15, 23, 30, 47, 60]) {
      for (const n of [1, 2, Math.floor(N / 3), N - 1, N].filter((v, i, xs) => v >= 1 && xs.indexOf(v) === i)) {
        for (const a of ALPHAS) {
          const bounds = Array.from({ length: n + 1 }, (_, x) => boundOf({ size: N, sample: n, found: x, alpha: a }));
          for (let D = 0; D <= N; D++) {
            // P(D > bound(X)) = Σ_x P(X = x) · [D > bound(x)]
            let missed = 0n;
            for (let x = 0; x <= n; x++) if (D > bounds[x]!) missed += C(D, x) * C(N - D, n - x);
            expect(missed * BigInt(a.den) <= BigInt(a.num) * C(N, n)).toBe(true);
          }
        }
      }
    }
  });

  // PY-5r: the second evaluation follows from the first by one step, and a fault says which way a figure is off.
  test("the verdict says which way a stated figure is off — for every batch to 16 items, every draw, every count found and every figure", () => {
    for (let N = 1; N <= 16; N++) {
      for (let n = 1; n <= N; n++) {
        for (const a of ALPHAS) {
          for (let x = 0; x <= n; x++) {
            const b = refBound(N, n, x, a);
            for (let s = 0; s <= N; s++) {
              expect(boundVerdict({ size: N, sample: n, found: x, alpha: a, bound: s })).toBe(s === b ? "exact" : s < b ? "too low" : "too high");
            }
            expect(limitVerdict({ size: N, sample: n, accept: x, alpha: a, limit: b })).toBe("exact");
          }
        }
      }
    }
  });

  test("over seeded cases to the caps, the verdict agrees with two evaluations made directly — the one-step count for D + 1 is exact", () => {
    const rand = seeded(41);
    for (let i = 0; i < 40; i++) {
      const N = intIn(rand, 2, BATCH_MAX_SIZE);
      const n = intIn(rand, 1, Math.min(N, 2000));
      const x = intIn(rand, 0, Math.min(n, 60));
      const a = ALPHAS[intIn(rand, 0, ALPHAS.length - 1)]!;
      const total = binomial(N, n);
      const above = (d: number): boolean => drawsWithAtMost(N, d, n, x) * BigInt(a.den) > BigInt(a.num) * total;
      const ceiling = N - n + x;
      const b = boundOf({ size: N, sample: n, found: x, alpha: a });
      for (const s of [b - 2, b - 1, b, b + 1, b + 2].filter((v) => v >= x && v <= ceiling)) {
        const direct = !above(s) ? "too high" : s === ceiling || !above(s + 1) ? "exact" : "too low";
        expect(boundVerdict({ size: N, sample: n, found: x, alpha: a, bound: s })).toBe(direct);
      }
    }
  }, 60_000);

  test("a census gives the count found, exactly", () => {
    for (const N of [1, 7, 40, 500]) for (const x of [0, 1, Math.floor(N / 2)].filter((v) => v <= N)) expect(boundOf({ size: N, sample: N, found: x, alpha: { num: 1, den: 20 } })).toBe(x);
  });

  test("monotone, over seeded cases to 5,000 items: fewer short items never make a clean draw less likely; a larger draw never makes it more likely; more found is never less likely", () => {
    const rand = seeded(11);
    for (let i = 0; i < 300; i++) {
      const N = intIn(rand, 2, 5000);
      const n = intIn(rand, 1, Math.min(N - 1, 400));
      const D = intIn(rand, 0, N - 1);
      const x = intIn(rand, 0, Math.min(n, 5));
      const at = (d: number, s: number, f: number): { num: bigint; den: bigint } => chanceAtMost(N, d, s, f);
      const lt = (p: { num: bigint; den: bigint }, q: { num: bigint; den: bigint }): boolean => p.num * q.den <= q.num * p.den;
      expect(lt(at(D + 1, n, x), at(D, n, x))).toBe(true);
      expect(lt(at(D, n + 1, x), at(D, n, x))).toBe(true);
      if (x < n) expect(lt(at(D, n, x), at(D, n, x + 1))).toBe(true);
    }
  });
});

describe("the plan", () => {
  test("planFor gives the smallest draw: it meets the wanted limit, one fewer does not, and its own limit is within the one wanted", () => {
    const rand = seeded(23);
    for (let i = 0; i < 60; i++) {
      const size = intIn(rand, 20, 20_000);
      const limit = intIn(rand, 1, Math.floor(size / 10));
      const accept = intIn(rand, 0, Math.min(3, limit));
      const alpha = ALPHAS[intIn(rand, 1, ALPHAS.length - 1)]!;
      let plan: { sample: number; limit: number };
      try {
        plan = planFor({ size, limit, accept, alpha });
      } catch {
        continue; // a plan that would need more than the cap is refused — tested below
      }
      const meets = (n: number): boolean => !(drawsWithAtMost(size, limit + 1, n, accept) * BigInt(alpha.den) > BigInt(alpha.num) * binomial(size, n));
      expect(meets(plan.sample)).toBe(true);
      if (plan.sample - 1 > accept) expect(meets(plan.sample - 1)).toBe(false);
      expect(plan.limit).toBeLessThanOrEqual(limit);
      expect(plan.limit).toBe(limitOf({ size, sample: plan.sample, accept, alpha }));
      expect(isExactLimit({ size, sample: plan.sample, accept, alpha, limit: plan.limit })).toBe(true);
    }
  });

  test("accepting with no more found than the plan accepts keeps the bound within the plan's limit", () => {
    const rand = seeded(31);
    for (let i = 0; i < 200; i++) {
      const size = intIn(rand, 10, 3000);
      const sample = intIn(rand, 2, Math.min(size, 300));
      const accept = intIn(rand, 0, Math.min(sample - 1, 4));
      const alpha = ALPHAS[intIn(rand, 0, ALPHAS.length - 1)]!;
      const limit = limitOf({ size, sample, accept, alpha });
      for (let x = 0; x <= accept; x++) expect(boundOf({ size, sample, found: x, alpha })).toBeLessThanOrEqual(limit);
    }
  });

  test("a plan that needs more than the cap is refused, with what to change", () => {
    expect(() => planFor({ size: BATCH_MAX_SIZE, limit: 10, accept: 0, alpha: { num: 1, den: 1000 } })).toThrow(/needs more than 10000 items checked/);
  });

  test("the textbook figures: 140 of 2,000 for a limit of 40 at 1 in 20 with none found; 2,987 of 1,000,000 for a limit of 1,000", () => {
    expect(planFor({ size: 2000, limit: 40, accept: 0, alpha: { num: 1, den: 20 } })).toEqual({ sample: 140, limit: 40 });
    expect(planFor({ size: 1_000_000, limit: 1000, accept: 0, alpha: { num: 1, den: 20 } }).sample).toBe(2987);
  });
});

describe("limits", () => {
  test("a chance is two whole numbers, at most 1 in 2, with a denominator up to 1,000,000", () => {
    expect(alphaProblem({ num: 1, den: 20 })).toBeNull();
    expect(alphaProblem({ num: 1, den: 2 })).toBeNull();
    expect(alphaProblem({ num: 3, den: 4 })).toContain("above 1 in 2");
    expect(alphaProblem({ num: 0, den: 20 })).not.toBeNull();
    expect(alphaProblem({ num: 1, den: ALPHA_MAX_DEN + 1 })).not.toBeNull();
    expect(alphaProblem({ num: 1.5, den: 20 })).not.toBeNull();
  });

  test("out-of-range inputs are refused, never computed", () => {
    expect(() => boundOf({ size: BATCH_MAX_SIZE + 1, sample: 10, found: 0, alpha: { num: 1, den: 20 } })).toThrow();
    expect(() => boundOf({ size: 100_000, sample: BATCH_MAX_SAMPLE + 1, found: 0, alpha: { num: 1, den: 20 } })).toThrow();
    expect(() => boundOf({ size: 100, sample: 10, found: 11, alpha: { num: 1, den: 20 } })).toThrow();
    expect(isExactBound({ size: 100, sample: 10, found: 2, alpha: { num: 1, den: 20 }, bound: 1 })).toBe(false);
  });

  test("certifying a bound at both caps stays under a second", () => {
    const a = { num: 1, den: 20 };
    const bound = 772; // boundOf at these caps, measured once
    const t = performance.now();
    expect(isExactBound({ size: BATCH_MAX_SIZE, sample: BATCH_MAX_SAMPLE, found: 3, alpha: a, bound })).toBe(true);
    expect(performance.now() - t).toBeLessThan(1000);
  }, 30_000);

  // PY-5r: the more found, the longer the sum. Certifying with half the draw found short took about 8 seconds (two
  // evaluations of 5,000 big-number products each, measured 2026-11-26); now each term is one small step.
  test("certifying at both caps stays under a second at the costliest count found — half the draw — and refuses one more and one less", () => {
    const a = { num: 1, den: 20 };
    const bound = 508_232; // boundOf at these caps with 5,000 found, measured once
    const t = performance.now();
    expect(isExactBound({ size: BATCH_MAX_SIZE, sample: BATCH_MAX_SAMPLE, found: 5000, alpha: a, bound })).toBe(true);
    expect(performance.now() - t).toBeLessThan(1000);
    expect(isExactBound({ size: BATCH_MAX_SIZE, sample: BATCH_MAX_SAMPLE, found: 5000, alpha: a, bound: bound + 1 })).toBe(false);
    expect(isExactBound({ size: BATCH_MAX_SIZE, sample: BATCH_MAX_SAMPLE, found: 5000, alpha: a, bound: bound - 1 })).toBe(false);
  }, 60_000);
});

describe("batch-chance@1 — the conformance file", () => {
  interface Case {
    readonly name: string;
    readonly size: number;
    readonly sample: number;
    readonly found: number;
    readonly alpha: Alpha;
    readonly short: number;
    readonly drawsWithAtMost: string;
    readonly draws: string;
    readonly bound: number;
  }
  const file = JSON.parse(readFileSync(join(import.meta.dir, "..", "..", "..", "specs", "attestation", "tck", "batch-chance@1", "cases.json"), "utf8")) as { cases: Case[] };

  test("every case reaches its stated counts and bound", () => {
    expect(file.cases.length).toBeGreaterThanOrEqual(10);
    for (const c of file.cases) {
      const ch = chanceAtMost(c.size, c.short, c.sample, c.found);
      expect(ch.num.toString()).toBe(c.drawsWithAtMost);
      expect(ch.den.toString()).toBe(c.draws);
      expect(boundOf({ size: c.size, sample: c.sample, found: c.found, alpha: c.alpha })).toBe(c.bound);
    }
  });
});
