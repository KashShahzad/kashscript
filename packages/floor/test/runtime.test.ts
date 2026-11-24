import { describe, expect, test } from "bun:test";
import { FLOOR_K, RULES, suppress, suppressSeries } from "../src/index.js";

describe("suppress — the display rule (d97(i))", () => {
  test("k is 5", () => {
    expect(FLOOR_K).toBe(5);
  });

  test("a count at or above k is shown; below it, null", () => {
    expect(suppress(5)).toBe(5 as never);
    expect(suppress(1234)).toBe(1234 as never);
    expect(suppress(4)).toBeNull();
    expect(suppress(1)).toBeNull();
  });

  test("zero and a negative (noised) value read as fewer than k", () => {
    expect(suppress(0)).toBeNull();
    expect(suppress(-2.5)).toBeNull();
  });

  test("a larger k may be passed; a smaller one, a fraction or nonsense never", () => {
    expect(suppress(6, 7)).toBeNull();
    expect(suppress(7, 7)).toBe(7 as never);
    expect(() => suppress(9, 4)).toThrow(/at least 5/);
    expect(() => suppress(9, 5.5)).toThrow(RangeError);
    expect(() => suppress(Number.NaN)).toThrow(TypeError);
    expect(() => suppress(Number.POSITIVE_INFINITY)).toThrow(TypeError);
  });
});

describe("suppressSeries — a whole and its parts", () => {
  test("every part shown: the total is shown", () => {
    const s = suppressSeries({ jan: 7, feb: 9 });
    expect(s.cells).toEqual({ jan: 7, feb: 9 } as never);
    expect(s.total).toBe(16 as never);
  });

  test("a hidden part the total would give away by subtraction: the total is withheld", () => {
    const s = suppressSeries([7, 3, 9]);
    expect(s.cells).toEqual([7, null, 9] as never);
    expect(s.total).toBe("withheld");
  });

  test("several hidden parts withhold the total too: two hidden 4s sum to 8, and each is known to be below 5", () => {
    const s = suppressSeries([10, 4, 4]);
    expect(s.cells).toEqual([10, null, null] as never);
    expect(s.total).toBe("withheld");
    expect(suppressSeries({ a: 10, b: 4, c: 4, d: 4 }).total).toBe("withheld");
  });

  test("a hidden remainder of zero withholds nothing: it identifies no one", () => {
    const s = suppressSeries([0, 0, 12]);
    expect(s.total).toBe(12 as never);
  });

  test("a small total reads fewer than k; withheld is never used for it", () => {
    expect(suppressSeries([1, 2]).total).toBeNull();
  });

  test("a total that is not the sum (a longer window) is suppressed with the same rule", () => {
    expect(suppressSeries([6, 6], { total: 15 }).total).toBe("withheld");
    expect(suppressSeries([6, 6], { total: 12 }).total).toBe(12 as never);
    expect(() => suppressSeries([6, 6], { total: 3 })).toThrow(/smaller than the sum/);
  });

  test("k below 5 is refused", () => {
    expect(() => suppressSeries([1], { k: 3 })).toThrow(/at least 5/);
  });
});

describe("RULES", () => {
  test("seven rules, each naming its decisions", () => {
    expect(Object.keys(RULES).sort()).toEqual(["decision-without-rule", "declined-state", "person-lookup", "person-score", "price-per-record", "undeclared-route", "unsuppressed-count"]);
    for (const r of Object.values(RULES)) expect(r.decisions.length).toBeGreaterThan(0);
  });
});
