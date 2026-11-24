/**
 * The display rule for counts (ECOSYSTEM d97(i): *k* = 5 wherever a count is shown; d85(b)11: no total traces back
 * to a person; d91(f) and its dated note of 2026-11-20).
 *
 * This is the display half of the founder's ruling — *noise first, then k = 5 as display*. The noise and its ε are
 * KS-Q7's and not built. Suppressing raw counts still leaks by differencing across time and across overlapping
 * windows (`specs/attestation/README.md` §3.3); what this module stops is a count below k being shown, and a total
 * giving a hidden part away by subtraction.
 *
 * `FloorCount` is a branded number: only `suppress` makes one, so an aggregate typed with it cannot carry a raw count
 * past the repository's own type check, and the scanner refuses a cast to it.
 */

declare const floorCountBrand: unique symbol;

/** A count that passed the floor: a number at or above k, or `null`, which reads *fewer than k*. */
export type FloorCount = (number & { readonly [floorCountBrand]: true }) | null;

/** A total beside its parts: a `FloorCount`, or `"withheld"` when showing it would let a part below k be worked out. */
export type FloorTotal = FloorCount | "withheld";

/** d97(i). A larger k may be passed; a smaller one never. */
export const FLOOR_K = 5;

function checkK(k: number): void {
  if (!Number.isInteger(k) || k < FLOOR_K) {
    throw new RangeError(`suppress: k must be a whole number of at least ${FLOOR_K} (d97(i)); got ${String(k)}`);
  }
}

function checkCount(n: number, what: string): void {
  if (typeof n !== "number" || !Number.isFinite(n)) {
    throw new TypeError(`${what}: a count must be a finite number; got ${String(n)}`);
  }
}

/**
 * A count at or above k is shown; below it, `null` — the display says *fewer than k*. Zero is below k, and so is a
 * negative value, which a noised count can be.
 */
export function suppress(n: number, k: number = FLOOR_K): FloorCount {
  checkK(k);
  checkCount(n, "suppress");
  return n >= k ? (n as FloorCount) : null;
}

export interface SeriesOptions {
  /** At least 5. */
  readonly k?: number;
  /** The total, when it is not the sum of the cells (it may not be smaller than their sum). */
  readonly total?: number;
}

export interface FloorSeries<K extends string> {
  readonly cells: { readonly [P in K]: FloorCount };
  readonly total: FloorTotal;
}

export interface FloorList {
  readonly cells: readonly FloorCount[];
  readonly total: FloorTotal;
}

/**
 * A series and its total, suppressed together. Each cell passes `suppress`. A total below k reads *fewer than k*,
 * like any count. A total of k or more is `"withheld"` whenever the part a reader cannot see — the total less the
 * shown cells — is above zero, because subtracting gives it away (and several hidden cells, each known to be below k,
 * can be solved from their sum); otherwise it is shown. A withheld total is never shown as *fewer than k*, which would
 * be false, and a hidden remainder of zero withholds nothing: it identifies no one. The audit publishes no series
 * until its privacy bound is designed (d97(i), d95(d)); this is for a host's own display.
 *
 * It is a rule about parts, so it fits any whole and its parts — twelve months and the year, decisions and the
 * practice ones among them.
 */
export function suppressSeries<K extends string>(cells: Readonly<Record<K, number>>, opts?: SeriesOptions): FloorSeries<K>;
export function suppressSeries(cells: readonly number[], opts?: SeriesOptions): FloorList;
export function suppressSeries(cells: Readonly<Record<string, number>> | readonly number[], opts: SeriesOptions = {}): FloorSeries<string> | FloorList {
  const k = opts.k ?? FLOOR_K;
  checkK(k);
  const values = Array.isArray(cells) ? (cells as readonly number[]) : Object.values(cells as Readonly<Record<string, number>>);
  for (const v of values) checkCount(v, "suppressSeries");
  const sum = values.reduce((a, b) => a + b, 0);
  const raw = opts.total ?? sum;
  checkCount(raw, "suppressSeries");
  if (raw < sum) throw new RangeError(`suppressSeries: the total (${raw}) is smaller than the sum of its cells (${sum})`);
  const shownSum = values.filter((v) => v >= k).reduce((a, b) => a + b, 0);
  const workedOut = raw - shownSum;
  // Withheld whenever any part is hidden and the hidden remainder is above zero: two hidden parts of 4 sum to 8, and a
  // reader who knows each is below 5 then knows both. Only a remainder of zero, which names no one, lets it show.
  const total: FloorTotal = raw >= k && workedOut > 0 ? "withheld" : suppress(raw, k);
  if (Array.isArray(cells)) return { cells: (cells as readonly number[]).map((v) => suppress(v, k)), total };
  const out: Record<string, FloorCount> = {};
  for (const [key, v] of Object.entries(cells as Readonly<Record<string, number>>)) out[key] = suppress(v, k);
  return { cells: out, total };
}
