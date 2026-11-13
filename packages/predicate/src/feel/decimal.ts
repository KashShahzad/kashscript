/**
 * FEEL's number: a decimal, never a binary float (DMN §10.3.2.3.1 — IEEE 754
 * decimal128 semantics: 34 significant digits, rounding half to even).
 *
 * A value is `coefficient × 10^exponent`, both exact. Sums of money therefore
 * never drift (0.1 + 0.2 = 0.3), and every platform — a phone, a browser, a
 * server — computes the same bits. No dependency: BigInt only.
 */

const SIGNIFICANT = 34;
const TEN = 10n;

function digitsOf(c: bigint): number {
  const s = c < 0n ? (-c).toString() : c.toString();
  return c === 0n ? 1 : s.length;
}

function pow10(n: number): bigint {
  return TEN ** BigInt(n);
}

export class Decimal {
  private constructor(
    /** Signed coefficient. Normalised: no trailing zeros unless the value is zero. */
    readonly coefficient: bigint,
    readonly exponent: number,
  ) {}

  static readonly ZERO = new Decimal(0n, 0);
  static readonly ONE = new Decimal(1n, 0);

  /** Build, normalise, and round to 34 significant digits. */
  static of(coefficient: bigint, exponent: number, sticky = false): Decimal {
    let c = coefficient;
    let e = exponent;
    const d = digitsOf(c);
    if (d > SIGNIFICANT) {
      // Round half to even on the magnitude. `sticky` says digits were already
      // dropped below these (a division's remainder), so an exact half is more.
      const drop = d - SIGNIFICANT;
      const div = pow10(drop);
      const neg = c < 0n;
      const abs = neg ? -c : c;
      let q = abs / div;
      const twice = (abs % div) * 2n;
      if (twice > div || (twice === div && (sticky || q % 2n === 1n))) q += 1n;
      c = neg ? -q : q;
      e += drop;
      if (digitsOf(c) > SIGNIFICANT) {
        c /= TEN; // 99…9 rounded up to 100…0: the dropped digit is a zero
        e += 1;
      }
    }
    if (c === 0n) return new Decimal(0n, 0);
    while (c % TEN === 0n) {
      c /= TEN;
      e += 1;
    }
    return new Decimal(c, e);
  }

  /** A FEEL numeric literal or a plain decimal string: `-12`, `3.50`, `.5`, `1e3` (exponent allowed only here, for JSON input). */
  static parse(text: string): Decimal | null {
    const m = /^([+-])?(\d+)?(?:\.(\d*))?(?:[eE]([+-]?\d{1,6}))?$/.exec(text.trim());
    if (m === null) return null;
    const int = m[2] ?? "";
    const frac = m[3] ?? "";
    if (int === "" && frac === "") return null;
    const sign = m[1] === "-" ? -1n : 1n;
    const exp = (m[4] !== undefined ? Number.parseInt(m[4], 10) : 0) - frac.length;
    const c = BigInt((int || "0") + frac) * sign;
    return Decimal.of(c, exp);
  }

  /** A JSON number. NaN and the infinities are not numbers in FEEL. */
  static fromNumber(n: number): Decimal | null {
    if (!Number.isFinite(n)) return null;
    return Decimal.parse(String(n));
  }

  static fromInt(n: number | bigint): Decimal {
    return Decimal.of(BigInt(n), 0);
  }

  isZero(): boolean {
    return this.coefficient === 0n;
  }

  isInteger(): boolean {
    return this.exponent >= 0;
  }

  sign(): -1 | 0 | 1 {
    return this.coefficient === 0n ? 0 : this.coefficient < 0n ? -1 : 1;
  }

  neg(): Decimal {
    return new Decimal(-this.coefficient, this.exponent);
  }

  private static align(a: Decimal, b: Decimal): [bigint, bigint, number] {
    const e = Math.min(a.exponent, b.exponent);
    return [a.coefficient * pow10(a.exponent - e), b.coefficient * pow10(b.exponent - e), e];
  }

  add(b: Decimal): Decimal {
    const [x, y, e] = Decimal.align(this, b);
    return Decimal.of(x + y, e);
  }

  sub(b: Decimal): Decimal {
    return this.add(b.neg());
  }

  mul(b: Decimal): Decimal {
    return Decimal.of(this.coefficient * b.coefficient, this.exponent + b.exponent);
  }

  /** Null on division by zero, as FEEL says. */
  div(b: Decimal): Decimal | null {
    if (b.coefficient === 0n) return null;
    if (this.coefficient === 0n) return Decimal.ZERO;
    const shift = Math.max(0, SIGNIFICANT + 2 + digitsOf(b.coefficient) - digitsOf(this.coefficient));
    const n = this.coefficient * pow10(shift);
    const q = n / b.coefficient;
    const r = n % b.coefficient;
    return Decimal.of(q, this.exponent - b.exponent - shift, r !== 0n);
  }

  cmp(b: Decimal): -1 | 0 | 1 {
    const [x, y] = Decimal.align(this, b);
    return x < y ? -1 : x > y ? 1 : 0;
  }

  eq(b: Decimal): boolean {
    return this.coefficient === b.coefficient && this.exponent === b.exponent;
  }

  /** Exact integer value, or null when it has a fraction. */
  toBigInt(): bigint | null {
    if (this.exponent < 0) return null;
    return this.coefficient * pow10(this.exponent);
  }

  /** The nearest JS number (display and small integer use only — never for arithmetic). */
  toNumber(): number {
    return Number(this.toString());
  }

  /** Plain notation, no exponent: `1500.5`, `-0.25`, `100`. */
  toString(): string {
    const neg = this.coefficient < 0n;
    const digits = (neg ? -this.coefficient : this.coefficient).toString();
    let out: string;
    if (this.exponent >= 0) out = digits + "0".repeat(this.exponent);
    else {
      const point = digits.length + this.exponent;
      out = point > 0 ? `${digits.slice(0, point)}.${digits.slice(point)}` : `0.${"0".repeat(-point)}${digits}`;
    }
    return neg ? `-${out}` : out;
  }
}
