/**
 * FEEL values in the subset, FEEL equality and ordering, and the typed input
 * a criterion's claims become (DMN's itemDefinition role: a JSON string is a
 * `date` only because the rule says that claim is a date).
 */

import { Decimal } from "./decimal";
import {
  formatTemporal,
  instantOf,
  parseDate,
  parseDateTime,
  parseDuration,
  epochDay,
  type DaysTimeDuration,
  type FeelDate,
  type FeelDateTime,
  type Temporal,
  type YearsMonthsDuration,
} from "./temporal";

/** A FEEL context: ordered, string-keyed. Its own class, so a context is never confused with a temporal value. */
export class FeelContext {
  constructor(readonly entries: ReadonlyMap<string, FeelValue>) {}

  static from(obj: Readonly<Record<string, FeelValue>>): FeelContext {
    return new FeelContext(new Map(Object.entries(obj)));
  }

  get(name: string): FeelValue {
    return this.entries.has(name) ? (this.entries.get(name) as FeelValue) : null;
  }

  has(name: string): boolean {
    return this.entries.has(name);
  }
}

export type FeelValue = null | boolean | string | Decimal | Temporal | readonly FeelValue[] | FeelContext;

export type FeelTypeName =
  | "null"
  | "boolean"
  | "string"
  | "number"
  | "date"
  | "date and time"
  | "days and time duration"
  | "years and months duration"
  | "list"
  | "context";

export function typeOf(v: FeelValue): FeelTypeName {
  if (v === null) return "null";
  if (typeof v === "boolean") return "boolean";
  if (typeof v === "string") return "string";
  if (v instanceof Decimal) return "number";
  if (v instanceof FeelContext) return "context";
  if (Array.isArray(v)) return "list";
  return (v as Temporal).kind;
}

export const isList = (v: FeelValue): v is readonly FeelValue[] => Array.isArray(v);

/**
 * FEEL `=`. Null equals only null. Values of different types are not
 * comparable, so the answer is null (DMN §10.3.2.9.1); lists and contexts
 * compare element by element.
 */
export function feelEquals(a: FeelValue, b: FeelValue): boolean | null {
  if (a === null || b === null) return a === null && b === null;
  const ta = typeOf(a);
  const tb = typeOf(b);
  if (ta !== tb) return null;
  switch (ta) {
    case "boolean":
    case "string":
      return a === b;
    case "number":
      return (a as Decimal).eq(b as Decimal);
    case "date": {
      const x = a as FeelDate;
      const y = b as FeelDate;
      return x.year === y.year && x.month === y.month && x.day === y.day;
    }
    case "date and time":
      return instantOf(a as FeelDateTime) === instantOf(b as FeelDateTime);
    case "days and time duration":
      return (a as DaysTimeDuration).nanos === (b as DaysTimeDuration).nanos;
    case "years and months duration":
      return (a as YearsMonthsDuration).months === (b as YearsMonthsDuration).months;
    case "list": {
      const x = a as readonly FeelValue[];
      const y = b as readonly FeelValue[];
      if (x.length !== y.length) return false;
      for (let i = 0; i < x.length; i++) {
        const e = feelEquals(x[i]!, y[i]!);
        if (e !== true) return e;
      }
      return true;
    }
    case "context": {
      const x = (a as FeelContext).entries;
      const y = (b as FeelContext).entries;
      if (x.size !== y.size) return false;
      for (const [k, v] of x) {
        if (!y.has(k)) return false;
        const e = feelEquals(v, y.get(k)!);
        if (e !== true) return e;
      }
      return true;
    }
    default:
      return null;
  }
}

/** FEEL ordering: -1, 0, 1, or null when the two are not of one ordered type. */
export function feelCompare(a: FeelValue, b: FeelValue): -1 | 0 | 1 | null {
  if (a === null || b === null) return null;
  const ta = typeOf(a);
  if (ta !== typeOf(b)) return null;
  const cmp = (x: number | bigint, y: number | bigint): -1 | 0 | 1 => (x < y ? -1 : x > y ? 1 : 0);
  switch (ta) {
    case "number":
      return (a as Decimal).cmp(b as Decimal);
    case "string": {
      const x = a as string;
      const y = b as string;
      return x < y ? -1 : x > y ? 1 : 0;
    }
    case "date": {
      const x = a as FeelDate;
      const y = b as FeelDate;
      return cmp(epochDay(x.year, x.month, x.day), epochDay(y.year, y.month, y.day));
    }
    case "date and time":
      return cmp(instantOf(a as FeelDateTime), instantOf(b as FeelDateTime));
    case "days and time duration":
      return cmp((a as DaysTimeDuration).nanos, (b as DaysTimeDuration).nanos);
    case "years and months duration":
      return cmp((a as YearsMonthsDuration).months, (b as YearsMonthsDuration).months);
    default:
      return null;
  }
}

/* ── typed input: what a claim becomes ─────────────────────────────────── */

/** The DMN types a rule may give a claim it reads. */
export const SCALAR_TYPES = [
  "string",
  "number",
  "boolean",
  "date",
  "date and time",
  "days and time duration",
  "years and months duration",
] as const;
export type ScalarType = (typeof SCALAR_TYPES)[number];
/** `list of <scalar>` — DMN's collection itemDefinition. */
export type InputType = ScalarType | `list of ${ScalarType}`;

export function isInputType(t: unknown): t is InputType {
  if (typeof t !== "string") return false;
  const base = t.startsWith("list of ") ? t.slice("list of ".length) : t;
  return (SCALAR_TYPES as readonly string[]).includes(base);
}

const NUMERIC_STRING = /^-?(?:\d+(?:\.\d+)?|\.\d+)$/;

function scalarFrom(json: unknown, type: ScalarType): FeelValue {
  switch (type) {
    case "string":
      return typeof json === "string" ? json : null;
    case "boolean":
      return typeof json === "boolean" ? json : null;
    case "number":
      if (typeof json === "number") return Decimal.fromNumber(json);
      if (typeof json === "string" && NUMERIC_STRING.test(json)) return Decimal.parse(json);
      return null;
    case "date":
      return typeof json === "string" ? parseDate(json) : null;
    case "date and time":
      return typeof json === "string" ? parseDateTime(json) : null;
    case "days and time duration": {
      const d = typeof json === "string" ? parseDuration(json) : null;
      return d !== null && d.kind === "days and time duration" ? d : null;
    }
    case "years and months duration": {
      const d = typeof json === "string" ? parseDuration(json) : null;
      return d !== null && d.kind === "years and months duration" ? d : null;
    }
  }
}

/** A JSON claim as the typed FEEL value the rule declares. A value that does not read as its type is null — never coerced. */
export function fromJson(json: unknown, type: InputType): FeelValue {
  if (json === undefined || json === null) return null;
  if (type.startsWith("list of ")) {
    if (!Array.isArray(json)) return null;
    const inner = type.slice("list of ".length) as ScalarType;
    return json.map((j) => scalarFrom(j, inner));
  }
  return scalarFrom(json, type as ScalarType);
}

/* ── display ───────────────────────────────────────────────────────────── */

export function show(v: FeelValue): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return String(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (v instanceof Decimal) return v.toString();
  if (v instanceof FeelContext) return `{${[...v.entries].map(([k, x]) => `${k}: ${show(x)}`).join(", ")}}`;
  if (Array.isArray(v)) return `[${v.map(show).join(", ")}]`;
  return formatTemporal(v as Temporal);
}
