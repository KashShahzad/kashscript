/**
 * The FEEL subset's evaluator. Pure: no clock, no network, no randomness, no
 * global state. Every loop runs over a finite list the input supplied, and a
 * step budget stops a pathological rule, so evaluating a stranger's rule
 * always ends — with an answer, or with null.
 *
 * FEEL's semantics for a value of the wrong type is null, never an exception,
 * and that is what this returns.
 */

import { Decimal } from "./decimal";
import { BUILTINS, type Builtin, type Node, type Test } from "./parser";
import {
  dateAddMonths,
  dateAddNanos,
  dateMinusDate,
  dateTimeAddMonths,
  dateTimeAddNanos,
  dateTimeMinus,
  dtDuration,
  localNanosOfDay,
  makeDate,
  monthsBetween,
  NANOS_PER_DAY,
  NANOS_PER_SECOND,
  parseDate,
  parseDateTime,
  parseDuration,
  ymDuration,
  type DaysTimeDuration,
  type FeelDate,
  type FeelDateTime,
  type YearsMonthsDuration,
} from "./temporal";
import { feelCompare, feelEquals, FeelContext, typeOf, type FeelValue } from "./values";

export const DEFAULT_BUDGET = 100_000;

export class BudgetExceeded extends Error {
  constructor() {
    super("the condition took more steps than its budget");
    this.name = "BudgetExceeded";
  }
}

/** Variables in scope: a chain, innermost first. */
export class Scope {
  constructor(
    private readonly vars: ReadonlyMap<string, FeelValue>,
    private readonly parent: Scope | null = null,
    /** A filter's current item: its entries resolve before the outer scope. */
    private readonly item: FeelValue | undefined = undefined,
  ) {}

  static of(vars: Readonly<Record<string, FeelValue>>): Scope {
    return new Scope(new Map(Object.entries(vars)));
  }

  child(vars: ReadonlyMap<string, FeelValue>): Scope {
    return new Scope(vars, this);
  }

  withItem(item: FeelValue): Scope {
    return new Scope(new Map([["item", item]]), this, item);
  }

  lookup(name: string): FeelValue | undefined {
    if (this.item instanceof FeelContext && this.item.has(name)) return this.item.get(name);
    if (this.vars.has(name)) return this.vars.get(name);
    return this.parent?.lookup(name);
  }
}

interface Ctx {
  steps: number;
  readonly budget: number;
}

const isDate = (v: FeelValue): v is FeelDate => typeOf(v) === "date";
const isDateTime = (v: FeelValue): v is FeelDateTime => typeOf(v) === "date and time";
const isDtd = (v: FeelValue): v is DaysTimeDuration => typeOf(v) === "days and time duration";
const isYmd = (v: FeelValue): v is YearsMonthsDuration => typeOf(v) === "years and months duration";
const isNum = (v: FeelValue): v is Decimal => v instanceof Decimal;
const isList = (v: FeelValue): v is readonly FeelValue[] => Array.isArray(v);

/** A date as the date-time at its midnight, UTC — how FEEL subtracts a date from a date-time. */
function midnightUtc(d: FeelDate): FeelDateTime {
  return { kind: "date and time", year: d.year, month: d.month, day: d.day, hour: 0, minute: 0, second: 0, nanos: 0, offsetMinutes: 0 };
}

/** n × months, truncated toward zero (TCK 0100: P1Y11M × −2.5 = −P4Y9M). */
function scaleMonths(months: number, factor: Decimal, divide: boolean): YearsMonthsDuration | null {
  const r = divide ? Decimal.fromInt(months).div(factor) : Decimal.fromInt(months).mul(factor);
  if (r === null) return null;
  const t = truncate(r);
  return t === null || !Number.isSafeInteger(Number(t)) ? null : ymDuration(Number(t));
}

function scaleNanos(nanos: bigint, factor: Decimal, divide: boolean): DaysTimeDuration | null {
  const r = divide ? Decimal.of(nanos, 0).div(factor) : Decimal.of(nanos, 0).mul(factor);
  if (r === null) return null;
  const t = truncate(r);
  return t === null ? null : dtDuration(t);
}

function truncate(d: Decimal): bigint | null {
  if (d.exponent >= 0) return d.toBigInt();
  const div = 10n ** BigInt(-d.exponent);
  return d.coefficient / div;
}

function arith(op: "+" | "-" | "*" | "/", a: FeelValue, b: FeelValue): FeelValue {
  if (a === null || b === null) return null;
  if (isNum(a) && isNum(b)) {
    switch (op) {
      case "+":
        return a.add(b);
      case "-":
        return a.sub(b);
      case "*":
        return a.mul(b);
      case "/":
        return a.div(b);
    }
  }
  if (op === "+" && typeof a === "string" && typeof b === "string") return a + b;
  if (op === "+" || op === "-") {
    const sign = op === "+" ? 1 : -1;
    if (isYmd(a) && isYmd(b)) return ymDuration(a.months + sign * b.months);
    if (isDtd(a) && isDtd(b)) return dtDuration(op === "+" ? a.nanos + b.nanos : a.nanos - b.nanos);
    if (isDate(a) && isYmd(b)) return dateAddMonths(a, sign * b.months);
    if (isDateTime(a) && isYmd(b)) return dateTimeAddMonths(a, sign * b.months);
    if (isDate(a) && isDtd(b)) return dateAddNanos(a, op === "+" ? b.nanos : -b.nanos);
    if (isDateTime(a) && isDtd(b)) return dateTimeAddNanos(a, op === "+" ? b.nanos : -b.nanos);
    if (op === "+") {
      if (isYmd(a) && isDate(b)) return dateAddMonths(b, a.months);
      if (isYmd(a) && isDateTime(b)) return dateTimeAddMonths(b, a.months);
      if (isDtd(a) && isDate(b)) return dateAddNanos(b, a.nanos);
      if (isDtd(a) && isDateTime(b)) return dateTimeAddNanos(b, a.nanos);
    } else {
      if (isDate(a) && isDate(b)) return dateMinusDate(a, b);
      if (isDateTime(a) && isDateTime(b)) return dateTimeMinus(a, b);
      if (isDate(a) && isDateTime(b)) return dateTimeMinus(midnightUtc(a), b);
      if (isDateTime(a) && isDate(b)) return dateTimeMinus(a, midnightUtc(b));
    }
    return null;
  }
  if (op === "*") {
    if (isYmd(a) && isNum(b)) return scaleMonths(a.months, b, false);
    if (isNum(a) && isYmd(b)) return scaleMonths(b.months, a, false);
    if (isDtd(a) && isNum(b)) return scaleNanos(a.nanos, b, false);
    if (isNum(a) && isDtd(b)) return scaleNanos(b.nanos, a, false);
    return null;
  }
  // "/"
  if (isYmd(a) && isNum(b)) return scaleMonths(a.months, b, true);
  if (isDtd(a) && isNum(b)) return scaleNanos(a.nanos, b, true);
  if (isYmd(a) && isYmd(b)) return Decimal.fromInt(a.months).div(Decimal.fromInt(b.months));
  if (isDtd(a) && isDtd(b)) return Decimal.of(a.nanos, 0).div(Decimal.of(b.nanos, 0));
  return null;
}

function and3(a: FeelValue, b: () => FeelValue): boolean | null {
  if (a === false) return false;
  const rb = b();
  if (rb === false) return false;
  return a === true && rb === true ? true : null;
}

function or3(a: FeelValue, b: () => FeelValue): boolean | null {
  if (a === true) return true;
  const rb = b();
  if (rb === true) return true;
  return a === false && rb === false ? false : null;
}

function cmpOp(op: string, a: FeelValue, b: FeelValue): boolean | null {
  if (op === "=") return feelEquals(a, b);
  if (op === "!=") {
    const e = feelEquals(a, b);
    return e === null ? null : !e;
  }
  const c = feelCompare(a, b);
  if (c === null) return null;
  switch (op) {
    case "<":
      return c < 0;
    case "<=":
      return c <= 0;
    case ">":
      return c > 0;
    default:
      return c >= 0;
  }
}

function property(v: FeelValue, name: string): FeelValue {
  if (v instanceof FeelContext) return v.get(name);
  if (isDate(v) || isDateTime(v)) {
    if (name === "year") return Decimal.fromInt(v.year);
    if (name === "month") return Decimal.fromInt(v.month);
    if (name === "day") return Decimal.fromInt(v.day);
    if (isDateTime(v)) {
      if (name === "hour") return Decimal.fromInt(v.hour);
      if (name === "minute") return Decimal.fromInt(v.minute);
      if (name === "second") return Decimal.of(BigInt(v.second) * NANOS_PER_SECOND + BigInt(v.nanos), -9);
    }
    return null;
  }
  if (isYmd(v)) {
    const sign = v.months < 0 ? -1 : 1;
    if (name === "years") return Decimal.fromInt(sign * Math.floor(Math.abs(v.months) / 12));
    if (name === "months") return Decimal.fromInt(sign * (Math.abs(v.months) % 12));
    return null;
  }
  if (isDtd(v)) {
    const neg = v.nanos < 0n;
    let n = neg ? -v.nanos : v.nanos;
    const days = n / NANOS_PER_DAY;
    n -= days * NANOS_PER_DAY;
    const secs = n / NANOS_PER_SECOND;
    const s = (x: bigint): Decimal => Decimal.of(neg ? -x : x, 0);
    if (name === "days") return s(days);
    if (name === "hours") return s(secs / 3600n);
    if (name === "minutes") return s((secs % 3600n) / 60n);
    if (name === "seconds") return s(secs % 60n);
    return null;
  }
  return null;
}

/** Bind a call's arguments to one of the builtin's signatures, by position or by name. */
function bindArgs(fn: Builtin, args: readonly FeelValue[], named: Readonly<Record<string, FeelValue>> | null): readonly FeelValue[] | null {
  const sigs = BUILTINS[fn] as readonly (readonly string[] | "variadic")[];
  if (named === null) {
    if (sigs.includes("variadic") && args.length >= 1) return args;
    return sigs.some((s) => s !== "variadic" && s.length === args.length) ? args : null;
  }
  const keys = Object.keys(named);
  for (const s of sigs) {
    if (s === "variadic") continue;
    if (s.length === keys.length && s.every((p) => keys.includes(p))) return s.map((p) => named[p]!);
  }
  return null;
}

function listArg(fn: Builtin, args: readonly FeelValue[]): readonly FeelValue[] | null {
  const variadic = (BUILTINS[fn] as readonly unknown[]).includes("variadic");
  if (args.length === 1) {
    const a = args[0]!;
    if (isList(a)) return a;
    return variadic ? [a] : null;
  }
  return variadic ? args : null;
}

function extreme(items: readonly FeelValue[], want: 1 | -1): FeelValue {
  if (items.length === 0) return null;
  let best: FeelValue = items[0] as FeelValue;
  for (const x of items.slice(1)) {
    const c = feelCompare(x, best);
    if (c === null) return null;
    if (c === want) best = x;
  }
  return feelCompare(best, best) === null ? null : best;
}

function callBuiltin(fn: Builtin, args: readonly FeelValue[]): FeelValue {
  switch (fn) {
    case "not": {
      const a = args[0];
      return typeof a === "boolean" ? !a : null;
    }
    case "count": {
      const a = args[0];
      return isList(a ?? null) ? Decimal.fromInt((a as readonly FeelValue[]).length) : null;
    }
    case "sum": {
      const items = listArg(fn, args);
      if (items === null || items.length === 0) return null;
      let total = Decimal.ZERO;
      for (const x of items) {
        if (!isNum(x)) return null;
        total = total.add(x);
      }
      return total;
    }
    case "min":
    case "max": {
      const items = listArg(fn, args);
      return items === null ? null : extreme(items, fn === "min" ? -1 : 1);
    }
    case "list contains": {
      const [list, el] = args;
      if (!isList(list ?? null)) return null;
      return (list as readonly FeelValue[]).some((x) => feelEquals(x, el ?? null) === true);
    }
    case "distinct values": {
      const list = args[0];
      if (!isList(list ?? null)) return null;
      const out: FeelValue[] = [];
      for (const x of list as readonly FeelValue[]) if (!out.some((y) => feelEquals(x, y) === true)) out.push(x);
      return out;
    }
    case "date": {
      if (args.length === 3) {
        const [y, m, d] = args;
        if (!isNum(y ?? null) || !isNum(m ?? null) || !isNum(d ?? null)) return null;
        const [yy, mm, dd] = [y, m, d].map((x) => (x as Decimal).toBigInt());
        if (yy === null || mm === null || dd === null || yy === undefined || mm === undefined || dd === undefined) return null;
        return makeDate(Number(yy), Number(mm), Number(dd));
      }
      const a = args[0] ?? null;
      if (typeof a === "string") return parseDate(a);
      if (isDate(a)) return a;
      if (isDateTime(a)) return makeDate(a.year, a.month, a.day);
      return null;
    }
    case "date and time": {
      const a = args[0] ?? null;
      if (typeof a === "string") return parseDateTime(a);
      if (isDateTime(a)) return a;
      return null;
    }
    case "duration": {
      const a = args[0] ?? null;
      return typeof a === "string" ? parseDuration(a) : null;
    }
    case "years and months duration": {
      const [from, to] = args;
      const parts = (v: FeelValue | undefined) =>
        isDate(v ?? null)
          ? { year: (v as FeelDate).year, month: (v as FeelDate).month, day: (v as FeelDate).day, rest: 0n }
          : isDateTime(v ?? null)
            ? { year: (v as FeelDateTime).year, month: (v as FeelDateTime).month, day: (v as FeelDateTime).day, rest: localNanosOfDay(v as FeelDateTime) }
            : null;
      const f = parts(from);
      const t = parts(to);
      return f === null || t === null ? null : monthsBetween(f, t);
    }
  }
}

function atLiteral(text: string): FeelValue {
  return parseDate(text) ?? parseDateTime(text) ?? parseDuration(text);
}

function testHolds(v: FeelValue, t: Test, scope: Scope, ctx: Ctx): boolean | null {
  switch (t.k) {
    case "cmp":
      return cmpOp(t.op, v, ev(t.e, scope, ctx));
    case "interval": {
      const lo = ev(t.lo, scope, ctx);
      const hi = ev(t.hi, scope, ctx);
      return and3(cmpOp(t.loClosed ? ">=" : ">", v, lo), () => cmpOp(t.hiClosed ? "<=" : "<", v, hi));
    }
    case "expr": {
      const x = ev(t.e, scope, ctx);
      if (isList(x)) return x.some((y) => feelEquals(v, y) === true);
      return feelEquals(v, x);
    }
  }
}

function ev(n: Node, scope: Scope, ctx: Ctx): FeelValue {
  ctx.steps += 1;
  if (ctx.steps > ctx.budget) throw new BudgetExceeded();
  switch (n.k) {
    case "num":
      return n.v;
    case "str":
      return n.v;
    case "bool":
      return n.v;
    case "null":
      return null;
    case "at":
      return atLiteral(n.text);
    case "name": {
      const v = scope.lookup(n.name);
      return v === undefined ? null : v;
    }
    case "path": {
      const t = ev(n.target, scope, ctx);
      if (isList(t)) return t.map((x) => property(x, n.name));
      return t === null ? null : property(t, n.name);
    }
    case "filter": {
      const t = ev(n.target, scope, ctx);
      if (t === null) return null;
      const items = isList(t) ? t : [t];
      const out: FeelValue[] = [];
      for (const item of items) if (ev(n.test, scope.withItem(item), ctx) === true) out.push(item);
      return out;
    }
    case "index": {
      const t = ev(n.target, scope, ctx);
      if (t === null) return null;
      const items = isList(t) ? t : [t];
      const i = n.index.toBigInt();
      if (i === null || i === 0n) return null;
      const at = i > 0n ? Number(i) - 1 : items.length + Number(i);
      return at >= 0 && at < items.length ? (items[at] as FeelValue) : null;
    }
    case "call": {
      const args = n.args.map((a) => ev(a, scope, ctx));
      const named = n.named === null ? null : Object.fromEntries(Object.entries(n.named).map(([k, a]) => [k, ev(a, scope, ctx)]));
      const bound = bindArgs(n.fn, args, named);
      return bound === null ? null : callBuiltin(n.fn, bound);
    }
    case "list":
      return n.items.map((x) => ev(x, scope, ctx));
    case "neg": {
      const v = ev(n.e, scope, ctx);
      if (isNum(v)) return v.neg();
      if (isDtd(v)) return dtDuration(-v.nanos);
      if (isYmd(v)) return ymDuration(-v.months);
      return null;
    }
    case "arith":
      return arith(n.op, ev(n.l, scope, ctx), ev(n.r, scope, ctx));
    case "cmp":
      return cmpOp(n.op, ev(n.l, scope, ctx), ev(n.r, scope, ctx));
    case "and":
      return and3(ev(n.l, scope, ctx), () => ev(n.r, scope, ctx));
    case "or":
      return or3(ev(n.l, scope, ctx), () => ev(n.r, scope, ctx));
    case "between": {
      const v = ev(n.e, scope, ctx);
      const lo = ev(n.lo, scope, ctx);
      const hi = ev(n.hi, scope, ctx);
      return and3(cmpOp(">=", v, lo), () => cmpOp("<=", v, hi));
    }
    case "in": {
      const v = ev(n.e, scope, ctx);
      let sawNull = false;
      for (const t of n.tests) {
        const r = testHolds(v, t, scope, ctx);
        if (r === true) return true;
        if (r === null) sawNull = true;
      }
      return sawNull ? null : false;
    }
    case "quant": {
      const lists: (readonly FeelValue[])[] = [];
      for (const it of n.iters) {
        const l = ev(it.list, scope, ctx);
        if (l === null) return null;
        lists.push(isList(l) ? l : [l]);
      }
      const bindings: Map<string, FeelValue>[] = [];
      const walk = (i: number, acc: Map<string, FeelValue>): void => {
        if (i === lists.length) {
          bindings.push(new Map(acc));
          return;
        }
        for (const x of lists[i]!) {
          ctx.steps += 1;
          if (ctx.steps > ctx.budget) throw new BudgetExceeded();
          acc.set(n.iters[i]!.name, x);
          walk(i + 1, acc);
        }
        acc.delete(n.iters[i]!.name);
      };
      walk(0, new Map());
      for (const b of bindings) {
        const r = ev(n.satisfies, scope.child(b), ctx);
        if (n.every && r !== true) return false;
        if (!n.every && r === true) return true;
      }
      return n.every;
    }
  }
}

export interface EvaluateResult {
  readonly value: FeelValue;
  /** True when the step budget stopped evaluation; the value is then null. */
  readonly exhausted: boolean;
}

/** Evaluate a parsed expression in a scope. Never throws for a value of the wrong type — that is null, as FEEL says. */
export function evaluateNode(node: Node, scope: Scope, budget = DEFAULT_BUDGET): EvaluateResult {
  const ctx: Ctx = { steps: 0, budget };
  try {
    return { value: ev(node, scope, ctx), exhausted: false };
  } catch (e) {
    if (e instanceof BudgetExceeded) return { value: null, exhausted: true };
    throw e;
  }
}
