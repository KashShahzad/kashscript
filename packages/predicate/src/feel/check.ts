/**
 * The static check a condition passes before any rule carrying it validates:
 * it parses inside the subset, every name it reads is bound, and its answer
 * is a yes or a no — **never a number**, so a condition can never be a score.
 * It also reports what the condition reads, so a rule can require those
 * claims in every disclosure option and know which thresholds it uses.
 */

import { FeelSyntaxError } from "./lexer";
import { parseFeel, type Node, type Test } from "./parser";
import { parseDate, parseDateTime, parseDuration } from "./temporal";

export type StaticType =
  | { readonly t: "number" | "string" | "boolean" | "date" | "date and time" | "days and time duration" | "years and months duration" | "null" | "any" }
  | { readonly t: "list"; readonly of: StaticType }
  | { readonly t: "context"; readonly fields: Readonly<Record<string, StaticType>> };

export const T = {
  any: { t: "any" } as StaticType,
  number: { t: "number" } as StaticType,
  string: { t: "string" } as StaticType,
  boolean: { t: "boolean" } as StaticType,
  date: { t: "date" } as StaticType,
  dateTime: { t: "date and time" } as StaticType,
  dtd: { t: "days and time duration" } as StaticType,
  ymd: { t: "years and months duration" } as StaticType,
  nul: { t: "null" } as StaticType,
  list: (of: StaticType): StaticType => ({ t: "list", of }),
  context: (fields: Readonly<Record<string, StaticType>>): StaticType => ({ t: "context", fields }),
};

export interface FeelProblem {
  readonly message: string;
  readonly pos: number | null;
  /** FEEL that the subset does not include, as opposed to an error in the expression. */
  readonly outsideSubset: boolean;
}

export interface CheckResult {
  readonly ok: boolean;
  readonly problems: readonly FeelProblem[];
  readonly ast: Node | null;
  /** Top-level names the condition reads. */
  readonly names: readonly string[];
  /** Field names it reads from contexts (a criterion's claim ids). */
  readonly fields: readonly string[];
}

interface Env {
  readonly vars: ReadonlyMap<string, StaticType>;
  readonly item: StaticType | null;
  readonly parent: Env | null;
}

function lookup(env: Env | null, name: string, onField: (n: string) => void, onTop: (n: string) => void): StaticType | undefined {
  for (let e = env; e !== null; e = e.parent) {
    if (e.item !== null) {
      if (e.item.t === "context" && Object.prototype.hasOwnProperty.call(e.item.fields, name)) {
        onField(name);
        return e.item.fields[name];
      }
      if (name === "item") return e.item;
    }
    if (e.vars.has(name)) {
      if (e.parent === null) onTop(name);
      return e.vars.get(name);
    }
  }
  return undefined;
}

const SCALARS_COMPARED = new Set(["number", "string", "date", "date and time", "days and time duration", "years and months duration", "boolean"]);

class Checker {
  readonly problems: FeelProblem[] = [];
  readonly names = new Set<string>();
  readonly fields = new Set<string>();

  private fail(message: string, pos: number | null = null): StaticType {
    this.problems.push({ message, pos, outsideSubset: false });
    return T.any;
  }

  type(n: Node, env: Env): StaticType {
    switch (n.k) {
      case "num":
        return T.number;
      case "str":
        return T.string;
      case "bool":
        return T.boolean;
      case "null":
        return T.nul;
      case "at":
        if (parseDate(n.text) !== null) return T.date;
        if (parseDateTime(n.text) !== null) return T.dateTime;
        return this.durationType(n.text);
      case "name": {
        const t = lookup(env, n.name, (f) => this.fields.add(f), (v) => this.names.add(v));
        return t ?? this.fail(`the name ${JSON.stringify(n.name)} is not bound — a condition reads only its claims, its parameters and asOf`, n.pos);
      }
      case "path": {
        const t = this.type(n.target, env);
        return this.pathType(t, n.name);
      }
      case "filter": {
        const t = this.type(n.target, env);
        const el = t.t === "list" ? t.of : t;
        if (el.t === "any") return this.fail("a filter over a list whose items are not known — the names inside it cannot be checked");
        this.type(n.test, { vars: new Map(), item: el, parent: env });
        return T.list(el);
      }
      case "index": {
        const t = this.type(n.target, env);
        return t.t === "list" ? t.of : t;
      }
      case "call":
        return this.callType(n, env);
      case "list": {
        const items = n.items.map((x) => this.type(x, env));
        return T.list(items[0] ?? T.any);
      }
      case "neg": {
        const t = this.type(n.e, env);
        return t.t === "number" || t.t === "days and time duration" || t.t === "years and months duration" ? t : T.any;
      }
      case "arith":
        return this.arithType(n.op, this.type(n.l, env), this.type(n.r, env));
      case "cmp": {
        const l = this.type(n.l, env);
        const r = this.type(n.r, env);
        this.comparable(l, r, n.op);
        return T.boolean;
      }
      case "and":
      case "or":
        this.type(n.l, env);
        this.type(n.r, env);
        return T.boolean;
      case "between": {
        const v = this.type(n.e, env);
        this.comparable(v, this.type(n.lo, env), "between");
        this.comparable(v, this.type(n.hi, env), "between");
        return T.boolean;
      }
      case "in": {
        const v = this.type(n.e, env);
        for (const t of n.tests) this.testType(v, t, env);
        return T.boolean;
      }
      case "quant": {
        let inner: Env = env;
        for (const it of n.iters) {
          const lt = this.type(it.list, inner);
          inner = { vars: new Map([[it.name, lt.t === "list" ? lt.of : lt]]), item: null, parent: inner };
        }
        this.type(n.satisfies, inner);
        return T.boolean;
      }
    }
  }

  private durationType(text: string): StaticType {
    const d = parseDuration(text);
    if (d === null) return T.any;
    return d.kind === "days and time duration" ? T.dtd : T.ymd;
  }

  private pathType(t: StaticType, name: string): StaticType {
    if (t.t === "list") return T.list(this.pathType(t.of, name));
    if (t.t === "context") {
      if (!Object.prototype.hasOwnProperty.call(t.fields, name)) return this.fail(`there is no field ${JSON.stringify(name)} here`);
      this.fields.add(name);
      return t.fields[name]!;
    }
    if (t.t === "date" || t.t === "date and time") {
      if (["year", "month", "day"].includes(name) || (t.t === "date and time" && ["hour", "minute", "second"].includes(name))) return T.number;
      return this.fail(`a ${t.t} has no property ${JSON.stringify(name)}`);
    }
    if (t.t === "years and months duration") return ["years", "months"].includes(name) ? T.number : this.fail(`a duration has no property ${JSON.stringify(name)}`);
    if (t.t === "days and time duration") return ["days", "hours", "minutes", "seconds"].includes(name) ? T.number : this.fail(`a duration has no property ${JSON.stringify(name)}`);
    return T.any;
  }

  private callType(n: Extract<Node, { k: "call" }>, env: Env): StaticType {
    const args = n.args.map((a) => this.type(a, env));
    const named = n.named === null ? {} : Object.fromEntries(Object.entries(n.named).map(([k, a]) => [k, this.type(a, env)]));
    const first = args[0] ?? Object.values(named)[0] ?? T.any;
    switch (n.fn) {
      case "not":
      case "list contains":
        return T.boolean;
      case "count":
        return T.number;
      case "sum":
        return T.number;
      case "min":
      case "max":
        return args.length === 1 && first.t === "list" ? first.of : first;
      case "distinct values":
        return first;
      case "date":
        return T.date;
      case "date and time":
        return T.dateTime;
      case "duration": {
        const a = n.args[0] ?? n.named?.from;
        return a?.k === "str" ? this.durationType(a.v) : T.any;
      }
      case "years and months duration":
        return T.ymd;
    }
  }

  private arithType(op: string, l: StaticType, r: StaticType): StaticType {
    const k = `${l.t} ${op} ${r.t}`;
    const table: Record<string, StaticType> = {
      "number + number": T.number,
      "number - number": T.number,
      "number * number": T.number,
      "number / number": T.number,
      "string + string": T.string,
      "date + years and months duration": T.date,
      "date - years and months duration": T.date,
      "date + days and time duration": T.date,
      "date - days and time duration": T.date,
      "years and months duration + date": T.date,
      "days and time duration + date": T.date,
      "date and time + years and months duration": T.dateTime,
      "date and time - years and months duration": T.dateTime,
      "date and time + days and time duration": T.dateTime,
      "date and time - days and time duration": T.dateTime,
      "years and months duration + date and time": T.dateTime,
      "days and time duration + date and time": T.dateTime,
      "date - date": T.dtd,
      "date and time - date and time": T.dtd,
      "date - date and time": T.dtd,
      "date and time - date": T.dtd,
      "years and months duration + years and months duration": T.ymd,
      "years and months duration - years and months duration": T.ymd,
      "days and time duration + days and time duration": T.dtd,
      "days and time duration - days and time duration": T.dtd,
      "years and months duration * number": T.ymd,
      "number * years and months duration": T.ymd,
      "days and time duration * number": T.dtd,
      "number * days and time duration": T.dtd,
      "years and months duration / number": T.ymd,
      "days and time duration / number": T.dtd,
      "years and months duration / years and months duration": T.number,
      "days and time duration / days and time duration": T.number,
    };
    const hit = table[k];
    if (hit !== undefined) return hit;
    const known = (x: StaticType) => SCALARS_COMPARED.has(x.t);
    if (known(l) && known(r)) return this.fail(`${l.t} ${op} ${r.t} is always null`);
    return T.any;
  }

  private comparable(l: StaticType, r: StaticType, op: string): void {
    if (SCALARS_COMPARED.has(l.t) && SCALARS_COMPARED.has(r.t) && l.t !== r.t) {
      this.fail(`comparing a ${l.t} with a ${r.t} (${op}) is always null — convert one, for example date(asOf)`);
    }
  }

  private testType(v: StaticType, t: Test, env: Env): void {
    switch (t.k) {
      case "cmp":
        this.comparable(v, this.type(t.e, env), t.op);
        return;
      case "interval":
        this.comparable(v, this.type(t.lo, env), "in");
        this.comparable(v, this.type(t.hi, env), "in");
        return;
      case "expr": {
        const x = this.type(t.e, env);
        this.comparable(v, x.t === "list" ? x.of : x, "in");
        return;
      }
    }
  }
}

/**
 * Check a condition against the names in scope. `yesNo` (default true)
 * refuses any expression whose answer is not a boolean.
 */
export function checkFeel(src: string, names: Readonly<Record<string, StaticType>>, opts: { readonly yesNo?: boolean } = {}): CheckResult {
  let ast: Node;
  try {
    ast = parseFeel(src);
  } catch (e) {
    if (e instanceof FeelSyntaxError) {
      return { ok: false, problems: [{ message: e.message, pos: e.pos, outsideSubset: e.outsideSubset }], ast: null, names: [], fields: [] };
    }
    throw e;
  }
  const c = new Checker();
  const top = c.type(ast, { vars: new Map(Object.entries(names)), item: null, parent: null });
  if ((opts.yesNo ?? true) && top.t !== "boolean") {
    c.problems.push({ message: `a condition answers yes or no; this one answers a ${top.t === "any" ? "value of unknown type" : top.t} — a condition is never a number or a score`, pos: null, outsideSubset: false });
  }
  return { ok: c.problems.length === 0, problems: c.problems, ast, names: [...c.names], fields: [...c.fields] };
}
