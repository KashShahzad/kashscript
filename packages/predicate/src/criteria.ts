/**
 * One criterion, evaluated: the receipts its queries matched become a FEEL
 * list of contexts (one per receipt, its claims typed as the rule declares,
 * plus `issuer`), the rule's thresholds and `asOf` are bound beside it, and
 * the condition answers yes, no or null. Shared by the person's checklist and
 * the desk's routing, so the two can never disagree about what a rule means.
 */

import type { Criterion, DoorInputType, RuleBody } from "@kashscript/lexicons/extensions/door";
import { checkFeel, evaluateNode, FeelContext, fromJson, parseDateTime, parseFeel, Scope, T, type FeelDateTime, type FeelValue, type InputType, type Node, type StaticType } from "./feel";
import { DAY } from "./constants";
import type { ReceiptView } from "./receipts";

export function staticTypeOf(t: DoorInputType): StaticType {
  const scalar = (s: string): StaticType => {
    switch (s) {
      case "string":
        return T.string;
      case "number":
        return T.number;
      case "boolean":
        return T.boolean;
      case "date":
        return T.date;
      case "date and time":
        return T.dateTime;
      case "days and time duration":
        return T.dtd;
      default:
        return T.ymd;
    }
  };
  return t.startsWith("list of ") ? T.list(scalar(t.slice("list of ".length))) : scalar(t);
}

/** The names a criterion's condition may read, with their static types. */
export function conditionScope(rule: RuleBody, c: Criterion): Record<string, StaticType> {
  const names: Record<string, StaticType> = { asOf: T.dateTime };
  for (const [n, p] of Object.entries(rule.parameters ?? {})) names[n] = staticTypeOf(p.type);
  if (c.answer.by === "own-word") {
    for (const [f, t] of Object.entries(c.answer.fields)) names[f] = staticTypeOf(t);
  } else {
    const fields: Record<string, StaticType> = { issuer: T.string };
    for (const [id, t] of Object.entries(c.condition?.types ?? {})) fields[id] = staticTypeOf(t);
    names.receipts = T.list(T.context(fields));
  }
  return names;
}

/** `asOf` from an ISO date-time with an offset, or unix seconds. */
export function asOfValue(asOf: string | number): FeelDateTime {
  const iso = typeof asOf === "number" ? new Date(asOf * 1000).toISOString().replace(/\.\d{3}Z$/, "Z") : asOf;
  const dt = parseDateTime(iso);
  if (dt === null) throw new Error(`asOf must be a date and time with an offset or Z: ${String(asOf)}`);
  return dt;
}

export function asOfSeconds(asOf: string | number): number {
  return typeof asOf === "number" ? asOf : Math.floor(Date.parse(asOf) / 1000);
}

/** A receipt that matched one of the criterion's queries, with its claims by id. */
export interface MatchedReceipt {
  readonly queryId: string;
  readonly view: ReceiptView;
  readonly values: Readonly<Record<string, unknown>>;
}

/** Thresholds: public values, verified openings, or sealed (the condition then cannot be read here). */
export type Thresholds = { readonly kind: "values"; readonly values: Readonly<Record<string, FeelValue>> } | { readonly kind: "sealed" };

/**
 * A public rule's thresholds in clear, with an anchor's adopted values over
 * them (d85(b) rule 8). `local` is the adoption's own parameters — already
 * checked against the rule's bounds by `validateAdoption`.
 */
export function publicThresholds(rule: RuleBody, local?: Readonly<Record<string, string | number | boolean>>): Thresholds {
  if (rule.visibility === "private") return { kind: "sealed" };
  const values: Record<string, FeelValue> = {};
  for (const [n, p] of Object.entries(rule.parameters ?? {})) values[n] = fromJson(local?.[n] ?? p.value, p.type as InputType);
  return { kind: "values", values };
}

/** Which parameters a condition reads. */
export function parametersRead(rule: RuleBody, c: Criterion): string[] {
  if (c.condition === undefined) return [];
  const r = checkFeel(c.condition.feel, conditionScope(rule, c));
  const params = new Set(Object.keys(rule.parameters ?? {}));
  return r.names.filter((n) => params.has(n));
}

const astCache = new Map<string, Node>();
function ast(src: string): Node {
  let n = astCache.get(src);
  if (n === undefined) {
    n = parseFeel(src);
    if (astCache.size > 256) astCache.clear();
    astCache.set(src, n);
  }
  return n;
}

function contextOf(c: Criterion, m: MatchedReceipt): FeelValue {
  const entries: Record<string, FeelValue> = { issuer: m.view.issuer };
  for (const [id, t] of Object.entries(c.condition?.types ?? {})) entries[id] = fromJson(m.values[id], t as InputType);
  return FeelContext.from(entries);
}

export type Met = boolean | null;

export interface CriterionResult {
  /** true: met · false: not met · null: could not be read here (a sealed threshold, a type that did not read, the step budget). */
  readonly met: Met;
  readonly via: "receipts" | "predicate" | "own-word";
  /** The receipts it rests on — minimal by default (d27.2). */
  readonly chosen: readonly MatchedReceipt[];
  /** Other matching receipts the person may add. */
  readonly more: readonly MatchedReceipt[];
  readonly sealed: boolean;
  readonly exhausted: boolean;
}

/**
 * Only `true` is met — as a DMN decision table fires a rule only when its
 * conditions are true. A null (FEEL's `sum([])`, a claim that did not read as
 * its type) is not met; only a condition the step budget stopped is unread.
 */
function evalCondition(src: string, vars: Record<string, FeelValue>): { met: Met; exhausted: boolean } {
  const r = evaluateNode(ast(src), Scope.of(vars));
  return { met: r.exhausted ? null : r.value === true, exhausted: r.exhausted };
}

/** Does a predicate answer this criterion now? Its window must end within `freshDays` of `asOf`. */
export function predicateFresh(c: Criterion, m: MatchedReceipt, asOfSec: number): boolean {
  if (c.predicate === undefined || !m.view.counts) return false;
  const to = typeof m.values.windowTo === "string" ? Date.parse(m.values.windowTo) / 1000 : Number.NaN;
  return Number.isFinite(to) && to >= asOfSec - c.predicate.freshDays * DAY;
}

/**
 * Evaluate one criterion. `predicates` are matched predicate presentations,
 * `word` the person's own word (already read from its statement).
 */
export function evaluateCriterion(
  rule: RuleBody,
  c: Criterion,
  input: { readonly receipts: readonly MatchedReceipt[]; readonly predicates: readonly MatchedReceipt[]; readonly word: Readonly<Record<string, unknown>> | null },
  opts: { readonly asOf: string | number; readonly thresholds: Thresholds },
): CriterionResult {
  const asOf = asOfValue(opts.asOf);
  const asOfSec = asOfSeconds(opts.asOf);
  const sealedRead = opts.thresholds.kind === "sealed" && parametersRead(rule, c).length > 0;
  const params: Record<string, FeelValue> = opts.thresholds.kind === "values" ? { ...opts.thresholds.values } : Object.fromEntries(Object.keys(rule.parameters ?? {}).map((n) => [n, null]));

  if (c.answer.by === "own-word") {
    const word = input.word;
    if (word === null) return { met: false, via: "own-word", chosen: [], more: [], sealed: sealedRead, exhausted: false };
    const vars: Record<string, FeelValue> = { ...params, asOf };
    for (const [f, t] of Object.entries(c.answer.fields)) vars[f] = fromJson(word[f], t as InputType);
    if (c.condition === undefined) {
      const all = Object.keys(c.answer.fields).every((f) => vars[f] !== null);
      return { met: all, via: "own-word", chosen: [], more: [], sealed: false, exhausted: false };
    }
    const r = evalCondition(c.condition.feel, vars);
    return { met: sealedRead && r.met !== true ? null : r.met, via: "own-word", chosen: [], more: [], sealed: sealedRead, exhausted: r.exhausted };
  }

  const fresh = input.predicates.filter((p) => predicateFresh(c, p, asOfSec));
  if (fresh.length > 0) return { met: true, via: "predicate", chosen: [fresh[0]!], more: [], sealed: false, exhausted: false };

  // One record counts once, however it reaches the desk (AU-3, A7-03): a copy re-wrapped
  // with an extra field or a junk signature, or shown bare and countersigned, shares one
  // content identity. Several unlinkable SD-JWT copies of one record differ in every byte,
  // so a counting rule also reads each one's `record` id.
  const seenContent = new Set<string>();
  const seenRecords = new Set<string>();
  const counting = [...input.receipts]
    .filter((m) => m.view.counts)
    .sort((a, b) => (a.view.id < b.view.id ? -1 : a.view.id > b.view.id ? 1 : 0))
    .filter((m) => {
      if (seenContent.has(m.view.contentId)) return false;
      seenContent.add(m.view.contentId);
      if (m.values.record === undefined) return true;
      const k = JSON.stringify(m.values.record);
      if (seenRecords.has(k)) return false;
      seenRecords.add(k);
      return true;
    });
  if (c.condition === undefined) return { met: counting.length > 0, via: "receipts", chosen: counting.slice(0, 1), more: counting.slice(1), sealed: false, exhausted: false };
  const holds = (set: readonly MatchedReceipt[]): { met: Met; exhausted: boolean } =>
    evalCondition(c.condition!.feel, { ...params, asOf, receipts: set.map((m) => contextOf(c, m)) });

  const all = holds(counting);
  if (sealedRead) {
    // The threshold is the desk's to read; here the row says which receipts the rule reads.
    return { met: null, via: "receipts", chosen: counting, more: [], sealed: true, exhausted: all.exhausted };
  }
  if (all.met !== true) return { met: all.met, via: "receipts", chosen: counting, more: [], sealed: false, exhausted: all.exhausted };
  // Minimal by default: drop each receipt, in record-id order, while the condition still holds without it.
  let chosen = counting;
  for (const m of counting) {
    const without = chosen.filter((x) => x !== m);
    if (holds(without).met === true) chosen = without;
  }
  return { met: true, via: "receipts", chosen, more: counting.filter((m) => !chosen.includes(m)), sealed: false, exhausted: false };
}
