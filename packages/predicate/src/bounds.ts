/**
 * Bounds — the range or list an adopter may set a parameter within (d85(b)
 * rule 8: one open source per rulebook, local parameters within stated
 * bounds; the Eurocodes' nationally determined parameters are the precedent).
 *
 * A range bounds an ordered type — a number, a date, a date and time, or a
 * duration of one kind — and is compared with FEEL's own ordering, so `P18M`
 * sits between `P12M` and `P36M`. Anything else is bounded by a list.
 */

import type { RuleParameter1_1 } from "@kashscript/lexicons/extensions/door";
import { feelCompare, feelEquals, fromJson, type FeelValue, type InputType } from "./feel";

const ORDERED = new Set(["number", "date", "date and time", "days and time duration", "years and months duration"]);

/** What is wrong with a parameter's bounds, in plain words. Empty when they are sound. */
export function boundsProblems(p: RuleParameter1_1): string[] {
  const b = p.bounds;
  if (b === undefined) return [];
  const type = p.type as InputType;
  if (type.startsWith("list of ")) return ["a list cannot be bounded — bound one value"];
  const out: string[] = [];
  const value = p.value === undefined ? null : fromJson(p.value, type);
  if ("allowed" in b) {
    const allowed = b.allowed.map((v) => fromJson(v, type));
    if (allowed.some((v) => v === null)) out.push(`every allowed value reads as a ${p.type}`);
    else if (value !== null && !allowed.some((v) => feelEquals(v, value) === true)) out.push("the rule's own value is one of its allowed values");
    return out;
  }
  if (b.min === undefined && b.max === undefined) return ["bounds give a minimum, a maximum, or both — or a list of allowed values"];
  if (!ORDERED.has(type)) return [`a range bounds a number, a date or a duration — bound a ${p.type} with a list of allowed values`];
  const min = b.min === undefined ? null : fromJson(b.min, type);
  const max = b.max === undefined ? null : fromJson(b.max, type);
  if ((b.min !== undefined && min === null) || (b.max !== undefined && max === null)) return [`the bounds read as a ${p.type}`];
  if (min !== null && max !== null && feelCompare(min, max) === 1) out.push("the minimum is above the maximum");
  if (value !== null && !inBounds(p, value)) out.push("the rule's own value sits inside its bounds");
  return out;
}

/** Is `value` (already read as the parameter's type) within the parameter's bounds? A parameter with none is fixed: nothing is within. */
export function inBounds(p: RuleParameter1_1, value: FeelValue): boolean {
  const b = p.bounds;
  if (b === undefined || value === null) return false;
  const type = p.type as InputType;
  if ("allowed" in b) return b.allowed.some((a) => feelEquals(fromJson(a, type), value) === true);
  const min = b.min === undefined ? null : fromJson(b.min, type);
  const max = b.max === undefined ? null : fromJson(b.max, type);
  if (min !== null) {
    const c = feelCompare(value, min);
    if (c === null || c < 0) return false;
  }
  if (max !== null) {
    const c = feelCompare(value, max);
    if (c === null || c > 0) return false;
  }
  return true;
}
