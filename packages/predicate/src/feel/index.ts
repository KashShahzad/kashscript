/**
 * @kashscript/predicate/feel — a FEEL subset, from OMG's DMN 1.5 (literal
 * expressions only): enough for counts, dates, sums and thresholds, and
 * nothing that can loop, define a function or read a clock.
 *
 * **A subset, never a dialect.** An expression this parser accepts is FEEL
 * that any DMN engine evaluates the same way; what the subset does not hold
 * is refused by name. The DMN TCK cases it claims are in `test/tck`, and the
 * test there proves every extracted case either passes or is refused — none
 * gives a wrong answer. See `specs/feel-subset.md`.
 */

import { DEFAULT_BUDGET, evaluateNode, Scope, type EvaluateResult } from "./evaluate";
import { FeelSyntaxError } from "./lexer";
import { parseFeel, type Node } from "./parser";
import type { FeelValue } from "./values";

export { Decimal } from "./decimal";
export { FeelSyntaxError } from "./lexer";
export { parseFeel, BUILTINS, MAX_DEPTH, MAX_SOURCE_BYTES, type Node, type Builtin } from "./parser";
export { evaluateNode, Scope, DEFAULT_BUDGET, BudgetExceeded, type EvaluateResult } from "./evaluate";
export { checkFeel, T, type CheckResult, type FeelProblem, type StaticType } from "./check";
export {
  FeelContext,
  feelEquals,
  feelCompare,
  fromJson,
  isInputType,
  show,
  typeOf,
  SCALAR_TYPES,
  type FeelValue,
  type FeelTypeName,
  type InputType,
  type ScalarType,
} from "./values";
export {
  parseDate,
  parseDateTime,
  parseDuration,
  formatTemporal,
  type FeelDate,
  type FeelDateTime,
  type DaysTimeDuration,
  type YearsMonthsDuration,
  type Temporal,
} from "./temporal";

/** Parse and evaluate in one step. A syntax error or a construct outside the subset throws `FeelSyntaxError`. */
export function evaluateFeel(src: string | Node, vars: Readonly<Record<string, FeelValue>>, budget = DEFAULT_BUDGET): EvaluateResult {
  const ast = typeof src === "string" ? parseFeel(src) : src;
  return evaluateNode(ast, Scope.of(vars), budget);
}

/** True when the subset accepts the expression (it parses; names are not checked). */
export function inSubset(src: string): boolean {
  try {
    parseFeel(src);
    return true;
  } catch (e) {
    if (e instanceof FeelSyntaxError) return false;
    throw e;
  }
}
