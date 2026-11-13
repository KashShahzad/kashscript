/**
 * Runs the extracted DMN TCK cases through the subset and sorts each one:
 *   pass    — the subset accepts it and answers what the TCK expects;
 *   refused — the subset refuses it by name (FEEL it does not hold), or a
 *             value it reads is outside the subset (a local date-time, a time);
 *   wrong   — the subset accepted it and answered differently. Must be empty.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Decimal, evaluateFeel, FeelContext, feelEquals, FeelSyntaxError, parseDate, parseDateTime, parseDuration, parseFeel, show, type FeelValue } from "../../src/feel";
import type { TckCase, TckValue } from "../../scripts/tck-extract";

export interface TckFile {
  readonly source: string;
  readonly commit: string;
  readonly folders: readonly string[];
  readonly cases: readonly TckCase[];
}

export function loadTck(): TckFile {
  return JSON.parse(readFileSync(join(import.meta.dir, "cases.json"), "utf8")) as TckFile;
}

class Outside extends Error {}

function toFeel(v: TckValue): FeelValue {
  switch (v.type) {
    case "null":
      return null;
    case "string":
      return v.value;
    case "boolean":
      return v.value === "true";
    case "decimal": {
      if (/^(NaN|-?INF)$/.test(v.value)) throw new Outside("not a FEEL number");
      const d = Decimal.parse(v.value);
      if (d === null) throw new Outside(`unreadable number ${v.value}`);
      return d;
    }
    case "date": {
      const d = parseDate(v.value);
      if (d === null) throw new Outside(`a date outside the subset: ${v.value}`);
      return d;
    }
    case "dateTime": {
      const d = parseDateTime(v.value);
      if (d === null) throw new Outside(`a date and time outside the subset: ${v.value}`);
      return d;
    }
    case "duration": {
      const d = parseDuration(v.value);
      if (d === null) throw new Outside(`a duration outside the subset: ${v.value}`);
      return d;
    }
    case "list":
      return v.items.map(toFeel);
    case "context":
      return new FeelContext(new Map(Object.entries(v.entries).map(([k, x]) => [k, toFeel(x)])));
    default:
      throw new Outside(`a ${v.type} value is outside the subset`);
  }
}

export type Verdict =
  | { readonly kind: "pass"; readonly c: TckCase }
  | { readonly kind: "refused"; readonly c: TckCase; readonly why: string }
  | { readonly kind: "wrong"; readonly c: TckCase; readonly got: string; readonly want: string };

export function runCase(c: TckCase): Verdict {
  let ast;
  try {
    ast = parseFeel(c.expression);
  } catch (e) {
    if (e instanceof FeelSyntaxError) return { kind: "refused", c, why: `${e.outsideSubset ? "outside the subset" : "does not parse"}: ${e.message}` };
    throw e;
  }
  let inputs: Record<string, FeelValue>;
  let want: FeelValue;
  try {
    inputs = Object.fromEntries(Object.entries(c.inputs).map(([k, v]) => [k, toFeel(v)]));
    want = c.errorResult ? null : toFeel(c.expected);
  } catch (e) {
    if (e instanceof Outside) return { kind: "refused", c, why: e.message };
    throw e;
  }
  const got = evaluateFeel(ast, inputs).value;
  const same = got === null || want === null ? got === want : feelEquals(got, want) === true && sameKind(got, want);
  return same ? { kind: "pass", c } : { kind: "wrong", c, got: show(got), want: show(want) };
}

/** FEEL `=` treats a date and time equal across offsets; the TCK's expected value names its offset, so match it too. */
function sameKind(a: FeelValue, b: FeelValue): boolean {
  if (Array.isArray(a) && Array.isArray(b)) return a.every((x, i) => sameKind(x, b[i]!));
  return show(a) === show(b) || !(typeof a === "object" && a !== null && "offsetMinutes" in a);
}

export function runAll(): { pass: Verdict[]; refused: Verdict[]; wrong: Verdict[]; file: TckFile } {
  const file = loadTck();
  const out = { pass: [] as Verdict[], refused: [] as Verdict[], wrong: [] as Verdict[], file };
  for (const c of file.cases) {
    const v = runCase(c);
    out[v.kind].push(v);
  }
  return out;
}

if (import.meta.main) {
  const r = runAll();
  console.log(`pass ${r.pass.length} · refused ${r.refused.length} · wrong ${r.wrong.length} (of ${r.file.cases.length}, TCK ${r.file.commit.slice(0, 7)})`);
  const byFolder = new Map<string, number[]>();
  for (const [i, list] of [r.pass, r.refused, r.wrong].entries()) {
    for (const v of list) {
      const row = byFolder.get(v.c.folder) ?? [0, 0, 0];
      row[i]! += 1;
      byFolder.set(v.c.folder, row);
    }
  }
  for (const [f, [p, rf, w]] of byFolder) console.log(`  ${f}: pass ${p} · refused ${rf} · wrong ${w}`);
  const limit = Number(process.argv[2] ?? 40);
  for (const v of r.wrong.slice(0, limit)) {
    if (v.kind === "wrong") console.log(`WRONG ${v.c.folder} ${v.c.id}\n   ${v.c.expression}\n   got  ${v.got}\n   want ${v.want}`);
  }
}
