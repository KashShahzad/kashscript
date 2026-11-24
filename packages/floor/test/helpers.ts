import { copyFileSync, cpSync, existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { checkFloor, type FloorReport } from "../src/check.js";
import { CITE, RULES, decisionRefs } from "../src/rules.js";

export const FIXTURES = join(import.meta.dir, "fixtures");

export function scratch(prefix = "floor-"): string {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** A fixture's boot lines, written outside the repository (a tracked boot log is refused, rightly). */
export function bootLogFor(root: string): string[] {
  const lines = join(root, "boot-lines.jsonl");
  if (!existsSync(lines)) return [];
  const f = join(scratch(), "boot.log");
  copyFileSync(lines, f);
  return [f];
}

export function runFixture(name: string): FloorReport {
  const root = join(FIXTURES, name);
  return checkFloor({ root, bootLogs: bootLogFor(root) });
}

/** A writable copy of a fixture, for a test that changes one thing in it. */
export function copyFixture(name: string): string {
  const dest = join(scratch(), name);
  cpSync(join(FIXTURES, name), dest, { recursive: true });
  return dest;
}

export const pairs = (r: FloorReport): string[] => r.findings.map((f) => `${f.rule} | ${f.at}`).sort();

/** Every cite of a finding is a decision its rule enforces (RULES), and there is at least one. */
export function citesBelong(r: FloorReport): string[] {
  const wrong: string[] = [];
  for (const f of r.findings) {
    if (f.rule === "manifest") continue;
    if (f.cites.length === 0) wrong.push(`${f.at}: no decision cited`);
    const own = RULES[f.rule].decisions;
    const ownRefs = own.flatMap((d) => decisionRefs(d));
    for (const c of f.cites) {
      const text = CITE[c];
      const refs = decisionRefs(text);
      const ok = refs.length === 0 ? own.some((d) => text.startsWith(d)) : ownRefs.includes(refs[0]!);
      if (!ok) wrong.push(`${f.at}: cites ${text}, which ${f.rule} does not list`);
    }
  }
  return wrong;
}
