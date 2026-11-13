/**
 * Extract the DMN TCK cases the FEEL subset is tested against
 * (https://github.com/dmn-tck/tck, Apache-2.0) into `test/tck/cases.json`.
 *
 *   bun scripts/tck-extract.ts <checkout-dir> <commit-sha>
 *
 * `<checkout-dir>` holds `TestCases/compliance-level-3/<case>/` folders, or the
 * case folders directly. Its files are data: this script reads them as text and
 * never runs or imports anything from them.
 *
 * Only decisions whose logic is one literal expression, reading input data and
 * no other decision, are taken. Every test case of such a decision becomes one
 * extracted case: the expression, its typed inputs, and the typed expected
 * value (or that the TCK expects an error, which FEEL reports as null).
 */

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export const CLAIMED_FOLDERS = [
  "0001-filter",
  "0012-list-functions",
  "0016-some-every",
  "0064-feel-conjunction",
  "0065-feel-disjunction",
  "0066-feel-negation",
  "0068-feel-equality",
  "0071-feel-between",
  "0072-feel-in",
  "0090-feel-paths",
  "0099-arithmetic-negation",
  "0100-arithmetic",
  "1115-feel-date-function",
  "1117-feel-date-and-time-function",
  "1120-feel-duration-function",
  "1121-feel-years-and-months-duration-function",
] as const;

/* ── a minimal XML reader (machine-written files, no DTDs) ─────────────── */

interface El {
  readonly name: string;
  readonly attrs: Readonly<Record<string, string>>;
  readonly children: El[];
  text: string;
}

function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h: string) => String.fromCodePoint(Number.parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d: string) => String.fromCodePoint(Number.parseInt(d, 10)))
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

const local = (n: string): string => n.slice(n.indexOf(":") + 1);

export function parseXml(src: string): El {
  const root: El = { name: "#root", attrs: {}, children: [], text: "" };
  const stack: El[] = [root];
  const re = /<!--[\s\S]*?-->|<\?[\s\S]*?\?>|<!\[CDATA\[([\s\S]*?)\]\]>|<(\/?)([A-Za-z_][\w.:-]*)((?:\s+[\w.:-]+\s*=\s*(?:"[^"]*"|'[^']*'))*)\s*(\/?)>|([^<]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const top = stack[stack.length - 1]!;
    if (m[1] !== undefined) {
      top.text += m[1];
    } else if (m[3] !== undefined) {
      const name = local(m[3]);
      if (m[2] === "/") {
        stack.pop();
        continue;
      }
      const attrs: Record<string, string> = {};
      for (const a of (m[4] ?? "").matchAll(/([\w.:-]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
        attrs[local(a[1]!)] = decodeEntities(a[2] ?? a[3] ?? "");
      }
      const el: El = { name, attrs, children: [], text: "" };
      top.children.push(el);
      if (m[5] !== "/") stack.push(el);
    } else if (m[6] !== undefined) {
      top.text += decodeEntities(m[6]);
    }
  }
  return root;
}

const kids = (e: El, name: string): El[] => e.children.filter((c) => c.name === name);
const kid = (e: El, name: string): El | undefined => e.children.find((c) => c.name === name);

/* ── typed values ──────────────────────────────────────────────────────── */

export type TckValue =
  | { readonly type: "null" }
  | { readonly type: "string" | "decimal" | "boolean" | "date" | "dateTime" | "duration" | "time" | "other"; readonly value: string; readonly xsd?: string }
  | { readonly type: "list"; readonly items: readonly TckValue[] }
  | { readonly type: "context"; readonly entries: Readonly<Record<string, TckValue>> };

function valueOf(holder: El): TckValue {
  const list = kid(holder, "list");
  if (list !== undefined) return { type: "list", items: kids(list, "item").map(valueOf) };
  const comps = kids(holder, "component");
  if (comps.length > 0) return { type: "context", entries: Object.fromEntries(comps.map((c) => [c.attrs.name ?? "", valueOf(c)])) };
  const v = kid(holder, "value");
  if (v === undefined) return { type: "null" };
  if (v.attrs.nil === "true") return { type: "null" };
  const xsd = local(v.attrs.type ?? "xsd:string");
  const text = v.text.trim();
  switch (xsd) {
    case "string":
      return { type: "string", value: v.text };
    case "decimal":
    case "double":
    case "integer":
    case "int":
    case "long":
    case "float":
      return { type: "decimal", value: text, xsd };
    case "boolean":
      return { type: "boolean", value: text };
    case "date":
      return { type: "date", value: text };
    case "dateTime":
      return { type: "dateTime", value: text };
    case "duration":
    case "dayTimeDuration":
    case "yearMonthDuration":
      return { type: "duration", value: text };
    case "time":
      return { type: "time", value: text };
    default:
      return { type: "other", value: text, xsd };
  }
}

/* ── extraction ────────────────────────────────────────────────────────── */

export interface TckCase {
  readonly folder: string;
  readonly id: string;
  readonly decision: string;
  readonly expression: string;
  readonly inputs: Readonly<Record<string, TckValue>>;
  readonly expected: TckValue;
  /** The TCK expects an error; FEEL reports it as null. */
  readonly errorResult: boolean;
}

function folderPath(root: string, folder: string): string {
  const nested = join(root, "TestCases", "compliance-level-3", folder);
  return existsSync(nested) ? nested : join(root, folder);
}

export function extractFolder(root: string, folder: string): { cases: TckCase[]; skipped: number } {
  const dir = folderPath(root, folder);
  const model = parseXml(readFileSync(join(dir, `${folder}.dmn`), "utf8"));
  const tests = parseXml(readFileSync(join(dir, `${folder}-test-01.xml`), "utf8"));
  const definitions = kid(model, "definitions")!;
  const literal = new Map<string, string>();
  for (const d of kids(definitions, "decision")) {
    const lit = kid(d, "literalExpression");
    const reqs = kids(d, "informationRequirement");
    const readsDecision = reqs.some((r) => kid(r, "requiredDecision") !== undefined);
    const usesKnowledge = kids(d, "knowledgeRequirement").length > 0;
    if (lit === undefined || readsDecision || usesKnowledge) continue;
    const text = kid(lit, "text")?.text;
    if (text !== undefined) literal.set(d.attrs.name ?? "", text.trim());
  }
  const cases: TckCase[] = [];
  let skipped = 0;
  for (const tc of kids(kid(tests, "testCases")!, "testCase")) {
    const inputs: Record<string, TckValue> = {};
    for (const inp of kids(tc, "inputNode")) inputs[inp.attrs.name ?? ""] = valueOf(inp);
    for (const rn of kids(tc, "resultNode")) {
      const name = rn.attrs.name ?? "";
      const expression = literal.get(name);
      if (expression === undefined) {
        skipped++;
        continue;
      }
      const expected = kid(rn, "expected");
      cases.push({
        folder,
        id: `${tc.attrs.id ?? ""}/${name}`,
        decision: name,
        expression,
        inputs,
        expected: expected === undefined ? { type: "null" } : valueOf(expected),
        errorResult: rn.attrs.errorResult === "true",
      });
    }
  }
  return { cases, skipped };
}

if (import.meta.main) {
  const [root, sha] = process.argv.slice(2);
  if (root === undefined || sha === undefined || !/^[0-9a-f]{40}$/.test(sha)) {
    console.error("usage: bun scripts/tck-extract.ts <checkout-dir> <40-hex commit sha>");
    process.exit(2);
  }
  const all: TckCase[] = [];
  for (const folder of CLAIMED_FOLDERS) {
    const { cases, skipped } = extractFolder(root, folder);
    all.push(...cases);
    console.log(`${folder}: ${cases.length} cases${skipped > 0 ? ` (${skipped} read another decision — not extracted)` : ""}`);
  }
  const out = join(import.meta.dir, "..", "test", "tck");
  writeFileSync(
    join(out, "cases.json"),
    `${JSON.stringify({ source: "https://github.com/dmn-tck/tck", commit: sha, licence: "Apache-2.0", folders: CLAIMED_FOLDERS, cases: all }, null, 1)}\n`,
  );
  console.log(`${all.length} cases → test/tck/cases.json`);
}
