/**
 * @kashscript/floor/check — the scanner. `checkFloor({ root })` reads `floor.manifest.json`, runs the detector's own
 * self-test, discovers what the repository mounts, and checks the seven rules. Every finding names the decisions it
 * enforces; waivers carry their reason and decision; waived findings are reported, never hidden.
 */

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { CITE, RULES, circular, decisionRefs, type CiteKey, type RuleId } from "./rules.js";
import { covers, keyText, looseGlob, parseRouteKey, specificity, validateManifest, type Manifest, type RouteDecl, type RouteKey, type Waiver } from "./manifest.js";
import { DEFAULT_EXCLUDES, Tree as FileTree, globToRegExp, matchesAny } from "./scan/files.js";
import {
  BAND_NAMES,
  DEFAULT_ENTRANCES,
  MONEY,
  PATH_PERSON_NOUNS,
  declineKind,
  forbiddenPrice,
  isActorColumn,
  isAnswerObject,
  isDecisionField,
  isOutcomeFilter,
  isPersonIdentifier,
  isPersonRef,
  isSubjectRef,
  namesDecision,
  namesPerson,
  priceNamed,
  scoreShaped,
  tokens,
} from "./scan/words.js";
import { emptySchema, prismaNonNull, readPrisma, resolveRelations, type PrismaModel } from "./scan/prisma.js";
import { columnValues, emptySqlModel, everyCountWrapped, isCanonicalFloorSuppress, readSql, type SqlModel } from "./scan/sql.js";
import { propertySchema, readLexiconJson } from "./scan/json-schema.js";
import { Sources, declTree, isPriceValue, isTsFile, isWithin, leaves, mergeTrees, objects, ts, typeTree, valueTree, type FloorCtx, type LeafAt, type Tree } from "./scan/ts.js";
import { copyTexts, countSites, dslObjects, escapeCasts, exportedConsts, exportedFunction, memberNames, suppressHits } from "./scan/ts-scans.js";
import { discoverRoutes, type OracleRoute } from "./scan/oracles.js";
import { runSelftest } from "./selftest.js";

export type FindingRule = RuleId | "manifest";

export interface Finding {
  readonly rule: FindingRule;
  /** The finding's identity — what a waiver names. Never a line number. */
  readonly at: string;
  readonly what: string;
  /** Where to look: a file and line, when there is one. */
  readonly where: string | undefined;
  readonly cites: readonly CiteKey[];
  readonly waivable: boolean;
  /** A decision a waiver of this finding must cite: the one that allows its exception (a percentage: d63(a)). */
  readonly requires: string | undefined;
}

export interface WaivedFinding extends Finding {
  readonly waiver: Waiver;
}

export interface FloorReport {
  readonly root: string;
  readonly repository: string | undefined;
  readonly findings: readonly Finding[];
  readonly waived: readonly WaivedFinding[];
  readonly routes: readonly OracleRoute[];
  readonly notes: readonly string[];
  /** The detector's own self-test failures; a non-empty list fails the run. */
  readonly selftest: readonly string[];
  readonly ok: boolean;
}

export interface CheckOptions {
  readonly root: string;
  /** Default: `<root>/floor.manifest.json`. */
  readonly manifest?: string;
  /** Boot logs written in CI; they take the place of the manifest's own. */
  readonly bootLogs?: readonly string[];
}

export class ManifestUnreadable extends Error {}

/** The finding's sentence and its decisions, as the report prints them. */
export function citesOf(f: Finding): string[] {
  return f.cites.map((c) => CITE[c]);
}

class Run {
  readonly findings = new Map<string, Finding>();
  readonly notes: string[] = [];
  readonly files: FileTree;
  readonly sources: Sources;
  readonly floor: FloorCtx;
  readonly sqlModels: SqlModel[] = [];

  constructor(
    readonly root: string,
    readonly manifest: Manifest,
  ) {
    this.files = new FileTree(root);
    this.sources = new Sources(root);
    this.floor = { self: rootPackageName(root) === "@kashscript/floor" };
  }

  add(rule: FindingRule, at: string, what: string, cites: readonly CiteKey[], opts: { waivable?: boolean; where?: string; requires?: string } = {}): void {
    const id = `${rule}|${at}`;
    if (this.findings.has(id)) return;
    this.findings.set(id, { rule, at, what, where: opts.where, cites, waivable: opts.waivable ?? true, requires: opts.requires });
  }

  problem(at: string, what: string): void {
    this.add("manifest", at, what, [], { waivable: false });
  }
}

function rootPackageName(root: string): string | undefined {
  try {
    const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as { name?: unknown };
    return typeof pkg.name === "string" ? pkg.name : undefined;
  } catch {
    return undefined;
  }
}

const LOOKUP: readonly CiteKey[] = ["d41Lookup", "d85b2", "d91hLookup"];
const SCORES: readonly CiteKey[] = ["d27", "d41Scores", "d43Counts", "d85b3", "std7"];
const COUNTS: readonly CiteKey[] = ["d97i", "d85b11", "d91f"];
const DECISION: readonly CiteKey[] = ["d43Version", "d84Rule11", "d84P3", "d85b5", "d85b7"];
const PRICE_NAME: readonly CiteKey[] = ["d84c", "d96a", "d50", "d85b12"];

/** A percentage is waived only by the decision that allows one: d63(a), the marketplace's commission on its bookings. */
const pctRequires = (bad: string | undefined): { requires?: string } => (bad?.startsWith("a percentage") === true ? { requires: "d63(a)" } : {});

/* ── routes ──────────────────────────────────────────────────────────────── */

interface Effective {
  /** The manifest key that declares it. */
  readonly declKey: string;
  readonly decl: RouteDecl;
  /** The concrete route: the manifest key itself, or a route an oracle found under a glob key. */
  readonly key: RouteKey;
  readonly oracle: OracleRoute | undefined;
}

function routes(run: Run, discovered: readonly OracleRoute[]): Effective[] {
  const declared = [...run.manifest.routes].map(([text, decl]) => ({ text, decl, key: parseRouteKey(text)! }));
  const used = new Set<string>();
  const out: Effective[] = [];
  for (const r of discovered) {
    const candidates = declared.filter((d) => covers(d.key, r.key));
    if (candidates.length === 0) {
      if (!r.closed) {
        run.add("undeclared-route", `route:${r.text}`, `is mounted (${r.source}) and not in the manifest: declare its subject and shape`, ["d91hAbsent"], { waivable: false });
      }
      continue;
    }
    const best = Math.max(...candidates.map((c) => specificity(c.key)));
    const top = candidates.filter((c) => specificity(c.key) === best);
    if (top.length > 1 && new Set(top.map((t) => JSON.stringify(t.decl))).size > 1) {
      run.problem(`route:${r.text}`, `is covered as closely by ${top.map((t) => `"${t.text}"`).join(" and ")}, which say different things`);
    }
    const chosen = top[0]!;
    used.add(chosen.text);
    if (chosen.key.glob) out.push({ declKey: chosen.text, decl: chosen.decl, key: r.key, oracle: r });
  }
  const byText = new Map(discovered.map((r) => [r.text, r]));
  for (const d of declared) {
    if (!d.key.glob) out.push({ declKey: d.text, decl: d.decl, key: d.key, oracle: byText.get(keyText(d.key)) });
    if (used.has(d.text) || d.decl.outsideOracle !== undefined) continue;
    if (d.key.glob) run.problem(`route:${d.text}`, "matches no mounted route");
    else run.add("undeclared-route", `stale:${d.text}`, "is declared, but no oracle mounts it: remove it, or say why no oracle can see it (\"outsideOracle\")", ["d91hAbsent"], { waivable: false });
  }
  return out;
}

/** Path parameters as written: `:userId`, `[userId]`, `{userId}`. */
function paramNames(target: string): string[] {
  return target
    .split("/")
    .map((s) => /^\[{1,2}(?:\.\.\.)?([^\]]+)\]{1,2}$/.exec(s)?.[1] ?? /^:([A-Za-z_]\w*)/.exec(s)?.[1] ?? /^\{([^}]+)\}$/.exec(s)?.[1])
    .filter((x): x is string => x !== undefined);
}

function nounsIn(key: RouteKey): string[] {
  const words: string[] = [];
  if (key.method === "TOOL") words.push(...tokens(key.target));
  else if (key.method === "ACTION") words.push(...tokens(key.target.split("#").pop() ?? ""));
  else {
    for (const seg of key.target.split("/")) {
      if (seg === "" || seg.includes("*")) continue;
      const param = paramNames(seg)[0];
      words.push(...tokens(param ?? seg));
    }
  }
  return [...new Set(words.filter((w) => PATH_PERSON_NOUNS.has(w)))];
}

function personLookup(run: Run, eff: readonly Effective[]): void {
  const seenDecl = new Set<string>();
  for (const e of eff) {
    const { decl } = e;
    const at = `route:${e.declKey}`;
    if (!seenDecl.has(e.declKey)) {
      seenDecl.add(e.declKey);
      if (decl.subject === "person" && ["one", "list", "search", "lookup"].includes(decl.shape)) {
        run.add("person-lookup", at, `is about a person and its shape is "${decl.shape}": a route that ${decl.shape === "one" ? "looks up one person" : decl.shape === "list" ? "lists persons" : decl.shape === "search" ? "searches for persons" : "looks a person up"}`, LOOKUP, { waivable: false });
      } else if (decl.shape === "lookup") {
        run.add("person-lookup", at, "has the shape \"lookup\": it finds a record by a person's identifier", LOOKUP, { waivable: false });
      }
      if (decl.shape === "push") run.add("person-lookup", at, "pushes to a person who has not come to it", ["d91hPush", "d84P43"], { waivable: false });
      if (decl.subject === "person" && decl.shape === "aggregate") {
        run.add("person-lookup", at, "counts the acts of one person: totals are of many, never a profile of one", ["d85b2", "d91hLookup"], { waivable: false });
      }
      if (decl.shape === "export" && decl.to !== "own-book") {
        run.add("person-lookup", at, `exports in bulk to "${decl.to ?? ""}": an export goes only to the organisation's own book`, ["d41Export", "d91hExport"], { waivable: false });
      }
      for (const q of decl.query) {
        if (isPersonIdentifier(q, decl.subject)) run.add("person-lookup", `query:${e.declKey}?${q}`, `takes "${q}", a person's identifier, as a query: that is a lookup`, LOOKUP, { waivable: false });
      }
    }
    for (const p of paramNames(e.key.target)) {
      if (isPersonIdentifier(p, decl.shape === "self" || decl.shape === "presented" ? "person" : decl.subject)) {
        run.add("person-lookup", `param:${keyText(e.key)}#${p}`, `takes a person's identifier ("${p}") in its path: that is a lookup`, LOOKUP, { waivable: false });
      }
    }
    if (e.key.method === "RPC" && e.oracle !== undefined && !e.oracle.closed) {
      for (const a of e.oracle.args) {
        if (isPersonIdentifier(a, decl.subject === "public" ? "record" : decl.subject)) {
          run.add("person-lookup", `arg:${keyText(e.key)}#${a}`, `takes a person's identifier ("${a}") as an argument: that is a lookup`, LOOKUP, { waivable: false });
        }
      }
      const returned = e.oracle.returnsSetOf;
      if (returned !== undefined && namesPerson(returned) && decl.subject !== "person") {
        run.add("person-lookup", `returns:${keyText(e.key)}`, `returns rows of "${returned}", a table of persons, yet is declared about "${decl.subject}"`, LOOKUP, { waivable: false });
      }
    }
    if (decl.subject === "person" && decl.shape === "self" && e.key.method === "REST" && e.oracle !== undefined && !e.oracle.self) {
      run.add("person-lookup", `policy:${keyText(e.key)}`, "is declared the caller's own, but its row policy does not key rows to the caller (auth.uid())", LOOKUP, { waivable: false });
    }
    if (decl.subject !== "person") {
      const nouns = nounsIn(e.key);
      if (nouns.length > 0) {
        run.add("person-lookup", `noun:${keyText(e.key)}`, `names ${nouns.map((n) => `"${n}"`).join(", ")} yet is declared about "${decl.subject}": declare it about a person, or waive with why it is not`, LOOKUP);
      }
    }
  }
}

function declinedRoutes(run: Run, eff: readonly Effective[]): void {
  const seen = new Set<string>();
  for (const e of eff) {
    if (seen.has(e.declKey)) continue;
    seen.add(e.declKey);
    const { decl } = e;
    const answers = isAnswerObject((parseRouteKey(e.declKey)?.target ?? e.key.target).replace(/[/#.:*]/g, " "));
    const listing = ["list", "search", "export"].includes(decl.shape);
    for (const s of decl.states) {
      const kind = declineKind(s);
      if (kind === undefined) continue;
      if (answers && (kind === "decline" || kind === "refusal")) {
        run.add("declined-state", `state:${e.declKey}=${s}`, `returns "${s}" for what a person answers: a decline leaves no state`, ["d49a", "std27"]);
      } else if (listing) {
        run.add("declined-state", `state:${e.declKey}=${s}`, `lists "${s}" (shape "${decl.shape}"): ${kind === "no-show" ? "a list of who did not come" : kind === "refusal" ? "a list of refusals" : "a list of declines"}`, kind === "no-show" ? ["d41Report", "d85b3"] : kind === "refusal" ? ["d91hRefusal"] : ["d49a", "d91hRefusal"], kind === "refusal" ? { requires: "d84 P3" } : {});
      }
    }
    for (const q of decl.query) {
      if (isOutcomeFilter(q)) run.add("declined-state", `filter:${e.declKey}?${q}`, `filters on "${q}": a query that picks out refusals`, ["d91hRefusal"]);
    }
  }
}

/* ── schemas ─────────────────────────────────────────────────────────────── */

function personSets<T extends { name: string }>(items: readonly T[], extra: readonly string[], isPerson: (t: T) => boolean, keyed: (t: T, persons: ReadonlySet<string>) => boolean): { persons: Set<string>; keyed: Set<string> } {
  const persons = new Set(items.filter((t) => isPerson(t) || extra.includes(t.name)).map((t) => t.name));
  const k = new Set(items.filter((t) => !persons.has(t.name) && keyed(t, persons)).map((t) => t.name));
  return { persons, keyed: k };
}

function scorePrisma(run: Run, models: readonly PrismaModel[], extra: readonly string[]): ReadonlySet<string> {
  const { persons, keyed } = personSets(
    models,
    extra,
    (m) => namesPerson(m.name) || namesPerson(m.dbName) || extra.includes(m.dbName),
    (m, p) => m.fields.some((f) => (f.relation ? p.has(f.type) && !isActorColumn(f.name) : isSubjectRef(f.name))),
  );
  for (const m of models) {
    if (!persons.has(m.name) && !keyed.has(m.name)) continue;
    const about = persons.has(m.name) ? "a person" : "a row keyed to a person";
    if (scoreShaped(m.name, m.name)) {
      run.add("person-score", `prisma:${m.name}`, `is a table of ${tokens(m.name).join(" ")} kept on ${about}`, SCORES, { where: m.file });
      continue;
    }
    for (const f of m.fields) {
      if (f.relation || !scoreShaped(f.name, m.name)) continue;
      const cites: CiteKey[] = [...SCORES, ...(tokens(f.name).includes("standing") ? (["d42Standing"] as CiteKey[]) : [])];
      run.add("person-score", `prisma:${m.name}.${f.name}`, `is shaped as a score, a rank or a count, on ${about}`, cites, { where: m.file });
    }
  }
  return new Set([...persons, ...keyed]);
}

function scoreSql(run: Run, model: SqlModel, extra: readonly string[]): ReadonlySet<string> {
  const rels = [...model.relations.values()].filter((r) => r.kind === "table");
  const { persons, keyed } = personSets(
    rels,
    extra,
    (r) => namesPerson(r.name),
    (r, p) => [...r.columns.values()].some((c) => !isActorColumn(c.name) && (isSubjectRef(c.name) || (c.references !== undefined && p.has(c.references)))),
  );
  for (const r of rels) {
    if (!persons.has(r.name) && !keyed.has(r.name)) continue;
    const about = persons.has(r.name) ? "a person" : "a row keyed to a person";
    if (scoreShaped(r.name, r.name)) {
      run.add("person-score", `sql:${r.name}`, `is a table of ${tokens(r.name).join(" ")} kept on ${about}`, SCORES, { where: r.file });
      continue;
    }
    for (const c of r.columns.values()) {
      if (!scoreShaped(c.name, r.name)) continue;
      const cites: CiteKey[] = [...SCORES, ...(tokens(c.name).includes("standing") ? (["d42Standing"] as CiteKey[]) : [])];
      run.add("person-score", `sql:${r.name}.${c.name}`, `is shaped as a score, a rank or a count, on ${about}`, cites, { where: r.file });
    }
  }
  return new Set([...persons, ...keyed]);
}

function hasRuleVersion(fields: ReadonlyArray<{ name: string; nonNull: boolean }>, declared: string | undefined): "yes" | "nullable" | "no" {
  if (declared !== undefined) {
    const f = fields.find((x) => x.name === declared);
    return f === undefined ? "no" : f.nonNull ? "yes" : "nullable";
  }
  const direct = fields.find((f) => tokens(f.name).join(" ") === "rule version");
  if (direct !== undefined) return direct.nonNull ? "yes" : "nullable";
  const rule = fields.find((f) => {
    const t = tokens(f.name);
    return t[0] === "rule" && (t.length === 1 || ["id", "ref", "did", "key", "uri"].includes(t[t.length - 1]!));
  });
  const version = fields.find((f) => f.name.toLowerCase() === "version");
  if (rule !== undefined && version !== undefined) return version.nonNull ? "yes" : "nullable";
  return "no";
}

function decisionsAndDeclines(run: Run, kind: "prisma" | "sql", name: string, dbName: string, fields: ReadonlyArray<{ name: string; nonNull: boolean; values: readonly string[] }>, where: string, personal: boolean): void {
  const declared = run.manifest.schemas.decisions.get(name) ?? run.manifest.schemas.decisions.get(dbName);
  const answer = isAnswerObject(name) || isAnswerObject(dbName);
  const refusing = (v: string): boolean => {
    const k = declineKind(v);
    return k === "decline" || k === "refusal";
  };
  // An outcome field makes a decision only when it can say no; a deliverable's or an audit entry's outcome does not.
  const outcomeSaysNo = fields.some((f) => tokens(f.name).pop() === "outcome" && f.values.some(refusing));
  const decision = !answer && (declared !== undefined || namesDecision(name) || namesDecision(dbName) || outcomeSaysNo || fields.some((f) => isDecisionField(f.name)));
  if (!answer && !decision && personal) {
    for (const f of fields) {
      for (const value of f.values.filter(refusing)) {
        run.add("decision-without-rule", `refusal:${kind}:${name}.${f.name}=${value}`, `keeps "${value}" about a person outside a decision: a no is a named person's decision that names its rule version`, DECISION, { where });
      }
    }
  }
  if (decision) {
    const v = hasRuleVersion(fields, declared);
    if (v !== "yes") {
      run.add("decision-without-rule", `decision:${kind}:${name}`, v === "nullable" ? "is a decision whose rule version may be null" : "is a decision that names no rule version (ruleVersion, or ruleId and version)", DECISION, { where });
    }
  }
  if (answer) {
    for (const f of fields) {
      for (const value of f.values) {
        const k = declineKind(value);
        if (k === "decline" || k === "refusal") run.add("declined-state", `${kind}:${name}.${f.name}=${value}`, `keeps "${value}" for what a person answers: a decline leaves no trace`, ["d49a", "std27"], { where });
      }
    }
  }
}

function schemas(run: Run): void {
  const s = run.manifest.schemas;
  if (s.prisma.length > 0) {
    const schema = emptySchema();
    const files = run.files.select(s.prisma);
    if (files.length === 0) run.problem("manifest.schemas.prisma", "matches no file");
    for (const f of files) readPrisma(schema, f, run.files.read(f));
    resolveRelations(schema);
    const models = [...schema.models.values()].filter((m) => m.kind !== "type");
    const personal = scorePrisma(run, models, s.persons);
    for (const m of models) {
      const fields = m.fields.filter((f) => !f.relation).map((f) => ({ name: f.name, nonNull: prismaNonNull(f), values: schema.enums.get(f.type) ?? [] }));
      decisionsAndDeclines(run, "prisma", m.name, m.dbName, fields, m.file, personal.has(m.name));
    }
  }
  if (s.sql.length > 0) {
    const model = emptySqlModel();
    const files = run.files.select(s.sql).sort();
    if (files.length === 0) run.problem("manifest.schemas.sql", "matches no file");
    for (const f of files) readSql(model, f, run.files.read(f));
    run.sqlModels.push(model);
    const personal = scoreSql(run, model, s.persons);
    for (const r of model.relations.values()) {
      if (r.kind !== "table") continue;
      const fields = [...r.columns.values()].map((c) => ({ name: c.name, nonNull: c.notNull, values: columnValues(model, r, c) }));
      decisionsAndDeclines(run, "sql", r.name, r.name, fields, r.file, personal.has(r.name));
    }
  }
  if (s.lexicons.length > 0) {
    const files = run.files.select(s.lexicons);
    if (files.length === 0) run.problem("manifest.schemas.lexicons", "matches no file");
    for (const f of files) {
      if (f.endsWith(".json")) lexiconJson(run, f);
      else if (isTsFile(f)) lexiconDsl(run, f);
    }
  }
}

function lexiconJson(run: Run, file: string): void {
  const doc = readLexiconJson(file, run.files.read(file));
  if ("error" in doc) {
    run.problem(`lexicon:${file}`, `is not JSON: ${doc.error}`);
    return;
  }
  const byPointer = new Map(doc.objects.map((o) => [o.pointer, o]));
  const personal = new Map<string, boolean>();
  // An object is about a person when the lexicon is, when it holds a reference to one, or when an enclosing object
  // holds a reference to its subject (holderDid, userId) — never an actor's (a rule's author does not make its parts personal).
  const subjectAbove = (pointer: string | undefined): boolean => {
    if (pointer === undefined) return false;
    const o = byPointer.get(pointer);
    return o !== undefined && ([...o.properties.keys()].some((p) => isSubjectRef(p)) || subjectAbove(o.parent));
  };
  const isPersonal = (pointer: string): boolean => {
    const cached = personal.get(pointer);
    if (cached !== undefined) return cached;
    const o = byPointer.get(pointer);
    const v = namesPerson(doc.name) || (o !== undefined && ([...o.properties.keys()].some((p) => isPersonRef(p)) || subjectAbove(o.parent)));
    personal.set(pointer, v);
    return v;
  };
  for (const o of doc.objects) {
    if (!isPersonal(o.pointer)) continue;
    for (const p of o.properties.keys()) {
      if (scoreShaped(p, doc.name)) run.add("person-score", `lexicon:${file}#${o.pointer === "/" ? "" : o.pointer}/properties/${p}`, `is shaped as a score, a rank or a count, in a record about a person (${doc.name})`, SCORES, { where: file });
    }
  }
  if (namesDecision(doc.name)) {
    const top = byPointer.get("/");
    const rule = top === undefined ? undefined : propertySchema(top, "rule");
    const ruleRequired = Array.isArray(rule?.required) ? (rule.required as unknown[]) : [];
    const ok = top !== undefined && ((top.required.includes("rule") && ruleRequired.includes("version")) || top.required.includes("ruleVersion"));
    if (!ok) run.add("decision-without-rule", `decision:lexicon:${file}`, `is a decision lexicon (${doc.name}) that does not require its rule's version`, DECISION, { where: file });
  }
}

function lexiconDsl(run: Run, file: string): void {
  const sf = run.sources.get(run.files.abs(file));
  if (sf === undefined) return;
  const objs = dslObjects(sf);
  const byPath = new Map(objs.map((o) => [o.path, o]));
  const personal = (path: string): boolean => {
    const parts = path.split(".");
    for (let i = parts.length; i > 0; i--) {
      const p = parts.slice(0, i).join(".");
      if (namesPerson(parts[i - 1]!)) return true;
      const o = byPath.get(p);
      // The object itself: any reference to a person; an enclosing object: only its subject's (as for JSON Schema).
      const ref = i === parts.length ? isPersonRef : isSubjectRef;
      if (o !== undefined && [...o.props.keys()].some((k) => ref(k))) return true;
    }
    return false;
  };
  for (const o of objs) {
    if (!personal(o.path)) continue;
    for (const p of o.props.keys()) {
      if (scoreShaped(p, o.path)) run.add("person-score", `lexicon:${file}#${o.path}.${p}`, "is shaped as a score, a rank or a count, in a record about a person", SCORES, { where: `${file}:${o.line}` });
    }
  }
  for (const o of objs) {
    if (o.path.includes(".") || !namesDecision(o.path)) continue;
    const rule = byPath.get(`${o.path}.rule`);
    const ok = (o.required.includes("rule") && rule !== undefined && rule.required.includes("version")) || o.required.includes("ruleVersion");
    if (!ok) run.add("decision-without-rule", `decision:lexicon:${file}#${o.path}`, "is a decision schema that does not require its rule's version", DECISION, { where: `${file}:${o.line}` });
  }
}

/* ── sources: suppress, counts, prices ───────────────────────────────────── */

interface AggregateFn {
  readonly file: string;
  readonly node: ts.Node;
}

function aggregates(run: Run): AggregateFn[] {
  const fns: AggregateFn[] = [];
  const sqlNames = new Set<string>();
  for (const [name, a] of run.manifest.aggregates) {
    if (a.sql !== undefined) {
      sqlNames.add(a.sql);
      let body: string | undefined;
      for (const m of run.sqlModels) {
        for (const fn of m.functions.values()) if (fn.name === a.sql) body = fn.body;
        for (const rel of m.relations.values()) if (rel.name === a.sql && rel.kind === "view") body = rel.body;
      }
      if (body === undefined) {
        run.problem(`manifest.aggregates["${name}"]`, `names the SQL function or view "${a.sql}", which no SQL the floor reads defines`);
        continue;
      }
      const w = everyCountWrapped(body);
      if (!w.wrapped) run.add("unsuppressed-count", `sql-aggregate:${name}`, `counts or sums ${w.bare} time(s) outside floor_suppress(): every count it returns passes it`, COUNTS);
      continue;
    }
    if (a.file === undefined || a.export === undefined) continue;
    const abs = run.files.abs(a.file);
    const sf = existsSync(abs) ? run.sources.get(abs) : undefined;
    if (sf === undefined) {
      run.problem(`manifest.aggregates["${name}"]`, `names ${a.file}, which cannot be read`);
      continue;
    }
    const fn = exportedFunction(sf, a.export);
    if (fn === undefined) {
      run.problem(`manifest.aggregates["${name}"]`, `${a.file} exports no function ${a.export}`);
      continue;
    }
    fns.push({ file: a.file, node: fn.node });
    for (const line of escapeCasts(fn.node)) {
      run.add("unsuppressed-count", `cast-any:${name}`, `${a.export} casts to any or unknown: a raw count can hide behind it past the declared type`, COUNTS, { waivable: false, where: `${a.file}:${line}` });
    }
    if (fn.returnType === undefined) {
      run.add("unsuppressed-count", `type:${name}`, `${a.export} declares no return type, so the floor cannot see that its counts are FloorCounts`, COUNTS, { waivable: false, where: a.file });
      continue;
    }
    const tree = typeTree(fn.returnType, abs, { sources: run.sources, floor: run.floor, seen: new Set() });
    const usedRaw = new Set<string>();
    for (const l of leaves(tree)) {
      if (!["number", "bigint", "any", "unknown", "unresolved"].includes(l.cls)) continue;
      if (a.raw[l.path] !== undefined) {
        usedRaw.add(l.path);
        continue;
      }
      const what = l.cls === "unresolved" ? `is typed ${l.text}, which the floor cannot see into` : `is typed ${l.text}, not the floor's FloorCount`;
      run.add("unsuppressed-count", `type:${name}#${l.path === "" ? "(return)" : l.path}`, `${what}: a count leaves only through suppress (or the manifest's "raw" says why not)`, COUNTS, { where: a.file });
    }
    for (const p of Object.keys(a.raw)) if (!usedRaw.has(p)) run.problem(`manifest.aggregates["${name}"].raw["${p}"]`, "names no raw number in the aggregate's return type");
  }
  return fns;
}

// A dollar figure ends at a space or punctuation, so a regex replacement such as "$1[secret]" is not one.
const FIGURE = /(?<![\w$])(?:USD|PKR|EUR|GBP|AED|SAR|Rs\.?)\s?\d[\d,.]*|(?<![\w$])\$\s?\d[\d,.]*(?![\w[])/;

function sourcesScan(run: Run, aggregateFns: readonly AggregateFn[], priceFiles: ReadonlySet<string>): void {
  const files = run.files.select(run.manifest.sources, { defaultExcludes: true }).filter(isTsFile);
  const countKeys = [...run.manifest.counts.keys()].map((k) => ({ k, re: looseGlob(k) }));
  const classified = (key: string): boolean => countKeys.some((c) => c.re.test(key));
  for (const rel of files) {
    const abs = run.files.abs(rel);
    const sf = run.sources.get(abs);
    if (sf === undefined) continue;
    const runtimeFile = run.floor.self && rel === "src/suppress.ts";
    for (const h of suppressHits(sf, abs, run.floor, runtimeFile)) {
      const at = `${h.kind === "not-floor" ? "suppress" : h.kind}:${rel}#${h.fn}`;
      run.add("unsuppressed-count", at, h.detail, COUNTS, { waivable: false, where: `${rel}:${h.line}` });
    }
    const inAggregate = aggregateFns.filter((a) => a.file === rel);
    for (const site of countSites(sf)) {
      const key = `${rel}#${site.fn}`;
      if (inAggregate.some((a) => site.fnNode !== undefined && (site.fnNode === a.node || isWithin(site.fnNode, a.node)))) continue;
      if (classified(key)) continue;
      run.add("unsuppressed-count", `count:${key}`, `computes a count (${site.what}) that is neither inside a declared aggregate nor classified in "counts" (own or internal, with why)`, COUNTS, { waivable: false, where: `${rel}:${site.line}` });
    }
    if (priceFiles.has(rel)) continue;
    const exported = new Set<string>();
    for (const c of exportedConsts(sf)) {
      exported.add(c.name);
      if (!priceNamed(c.name) && forbiddenPrice(c.name, false) === undefined) continue;
      const vals = leaves(valueTree(c.init, sf));
      if (!vals.some(isPriceValue)) continue;
      const bad = forbiddenPrice(c.name, true);
      run.add("price-per-record", `price-source:${rel}#${c.name}`, bad !== undefined ? `is ${bad}, outside the price files` : "is a price written outside the manifest's price files", bad !== undefined ? PRICE_NAME : ["d96d", "d50"], { where: `${rel}:${c.line}`, ...pctRequires(bad) });
    }
    for (const m of memberNames(sf)) {
      if (!m.priceLike || (m.container === "" && exported.has(m.member))) continue;
      // A kebab-case key is data (a place's slug, a rule's id), never a field name.
      if (/^[a-z0-9]+(-[a-z0-9]+)+$/.test(m.member)) continue;
      const bad = forbiddenPrice(m.member, tokens(m.container).some((t) => MONEY.has(t)));
      if (bad === undefined) continue;
      run.add("price-per-record", `price-name:${rel}#${m.container === "" ? "" : `${m.container}.`}${m.member}`, `is ${bad}`, PRICE_NAME, { where: `${rel}:${m.line}`, ...pctRequires(bad) });
    }
    for (const t of copyTexts(sf)) {
      const m = FIGURE.exec(t.text);
      if (m === null) continue;
      if (m[0].startsWith("$") && (t.text.match(/[A-Za-z]/g)?.length ?? 0) < 3) continue;
      const figure = m[0].trim().replace(/[.,]+$/, "");
      run.add("price-per-record", `figure:${rel}#${figure}`, `writes a price figure ("${figure}") outside the price files`, ["d96d"], { where: `${rel}:${t.line}` });
    }
  }
}

/* ── prices ──────────────────────────────────────────────────────────────── */

interface PriceRoot {
  readonly file: string;
  readonly tree: Tree;
}

function jsonTree(v: unknown): Tree {
  if (Array.isArray(v)) return { kind: "array", element: v.length === 0 ? { kind: "leaf", cls: "nullish", text: "[]" } : v.map(jsonTree).reduce((a, b) => mergeTrees(a, b)) };
  if (typeof v === "object" && v !== null) return { kind: "object", members: new Map(Object.entries(v).map(([k, x]) => [k, jsonTree(x)])) };
  if (typeof v === "number") return { kind: "leaf", cls: "num", text: String(v) };
  if (typeof v === "string") return { kind: "leaf", cls: "str", text: v };
  return { kind: "leaf", cls: "lit", text: String(v) };
}

function priceRoots(run: Run, rel: string): PriceRoot[] {
  if (rel.endsWith(".json")) {
    try {
      const doc = JSON.parse(run.files.read(rel)) as unknown;
      const tree = jsonTree(doc);
      return [{ file: rel, tree }];
    } catch (e) {
      run.problem(`price:${rel}`, `is not JSON: ${(e as Error).message}`);
      return [];
    }
  }
  const abs = run.files.abs(rel);
  const sf = run.sources.get(abs);
  if (sf === undefined) return [];
  const out: PriceRoot[] = [];
  const ctx = { sources: run.sources, floor: run.floor, seen: new Set<string>() };
  const named = (name: string, tree: Tree): PriceRoot => ({ file: rel, tree: { kind: "object", members: new Map([[name, tree]]) } });
  const localDecl = (name: string): PriceRoot | undefined => {
    for (const s of sf.statements) {
      if ((ts.isInterfaceDeclaration(s) || ts.isTypeAliasDeclaration(s)) && s.name.text === name) return named(name, declTree(s, abs, ctx));
      if (ts.isVariableStatement(s)) for (const d of s.declarationList.declarations) if (ts.isIdentifier(d.name) && d.name.text === name && d.initializer !== undefined) return named(name, valueTree(d.initializer, sf));
    }
    return undefined;
  };
  for (const s of sf.statements) {
    const exported = ts.canHaveModifiers(s) && (ts.getModifiers(s) ?? []).some((m) => m.kind === ts.SyntaxKind.ExportKeyword);
    if ((ts.isInterfaceDeclaration(s) || ts.isTypeAliasDeclaration(s)) && exported) out.push(named(s.name.text, declTree(s, abs, ctx)));
    else if (ts.isVariableStatement(s) && exported) {
      for (const d of s.declarationList.declarations) if (ts.isIdentifier(d.name) && d.initializer !== undefined) out.push(named(d.name.text, valueTree(d.initializer, sf)));
    } else if (ts.isExportDeclaration(s) && s.moduleSpecifier === undefined && s.exportClause !== undefined && ts.isNamedExports(s.exportClause)) {
      for (const el of s.exportClause.elements) {
        const r = localDecl((el.propertyName ?? el.name).text);
        if (r !== undefined) out.push(r);
      }
    }
  }
  return out;
}

function segmentsOf(path: string): string[] {
  return path.replace(/\[\]/g, ".[]").split(".").filter((s) => s !== "");
}

function patternMatches(pattern: string, path: string): boolean {
  const p = segmentsOf(pattern);
  const s = segmentsOf(path);
  const memo = new Map<string, boolean>();
  const go = (i: number, j: number): boolean => {
    const k = `${i},${j}`;
    const hit = memo.get(k);
    if (hit !== undefined) return hit;
    let r: boolean;
    if (i === p.length) r = j === s.length;
    else if (p[i] === "**") r = go(i + 1, j) || (j < s.length && go(i, j + 1));
    else if (j === s.length) r = false;
    else if (p[i] === "*") r = go(i + 1, j + 1);
    else r = p[i] === s[j] && go(i + 1, j + 1);
    memo.set(k, r);
    return r;
  };
  return go(0, 0);
}

function patternSpecificity(pattern: string): number {
  const segs = segmentsOf(pattern);
  return segs.filter((s) => s !== "*" && s !== "**").length * 10 - (segs.includes("**") ? 1 : 0);
}

function prices(run: Run): Set<string> {
  const p = run.manifest.prices;
  const files = new Set(p.files.length === 0 ? [] : run.files.select(p.files));
  if (p.files.length > 0 && files.size === 0) run.problem("manifest.prices.files", "matches no file");
  const entrances = new Set([...DEFAULT_ENTRANCES, ...p.entrances]);
  const used = new Set<string>();
  for (const rel of files) {
    for (const root of priceRoots(run, rel)) {
      const kindAt = new Map<string, string>();
      const all: LeafAt[] = leaves(root.tree);
      for (const l of all) {
        const matching = [...p.fields].filter(([pat]) => patternMatches(pat, l.path));
        for (const [pat] of matching) used.add(pat);
        const at = `price:${rel}#${l.path}`;
        if (matching.length === 0) {
          run.add("price-per-record", at, "is a field of a price file the manifest does not name (prices.fields)", ["d50", "d96d"], { where: rel });
        } else {
          const best = Math.max(...matching.map(([pat]) => patternSpecificity(pat)));
          const top = matching.filter(([pat]) => patternSpecificity(pat) === best);
          if (new Set(top.map(([, k]) => k)).size > 1) run.problem(at, `is named as closely by ${top.map(([pat, k]) => `"${pat}" (${k})`).join(" and ")}`);
          kindAt.set(l.path, top[0]![1]);
        }
        for (const seg of segmentsOf(l.path)) {
          if (seg === "*" || seg === "[]") continue;
          const bad = forbiddenPrice(seg, true);
          if (bad !== undefined) run.add("price-per-record", `price-name:${rel}#${l.path}`, `is ${bad}`, PRICE_NAME, { where: rel, ...pctRequires(bad) });
        }
        if (l.cls === "computed") run.add("price-per-record", `price-unread:${rel}#${l.path}`, "is a price the floor cannot read: write it as a literal", ["d96d"], { where: rel });
        if (kindAt.get(l.path) === "outcome" && l.inList) run.add("price-per-record", `price-tier:${rel}#${l.path}`, "is an outcome price inside a list: one fixed price per accepted outcome, never a tier table", ["d96a"], { where: rel });
      }
      for (const o of objects(root.tree)) {
        for (const kind of ["outcome", "allowance"] as const) {
          const named = o.leafMembers.filter((m) => kindAt.get(m.path) === kind && !entrances.has(m.name) && !BAND_NAMES.has(m.name.toLowerCase()));
          if (named.length > 1) {
            run.add("price-per-record", `price-object:${rel}#${o.path}`, `holds ${named.length} ${kind === "outcome" ? "prices for one accepted outcome" : "allowances"} (${named.map((m) => m.name).join(", ")}): one fixed price and one monthly allowance, by entrance`, ["d96a"], { where: rel });
          }
        }
      }
    }
  }
  for (const pat of p.fields.keys()) if (!used.has(pat)) run.problem(`manifest.prices.fields["${pat}"]`, "matches no field of the price files");
  return files;
}

/* ── aliases of the floor ────────────────────────────────────────────────── */

function stripJsonComments(text: string): string {
  let out = "";
  let inStr = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inStr) {
      out += c;
      if (c === "\\") {
        out += text[i + 1] ?? "";
        i++;
      } else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') {
      inStr = true;
      out += c;
    } else if (c === "/" && text[i + 1] === "/") {
      while (i < text.length && text[i] !== "\n") i++;
    } else if (c === "/" && text[i + 1] === "*") {
      i += 2;
      while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i++;
    } else out += c;
  }
  return out.replace(/,(\s*[}\]])/g, "$1");
}

function aliases(run: Run): void {
  const isFloorKey = (k: string): boolean => k === "@kashscript/floor" || k.startsWith("@kashscript/floor/");
  const monorepo = run.files.exists("packages/floor/package.json") && run.floor.self === false && (() => {
    try {
      return (JSON.parse(run.files.read("packages/floor/package.json")) as { name?: string }).name === "@kashscript/floor";
    } catch {
      return false;
    }
  })();
  const flag = (at: string, what: string): void => run.add("unsuppressed-count", `alias:${at}`, what, COUNTS, { waivable: false, where: at.split("#")[0] ?? at });
  // Tests and fixtures are skipped, as the source scan skips them: their configuration never reaches what is served.
  const skipped = DEFAULT_EXCLUDES.map(globToRegExp);
  for (const rel of run.files.files()) {
    if (matchesAny(rel, skipped)) continue;
    const name = rel.split("/").pop() ?? rel;
    if (/^tsconfig.*\.json$/.test(name)) {
      try {
        const cfg = JSON.parse(stripJsonComments(run.files.read(rel))) as { compilerOptions?: { paths?: Record<string, unknown> } };
        for (const k of Object.keys(cfg.compilerOptions?.paths ?? {})) if (isFloorKey(k)) flag(`${rel}#paths`, `maps "${k}" to another file: the floor is imported from its package, never through an alias`);
      } catch {
        // not JSON the floor can read; tsc will say so
      }
    } else if (name === "package.json") {
      let pkg: Record<string, unknown>;
      try {
        pkg = JSON.parse(run.files.read(rel)) as Record<string, unknown>;
      } catch {
        continue;
      }
      for (const field of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "overrides", "resolutions"]) {
        const deps = pkg[field];
        if (typeof deps !== "object" || deps === null) continue;
        for (const [k, v] of Object.entries(deps as Record<string, unknown>)) {
          if (!isFloorKey(k) || typeof v !== "string") continue;
          if (/^(file:|link:|portal:|patch:|git|https?:|github:|\.|\/)/.test(v) || (v.startsWith("workspace:") && !monorepo)) {
            flag(`${rel}#${field}`, `points ${k} at "${v}", not the published package`);
          }
        }
      }
      const pnpm = pkg.pnpm as { patchedDependencies?: Record<string, unknown>; overrides?: Record<string, unknown> } | undefined;
      for (const k of [...Object.keys(pnpm?.patchedDependencies ?? {}), ...Object.keys(pnpm?.overrides ?? {})]) {
        if (k.includes("@kashscript/floor")) flag(`${rel}#pnpm`, `patches or overrides ${k}`);
      }
    } else if (name === "pnpm-workspace.yaml") {
      const text = run.files.read(rel);
      if (/patchedDependencies:[\s\S]*@kashscript\/floor/.test(text)) flag(`${rel}#patchedDependencies`, "patches @kashscript/floor");
    } else if (/^@kashscript__floor/.test(name) && rel.includes("patches/")) {
      flag(`${rel}#patch`, "is a patch of @kashscript/floor");
    }
  }
}

/* ── coverage: what the manifest must not leave out ──────────────────────── */

/**
 * The floor looks for itself: every Next app and Pages folder, every Supabase folder, every Cloudflare Worker, every
 * Prisma schema, every migration, every lexicon and every TypeScript or JavaScript file outside tests. Each must be
 * covered by the manifest or listed in `excluded` with why — otherwise the manifest, written by the repository it
 * checks, would decide what the floor sees.
 */
function coverage(run: Run): void {
  const m = run.manifest;
  const skip = [...DEFAULT_EXCLUDES.map(globToRegExp), ...[...m.excluded.keys()].map(globToRegExp)];
  const files = run.files.files().filter((f) => !matchesAny(f, skip));
  const selects = (patterns: readonly string[]): ((f: string) => boolean) => {
    const inc = patterns.filter((p) => !p.startsWith("!")).map(globToRegExp);
    const exc = patterns.filter((p) => p.startsWith("!")).map((p) => globToRegExp(p.slice(1)));
    return (f) => matchesAny(f, inc) && !matchesAny(f, exc);
  };
  const gap = (at: string, what: string): void => run.problem(`coverage:${at}`, what);
  if (m.oracles.length === 0 && m.serves !== "none") gap("oracles", 'names no oracle: say how the floor finds what is served, or "serves": "none"');

  const trim = (p: string): string => p.replace(/\/+$/, "");
  const nextApps = new Set(m.oracles.flatMap((o) => (o.kind === "next-app" ? [trim(o.app)] : [])));
  const nextPages = new Set(m.oracles.flatMap((o) => (o.kind === "next-pages" ? [trim(o.dir)] : [])));
  const supa = new Set(m.oracles.flatMap((o) => (o.kind === "supabase" ? [trim(o.dir)] : [])));
  const fileSet = new Set(run.files.files());
  const hasNextConfig = (dir: string): boolean => ["js", "mjs", "ts", "cjs"].some((x) => fileSet.has(`${dir === "" ? "" : `${dir}/`}next.config.${x}`));
  const seen = new Set<string>();
  const once = (key: string, f: () => void): void => {
    if (!seen.has(key)) {
      seen.add(key);
      f();
    }
  };
  const inSources = selects(m.sources);
  const inPrisma = selects(m.schemas.prisma);
  const inSql = selects(m.schemas.sql);
  const inLexicons = selects(m.schemas.lexicons);
  const sourceGaps = new Map<string, number>();
  for (const f of files) {
    const segs = f.split("/");
    const name = segs[segs.length - 1]!;
    if (/^(page|route)\.(tsx|ts|jsx|js|mjs|mdx)$/.test(name)) {
      const i = segs.indexOf("app");
      if (i >= 0) {
        const root = segs.slice(0, i + 1).join("/");
        if (!nextApps.has(root)) once(`next-app:${root}`, () => gap(`next-app:${root}`, "holds Next routes no next-app oracle reads"));
      }
    }
    const pi = segs.indexOf("pages");
    if (pi >= 0 && pi < segs.length - 1 && /\.(tsx|ts|jsx|js|mjs|mdx)$/.test(name)) {
      const parent = segs.slice(0, pi).join("/");
      const grand = segs.slice(0, Math.max(0, pi - 1)).join("/");
      const root = segs.slice(0, pi + 1).join("/");
      if ((hasNextConfig(parent) || (segs[pi - 1] === "src" && hasNextConfig(grand))) && !nextPages.has(root)) {
        once(`next-pages:${root}`, () => gap(`next-pages:${root}`, "holds Pages Router routes no next-pages oracle reads"));
      }
    }
    const si = segs.indexOf("supabase");
    if (si >= 0 && (segs[si + 1] === "migrations" || segs[si + 1] === "functions")) {
      const root = segs.slice(0, si + 1).join("/");
      if (!supa.has(root)) once(`supabase:${root}`, () => gap(`supabase:${root}`, "is a Supabase project no supabase oracle reads"));
    }
    if (/^wrangler\.(toml|json|jsonc)$/.test(name)) {
      gap(`worker:${f}`, 'is a Cloudflare Worker, and no oracle reads its routes: exclude it with why, and declare its routes with "outsideOracle"');
    }
    if (name.endsWith(".prisma") && !inPrisma(f)) gap(`prisma:${f}`, "is a Prisma schema not in schemas.prisma");
    const supabaseMigration = segs.some((s, i) => s === "supabase" && segs[i + 1] === "migrations");
    if (name.endsWith(".sql") && segs.includes("migrations") && !supabaseMigration && !inSql(f)) {
      gap(`sql:${f}`, "is a migration not in schemas.sql");
    }
    if ((name.endsWith(".schema.json") || (segs.includes("lexicons") && name.endsWith(".json"))) && !inLexicons(f)) gap(`lexicon:${f}`, "is a lexicon not in schemas.lexicons");
    if (isTsFile(f) && !inSources(f)) {
      const group = segs.length <= 2 ? segs.slice(0, -1).join("/") || "." : segs.slice(0, 2).join("/");
      sourceGaps.set(group, (sourceGaps.get(group) ?? 0) + 1);
    }
  }
  for (const [group, n] of sourceGaps) gap(`sources:${group}`, `holds ${n} source file(s) not in "sources": add them, or exclude them with why`);
}

/* ── waivers ─────────────────────────────────────────────────────────────── */

function waive(run: Run): WaivedFinding[] {
  const waived: WaivedFinding[] = [];
  for (const w of run.manifest.waivers) {
    const at = `manifest.waivers[${w.index}]`;
    if (circular(w.rule, w.decision)) {
      run.problem(at, `cites only what its own rule enforces (${RULES[w.rule].decisions.join(", ")}): a waiver names the decision that allows the exception`);
      continue;
    }
    const re = looseGlob(w.at);
    const matched = [...run.findings.entries()].filter(([, f]) => f.rule === w.rule && re.test(f.at));
    if (matched.length === 0) {
      run.problem(at, `matches no ${w.rule} finding ("${w.at}")`);
      continue;
    }
    const fixed = matched.filter(([, f]) => !f.waivable);
    if (fixed.length > 0) run.problem(at, `names ${fixed.map(([, f]) => f.at).join(", ")}, which cannot be waived`);
    const cited = new Set(decisionRefs(w.decision));
    for (const [id, f] of matched) {
      if (!f.waivable) continue;
      if (f.requires !== undefined && !decisionRefs(f.requires).every((r) => cited.has(r))) {
        run.problem(at, `waives ${f.at}, whose exception only ${f.requires} allows: cite it`);
        continue;
      }
      run.findings.delete(id);
      waived.push({ ...f, waiver: w });
    }
  }
  return waived;
}

/* ── the run ─────────────────────────────────────────────────────────────── */

export function readManifest(root: string, path?: string): unknown {
  const file = resolve(root, path ?? "floor.manifest.json");
  if (!existsSync(file)) throw new ManifestUnreadable(`no manifest at ${file}`);
  try {
    return JSON.parse(readFileSync(file, "utf8").replace(/^﻿/, ""));
  } catch (e) {
    throw new ManifestUnreadable(`${file} is not JSON: ${(e as Error).message}`);
  }
}

export function checkFloor(opts: CheckOptions): FloorReport {
  const root = resolve(opts.root);
  const selftest = runSelftest();
  const { manifest, problems } = validateManifest(readManifest(root, opts.manifest));
  const run = new Run(root, manifest);
  for (const p of problems) run.problem(p.at, p.what);
  coverage(run);

  const found = discoverRoutes(manifest.oracles, { root, files: run.files, sources: run.sources, bootLogs: opts.bootLogs ?? [] });
  for (const p of found.problems) run.add("undeclared-route", p.at, p.what, ["d91hAbsent"], { waivable: false });
  run.notes.push(...found.notes);
  run.sqlModels.push(...found.sql);

  const eff = routes(run, found.routes);
  personLookup(run, eff);
  declinedRoutes(run, eff);

  schemas(run);
  const priceFiles = prices(run);
  const aggregateFns = aggregates(run);
  sourcesScan(run, aggregateFns, priceFiles);

  // Exposed SQL that counts: an aggregate wrapped in floor_suppress, or classified.
  const sqlAggregates = new Set([...manifest.aggregates.values()].map((a) => a.sql).filter((s): s is string => s !== undefined));
  const countKeys = [...manifest.counts.keys()].map(looseGlob);
  for (const r of found.routes) {
    if (!r.counts || r.closed || r.sqlName === undefined) continue;
    if (sqlAggregates.has(r.sqlName) || matchesAny(`sql:${r.sqlName}`, countKeys)) continue;
    run.add("unsuppressed-count", `count:sql:${r.sqlName}`, `is served (${r.text}) and counts or sums: declare it an SQL aggregate wrapped in floor_suppress(), or classify it in "counts"`, COUNTS, { waivable: false, where: r.source.replace(/^supabase /, "") });
  }
  // A served table's counter columns are counts too: anyone the policy lets in reads them raw.
  for (const r of found.routes) {
    if (r.closed || r.sqlName === undefined) continue;
    for (const c of r.countColumns) {
      const key = `sql:${r.sqlName}.${c}`;
      if (matchesAny(key, countKeys)) continue;
      run.add("unsuppressed-count", `count:${key}`, `is a count served raw (${r.text}): close the table to clients and serve it through floor_suppress(), or classify it in "counts"`, COUNTS, { waivable: false, where: r.source.replace(/^supabase /, "") });
    }
  }
  // floor_suppress must be the floor's own: a copy that returns n whole would pass every wrap check.
  for (const m of run.sqlModels) {
    for (const fn of m.functions.values()) {
      if (fn.name === "floor_suppress" && !isCanonicalFloorSuppress(fn)) {
        run.add("unsuppressed-count", `counterfeit:sql:${fn.schema}.floor_suppress`, "is not the floor_suppress @kashscript/floor ships (sql/floor_suppress.sql): copy it unchanged", COUNTS, { waivable: false, where: fn.file });
      }
    }
  }

  aliases(run);
  if (manifest.aggregates.size > 0) {
    run.notes.push("counts pass suppress for display (k = 5); the noise the founder ruled comes first (2026-11-20) is KS-Q7's and not built, so these counts hold the display rule, not a privacy bound");
  }
  const waived = waive(run);
  const findings = [...run.findings.values()];
  return {
    root,
    repository: manifest.repository,
    findings,
    waived,
    routes: found.routes,
    notes: run.notes,
    selftest,
    ok: findings.length === 0 && selftest.length === 0,
  };
}

/** Exported for the selftest and the tests. */
export const internal = { patternMatches, patternSpecificity, paramNames, nounsIn, globToRegExp };
