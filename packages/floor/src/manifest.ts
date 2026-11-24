/**
 * floor.manifest.json — what a repository declares: every mounted route with its subject and shape, every exported
 * aggregate, every classified count, every price field, where its schemas and sources are, and its waivers.
 * The validator is strict: an unknown key, a word outside the vocabulary, or a waiver without its reason and decision
 * is a manifest problem, and a manifest problem is never waived.
 */

import { RULES, type RuleId } from "./rules.js";

export const SUBJECTS = ["person", "organisation", "mandate", "record", "rule", "place", "public"] as const;
export const SHAPES = ["one", "list", "search", "lookup", "aggregate", "action", "self", "presented", "export", "push", "closed"] as const;
export const PRICE_KINDS = ["flat", "band", "outcome", "allowance", "structure"] as const;
export const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "ANY", "PAGE", "ACTION", "TOOL", "REST", "RPC", "WS"] as const;

export type Subject = (typeof SUBJECTS)[number];
export type Shape = (typeof SHAPES)[number];
export type PriceKind = (typeof PRICE_KINDS)[number];

export interface RouteDecl {
  readonly subject: Subject;
  readonly shape: Shape;
  readonly aggregates: readonly string[];
  readonly states: readonly string[];
  readonly query: readonly string[];
  readonly to: string | undefined;
  readonly why: string | undefined;
  readonly outsideOracle: string | undefined;
}

export interface AggregateDecl {
  readonly file: string | undefined;
  readonly export: string | undefined;
  readonly sql: string | undefined;
  readonly raw: Readonly<Record<string, string>>;
}

export interface CountDecl {
  readonly kind: "own" | "internal";
  readonly why: string;
}

export type OracleDecl =
  | { readonly kind: "boot-log"; readonly files: readonly string[] }
  | { readonly kind: "next-app"; readonly app: string; readonly host: string | undefined; readonly actions: string | undefined }
  | { readonly kind: "next-pages"; readonly dir: string; readonly host: string | undefined }
  | { readonly kind: "supabase"; readonly dir: string; readonly schemas: readonly string[]; readonly host: string | undefined }
  | { readonly kind: "ts-table"; readonly file: string; readonly export: string; readonly key: string | undefined; readonly host: string | undefined };

export interface Waiver {
  readonly rule: RuleId;
  readonly at: string;
  readonly reason: string;
  readonly decision: string;
  /** Its place in the manifest's list, for the report. */
  readonly index: number;
}

export interface Manifest {
  readonly repository: string | undefined;
  /** "none": the repository serves no route, so it needs no oracle. */
  readonly serves: "none" | undefined;
  /** What the floor would find by itself and is told to leave out, each with why. */
  readonly excluded: ReadonlyMap<string, string>;
  readonly oracles: readonly OracleDecl[];
  readonly routes: ReadonlyMap<string, RouteDecl>;
  readonly aggregates: ReadonlyMap<string, AggregateDecl>;
  readonly counts: ReadonlyMap<string, CountDecl>;
  readonly schemas: {
    readonly prisma: readonly string[];
    readonly sql: readonly string[];
    readonly lexicons: readonly string[];
    readonly persons: readonly string[];
    readonly decisions: ReadonlyMap<string, string>;
  };
  readonly sources: readonly string[];
  readonly prices: { readonly files: readonly string[]; readonly entrances: readonly string[]; readonly fields: ReadonlyMap<string, PriceKind> };
  readonly waivers: readonly Waiver[];
}

export interface ManifestProblem {
  readonly at: string;
  readonly what: string;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);

class V {
  readonly problems: ManifestProblem[] = [];
  bad(at: string, what: string): void {
    this.problems.push({ at, what });
  }
  keys(at: string, o: Obj, allowed: readonly string[]): void {
    for (const k of Object.keys(o)) if (!allowed.includes(k) && k !== "$schema" && k !== "$comment") this.bad(`${at}.${k}`, `an unknown key; the keys here are ${allowed.join(", ")}`);
  }
  str(at: string, v: unknown, opts: { required?: boolean } = {}): string | undefined {
    if (v === undefined) {
      if (opts.required === true) this.bad(at, "is required");
      return undefined;
    }
    if (typeof v !== "string" || v.trim() === "") {
      this.bad(at, "must be a non-empty string");
      return undefined;
    }
    return v;
  }
  strs(at: string, v: unknown): string[] {
    if (v === undefined) return [];
    if (!Array.isArray(v) || !v.every((x) => typeof x === "string" && x.trim() !== "")) {
      this.bad(at, "must be a list of non-empty strings");
      return [];
    }
    return v as string[];
  }
  word<T extends string>(at: string, v: unknown, words: readonly T[]): T | undefined {
    if (typeof v !== "string" || !(words as readonly string[]).includes(v)) {
      this.bad(at, `must be one of ${words.join(", ")}${v === "?" ? " (a draft's ? is not an answer)" : ""}`);
      return undefined;
    }
    return v as T;
  }
  obj(at: string, v: unknown): Obj {
    if (v === undefined) return {};
    if (!isObj(v)) {
      this.bad(at, "must be an object");
      return {};
    }
    return v;
  }
}

export function validateManifest(raw: unknown): { manifest: Manifest; problems: ManifestProblem[] } {
  const v = new V();
  let top: Obj = {};
  if (isObj(raw)) top = raw;
  else v.bad("manifest", "must be a JSON object");
  v.keys("manifest", top, ["floor", "repository", "serves", "excluded", "oracles", "routes", "aggregates", "counts", "schemas", "sources", "prices", "waivers"]);
  if (top.serves !== undefined && top.serves !== "none") v.bad("manifest.serves", 'is "none" or absent');
  const excluded = new Map<string, string>();
  for (const [glob, why] of Object.entries(v.obj("manifest.excluded", top.excluded))) {
    const w = v.str(`manifest.excluded["${glob}"]`, why);
    if (w !== undefined) excluded.set(glob, w);
  }
  if (top.floor !== 1) v.bad("manifest.floor", "must be 1, the manifest format this floor reads");

  const oracles: OracleDecl[] = [];
  const rawOracles = top.oracles === undefined ? [] : top.oracles;
  if (!Array.isArray(rawOracles)) v.bad("manifest.oracles", "must be a list");
  else {
    rawOracles.forEach((o, i) => {
      const at = `manifest.oracles[${i}]`;
      if (!isObj(o)) return v.bad(at, "must be an object");
      const kind = v.word(`${at}.kind`, o.kind, ["boot-log", "next-app", "next-pages", "supabase", "ts-table"] as const);
      if (kind === "next-pages") {
        v.keys(at, o, ["kind", "dir", "host"]);
        const dir = v.str(`${at}.dir`, o.dir, { required: true });
        if (dir !== undefined) oracles.push({ kind, dir, host: v.str(`${at}.host`, o.host) });
      }
      if (kind === "boot-log") {
        v.keys(at, o, ["kind", "files"]);
        oracles.push({ kind, files: v.strs(`${at}.files`, o.files) });
      } else if (kind === "next-app") {
        v.keys(at, o, ["kind", "app", "host", "actions"]);
        const app = v.str(`${at}.app`, o.app, { required: true });
        if (app !== undefined) oracles.push({ kind, app, host: v.str(`${at}.host`, o.host), actions: v.str(`${at}.actions`, o.actions) });
      } else if (kind === "supabase") {
        v.keys(at, o, ["kind", "dir", "schemas", "host"]);
        const dir = v.str(`${at}.dir`, o.dir, { required: true });
        const schemas = v.strs(`${at}.schemas`, o.schemas);
        if (dir !== undefined) oracles.push({ kind, dir, schemas: schemas.length > 0 ? schemas : ["public"], host: v.str(`${at}.host`, o.host) });
      } else if (kind === "ts-table") {
        v.keys(at, o, ["kind", "file", "export", "key", "host"]);
        const file = v.str(`${at}.file`, o.file, { required: true });
        const exp = v.str(`${at}.export`, o.export, { required: true });
        if (file !== undefined && exp !== undefined) oracles.push({ kind, file, export: exp, key: v.str(`${at}.key`, o.key), host: v.str(`${at}.host`, o.host) });
      }
    });
  }

  const routes = new Map<string, RouteDecl>();
  const rawAggregates = v.obj("manifest.aggregates", top.aggregates);
  for (const [key, d] of Object.entries(v.obj("manifest.routes", top.routes))) {
    const at = `manifest.routes["${key}"]`;
    const parsed = parseRouteKey(key);
    if (parsed === undefined) {
      v.bad(at, `is not a route key: write "METHOD /path" (METHOD one of ${METHODS.join(", ")}), with an optional host: "PAGE web:/about"`);
      continue;
    }
    if (parsed.glob && !globAllowed(parsed)) {
      v.bad(at, "a glob may cover pages, or API routes under a literal prefix of two segments (\"GET /api/v1/*\"); never every route, tool or action: a catch-all key declares nothing");
    }
    if (!isObj(d)) {
      v.bad(at, "must be an object");
      continue;
    }
    v.keys(at, d, ["subject", "shape", "aggregates", "states", "query", "to", "why", "outsideOracle"]);
    const subject = v.word(`${at}.subject`, d.subject, SUBJECTS);
    const shape = v.word(`${at}.shape`, d.shape, SHAPES);
    const aggregates = v.strs(`${at}.aggregates`, d.aggregates);
    const decl: RouteDecl = {
      subject: subject ?? "public",
      shape: shape ?? "action",
      aggregates,
      states: v.strs(`${at}.states`, d.states),
      query: v.strs(`${at}.query`, d.query),
      to: v.str(`${at}.to`, d.to),
      why: v.str(`${at}.why`, d.why),
      outsideOracle: v.str(`${at}.outsideOracle`, d.outsideOracle),
    };
    if (shape === "aggregate" && aggregates.length === 0) v.bad(at, "an aggregate route names its aggregates (\"aggregates\": [\"…\"])");
    for (const a of aggregates) if (!(a in rawAggregates)) v.bad(`${at}.aggregates`, `names "${a}", which manifest.aggregates does not declare`);
    if (shape === "closed" && decl.why === undefined) v.bad(at, "a closed route says why (\"why\")");
    if (shape === "export" && decl.to === undefined) v.bad(at, "an export says where it goes (\"to\": \"own-book\")");
    if (subject !== undefined && shape !== undefined) routes.set(key, decl);
  }

  const aggregates = new Map<string, AggregateDecl>();
  for (const [name, d] of Object.entries(rawAggregates)) {
    const at = `manifest.aggregates["${name}"]`;
    if (!isObj(d)) {
      v.bad(at, "must be an object");
      continue;
    }
    v.keys(at, d, ["file", "export", "sql", "raw"]);
    const file = v.str(`${at}.file`, d.file);
    const exp = v.str(`${at}.export`, d.export);
    const sql = v.str(`${at}.sql`, d.sql);
    const raw: Record<string, string> = {};
    for (const [p, why] of Object.entries(v.obj(`${at}.raw`, d.raw))) {
      const w = v.str(`${at}.raw["${p}"]`, why);
      if (w !== undefined) raw[p] = w;
    }
    if ((file === undefined) !== (exp === undefined)) v.bad(at, "a TypeScript aggregate names both its file and its export");
    if ((file === undefined) === (sql === undefined)) v.bad(at, "an aggregate is either TypeScript (file and export) or SQL (sql), and one of them");
    aggregates.set(name, { file, export: exp, sql, raw });
  }

  const counts = new Map<string, CountDecl>();
  for (const [k, d] of Object.entries(v.obj("manifest.counts", top.counts))) {
    const at = `manifest.counts["${k}"]`;
    if (!isObj(d)) {
      v.bad(at, "must be an object");
      continue;
    }
    v.keys(at, d, ["kind", "why"]);
    const kind = v.word(`${at}.kind`, d.kind, ["own", "internal"] as const);
    const why = v.str(`${at}.why`, d.why, { required: true });
    if (!k.includes("#") && !k.startsWith("sql:")) v.bad(at, 'a count key is "file#function" or "sql:name"');
    if (k.includes("*")) v.bad(at, "names one count site exactly: a glob would classify counts nobody has read");
    // A refused key is never applied: its counts stay findings, beside the problem.
    if (kind !== undefined && why !== undefined && !k.includes("*")) counts.set(k, { kind, why });
  }

  const s = v.obj("manifest.schemas", top.schemas);
  v.keys("manifest.schemas", s, ["prisma", "sql", "lexicons", "persons", "decisions"]);
  const decisions = new Map<string, string>();
  for (const [model, field] of Object.entries(v.obj("manifest.schemas.decisions", s.decisions))) {
    const f = v.str(`manifest.schemas.decisions["${model}"]`, field);
    if (f !== undefined) decisions.set(model, f);
  }

  const p = v.obj("manifest.prices", top.prices);
  v.keys("manifest.prices", p, ["files", "entrances", "fields"]);
  const fields = new Map<string, PriceKind>();
  for (const [pattern, kind] of Object.entries(v.obj("manifest.prices.fields", p.fields))) {
    const k = v.word(`manifest.prices.fields["${pattern}"]`, kind, PRICE_KINDS);
    if (k !== undefined) fields.set(pattern, k);
  }

  const waivers: Waiver[] = [];
  const rawWaivers = top.waivers === undefined ? [] : top.waivers;
  if (!Array.isArray(rawWaivers)) v.bad("manifest.waivers", "must be a list");
  else {
    rawWaivers.forEach((w, i) => {
      const at = `manifest.waivers[${i}]`;
      if (!isObj(w)) return v.bad(at, "must be an object");
      v.keys(at, w, ["rule", "at", "reason", "decision"]);
      const rule = v.word(`${at}.rule`, w.rule, Object.keys(RULES) as RuleId[]);
      const rawWhere = v.str(`${at}.at`, w.at, { required: true });
      if (rawWhere?.includes("*") === true) v.bad(`${at}.at`, "names one finding exactly: a glob could waive a whole rule");
      const where = rawWhere?.includes("*") === true ? undefined : rawWhere;
      const reason = v.str(`${at}.reason`, w.reason, { required: true });
      const decision = v.str(`${at}.decision`, w.decision, { required: true });
      const cites = decision !== undefined && /\bd\d{1,3}\b/i.test(decision);
      if (decision !== undefined && !cites) v.bad(`${at}.decision`, "cites a decision of the log (d63(a), d84 P3 …)");
      // An invalid waiver is never applied: its finding stays, beside the problem.
      if (rule !== undefined && where !== undefined && reason !== undefined && decision !== undefined && cites) waivers.push({ rule, at: where, reason, decision, index: i });
    });
  }

  const manifest: Manifest = {
    repository: v.str("manifest.repository", top.repository),
    serves: top.serves === "none" ? "none" : undefined,
    excluded,
    oracles,
    routes,
    aggregates,
    counts,
    schemas: {
      prisma: v.strs("manifest.schemas.prisma", s.prisma),
      sql: v.strs("manifest.schemas.sql", s.sql),
      lexicons: v.strs("manifest.schemas.lexicons", s.lexicons),
      persons: v.strs("manifest.schemas.persons", s.persons),
      decisions,
    },
    sources: v.strs("manifest.sources", top.sources),
    prices: { files: v.strs("manifest.prices.files", p.files), entrances: v.strs("manifest.prices.entrances", p.entrances), fields },
    waivers,
  };
  return { manifest, problems: v.problems };
}

/* ── route keys ──────────────────────────────────────────────────────────── */

export interface RouteKey {
  readonly method: string;
  readonly host: string | undefined;
  /** The target as written: a path, a tool's name, or an action's `file#name`. */
  readonly target: string;
  /** The target with parameters made anonymous (`:`, `:*`), for comparing. */
  readonly norm: string;
  readonly glob: boolean;
}

const PATHLESS = new Set(["ACTION", "TOOL"]);

/** Parameters compare equal whatever they are called: `:id`, `[id]`, `{id}` → `:`; catch-alls → `:*`. */
export function normalizePath(p: string): string {
  let s = p.replace(/\/{2,}/g, "/");
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s
    .split("/")
    .map((seg) => {
      if (/^\[\[\.\.\.[^\]]+\]\]$/.test(seg)) return ":*?";
      if (/^\[\.\.\.[^\]]+\]$/.test(seg)) return ":*";
      if (/^\[[^\]]+\]$/.test(seg)) return ":";
      if (/^:[A-Za-z_][\w]*\*$/.test(seg)) return ":*";
      if (/^:[A-Za-z_][\w]*(?:\{.*\})?\??$/.test(seg)) return ":";
      if (/^\{[^}]+\}$/.test(seg)) return ":";
      return seg;
    })
    .join("/");
}

export function parseRouteKey(text: string): RouteKey | undefined {
  const m = /^\s*([A-Z]+)\s+(\S.*?)\s*$/.exec(text);
  if (m === null) return undefined;
  let method = m[1]!;
  if (method === "ALL") method = "ANY";
  if (!(METHODS as readonly string[]).includes(method)) return undefined;
  let target = m[2]!;
  let host: string | undefined;
  const h = /^([a-z0-9][a-z0-9.-]*):(.+)$/.exec(target);
  if (h !== null && !(PATHLESS.has(method) && h[2]!.startsWith("/"))) {
    host = h[1]!;
    target = h[2]!;
  }
  if (!PATHLESS.has(method) && !target.startsWith("/")) return undefined;
  const norm = PATHLESS.has(method) ? target : normalizePath(target);
  const glob = PATHLESS.has(method) ? target.includes("*") : norm.split("/").some((seg) => seg === "*" || seg === "**" || (seg.includes("*") && !seg.startsWith(":")));
  return { method, host, target, norm, glob };
}

export function keyText(k: RouteKey): string {
  return `${k.method} ${k.host !== undefined ? `${k.host}:` : ""}${k.norm}`;
}

function globRegex(k: RouteKey): RegExp {
  if (PATHLESS.has(k.method)) return new RegExp(`^${k.norm.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
  const parts = k.norm.split("/").map((seg) => {
    if (seg === "**") return "(?:/[^/]+)*";
    if (seg === "") return "";
    const body = seg
      .split("*")
      .map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
      .join("[^/]*");
    return `/${body}`;
  });
  return new RegExp(`^${parts.join("")}$`);
}

/** Does a manifest key cover a discovered route? */
export function covers(decl: RouteKey, route: RouteKey): boolean {
  if (decl.method !== route.method || decl.host !== route.host) return false;
  if (!decl.glob) return decl.norm === route.norm;
  const re = globRegex(decl);
  return re.test(route.norm) || (route.norm === "/" && re.test(""));
}

/** Pages may be covered by a glob; API routes only under two literal segments; tools and actions never. */
export function globAllowed(k: RouteKey): boolean {
  if (k.method === "PAGE") return true;
  if (PATHLESS.has(k.method)) return false;
  const segs = k.norm.split("/").filter((s) => s !== "");
  let literal = 0;
  for (const s of segs) {
    if (s.includes("*")) break;
    literal++;
  }
  return literal >= 2;
}

/** More literal segments win; a `**` loses to a `*`. */
export function specificity(k: RouteKey): number {
  if (!k.glob) return 1_000_000;
  const segs = PATHLESS.has(k.method) ? [k.norm] : k.norm.split("/").filter((s) => s !== "");
  const literal = segs.filter((s) => !s.includes("*")).length;
  const deep = segs.some((s) => s === "**") ? 0 : 1;
  return literal * 10 + deep;
}

/** Waiver keys and count keys: `*` matches anything. */
export function looseGlob(pattern: string): RegExp {
  return new RegExp(`^${pattern.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
}
