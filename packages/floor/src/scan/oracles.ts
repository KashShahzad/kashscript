/**
 * Oracles: what a repository actually mounts, read from its code or its boot log, so a route cannot exist without a
 * line in the manifest (RW-17; d91(h): the forbidden gateways are absent from the API, which only a complete
 * inventory can show).
 *
 *   boot-log  — the engine's boot line, `{"routes":{"endpoints":157,"list":["GET /api/v1/me", …]}}`, or text lines
 *               `METHOD /path`. A log tracked by git is refused: a committed log is stale the day a route changes.
 *   next-app  — App Router route handlers (their exported methods), pages, metadata routes, and server actions.
 *   supabase  — edge functions, and the tables, views and functions PostgREST serves, each found closed when
 *               row-level security or a revoke shuts every client out.
 *   ts-table  — an exported table of tools or routes (an array or an object literal).
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { basename, isAbsolute, relative, resolve, sep } from "node:path";
import { keyText, parseRouteKey, type OracleDecl, type RouteKey } from "../manifest.js";
import type { Tree as FileTree } from "./files.js";
import { countsIn, emptySqlModel, functionClosed, readSql, relationClosed, relationSelf, type SqlModel } from "./sql.js";
import { Sources } from "./ts.js";
import { routeMethods, serverActions, tableEntries } from "./ts-scans.js";
import { MONEY, tokens } from "./words.js";

export interface OracleRoute {
  readonly key: RouteKey;
  /** The normalised key, for matching and reporting. */
  readonly text: string;
  /** Which oracle saw it, and where. */
  readonly source: string;
  readonly closed: boolean;
  readonly self: boolean;
  readonly counts: boolean;
  readonly sqlName: string | undefined;
  /** An RPC's parameter names. */
  readonly args: readonly string[];
  /** An RPC's `returns setof` table. */
  readonly returnsSetOf: string | undefined;
  /** A served table's columns shaped as counts (`endorsement_count`, `total_visits`). */
  readonly countColumns: readonly string[];
}

export interface OracleProblem {
  readonly at: string;
  readonly what: string;
}

export interface OracleResult {
  readonly routes: OracleRoute[];
  readonly problems: OracleProblem[];
  readonly notes: string[];
  readonly sql: SqlModel[];
}

export interface OracleCtx {
  readonly root: string;
  readonly files: FileTree;
  readonly sources: Sources;
  /** Boot logs given on the command line; they take the place of the manifest's own. */
  readonly bootLogs: readonly string[];
}

const route = (key: RouteKey, source: string, extra: Partial<Omit<OracleRoute, "key" | "text" | "source">> = {}): OracleRoute => ({
  key,
  text: keyText(key),
  source,
  closed: extra.closed ?? false,
  self: extra.self ?? false,
  counts: extra.counts ?? false,
  sqlName: extra.sqlName,
  args: extra.args ?? [],
  returnsSetOf: extra.returnsSetOf,
  countColumns: extra.countColumns ?? [],
});

/** A column shaped as a count, not money: `endorsement_count`, `total_visits`, `num_reports`. */
function countColumn(name: string, type: string): boolean {
  const t = tokens(name);
  return /int|numeric|bigint|smallint|serial|real|double/.test(type) && t.some((x) => ["count", "counts", "total", "totals", "num", "tally"].includes(x)) && !t.some((x) => MONEY.has(x));
}

/** Is a path tracked by git in this repository? undefined when git cannot say. */
function tracked(root: string, abs: string): boolean | undefined {
  const rel = relative(root, abs);
  if (rel.startsWith("..") || isAbsolute(rel)) return false;
  // Fixed arguments, no shell: git is asked whether the index holds this one path.
  const r = spawnSync("git", ["ls-files", "--error-unmatch", "--", rel], { cwd: root, encoding: "utf8", windowsHide: true }); // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process
  if (r.error !== undefined) return undefined;
  return r.status === 0;
}

function bootLog(o: Extract<OracleDecl, { kind: "boot-log" }>, ctx: OracleCtx, out: OracleResult): void {
  const files = ctx.bootLogs.length > 0 ? ctx.bootLogs : o.files;
  if (files.length === 0) {
    out.problems.push({ at: "oracle:boot-log", what: "has no log to read: pass --boot-log <file>, the boot line written in CI" });
    return;
  }
  for (const f of files) {
    const abs = resolve(ctx.root, f);
    const inside = relative(ctx.root, abs);
    // A stable name for the finding: the path inside the repository, or the file's own name for a log written elsewhere.
    const label = inside.startsWith("..") || isAbsolute(inside) ? basename(abs) : inside.split(sep).join("/");
    const at = `oracle:boot-log:${label}`;
    if (!existsSync(abs)) {
      out.problems.push({ at, what: "cannot be read: the file does not exist" });
      continue;
    }
    const t = tracked(ctx.root, abs);
    if (t === true) {
      out.problems.push({ at, what: "is tracked by git: a committed boot log is stale the day a route changes; write it in CI and pass it with --boot-log" });
      continue;
    }
    if (t === undefined) out.notes.push(`git did not answer, so whether ${label} is tracked was not checked`);
    let found = 0;
    for (const raw of readFileSync(abs, "utf8").replace(/^﻿/, "").split(/\r?\n/)) {
      const line = raw.trim();
      if (line === "") continue;
      if (line.startsWith("{")) {
        let obj: unknown;
        try {
          obj = JSON.parse(line);
        } catch {
          continue;
        }
        if (typeof obj !== "object" || obj === null) continue;
        const o2 = obj as Record<string, unknown>;
        const routesField = o2.routes;
        const list = Array.isArray(o2.list) ? o2.list : typeof routesField === "object" && routesField !== null && Array.isArray((routesField as Record<string, unknown>).list) ? ((routesField as Record<string, unknown>).list as unknown[]) : Array.isArray(routesField) ? routesField : undefined;
        if (list === undefined) continue;
        const endpoints = typeof routesField === "object" && routesField !== null ? (routesField as Record<string, unknown>).endpoints : undefined;
        if (typeof endpoints === "number" && endpoints !== list.length) {
          out.problems.push({ at, what: `lists ${list.length} routes but counts ${endpoints} endpoints: the list is not the whole table` });
        }
        for (const item of list) {
          const key = typeof item === "string" ? parseRouteKey(item) : undefined;
          if (key === undefined) {
            out.problems.push({ at, what: `holds an entry that is not "METHOD /path": ${JSON.stringify(item)}` });
            continue;
          }
          out.routes.push(route(key, `boot-log ${label}`));
          found++;
        }
      } else {
        const m = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|ANY|ALL|WS)\s+(\/\S*)$/.exec(line);
        const key = m === null ? undefined : parseRouteKey(`${m[1]} ${m[2]}`);
        if (key !== undefined) {
          out.routes.push(route(key, `boot-log ${label}`));
          found++;
        }
      }
    }
    if (found === 0) out.problems.push({ at, what: "names no routes: the engine must print mountedRoutes().list on its boot line" });
  }
}

const METADATA: ReadonlyArray<[RegExp, (dir: string) => string]> = [
  [/^sitemap\.(ts|tsx|js|jsx)$/, (d) => `${d}/sitemap.xml`],
  [/^robots\.(ts|tsx|js|jsx)$/, (d) => `${d}/robots.txt`],
  [/^manifest\.(ts|tsx|js|jsx)$/, (d) => `${d}/manifest.webmanifest`],
  [/^(opengraph-image|twitter-image|icon|apple-icon)\.(ts|tsx|js|jsx)$/, (d) => d],
];

function nextApp(o: Extract<OracleDecl, { kind: "next-app" }>, ctx: OracleCtx, out: OracleResult): void {
  const app = o.app.replace(/\/+$/, "");
  if (!ctx.files.isDir(app)) {
    out.problems.push({ at: `oracle:next-app:${app}`, what: "is not a folder" });
    return;
  }
  const host = o.host !== undefined ? `${o.host}:` : "";
  const add = (text: string, source: string): void => {
    const key = parseRouteKey(text);
    if (key === undefined) out.problems.push({ at: `oracle:next-app:${source}`, what: `gives a route the floor cannot read: ${text}` });
    else out.routes.push(route(key, `next-app ${source}`));
  };
  for (const rel of ctx.files.files()) {
    if (!rel.startsWith(`${app}/`)) continue;
    const parts = rel.slice(app.length + 1).split("/");
    const file = parts.pop()!;
    if (parts.some((p) => p.startsWith("_") || /^\(\.{1,3}\)/.test(p))) continue;
    const segs = parts.filter((p) => !/^\(.*\)$/.test(p) && !p.startsWith("@"));
    const dir = segs.length === 0 ? "" : `/${segs.join("/")}`;
    const path = dir === "" ? "/" : dir;
    if (/^route\.(ts|tsx|js|jsx|mjs)$/.test(file)) {
      const sf = ctx.sources.get(ctx.files.abs(rel));
      const methods = sf === undefined ? [] : routeMethods(sf);
      for (const m of methods.length > 0 ? methods : ["ANY"]) add(`${m} ${host}${path}`, rel);
    } else if (/^page\.(tsx|ts|jsx|js|mdx|md)$/.test(file)) {
      add(`PAGE ${host}${path}`, rel);
    } else {
      for (const [re, to] of METADATA) {
        const m = re.exec(file);
        if (m === null) continue;
        const target = re === METADATA[3]![0] ? `${dir}/${m[1]}` : to(dir);
        add(`GET ${host}${target === "" ? "/" : target}`, rel);
      }
    }
  }
  const actionsRoot = (o.actions ?? app.split("/").slice(0, -1).join("/")).replace(/\/+$/, "");
  const prefix = actionsRoot === "" ? "" : `${actionsRoot}/`;
  for (const rel of ctx.files.files()) {
    if (!rel.startsWith(prefix) || !/\.(ts|tsx|js|jsx|mjs)$/.test(rel) || rel.endsWith(".d.ts") || /\.(test|spec)\./.test(rel)) continue;
    let text: string;
    try {
      text = ctx.files.read(rel);
    } catch {
      continue;
    }
    if (!/["']use server["']/.test(text)) continue;
    const sf = ctx.sources.get(ctx.files.abs(rel));
    if (sf === undefined) continue;
    for (const name of serverActions(sf)) add(`ACTION ${rel}#${name}`, rel);
  }
}

function supabase(o: Extract<OracleDecl, { kind: "supabase" }>, ctx: OracleCtx, out: OracleResult): void {
  const dir = o.dir.replace(/\/+$/, "");
  if (!ctx.files.isDir(dir)) {
    out.problems.push({ at: `oracle:supabase:${dir}`, what: "is not a folder" });
    return;
  }
  const host = o.host !== undefined ? `${o.host}:` : "";
  const fnNames = new Set<string>();
  for (const rel of ctx.files.files()) {
    if (!rel.startsWith(`${dir}/functions/`)) continue;
    const name = rel.slice(dir.length + "/functions/".length).split("/")[0];
    if (name !== undefined && !name.startsWith("_") && !name.startsWith(".") && rel.includes("/", dir.length + "/functions/".length)) fnNames.add(name);
  }
  for (const name of [...fnNames].sort()) {
    const key = parseRouteKey(`ANY ${host}/functions/v1/${name}`);
    if (key !== undefined) out.routes.push(route(key, `supabase ${dir}/functions/${name}`));
  }
  const model = emptySqlModel();
  const migrations = ctx.files.files().filter((r) => r.startsWith(`${dir}/migrations/`) && r.endsWith(".sql")).sort();
  for (const rel of migrations) readSql(model, rel, ctx.files.read(rel));
  out.sql.push(model);
  for (const rel of model.relations.values()) {
    if (!o.schemas.includes(rel.schema)) continue;
    const key = parseRouteKey(`REST ${host}/rest/v1/${rel.name}`);
    const countColumns = [...rel.columns.values()].filter((c) => countColumn(c.name, c.type)).map((c) => c.name);
    if (key !== undefined) out.routes.push(route(key, `supabase ${rel.file}`, { closed: relationClosed(rel), self: relationSelf(rel), counts: rel.kind === "view" && countsIn(rel.body), sqlName: rel.name, countColumns }));
  }
  for (const fn of model.functions.values()) {
    if (!o.schemas.includes(fn.schema) || fn.trigger) continue;
    const key = parseRouteKey(`RPC ${host}/rest/v1/rpc/${fn.name}`);
    if (key !== undefined) out.routes.push(route(key, `supabase ${fn.file}`, { closed: functionClosed(fn), counts: countsIn(fn.body), sqlName: fn.name, args: fn.args, returnsSetOf: fn.returnsSetOf }));
  }
}

/** The Pages Router: `pages/api/**` are API routes (any method); every other page but `_app`, `_document`, `_error` is a page. */
function nextPages(o: Extract<OracleDecl, { kind: "next-pages" }>, ctx: OracleCtx, out: OracleResult): void {
  const dir = o.dir.replace(/\/+$/, "");
  if (!ctx.files.isDir(dir)) {
    out.problems.push({ at: `oracle:next-pages:${dir}`, what: "is not a folder" });
    return;
  }
  const host = o.host !== undefined ? `${o.host}:` : "";
  for (const rel of ctx.files.files()) {
    if (!rel.startsWith(`${dir}/`) || !/\.(ts|tsx|js|jsx|mjs|mdx)$/.test(rel) || rel.endsWith(".d.ts")) continue;
    const parts = rel.slice(dir.length + 1).replace(/\.(ts|tsx|js|jsx|mjs|mdx)$/, "").split("/");
    if (parts.some((p) => p.startsWith("_"))) continue;
    if (parts[parts.length - 1] === "index") parts.pop();
    const path = `/${parts.join("/")}`;
    const text = parts[0] === "api" ? `ANY ${host}${path}` : `PAGE ${host}${path}`;
    const key = parseRouteKey(text);
    if (key === undefined) out.problems.push({ at: `oracle:next-pages:${rel}`, what: `gives a route the floor cannot read: ${text}` });
    else out.routes.push(route(key, `next-pages ${rel}`));
  }
}

function tsTable(o: Extract<OracleDecl, { kind: "ts-table" }>, ctx: OracleCtx, out: OracleResult): void {
  const at = `oracle:ts-table:${o.file}#${o.export}`;
  const sf = ctx.files.exists(o.file) ? ctx.sources.get(ctx.files.abs(o.file)) : undefined;
  if (sf === undefined) {
    out.problems.push({ at, what: "cannot be read" });
    return;
  }
  const result = tableEntries(sf, o.export, o.key ?? "name");
  if ("error" in result) {
    out.problems.push({ at, what: result.error });
    return;
  }
  const host = o.host !== undefined ? `${o.host}:` : "";
  for (const e of result.entries) {
    let text: string | undefined;
    if (o.key === undefined && e.method !== undefined && e.path !== undefined) text = `${e.method.toUpperCase()} ${host}${e.path}`;
    else if ((e.name ?? e.mapKey) !== undefined) text = `TOOL ${host}${e.name ?? e.mapKey}`;
    const key = text === undefined ? undefined : parseRouteKey(text);
    if (key === undefined) out.problems.push({ at, what: `an entry on line ${e.line} has no name the floor can read` });
    else out.routes.push(route(key, `ts-table ${o.file}`));
  }
}

export function discoverRoutes(oracles: readonly OracleDecl[], ctx: OracleCtx): OracleResult {
  const out: OracleResult = { routes: [], problems: [], notes: [], sql: [] };
  for (const o of oracles) {
    if (o.kind === "boot-log") bootLog(o, ctx, out);
    else if (o.kind === "next-app") nextApp(o, ctx, out);
    else if (o.kind === "next-pages") nextPages(o, ctx, out);
    else if (o.kind === "supabase") supabase(o, ctx, out);
    else tsTable(o, ctx, out);
  }
  return out;
}
