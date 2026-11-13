#!/usr/bin/env bun
/**
 * scripts/check-public-tree.ts — the open protocol's tree holds nothing closed (AU-11, A10-04; ADR-0028).
 *
 * The public repository (KashShahzad/kashscript) holds the open protocol only: the twelve packages
 * that ecosystem decision 87's test opens — checking a record or the person's wallet needs them —
 * with their specs and the tools that test and publish them. The sites, the services, the internal
 * packages and the closed code that left on 2026-11-02 (hudhud, neuron, the Policy to door kit) stay
 * in the private archive. scripts/export-public-tree.ts builds the tree and runs this check; the
 * public repository's CI runs it on every push, so nothing closed is added there later.
 *
 *   bun scripts/check-public-tree.ts <root>                     # the tree
 *   bun scripts/check-public-tree.ts <root> --tarballs <dir>    # and every .tgz in <dir> (bun pm pack output)
 *
 * It checks:
 *   1. no path matches DENY (closed or private paths, credentials files);
 *   2. every relative Markdown link resolves inside the tree;
 *   3. scripts/trusted-publishing.json names exactly the packages under packages/ that are not private;
 *   4. each tarball holds only `package/` entries its package.json's `files` admits, none matching DENY.
 *
 * Exit 0 when all pass; 1 with every violation listed.
 */

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, dirname, join, posix, relative, resolve, sep } from "node:path";
import { spawnSync } from "node:child_process";

/** Paths that never enter the public tree or a tarball, each with its reason. Globs, repository-relative. */
export const DENY: readonly { readonly glob: string; readonly reason: string }[] = [
  { glob: "apps/**", reason: "the sites and labs are proprietary (d87: apps and operations are closed)" },
  { glob: "services/**", reason: "servers we operate, or retired ones (d87)" },
  { glob: "packages/catalog/**", reason: "internal, private: the site's catalogue" },
  { glob: "packages/brand-assets/**", reason: "internal, private: the sites' brand assets" },
  { glob: "packages/trade-core/**", reason: "retired (d59) and removed at AU-11; carried escrow and trustScore" },
  { glob: "packages/trade-sdk/**", reason: "retired (d59) and removed at AU-11" },
  { glob: "**/hudhud/**", reason: "closed code inside Oreoasis since 2026-11-02 (KS-P1, ADR-0024)" },
  { glob: "**/neuron/**", reason: "closed code inside Oreoasis since 2026-11-02 (KS-P1, ADR-0024)" },
  { glob: "**/neuron-lab/**", reason: "retired lab of closed code" },
  { glob: "**/policy-door/**", reason: "the Policy to door kit, closed tooling inside Oreoasis (d87, KS-P1)" },
  { glob: "specs/hudhud*", reason: "the specification of closed code" },
  { glob: "specs/neuron*", reason: "the specification of closed code" },
  { glob: "specs/trade-*", reason: "the specification of retired code" },
  { glob: "docs/legal/SSLA.md", reason: "the retired commercial licence, kept as a record in the archive" },
  { glob: "docs/archive/**", reason: "archived licences and plans" },
  { glob: "**/*.sol", reason: "the retired trade contracts" },
  { glob: "**/.npmrc", reason: "may hold an npm credential" },
  { glob: "**/.env", reason: "may hold credentials" },
  { glob: "**/.env.*", reason: "may hold credentials" },
  { glob: "**/*.pem", reason: "key material" },
  { glob: "**/*.key", reason: "key material" },
];

/** Names that mark closed code wherever they appear in a path. */
const DENY_NAME = /(^|[/._-])(hudhud|neuron|trade-core|trade-sdk|policy-door)([/._-]|$)/i;

export interface Violation {
  readonly check: "deny" | "link" | "trusted" | "tarball";
  readonly where: string;
  readonly reason: string;
}

const globs = DENY.map((d) => ({ ...d, g: new Bun.Glob(d.glob) }));

/** The deny reason for a repository-relative POSIX path, or undefined. */
export function denied(path: string): string | undefined {
  for (const d of globs) if (d.g.match(path)) return `${d.glob}: ${d.reason}`;
  if (DENY_NAME.test(path)) return "names closed code (hudhud, neuron, trade-core, trade-sdk, policy-door)";
  return undefined;
}

/** Every file under root, as POSIX paths relative to it; skips .git, node_modules, dist, .turbo and release/. */
export function listTree(root: string): string[] {
  const skip = new Set([".git", "node_modules", "dist", ".turbo", "release", ".gradle"]);
  const out: string[] = [];
  const walk = (dir: string): void => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (skip.has(e.name)) continue;
      const abs = join(dir, e.name);
      if (e.isDirectory()) walk(abs);
      else out.push(relative(root, abs).split(sep).join("/"));
    }
  };
  walk(root);
  return out.sort();
}

/** Relative link targets in a Markdown text, outside fenced code and inline code. */
export function markdownLinks(text: string): string[] {
  const unfenced = text.replace(/^(```|~~~)[\s\S]*?^\1/gm, "").replace(/`[^`\n]*`/g, "");
  const out: string[] = [];
  for (const m of unfenced.matchAll(/\[[^\]\n]*\]\(\s*(?:<([^>\n]+)>|([^)\s]+))(?:\s+"[^"]*")?\s*\)/g)) {
    const t = (m[1] ?? m[2])!;
    if (/^[a-z][a-z0-9+.-]*:/i.test(t) || t.startsWith("#") || t.startsWith("//")) continue;
    out.push(t);
  }
  return out;
}

export function checkLinks(root: string, files: readonly string[]): Violation[] {
  const have = new Set(files);
  const dirs = new Set<string>();
  for (const f of files) for (let d = posix.dirname(f); d !== "."; d = posix.dirname(d)) dirs.add(d);
  const v: Violation[] = [];
  for (const f of files) {
    if (!f.endsWith(".md")) continue;
    for (const raw of markdownLinks(readFileSync(join(root, f), "utf8"))) {
      let t = raw.split("#")[0]!.split("?")[0]!;
      if (!t) continue;
      try { t = decodeURIComponent(t); } catch { /* keep as written */ }
      const target = t.startsWith("/") ? t.slice(1) : posix.normalize(posix.join(posix.dirname(f), t));
      const clean = target.replace(/\/$/, "");
      if (clean.startsWith("..")) {
        v.push({ check: "link", where: f, reason: `${raw} leaves the tree` });
      } else if (!have.has(clean) && !dirs.has(clean)) {
        v.push({ check: "link", where: f, reason: `${raw} does not resolve (${clean})` });
      }
    }
  }
  return v;
}

export function checkTrusted(root: string): Violation[] {
  const file = join(root, "scripts", "trusted-publishing.json");
  if (!existsSync(file)) return [{ check: "trusted", where: "scripts/trusted-publishing.json", reason: "missing" }];
  const moved = new Set((JSON.parse(readFileSync(file, "utf8")) as { moved: string[] }).moved);
  const open = new Set<string>();
  const pk = join(root, "packages");
  if (existsSync(pk)) {
    for (const e of readdirSync(pk, { withFileTypes: true })) {
      const pj = join(pk, e.name, "package.json");
      if (!e.isDirectory() || !existsSync(pj)) continue;
      if ((JSON.parse(readFileSync(pj, "utf8")) as { private?: boolean }).private !== true) open.add(e.name);
    }
  }
  const v: Violation[] = [];
  for (const s of open) if (!moved.has(s)) v.push({ check: "trusted", where: `packages/${s}`, reason: "open package not listed in scripts/trusted-publishing.json" });
  for (const s of moved) if (!open.has(s)) v.push({ check: "trusted", where: `scripts/trusted-publishing.json`, reason: `lists "${s}", which is not an open package in this tree` });
  return v;
}

/**
 * The entries of a .tgz, via tar (present on Windows 10+, macOS and Linux). tar runs in the tarball's
 * own folder with a bare file name: GNU tar reads `C:\…` as a remote host, and bsdtar has no
 * --force-local.
 */
function tarEntries(tgz: string): string[] {
  const r = spawnSync("tar", ["-tzf", basename(tgz)], { cwd: dirname(tgz), encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`tar -tzf ${tgz} failed: ${r.stderr}`);
  return r.stdout.split(/\r?\n/).filter((l) => l && !l.endsWith("/"));
}

function tarFile(tgz: string, entry: string): string {
  const r = spawnSync("tar", ["-xzOf", basename(tgz), entry], { cwd: dirname(tgz), encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`tar -xzOf ${tgz} ${entry} failed: ${r.stderr}`);
  return r.stdout;
}

/** npm always includes these, whatever `files` says. */
const ALWAYS = /^(package\.json|README(\.[^/]*)?|LICEN[CS]E(\.[^/]*)?|CHANGELOG(\.[^/]*)?)$/i;

/** Check one tarball's entries against its own package.json `files` and DENY. Returns violations and the entry count. */
export function checkTarball(tgz: string, entries: readonly string[], manifestText: string): { violations: Violation[]; count: number } {
  const name = tgz.split(/[\\/]/).pop()!;
  const v: Violation[] = [];
  const files = ((JSON.parse(manifestText) as { files?: string[] }).files ?? []).map((f) => f.replace(/^\.\//, "").replace(/\/$/, ""));
  const globsOf = files.map((f) => new Bun.Glob(f));
  const admitted = (p: string): boolean =>
    ALWAYS.test(p) || files.some((f, i) => p === f || p.startsWith(`${f}/`) || globsOf[i]!.match(p));
  for (const e of entries) {
    if (!e.startsWith("package/")) {
      v.push({ check: "tarball", where: `${name}:${e}`, reason: "entry outside package/" });
      continue;
    }
    const p = e.slice("package/".length);
    const why = denied(p);
    if (why) v.push({ check: "tarball", where: `${name}:${p}`, reason: why });
    if (!admitted(p)) v.push({ check: "tarball", where: `${name}:${p}`, reason: "not admitted by the package's files field" });
  }
  return { violations: v, count: entries.length };
}

export function checkTree(root: string): { files: string[]; violations: Violation[] } {
  const files = listTree(root);
  const violations: Violation[] = [];
  for (const f of files) {
    const why = denied(f);
    if (why) violations.push({ check: "deny", where: f, reason: why });
  }
  violations.push(...checkLinks(root, files), ...checkTrusted(root));
  return { files, violations };
}

function main(): void {
  const args = process.argv.slice(2);
  const ti = args.indexOf("--tarballs");
  const tarDir = ti >= 0 ? args[ti + 1] : undefined;
  const root = args.find((a, i) => !a.startsWith("--") && (ti < 0 || i !== ti + 1));
  if (!root) {
    console.error("usage: bun scripts/check-public-tree.ts <root> [--tarballs <dir>]");
    process.exit(2);
  }
  const abs = resolve(root);
  const { files, violations } = checkTree(abs);
  console.log(`tree: ${files.length} files under ${abs}`);

  if (tarDir) {
    const dir = resolve(tarDir);
    const tgzs = readdirSync(dir).filter((f) => f.endsWith(".tgz")).sort();
    if (tgzs.length === 0) violations.push({ check: "tarball", where: dir, reason: "no .tgz found" });
    for (const t of tgzs) {
      const path = join(dir, t);
      const entries = tarEntries(path);
      const r = checkTarball(path, entries, tarFile(path, "package/package.json"));
      violations.push(...r.violations);
      console.log(`  ${t}: ${r.count} entries, ${r.violations.length} violation(s)`);
    }
  }

  if (violations.length === 0) {
    console.log("✓ the public tree holds nothing closed; links resolve; trusted publishing lists every open package");
    return;
  }
  console.error(`✗ ${violations.length} violation(s):`);
  for (const v of violations) console.error(`  [${v.check}] ${v.where} — ${v.reason}`);
  process.exit(1);
}

if (import.meta.main) main();
