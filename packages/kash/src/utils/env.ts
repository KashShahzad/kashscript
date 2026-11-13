/**
 * Project environment scanner.
 *
 * Walks up from a starting directory to find the host project's root, then
 * fingerprints three orthogonal axes:
 *
 *   • paradigm  — standalone / monorepo (turbo, nx, pnpm-workspace, bun, yarn)
 *   • manager   — bun / pnpm / npm / yarn
 *   • framework — next / vite / expo / astro / remix / sveltekit / unknown
 *
 * Pure I/O against the filesystem; no network calls, no mutations.
 */

import { promises as fs } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { KashCliError } from "../errors";

/* ── public types ────────────────────────────────────────────────── */

export type ProjectParadigm =
  | "standalone"
  | "monorepo-turbo"
  | "monorepo-nx"
  | "monorepo-pnpm"
  | "monorepo-bun"
  | "monorepo-yarn"
  | "monorepo-npm";

export type PackageManager = "bun" | "pnpm" | "npm" | "yarn";

export type Framework =
  | "next"
  | "vite"
  | "expo"
  | "astro"
  | "remix"
  | "sveltekit"
  | "cra"        // Create React App (react-scripts)
  | "react"      // Generic React app — has react/react-dom but no recognised wrapper (custom webpack, parcel, esbuild, etc.)
  | "unknown";

export interface EnvironmentReport {
  /** Absolute path to the project root (the directory containing the root package.json). */
  readonly root: string;
  /** Path the scanner started from. */
  readonly startedFrom: string;
  readonly paradigm: ProjectParadigm;
  readonly manager: PackageManager;
  readonly framework: Framework;
  /** Workspace package globs when paradigm is monorepo-*; empty when standalone. */
  readonly workspaces: readonly string[];
  /** Names of the per-axis signals that fired during detection (useful for debugging). */
  readonly signals: readonly string[];
}

export interface ScanOptions {
  /** Override the directory the scan starts from. Defaults to `process.cwd()`. */
  readonly cwd?: string;
  /** Maximum levels to walk upward looking for a package.json. Default 8. */
  readonly maxDepth?: number;
}

/* ── entry point ────────────────────────────────────────────────── */

export async function scanEnvironment(opts: ScanOptions = {}): Promise<EnvironmentReport> {
  const startedFrom = resolve(opts.cwd ?? process.cwd());
  const maxDepth    = opts.maxDepth ?? 8;
  const signals: string[] = [];

  const { root, rootPkg, nearestPkg } = await locateProjectRoot(startedFrom, maxDepth);
  signals.push(`root=${root}`);

  const paradigm  = await detectParadigm(root, rootPkg, signals);
  const manager   = await detectManager(root, signals);
  // Prefer the nearest package.json for framework detection — in a monorepo
  // the user's CURRENT package (e.g., apps/web) is what carries the framework
  // dep, not the workspace root's package.json.
  const framework = detectFramework(nearestPkg, signals);
  const workspaces = extractWorkspaceGlobs(rootPkg);

  return { root, startedFrom, paradigm, manager, framework, workspaces, signals };
}

/* ── root detection ─────────────────────────────────────────────── */

interface RawPackage {
  readonly path: string;
  readonly contents: Record<string, unknown>;
}

async function locateProjectRoot(
  startedFrom: string,
  maxDepth: number,
): Promise<{ readonly root: string; readonly rootPkg: RawPackage; readonly nearestPkg: RawPackage }> {
  // Walk upward; remember the FIRST package.json (the user's nearest package);
  // keep walking until we hit one with `workspaces` (workspace root) or until
  // we exhaust the parents. Both are returned — paradigm + manager use the
  // workspace root; framework uses the nearest package.
  let current = startedFrom;
  let firstHit: RawPackage | null = null;

  for (let depth = 0; depth <= maxDepth; depth++) {
    const pkgPath = join(current, "package.json");
    let pkg: Record<string, unknown> | null = null;
    try {
      const raw = await fs.readFile(pkgPath, "utf-8");
      pkg = JSON.parse(raw) as Record<string, unknown>;
    } catch { /* missing or unreadable */ }

    if (pkg) {
      const hit: RawPackage = { path: pkgPath, contents: pkg };
      if (firstHit === null) firstHit = hit;
      if (pkg.workspaces) return { root: current, rootPkg: hit, nearestPkg: firstHit };
    }

    const parent = dirname(current);
    if (parent === current) break; // reached fs root
    current = parent;
  }

  if (firstHit !== null) {
    return { root: dirname(firstHit.path), rootPkg: firstHit, nearestPkg: firstHit };
  }

  throw new KashCliError(
    `No package.json found in ${startedFrom} or any of its ancestors (up to depth ${maxDepth}).`,
    "PROJECT_NOT_FOUND",
  );
}

/* ── paradigm detection ─────────────────────────────────────────── */

async function detectParadigm(
  root: string,
  rootPkg: RawPackage,
  signals: string[],
): Promise<ProjectParadigm> {
  const has = (rel: string): Promise<boolean> => fileExists(join(root, rel));

  // Order matters: turbo / nx have their own config files; they win when present.
  if (await has("turbo.json"))         { signals.push("turbo.json"); return "monorepo-turbo"; }
  if (await has("nx.json"))            { signals.push("nx.json");    return "monorepo-nx";    }
  if (await has("pnpm-workspace.yaml")) { signals.push("pnpm-workspace.yaml"); return "monorepo-pnpm"; }

  if (rootPkg.contents.workspaces) {
    signals.push(`workspaces=${JSON.stringify(rootPkg.contents.workspaces)}`);
    if (await has("bun.lock"))        return "monorepo-bun";
    if (await has("yarn.lock"))       return "monorepo-yarn";
    return "monorepo-npm";
  }

  signals.push("no-workspace-marker");
  return "standalone";
}

/* ── manager detection ──────────────────────────────────────────── */

async function detectManager(root: string, signals: string[]): Promise<PackageManager> {
  // Order: bun.lock → bun (most specific), then pnpm, yarn, npm.
  if (await fileExists(join(root, "bun.lock")))           { signals.push("bun.lock");          return "bun"; }
  if (await fileExists(join(root, "bun.lockb")))          { signals.push("bun.lockb");         return "bun"; }
  if (await fileExists(join(root, "pnpm-lock.yaml")))     { signals.push("pnpm-lock.yaml");    return "pnpm"; }
  if (await fileExists(join(root, "yarn.lock")))          { signals.push("yarn.lock");         return "yarn"; }
  if (await fileExists(join(root, "package-lock.json")))  { signals.push("package-lock.json"); return "npm"; }
  signals.push("no-lockfile");
  return "npm"; // safe default
}

/* ── framework detection ────────────────────────────────────────── */

/**
 * Order matters. Specific framework wrappers come first so a project that
 * is e.g. Next+React doesn't get matched as the generic "react". The last
 * two entries — `cra` and `react` — are intentionally low-priority: they
 * fire only when no recognised framework wrapper is present.
 */
const FRAMEWORK_MARKERS: ReadonlyArray<{ readonly framework: Framework; readonly deps: readonly string[] }> = [
  { framework: "next",      deps: ["next"] },
  { framework: "remix",     deps: ["@remix-run/react", "@remix-run/node", "@remix-run/dev"] },
  { framework: "expo",      deps: ["expo"] },
  { framework: "astro",     deps: ["astro"] },
  { framework: "sveltekit", deps: ["@sveltejs/kit"] },
  { framework: "vite",      deps: ["vite"] },             // many wrappers include vite transitively
  { framework: "cra",       deps: ["react-scripts"] },    // F3: Create React App
  { framework: "react",     deps: ["react", "react-dom"] }, // F3: generic React (last resort)
];

function detectFramework(rootPkg: RawPackage, signals: string[]): Framework {
  const all = mergeDeps(rootPkg.contents);
  for (const { framework, deps } of FRAMEWORK_MARKERS) {
    for (const d of deps) {
      if (d in all) {
        signals.push(`dep=${d}@${String(all[d])}`);
        return framework;
      }
    }
  }
  signals.push("framework=unknown");
  return "unknown";
}

function mergeDeps(pkg: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] as const) {
    const block = pkg[k];
    if (block && typeof block === "object" && !Array.isArray(block)) {
      for (const [name, version] of Object.entries(block)) {
        if (typeof version === "string") out[name] = version;
      }
    }
  }
  return out;
}

/* ── workspace globs ────────────────────────────────────────────── */

function extractWorkspaceGlobs(rootPkg: RawPackage): readonly string[] {
  const w = rootPkg.contents.workspaces;
  if (!w) return [];
  if (Array.isArray(w)) return w.filter((s): s is string => typeof s === "string");
  if (typeof w === "object" && w !== null) {
    const packages = (w as { packages?: unknown }).packages;
    if (Array.isArray(packages)) return packages.filter((s): s is string => typeof s === "string");
  }
  return [];
}

/* ── helpers ─────────────────────────────────────────────────────── */

async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch { return false; }
}

/* ── pretty-printer (used by `kash status`) ─────────────────────── */

export function formatReport(r: EnvironmentReport): string {
  const lines = [
    `kash · environment report`,
    `   root       ${r.root}`,
    `   started    ${r.startedFrom}`,
    `   paradigm   ${r.paradigm}`,
    `   manager    ${r.manager}`,
    `   framework  ${r.framework}`,
  ];
  if (r.workspaces.length > 0) {
    lines.push(`   workspaces ${r.workspaces.join(", ")}`);
  }
  return lines.join("\n");
}
