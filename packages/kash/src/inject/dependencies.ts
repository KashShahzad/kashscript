/**
 * Universal dependency installer.
 *
 * Reads the user's package.json, compares against a list of {@link DependencySpec},
 * and spawns the appropriate manager command for the missing subset.
 * Idempotent: a re-run with an unchanged spec list is a no-op.
 */

import { promises as fs } from "node:fs";
import { join } from "node:path";

import { KashCliError } from "../errors";
import type { PackageManager } from "../utils/env";
import { spawnManager } from "../utils/spawn";
import type { DependencySpec } from "./blueprints/types";

export interface InstallPlan {
  readonly toInstall:    readonly DependencySpec[];
  readonly toInstallDev: readonly DependencySpec[];
  readonly toPeer:       readonly DependencySpec[];
  readonly alreadyPresent: readonly DependencySpec[];
}

/** Analyse a target package.json + a list of deps. Returns the subset that
 *  still needs installation (split by kind). */
export async function planInstall(
  pkgPath: string,
  specs: readonly DependencySpec[],
): Promise<InstallPlan> {
  const pkg = await readPackageJson(pkgPath);
  const deps     = (pkg.dependencies     as Record<string, string> | undefined) ?? {};
  const devDeps  = (pkg.devDependencies  as Record<string, string> | undefined) ?? {};
  const peerDeps = (pkg.peerDependencies as Record<string, string> | undefined) ?? {};

  const toInstall:    DependencySpec[] = [];
  const toInstallDev: DependencySpec[] = [];
  const toPeer:       DependencySpec[] = [];
  const alreadyPresent: DependencySpec[] = [];

  for (const s of specs) {
    if (s.peer) {
      if (s.name in peerDeps) alreadyPresent.push(s);
      else                    toPeer.push(s);
    } else if (s.dev) {
      if (s.name in devDeps) alreadyPresent.push(s);
      else                   toInstallDev.push(s);
    } else {
      if (s.name in deps || s.name in devDeps) alreadyPresent.push(s);
      else                                     toInstall.push(s);
    }
  }

  return { toInstall, toInstallDev, toPeer, alreadyPresent };
}

export interface InstallOptions {
  /** Don't actually run the manager — just report what would happen. */
  readonly dryRun?: boolean;
  /** Override the cwd the manager runs in. Default: dirname(pkgPath). */
  readonly cwd?: string;
  readonly reporter?: (line: string) => void;
}

export interface InstallResult {
  readonly executed:     readonly string[];  // shell strings, for the report
  readonly dryRun:       boolean;
}

/** Execute the plan against the user's package manager. */
export async function executeInstall(
  manager: PackageManager,
  pkgPath: string,
  plan: InstallPlan,
  opts: InstallOptions = {},
): Promise<InstallResult> {
  const cwd = opts.cwd ?? dirname(pkgPath);
  const executed: string[] = [];

  if (plan.toInstall.length > 0) {
    executed.push(await runManager(manager, "install", plan.toInstall, cwd, opts));
  }
  if (plan.toInstallDev.length > 0) {
    executed.push(await runManager(manager, "install-dev", plan.toInstallDev, cwd, opts));
  }
  // Peer deps aren't actually installed — they're declared via the JSON transformer.
  return { executed, dryRun: opts.dryRun === true };
}

/* ── manager dispatch ───────────────────────────────────────────── */

type InstallKind = "install" | "install-dev";

function managerCommand(manager: PackageManager, kind: InstallKind, specs: readonly DependencySpec[]): readonly string[] {
  const args = specs.map((s) => `${s.name}@${s.version}`);
  switch (manager) {
    case "bun":  return ["bun",  kind === "install-dev" ? "add"     : "add", ...(kind === "install-dev" ? ["-d"] : []), ...args];
    case "pnpm": return ["pnpm", "add", ...(kind === "install-dev" ? ["-D"] : []), ...args];
    case "yarn": return ["yarn", "add", ...(kind === "install-dev" ? ["-D"] : []), ...args];
    case "npm":  return ["npm",  "install", ...(kind === "install-dev" ? ["--save-dev"] : []), ...args];
  }
}

async function runManager(
  manager: PackageManager,
  kind: InstallKind,
  specs: readonly DependencySpec[],
  cwd: string,
  opts: InstallOptions,
): Promise<string> {
  const cmd = managerCommand(manager, kind, specs);
  const shellRepr = cmd.join(" ");
  opts.reporter?.(`$ ${shellRepr}`);

  if (opts.dryRun) return shellRepr;

  return new Promise<string>((resolve, reject) => {
    const proc = spawnManager(cmd[0]!, cmd.slice(1), { cwd, stdio: "inherit" });
    proc.on("error", (err) => reject(new KashCliError(
      `Failed to spawn ${cmd[0]}: ${err.message}`,
      "INVALID_INPUT",
      err,
    )));
    proc.on("exit", (code) => {
      if (code !== 0) {
        reject(new KashCliError(
          `\`${shellRepr}\` exited with code ${code}.`,
          "INVALID_INPUT",
        ));
        return;
      }
      resolve(shellRepr);
    });
  });
}

/* ── helpers ────────────────────────────────────────────────────── */

async function readPackageJson(pkgPath: string): Promise<Record<string, unknown>> {
  try {
    const raw = await fs.readFile(pkgPath, "utf-8");
    return JSON.parse(raw) as Record<string, unknown>;
  } catch (err) {
    throw new KashCliError(`Cannot read ${pkgPath}.`, "INVALID_INPUT", err);
  }
}

function dirname(p: string): string {
  const i = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  return i === -1 ? "." : p.slice(0, i);
}

export { join as joinPath };
