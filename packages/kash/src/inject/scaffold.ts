/**
 * Idempotent file scaffolding.
 *
 * Behaviour per file:
 *   • managed: false  →  create if missing; do NOT touch existing files.
 *     This is the default for any user-editable boilerplate.
 *   • managed: true   →  overwrite even when present; intended for
 *     vendored runtime files that the blueprint owns end-to-end.
 *   • `--force`       →  treat every file as `managed: true` for this run.
 *
 * Every write goes through {@link safeWriteFile} so an existing-file overwrite
 * always leaves a backup behind.
 */

import { promises as fs } from "node:fs";
import { dirname, resolve } from "node:path";

import { safeWriteFile, type SafeWriteOptions } from "../utils/backup";

export type ScaffoldAction = "created" | "updated" | "skipped" | "skipped-user-edited";

export interface ScaffoldFileSpec {
  /** Path relative to `cwd`. */
  readonly path: string;
  readonly content: string;
  readonly managed?: boolean;
  readonly mode?: number;
}

export interface ScaffoldResult {
  readonly path: string;
  readonly absolutePath: string;
  readonly action: ScaffoldAction;
  readonly bytesWritten: number;
  readonly backupPath: string | null;
  readonly dryRun: boolean;
}

export interface ScaffoldOptions extends SafeWriteOptions {
  /** Treat all files as `managed: true` for this run. */
  readonly force?: boolean;
}

export async function scaffoldFile(
  cwd: string,
  spec: ScaffoldFileSpec,
  opts: ScaffoldOptions = {},
): Promise<ScaffoldResult> {
  const absolute = resolve(cwd, spec.path);
  const exists   = await pathExists(absolute);
  const managed  = spec.managed ?? false;

  // ── decision table ──────────────────────────────────────────
  // exists?  | managed | force | action
  //   no     |   *     |   *   | created
  //   yes    |  true   |   *   | updated (backup)
  //   yes    | false   | true  | updated (backup)  ← --force escape hatch
  //   yes    | false   | false | skipped-user-edited

  if (!exists) {
    const w = await safeWriteFile(absolute, spec.content, opts);
    return wrap(spec.path, absolute, "created", w);
  }

  if (managed || opts.force) {
    // Compare existing content; skip if byte-identical (idempotency).
    const existing = await fs.readFile(absolute, "utf-8");
    if (existing === spec.content) {
      return {
        path: spec.path,
        absolutePath: absolute,
        action: "skipped",
        bytesWritten: 0,
        backupPath: null,
        dryRun: opts.dryRun === true,
      };
    }
    const w = await safeWriteFile(absolute, spec.content, opts);
    return wrap(spec.path, absolute, "updated", w);
  }

  return {
    path: spec.path,
    absolutePath: absolute,
    action: "skipped-user-edited",
    bytesWritten: 0,
    backupPath: null,
    dryRun: opts.dryRun === true,
  };
}

export async function scaffoldMany(
  cwd: string,
  specs: readonly ScaffoldFileSpec[],
  opts: ScaffoldOptions = {},
): Promise<readonly ScaffoldResult[]> {
  const results: ScaffoldResult[] = [];
  for (const s of specs) {
    // Ensure parent dirs exist (dry-run skips this; safeWriteFile handles it on apply).
    if (!opts.dryRun) await fs.mkdir(dirname(resolve(cwd, s.path)), { recursive: true });
    results.push(await scaffoldFile(cwd, s, opts));
  }
  return results;
}

/* ── helpers ────────────────────────────────────────────────────── */

async function pathExists(p: string): Promise<boolean> {
  try { await fs.access(p); return true; } catch { return false; }
}

function wrap(
  path: string,
  absolutePath: string,
  action: ScaffoldAction,
  write: { backupPath: string | null; dryRun: boolean; bytesWritten: number },
): ScaffoldResult {
  return {
    path,
    absolutePath,
    action,
    bytesWritten: write.bytesWritten,
    backupPath: write.backupPath,
    dryRun: write.dryRun,
  };
}
