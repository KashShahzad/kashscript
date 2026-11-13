/**
 * JSON Safe Modifier.
 *
 * Reads a JSON file (package.json, tsconfig.json), applies a list of
 * dot-path patches under one of three strategies, and writes the result
 * via {@link safeWriteJson} (which itself takes a backup or runs dry).
 *
 * Strategies:
 *   • `"set-if-missing"` — never overwrite an existing value at the path.
 *   • `"merge"`          — shallow-merge object values (skip non-objects).
 *   • `"replace"`        — force-overwrite the value at the path.
 *
 * Idempotency is built into `set-if-missing` and `merge` — a second run
 * with the same patch is a no-op (or yields the same merged result).
 *
 * Conflict safety: a patch whose intermediate path collides with an existing
 * non-object value (e.g. patching `scripts.test.unit` when `scripts.test` is
 * the string `"jest"`) is REFUSED rather than silently clobbering the host
 * value. The conflict is recorded in the returned `applied[]` with
 * `action: "conflict"`, the file is still written for the OTHER patches that
 * succeeded, and the caller can render the conflict for the user.
 */

import { promises as fs } from "node:fs";

import { KashCliError } from "../errors";
import { safeWriteJson, type SafeWriteOptions, type SafeWriteResult } from "../utils/backup";

export type PatchStrategy = "set-if-missing" | "merge" | "replace";

export interface JsonPatch {
  readonly path: string;
  readonly value: unknown;
  readonly strategy?: PatchStrategy;
}

export type AppliedPatch =
  | {
      readonly path: string;
      readonly action: "added" | "merged" | "replaced" | "skipped";
      readonly previous?: unknown;
      readonly next?: unknown;
    }
  | {
      readonly path: string;
      readonly action: "conflict";
      readonly previous?: unknown;
      /** Dot-path of the first non-object intermediate that blocked the write. */
      readonly conflictAt: string;
      /** Runtime kind of the blocking value: "string" / "number" / "boolean" / "array" / "null". */
      readonly conflictType: string;
    };

export interface ApplyResult {
  readonly file: string;
  readonly write: SafeWriteResult;
  /** Per-patch outcome — useful for the dry-run report. */
  readonly applied: ReadonlyArray<AppliedPatch>;
  /** True when one or more patches were skipped due to a structural conflict. */
  readonly hasConflicts: boolean;
}

/** Options for {@link applyJsonPatches} beyond the shared SafeWriteOptions. */
export interface ApplyJsonPatchesOptions extends SafeWriteOptions {
  /**
   * F1 escape hatch — when `true`, intermediate non-object values get
   * replaced wholesale instead of producing a conflict. Equivalent to the
   * pre-F1 v0.1 behaviour. The caller MUST surface a clear "this will
   * overwrite X" warning to the user before invoking with `force: true`.
   *
   * Default `false`: conflicts abort the file write entirely (no partial
   * apply) and the failing patches surface in `applied[]` for reporting.
   */
  readonly force?: boolean;
}

/** Apply a list of patches to a JSON file, preserving everything not touched. */
export async function applyJsonPatches(
  filePath: string,
  patches: readonly JsonPatch[],
  opts: ApplyJsonPatchesOptions = {},
): Promise<ApplyResult> {
  let original: Record<string, unknown>;
  let exists = true;
  try {
    const raw = await fs.readFile(filePath, "utf-8");
    original = JSON.parse(raw) as Record<string, unknown>;
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === "ENOENT") {
      original = {};
      exists = false;
    } else {
      throw new KashCliError(`Cannot read ${filePath}.`, "INVALID_INPUT", err);
    }
  }

  // Deep clone so we don't accidentally mutate the parsed reference.
  const next = structuredClone(original);
  const applied: AppliedPatch[] = [];

  for (const patch of patches) {
    const strategy = patch.strategy ?? "set-if-missing";
    const before = getPath(next, patch.path);

    if (strategy === "set-if-missing" && before !== undefined) {
      applied.push({ path: patch.path, action: "skipped", previous: before });
      continue;
    }

    if (strategy === "merge" && isPlainObject(before) && isPlainObject(patch.value)) {
      const merged = { ...(before as Record<string, unknown>), ...(patch.value as Record<string, unknown>) };
      if (isEqual(merged, before)) {
        applied.push({ path: patch.path, action: "skipped", previous: before });
        continue;
      }
      const r = setPath(next, patch.path, merged, opts.force === true);
      if (!r.ok) {
        applied.push({ path: patch.path, action: "conflict", previous: before, conflictAt: r.conflictAt, conflictType: r.conflictType });
        continue;
      }
      applied.push({ path: patch.path, action: "merged", previous: before, next: merged });
      continue;
    }

    if (strategy === "replace" || before === undefined || strategy === "merge") {
      // For "merge" on a non-object existing value, fall back to set semantics.
      const r = setPath(next, patch.path, patch.value, opts.force === true);
      if (!r.ok) {
        applied.push({ path: patch.path, action: "conflict", previous: before, conflictAt: r.conflictAt, conflictType: r.conflictType });
        continue;
      }
      applied.push({
        path: patch.path,
        action: before === undefined ? "added" : "replaced",
        previous: before,
        next: patch.value,
      });
    }
  }

  const hasConflicts = applied.some((a) => a.action === "conflict");
  const allSkippedOrConflict = applied.every((a) => a.action === "skipped" || a.action === "conflict");

  // F1 (audit-5): abort the file write entirely if any conflict surfaced.
  // The previous behaviour partial-applied the non-conflicting patches; the
  // audit recommends the conservative path — refuse to touch the file at
  // all so the user resolves manually (or re-runs with --force).
  if (hasConflicts) {
    return {
      file: filePath,
      write: { path: filePath, backupPath: null, dryRun: opts.dryRun === true, bytesWritten: 0 },
      applied,
      hasConflicts,
    };
  }

  // If no patch actually mutated `next`, don't touch the file.
  if (allSkippedOrConflict && exists) {
    return {
      file: filePath,
      write: { path: filePath, backupPath: null, dryRun: opts.dryRun === true, bytesWritten: 0 },
      applied,
      hasConflicts,
    };
  }

  const write = await safeWriteJson(filePath, next, opts);
  return { file: filePath, write, applied, hasConflicts };
}

/* ── tiny dot-path helpers ──────────────────────────────────────── */

function splitPath(p: string): readonly string[] {
  return p.split(".").filter((s) => s.length > 0);
}

function getPath(obj: Record<string, unknown>, path: string): unknown {
  const parts = splitPath(path);
  let cur: unknown = obj;
  for (const part of parts) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[part];
  }
  return cur;
}

type SetPathResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly conflictAt: string; readonly conflictType: string };

/**
 * Walk the dot-path and write `value` at the leaf. Returns a conflict if any
 * INTERMEDIATE key already holds a non-object value (string / number / boolean
 * / array / null) — clobbering those silently is how user `npm test`
 * scripts and similar host config get nuked. The patch author can target the
 * intermediate explicitly with `strategy: "replace"` if they really intend to
 * overwrite it; the CLI also exposes a `--force` flag (`opts.force = true`)
 * that replaces non-object intermediates with fresh objects — restoring the
 * pre-F1 behaviour for callers who have manually confirmed the intent.
 */
function setPath(
  obj: Record<string, unknown>,
  path: string,
  value: unknown,
  force = false,
): SetPathResult {
  const parts = splitPath(path);
  if (parts.length === 0) return { ok: true };
  let cur: Record<string, unknown> = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i]!;
    const existing = cur[key];
    if (existing === undefined) {
      const fresh: Record<string, unknown> = {};
      cur[key] = fresh;
      cur = fresh;
    } else if (isPlainObject(existing)) {
      cur = existing as Record<string, unknown>;
    } else if (force) {
      const fresh: Record<string, unknown> = {};
      cur[key] = fresh;
      cur = fresh;
    } else {
      return {
        ok: false,
        conflictAt: parts.slice(0, i + 1).join("."),
        conflictType: Array.isArray(existing) ? "array" : existing === null ? "null" : typeof existing,
      };
    }
  }
  cur[parts[parts.length - 1]!] = value;
  return { ok: true };
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b) return false;
  if (a === null || b === null) return false;
  if (typeof a === "object" && typeof b === "object") {
    const ka = Object.keys(a as Record<string, unknown>).sort();
    const kb = Object.keys(b as Record<string, unknown>).sort();
    if (ka.length !== kb.length) return false;
    for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return false;
    for (const k of ka) {
      if (!isEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k])) return false;
    }
    return true;
  }
  return false;
}
