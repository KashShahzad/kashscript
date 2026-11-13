/**
 * Non-destructive file mutation helpers.
 *
 * Before the CLI mutates ANY user file (package.json, tsconfig.json, source
 * files, etc.), it must either:
 *   1. Create a backup via `backupFile()`, OR
 *   2. Run in `dryRun` mode and merely report what would change.
 *
 * Backups live under `~/.kash/backups/` keyed by absolute-source path + UNIX
 * timestamp, so a misbehaving command can be rolled back manually.
 */

import { promises as fs } from "node:fs";
import { dirname, join, sep } from "node:path";

import { KashCliError } from "../errors";
import { backupsDir } from "./paths";

/** Result of a backup + write operation. */
export interface SafeWriteResult {
  readonly path: string;
  readonly backupPath: string | null;
  readonly dryRun: boolean;
  readonly bytesWritten: number;
}

export interface SafeWriteOptions {
  /** When true: log what would change, do not write. Default false. */
  readonly dryRun?: boolean;
  /** Skip backup when target file does not exist (no prior state to preserve). Default true. */
  readonly skipBackupWhenMissing?: boolean;
}

/**
 * Copy `filePath` to the backup store and return the backup's absolute path.
 *
 * Throws {@link KashCliError} (`UNSAFE_WRITE`) if `filePath` doesn't exist.
 */
export async function backupFile(filePath: string): Promise<string> {
  let stat;
  try {
    stat = await fs.stat(filePath);
  } catch (err) {
    throw new KashCliError(`Cannot back up missing file: ${filePath}`, "UNSAFE_WRITE", err);
  }
  if (!stat.isFile()) {
    throw new KashCliError(`Backup target is not a regular file: ${filePath}`, "UNSAFE_WRITE");
  }

  const dir = backupsDir();
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });

  // Slugify the absolute path so backups can mirror many sources.
  const slug = filePath.split(sep).join("_").replace(/[^a-zA-Z0-9._-]/g, "-");
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = join(dir, `${slug}.${stamp}.bak`);

  await fs.copyFile(filePath, backupPath);
  return backupPath;
}

/**
 * Write `content` to `filePath` after taking a backup. In `dryRun` mode the
 * function returns the SafeWriteResult without touching the filesystem.
 */
export async function safeWriteFile(
  filePath: string,
  content: string,
  opts: SafeWriteOptions = {},
): Promise<SafeWriteResult> {
  const dryRun = opts.dryRun ?? false;
  const skipMissing = opts.skipBackupWhenMissing ?? true;

  let backupPath: string | null = null;
  let exists = false;
  try { await fs.access(filePath); exists = true; } catch { exists = false; }

  if (exists) {
    if (dryRun) {
      backupPath = "(would back up here)";
    } else {
      backupPath = await backupFile(filePath);
    }
  } else if (!skipMissing) {
    throw new KashCliError(
      `Target ${filePath} does not exist and skipBackupWhenMissing=false.`,
      "UNSAFE_WRITE",
    );
  }

  const bytes = Buffer.byteLength(content, "utf-8");
  if (!dryRun) {
    await fs.mkdir(dirname(filePath), { recursive: true });
    await fs.writeFile(filePath, content, "utf-8");
  }

  return { path: filePath, backupPath, dryRun, bytesWritten: bytes };
}

/**
 * Write a JSON file (pretty-printed, trailing newline) with the same
 * backup-or-dry-run semantics as {@link safeWriteFile}.
 */
export async function safeWriteJson(
  filePath: string,
  value: unknown,
  opts: SafeWriteOptions = {},
): Promise<SafeWriteResult> {
  return safeWriteFile(filePath, JSON.stringify(value, null, 2) + "\n", opts);
}
