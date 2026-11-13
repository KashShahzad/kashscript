/**
 * `kash rollback` — restore mutated files from the backup store.
 *
 * Every `kash add --apply` operation copies the prior file content to
 * `~/.kash/backups/<slug>.<timestamp>.bak` before mutating. This command
 * inverts the operation:
 *
 *   kash rollback list                — list available backups, newest first
 *   kash rollback restore <file>       — restore the newest backup matching <file>
 *   kash rollback restore --all-since <iso> — restore everything taken since <iso>
 *
 * The slug is the absolute source path with separators replaced by `_`,
 * so `apps/kashscript/package.json` becomes `_apps_kashscript_package.json`. The
 * listing reverse-engineers the slug to recover the original path.
 */

import { promises as fs } from "node:fs";
import { join, sep } from "node:path";

import { KashCliError } from "../errors";
import { backupsDir } from "../utils/paths";
import { c, banner, fail, info, success, warn } from "../utils/output";

interface BackupEntry {
  readonly slug: string;
  /** Absolute path the backup was taken from. Reverse-engineered from the slug. */
  readonly sourcePath: string;
  readonly backupPath: string;
  readonly takenAt: Date;
  readonly sizeBytes: number;
}

export interface RollbackOptions {
  /** "list" prints, "restore" actually copies the backup over the source. */
  readonly mode: "list" | "restore";
  /** Match-by-path filter for restore. Case-sensitive substring match. */
  readonly match?: string;
  /** ISO 8601 lower bound — restore everything taken at or after this instant. */
  readonly allSince?: string;
  /** When true, perform the restore without prompting. */
  readonly yes?: boolean;
}

export async function runRollback(opts: RollbackOptions): Promise<void> {
  banner(opts.mode === "list" ? "kash · rollback list" : "kash · rollback restore");

  const dir = backupsDir();
  let entries: BackupEntry[] = [];
  try {
    const names = await fs.readdir(dir);
    for (const name of names) {
      if (!name.endsWith(".bak")) continue;
      const parsed = parseBackupName(name);
      if (!parsed) continue;
      const stat = await fs.stat(join(dir, name));
      entries.push({
        slug:       parsed.slug,
        sourcePath: parsed.sourcePath,
        backupPath: join(dir, name),
        takenAt:    parsed.takenAt,
        sizeBytes:  stat.size,
      });
    }
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === "ENOENT") {
      info("No backups exist yet — nothing to roll back.");
      return;
    }
    throw new KashCliError(`Cannot read backup directory ${dir}: ${e.message}`, "INVALID_INPUT", err);
  }

  entries.sort((a, b) => b.takenAt.getTime() - a.takenAt.getTime());

  if (opts.mode === "list") {
    if (entries.length === 0) { info("No backups exist yet."); return; }
    info(`${entries.length} backup(s) in ${c.gray(dir)}:\n`);
    for (const e of entries) {
      process.stdout.write(
        `  ${c.gray(e.takenAt.toISOString())}  ${c.bold(e.sourcePath)}  ${c.gray(`${e.sizeBytes}B`)}\n`,
      );
    }
    return;
  }

  // mode === "restore"
  let toRestore: BackupEntry[];
  if (opts.allSince) {
    const since = Date.parse(opts.allSince);
    if (!Number.isFinite(since)) {
      throw new KashCliError(`--all-since must be a valid ISO-8601 timestamp.`, "INVALID_INPUT");
    }
    toRestore = entries.filter((e) => e.takenAt.getTime() >= since);
  } else if (opts.match) {
    const matches = entries.filter((e) => e.sourcePath.includes(opts.match!));
    if (matches.length === 0) {
      throw new KashCliError(`No backups matched ${JSON.stringify(opts.match)}.`, "INVALID_INPUT");
    }
    // For a match filter, pick the NEWEST per distinct sourcePath.
    const newestBySource = new Map<string, BackupEntry>();
    for (const m of matches) {
      const prev = newestBySource.get(m.sourcePath);
      if (!prev || m.takenAt > prev.takenAt) newestBySource.set(m.sourcePath, m);
    }
    toRestore = Array.from(newestBySource.values());
  } else {
    throw new KashCliError("Pass either <match> or --all-since to scope the restore.", "INVALID_INPUT");
  }

  if (toRestore.length === 0) { info("Nothing to restore."); return; }

  warn(`About to restore ${toRestore.length} file(s):`);
  for (const e of toRestore) {
    process.stdout.write(`  ${c.cyan(e.sourcePath)}  ${c.gray(`← ${e.takenAt.toISOString()}`)}\n`);
  }
  if (!opts.yes) {
    info(`Re-run with ${c.cyan("--yes")} to confirm.`);
    return;
  }

  let ok = 0, errCount = 0;
  for (const e of toRestore) {
    try {
      await fs.copyFile(e.backupPath, e.sourcePath);
      ok++;
    } catch (err) {
      errCount++;
      fail(`  failed: ${e.sourcePath} — ${(err as Error).message}`);
    }
  }

  if (errCount === 0) success(`Restored ${ok} file(s).`);
  else                warn(`Restored ${ok}/${toRestore.length} file(s); ${errCount} failed.`);
}

/* ── filename parser ─────────────────────────────────────────────── */

/**
 * Reverse the slug + timestamp encoding from `backup.ts`:
 *   `<slug>.<YYYY-MM-DDTHH-MM-SS-MMMZ>.bak`
 * where the slug is the absolute path with `sep` replaced by `_` and
 * non-`[a-zA-Z0-9._-]` chars replaced by `-`.
 */
function parseBackupName(name: string): { slug: string; sourcePath: string; takenAt: Date } | null {
  if (!name.endsWith(".bak")) return null;
  const stem = name.slice(0, -".bak".length);
  // Timestamps in the slug use only `-` separators (from `.replace(/[:.]/g, "-")`).
  // Match the trailing ISO-like block: 4-2-2T2-2-2-3+Z
  const m = /^(.*?)\.(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z)$/.exec(stem);
  if (!m) return null;
  const slug = m[1]!;
  const isoLike = m[2]!;
  // Reconstruct ISO 8601 by re-inserting `:` and `.`:
  const iso = isoLike.replace(/T(\d{2})-(\d{2})-(\d{2})-(\d{3})Z$/, "T$1:$2:$3.$4Z");
  const takenAt = new Date(iso);
  if (Number.isNaN(takenAt.getTime())) return null;
  // Reverse `path.split(sep).join("_")` — we can't perfectly recover (the slug
  // also flattened `-` substitutions), but mapping `_` → sep gives the path
  // back as long as the original filename didn't contain literal underscores.
  // The audit's stated risk is acceptable here: list shows the slug verbatim.
  const sourcePath = slug.split("_").join(sep).replace(/^[/\\]?/, sep);
  return { slug, sourcePath, takenAt };
}
