/**
 * Walking a repository and matching globs, with no runtime beyond Node's own (the scanner runs under Node 20 and Bun).
 * Globs: `*` (within a segment), `**` (any number of segments), `?`, `{a,b}`; a leading `!` excludes.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";

/** Directories never walked. */
const SKIP_DIRS: ReadonlySet<string> = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".turbo", ".expo", "coverage", "out", "android", "ios", ".vercel",
  ".svelte-kit", ".cache",
]);

/** Paths a source glob never takes, whatever the manifest says: tests, declarations and generated code. */
export const DEFAULT_EXCLUDES: readonly string[] = [
  "**/*.test.*", "**/*.spec.*", "**/__tests__/**", "**/test/**", "**/tests/**", "**/fixtures/**", "**/*.d.ts",
  "**/database.types.ts", "**/prisma/generated/**",
];

export function toPosix(p: string): string {
  return p.split(sep).join("/");
}

function expandBraces(glob: string): string[] {
  const m = /\{([^{}]*)\}/.exec(glob);
  if (m === null) return [glob];
  const [whole, inner] = [m[0], m[1] ?? ""];
  const out: string[] = [];
  for (const alt of inner.split(",")) out.push(...expandBraces(glob.slice(0, m.index) + alt + glob.slice(m.index + whole.length)));
  return out;
}

/** One glob (braces expanded) as an anchored regular expression over a POSIX path. */
export function globToRegExp(glob: string): RegExp {
  const alts = expandBraces(glob).map((g) => {
    let re = "";
    for (let i = 0; i < g.length; i++) {
      const c = g[i]!;
      if (c === "*") {
        if (g[i + 1] === "*") {
          const before = i === 0 || g[i - 1] === "/";
          const after = g[i + 2] === "/" || i + 2 === g.length;
          if (before && after) {
            if (g[i + 2] === "/") {
              re += "(?:.*/)?";
              i += 2;
            } else {
              re += ".*";
              i += 1;
            }
            continue;
          }
          re += ".*";
          i += 1;
          continue;
        }
        re += "[^/]*";
      } else if (c === "?") {
        re += "[^/]";
      } else {
        re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
      }
    }
    return re;
  });
  return new RegExp(`^(?:${alts.join("|")})$`);
}

export function matchesAny(path: string, globs: readonly RegExp[]): boolean {
  return globs.some((g) => g.test(path));
}

/** Every file under `root`, as POSIX paths relative to it. */
export function walk(root: string): string[] {
  const out: string[] = [];
  const visit = (dir: string): void => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.isDirectory()) {
        if (!SKIP_DIRS.has(e.name)) visit(join(dir, e.name));
      } else if (e.isFile()) {
        out.push(toPosix(relative(root, join(dir, e.name))));
      }
    }
  };
  if (existsSync(root)) visit(root);
  return out.sort();
}

export class Tree {
  private all: string[] | undefined;
  constructor(readonly root: string) {}

  files(): readonly string[] {
    this.all ??= walk(this.root);
    return this.all;
  }

  /** The files matching the include globs and none of the exclude globs (`!…`), plus the default excludes when asked. */
  select(patterns: readonly string[], opts: { readonly defaultExcludes?: boolean } = {}): string[] {
    const include = patterns.filter((p) => !p.startsWith("!")).map(globToRegExp);
    const exclude = [
      ...patterns.filter((p) => p.startsWith("!")).map((p) => globToRegExp(p.slice(1))),
      ...(opts.defaultExcludes === true ? DEFAULT_EXCLUDES.map(globToRegExp) : []),
    ];
    return this.files().filter((f) => matchesAny(f, include) && !matchesAny(f, exclude));
  }

  read(rel: string): string {
    return readFileSync(resolve(this.root, rel), "utf8").replace(/^﻿/, "");
  }

  exists(rel: string): boolean {
    return existsSync(resolve(this.root, rel));
  }

  isDir(rel: string): boolean {
    try {
      return statSync(resolve(this.root, rel)).isDirectory();
    } catch {
      return false;
    }
  }

  abs(rel: string): string {
    return resolve(this.root, rel);
  }
}
