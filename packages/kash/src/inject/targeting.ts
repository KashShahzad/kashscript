/**
 * Monorepo target picker.
 *
 * In standalone projects, the target is the project root — easy.
 * In monorepos, the user has to choose: which app gets the integration?
 *   • `--target apps/kashscript`  — explicit, scriptable, what CI uses.
 *   • interactive prompt        — terminal users get an `enquirer` picker.
 *   • `--target shared`         — creates a new `packages/kash-shared`
 *                                  package and installs there instead.
 */

import { promises as fs } from "node:fs";
import { join, resolve } from "node:path";

import { KashCliError } from "../errors";
import type { EnvironmentReport } from "../utils/env";

export interface InjectionTarget {
  readonly mode: "standalone" | "monorepo-app" | "monorepo-shared-package";
  /** Absolute path to the directory the blueprint operates against. */
  readonly cwd: string;
  /** Workspace name relative to root (e.g., `apps/kashscript`), or undefined for standalone. */
  readonly workspace?: string;
}

export interface TargetingOptions {
  /** Explicit target workspace name (relative path) or `"shared"`. */
  readonly target?: string;
  /** Skip the interactive prompt — fall back to root if no target. */
  readonly nonInteractive?: boolean;
}

export async function resolveTarget(
  env: EnvironmentReport,
  opts: TargetingOptions = {},
): Promise<InjectionTarget> {
  if (env.paradigm === "standalone") {
    return { mode: "standalone", cwd: env.root };
  }

  // Monorepo path. Discover concrete workspaces from the globs.
  const workspaces = await expandWorkspaces(env.root, env.workspaces);

  // 1. Explicit `--target shared` keyword.
  if (opts.target === "shared") {
    const sharedRel = "packages/kash-shared";
    const sharedAbs = resolve(env.root, sharedRel);
    return { mode: "monorepo-shared-package", cwd: sharedAbs, workspace: sharedRel };
  }

  // 2. Explicit `--target <workspace-name>`.
  if (opts.target) {
    const match = workspaces.find((w) => w.name === opts.target || w.rel === opts.target);
    if (!match) {
      throw new KashCliError(
        `Target "${opts.target}" did not match any workspace (${workspaces.map((w) => w.rel).join(", ")}).`,
        "INVALID_INPUT",
      );
    }
    return { mode: "monorepo-app", cwd: match.abs, workspace: match.rel };
  }

  // 3. Non-interactive fallback — single-workspace monorepos pick automatically;
  //    multi-workspace monorepos refuse to choose silently.
  if (opts.nonInteractive || !process.stdin.isTTY) {
    if (workspaces.length === 1) {
      return { mode: "monorepo-app", cwd: workspaces[0]!.abs, workspace: workspaces[0]!.rel };
    }
    throw new KashCliError(
      `Monorepo detected with ${workspaces.length} workspaces; pass --target <name> ` +
      `(${workspaces.map((w) => w.rel).join(", ")}) or "--target shared".`,
      "INVALID_INPUT",
    );
  }

  // 4. Interactive prompt.
  return promptForTarget(env.root, workspaces);
}

/* ── workspace expansion ────────────────────────────────────────── */

interface DiscoveredWorkspace {
  readonly rel: string;
  readonly abs: string;
  readonly name: string;
}

async function expandWorkspaces(
  root: string,
  globs: readonly string[],
): Promise<readonly DiscoveredWorkspace[]> {
  const found: DiscoveredWorkspace[] = [];
  for (const g of globs) {
    // Only support `dir/*` globs in v1 — sufficient for turbo / pnpm / yarn / bun layouts.
    const m = /^([a-zA-Z0-9_./-]+)\/\*$/.exec(g);
    if (!m) continue;
    const base = m[1]!;
    const baseAbs = resolve(root, base);
    let entries: string[];
    try { entries = await fs.readdir(baseAbs); }
    catch { continue; }
    for (const entry of entries) {
      const dir = join(baseAbs, entry);
      const pkg = join(dir, "package.json");
      try {
        const raw = await fs.readFile(pkg, "utf-8");
        const json = JSON.parse(raw) as { name?: string };
        found.push({
          rel:  `${base}/${entry}`,
          abs:  dir,
          name: json.name ?? `${base}/${entry}`,
        });
      } catch { /* skip dirs without package.json */ }
    }
  }
  // Stable sort for consistent prompts.
  return [...found].sort((a, b) => a.rel.localeCompare(b.rel));
}

/* ── enquirer prompt ────────────────────────────────────────────── */

async function promptForTarget(
  root: string,
  workspaces: readonly DiscoveredWorkspace[],
): Promise<InjectionTarget> {
  let promptFn: <T>(opts: unknown) => Promise<T>;
  try {
    const mod = await import("enquirer");
    promptFn = (mod as unknown as { prompt: <T>(opts: unknown) => Promise<T> }).prompt;
  } catch {
    throw new KashCliError(
      "enquirer is not installed and no --target was supplied; cannot pick a workspace interactively.",
      "INVALID_INPUT",
    );
  }

  const choices: Array<{ name: string; message: string; hint: string }> = workspaces.map((w) => ({
    name:    w.rel,
    message: w.name,
    hint:    w.rel,
  }));
  choices.push({
    name:    "shared",
    message: "Create a shared package",
    hint:    "packages/kash-shared (new)",
  });

  const { picked } = await promptFn<{ readonly picked: string }>({
    type:    "select",
    name:    "picked",
    message: "Add the integration to which workspace?",
    choices,
  });

  if (picked === "shared") {
    const sharedRel = "packages/kash-shared";
    return { mode: "monorepo-shared-package", cwd: resolve(root, sharedRel), workspace: sharedRel };
  }
  const ws = workspaces.find((w) => w.rel === picked);
  if (!ws) throw new KashCliError("Workspace selection failed.", "INVALID_INPUT");
  return { mode: "monorepo-app", cwd: ws.abs, workspace: ws.rel };
}
