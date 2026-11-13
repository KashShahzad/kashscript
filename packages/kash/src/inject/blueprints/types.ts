/**
 * Blueprint — declarative description of an integration.
 *
 * A Blueprint is a list of OPERATIONS the injector executes idempotently
 * against a target project. Each operation knows how to:
 *
 *   1. Plan itself — analyse current state, decide if it would create,
 *      update, or skip.
 *   2. Apply itself — perform the actual mutation behind a backup.
 *   3. Verify itself — confirm post-conditions for `kash doctor`.
 *
 * Blueprints are pure data — no closures over the host environment.
 * `BlueprintFile.content` accepts a render function so the framework /
 * router / language detected at scan time can specialise the output.
 */

import type { EnvironmentReport } from "../../utils/env";

/* ── shared ─────────────────────────────────────────────────────── */

export type ProductId = "identity" | "terms" | "muffler" | "whiffin";

export interface DependencySpec {
  readonly name: string;
  readonly version: string;
  /** Required dev-time only. Default: false (regular dependency). */
  readonly dev?: boolean;
  /** Goes into `peerDependencies`. Default: false. */
  readonly peer?: boolean;
}

/* ── operation types ───────────────────────────────────────────── */

export type BlueprintOperation =
  | InstallDepOp
  | WriteFileOp
  | PatchPackageJsonOp
  | PatchTsconfigOp
  | PatchTurboJsonOp;

/**
 * F5 (audit-5): per-operation guard. Lets a blueprint say "only apply this
 * when the target meets these conditions" instead of using ad-hoc `when`
 * predicates. Checked by the planner before {@link RenderContext} is used,
 * so unmatched ops show as `filtered-out` in the plan instead of being
 * silently skipped.
 */
export interface OperationRequires {
  /** Apply only when env.framework is in this list. Empty/undefined = any. */
  readonly framework?: readonly string[];
  /** Apply only when env.paradigm is in this list. */
  readonly paradigm?: readonly string[];
  /** Apply only when the target already has a tsconfig.json — never auto-create. */
  readonly tsconfigExists?: boolean;
}

export interface InstallDepOp {
  readonly kind: "install-dep";
  readonly description: string;
  readonly spec: DependencySpec;
  readonly requires?: OperationRequires;
}

/** Render context passed to dynamic file content + verification render-props. */
export interface RenderContext {
  readonly env: EnvironmentReport;
  /** Absolute path to the directory operations are scoped to (e.g., apps/kashscript). */
  readonly cwd: string;
  /** Absolute path to the workspace root — for monorepo paradigms, this is the
   *  directory containing turbo.json / pnpm-workspace.yaml. For standalone projects
   *  this equals `cwd`. F6: used as the target for `patch-turbo-json` operations. */
  readonly workspaceRoot: string;
  /** App-supplied product identifier (used in scaffolded comments). */
  readonly product: ProductId;
}

export interface WriteFileOp {
  readonly kind: "write-file";
  readonly description: string;
  /** Path relative to the operation cwd. */
  readonly path: string;
  /** File content. Static string OR a function of the render context. */
  readonly content: string | ((ctx: RenderContext) => string);
  /**
   * `managed` files MAY be overwritten on re-run (e.g., vendored runtime).
   * `unmanaged` (default) files are user-editable: the injector creates them
   * the first time and never touches them again.
   */
  readonly managed?: boolean;
  /** Only emit when this predicate is true (e.g., "only on Next.js apps"). */
  readonly when?: (ctx: RenderContext) => boolean;
  /** Unix mode (default 0o644). */
  readonly mode?: number;
  /** F5: structured prerequisites — see {@link OperationRequires}. */
  readonly requires?: OperationRequires;
}

export interface PatchPackageJsonOp {
  readonly kind: "patch-package-json";
  readonly description: string;
  /** Dot-notation JSON path, e.g., `"scripts.kash:doctor"`. */
  readonly path: string;
  readonly value: unknown;
  /** Default semantics ("set-if-missing") never overwrite an existing value.
   *  "merge" performs a shallow object merge; "replace" forces overwrite. */
  readonly strategy?: "set-if-missing" | "merge" | "replace";
  readonly requires?: OperationRequires;
}

export interface PatchTsconfigOp {
  readonly kind: "patch-tsconfig";
  readonly description: string;
  /** Dot-notation path inside the tsconfig (e.g., `"compilerOptions.paths"`). */
  readonly path: string;
  readonly value: unknown;
  readonly strategy?: "set-if-missing" | "merge" | "replace";
  readonly requires?: OperationRequires;
}

/**
 * F6 (audit-5): patch turbo.json at the WORKSPACE ROOT (not the target
 * workspace's cwd). Only meaningful when `env.paradigm === "monorepo-turbo"`.
 * Authors SHOULD set `requires: { paradigm: ["monorepo-turbo"] }` so the
 * planner filters this op out on standalone / non-turbo monorepos instead
 * of creating an orphaned turbo.json.
 */
export interface PatchTurboJsonOp {
  readonly kind: "patch-turbo-json";
  readonly description: string;
  /** Dot-notation path inside turbo.json (e.g., `"tasks.kash:doctor"`). */
  readonly path: string;
  readonly value: unknown;
  readonly strategy?: "set-if-missing" | "merge" | "replace";
  readonly requires?: OperationRequires;
}

/* ── verifications (used by kash doctor) ────────────────────────── */

export type Verification =
  | FileExistsVerification
  | DependencyVerification
  | PackageJsonFieldVerification;

export interface FileExistsVerification {
  readonly kind: "file-exists";
  readonly description: string;
  readonly path: string;
}

export interface DependencyVerification {
  readonly kind: "dep-present";
  readonly description: string;
  readonly name: string;
  /** Optional semver-ish prefix check (`"^0.2."`). */
  readonly versionStartsWith?: string;
}

export interface PackageJsonFieldVerification {
  readonly kind: "package-json-field";
  readonly description: string;
  /** Dot-notation path. */
  readonly path: string;
}

/* ── blueprint ──────────────────────────────────────────────────── */

export interface Blueprint {
  readonly id: ProductId;
  readonly title: string;
  readonly description: string;
  /** Stable semver for this blueprint definition (independent of the underlying packages). */
  readonly blueprintVersion: string;
  readonly operations: readonly BlueprintOperation[];
  readonly verifications: readonly Verification[];
}
