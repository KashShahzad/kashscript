/**
 * Project Injector — orchestrator that walks a Blueprint, plans every
 * operation (idempotency check + dry-run preview), and applies them in
 * order.
 *
 * Flow per invocation:
 *   1. Resolve the {@link InjectionTarget} (standalone / monorepo).
 *   2. Build a `PlannedOperation[]` for every operation in the blueprint.
 *   3. Render the plan to the reporter (dry-run leaves here).
 *   4. Execute each planned op behind its own backup.
 *   5. Run the post-apply verifications and report the integration health.
 */

import { promises as fs } from "node:fs";
import { join } from "node:path";

import { KashCliError } from "../errors";
import { scanEnvironment, type EnvironmentReport } from "../utils/env";
import {
  type Blueprint,
  type BlueprintOperation,
  type InstallDepOp,
  type PatchPackageJsonOp,
  type PatchTsconfigOp,
  type PatchTurboJsonOp,
  type RenderContext,
  type Verification,
} from "./blueprints/types";
import { executeInstall, planInstall, type InstallPlan } from "./dependencies";
import { scaffoldFile, type ScaffoldResult } from "./scaffold";
import { applyJsonPatches, type ApplyResult, type JsonPatch } from "./transformer";
import { resolveTarget, type InjectionTarget, type TargetingOptions } from "./targeting";

export * from "./blueprints/types";
export * from "./blueprints";
export * from "./targeting";
export { applyJsonPatches } from "./transformer";
export { scaffoldFile, scaffoldMany } from "./scaffold";

/* ── planning types ─────────────────────────────────────────────── */

export type PlannedOperationStatus =
  | "would-create"
  | "would-update"
  | "would-merge"
  | "already-applied"
  | "user-edited"
  | "filtered-out";

export interface PlannedOperation {
  readonly op: BlueprintOperation;
  readonly status: PlannedOperationStatus;
  /** Human-readable line for the dry-run report. */
  readonly summary: string;
}

export interface InjectionResult {
  readonly target: InjectionTarget;
  readonly plan: readonly PlannedOperation[];
  readonly install?: { readonly plan: InstallPlan; readonly executed: readonly string[] };
  readonly scaffolds: readonly ScaffoldResult[];
  readonly jsonPatches: readonly ApplyResult[];
  readonly verification: VerificationReport;
  readonly dryRun: boolean;
}

export interface InjectionOptions extends TargetingOptions {
  /** Apply the plan. Default false (dry-run). */
  readonly apply?: boolean;
  /** Treat all scaffolded files as managed for this run; also enables transformer's intermediate-clobber. */
  readonly force?: boolean;
  /** Skip the dependency-install step entirely (still patches package.json). */
  readonly skipInstall?: boolean;
  /**
   * F5 (audit-5) escape hatch — when `true`, operations whose `requires.tsconfigExists`
   * would otherwise filter them out are allowed to proceed (auto-creating
   * tsconfig.json). Default `false` — protects projects that have deliberately
   * not adopted TypeScript from getting a surprise tsconfig.
   */
  readonly createTsconfig?: boolean;
  /** Progress reporter. */
  readonly reporter?: InjectionReporter;
  /** Pre-computed env scan (avoids re-walking the FS when the caller already has it). */
  readonly env: EnvironmentReport;
}

export interface InjectionReporter {
  readonly onPlan:        (plan: readonly PlannedOperation[]) => void;
  readonly onInstall:     (line: string) => void;
  readonly onScaffold:    (result: ScaffoldResult) => void;
  readonly onJsonPatch:   (result: ApplyResult) => void;
  readonly onVerification:(report: VerificationReport) => void;
}

const noopReporter: InjectionReporter = {
  onPlan:        () => {},
  onInstall:     () => {},
  onScaffold:    () => {},
  onJsonPatch:   () => {},
  onVerification:() => {},
};

/* ── entry point ────────────────────────────────────────────────── */

export async function inject(
  blueprint: Blueprint,
  opts: InjectionOptions,
): Promise<InjectionResult> {
  const dryRun   = opts.apply !== true;
  const reporter = opts.reporter ?? noopReporter;
  const target   = await resolveTarget(opts.env, opts);

  // Re-scan from the resolved target so framework detection reflects the
  // actual workspace (apps/kashscript's package.json carries `next`, not the
  // monorepo root's). Paradigm + manager are read once from opts.env at the
  // workspace-root level — those are stable across workspaces.
  const targetEnv = target.cwd === opts.env.root
    ? opts.env
    : await scanEnvironment({ cwd: target.cwd });

  const workspaceRoot = opts.env.root;                 // F6: monorepo root vs. target.cwd
  const ctx: RenderContext = { env: targetEnv, cwd: target.cwd, workspaceRoot, product: blueprint.id };
  const pkgPath   = join(target.cwd,    "package.json");
  const tscPath   = join(target.cwd,    "tsconfig.json");
  const turboPath = join(workspaceRoot, "turbo.json");  // F6: ALWAYS at the workspace root

  // F5: detect tsconfig once for use as a `requires` filter input.
  const tsconfigExists = await pathExists(tscPath);
  const requiresInput: RequiresInput = {
    env: targetEnv,
    tsconfigExists,
    createTsconfig: opts.createTsconfig === true,
  };

  const plan = await buildPlan(blueprint, ctx, { pkgPath, tscPath, requiresInput });
  reporter.onPlan(plan);

  /* ── 1. dependency install ─────────────────────────────── */
  let installRecord: InjectionResult["install"];
  if (!opts.skipInstall) {
    const specs = blueprint.operations
      .filter((o): o is InstallDepOp => o.kind === "install-dep")
      .filter((o) => requiresPass(o.requires, requiresInput))
      .map((o) => o.spec);
    if (specs.length > 0) {
      const ip = await planInstall(pkgPath, specs);
      const { executed } = await executeInstall(
        opts.env.manager,
        pkgPath,
        ip,
        { dryRun, cwd: target.cwd, reporter: reporter.onInstall },
      );
      installRecord = { plan: ip, executed };
    }
  }

  /* ── 2. file scaffolding ─────────────────────────────────── */
  const scaffolds: ScaffoldResult[] = [];
  for (const op of blueprint.operations) {
    if (op.kind !== "write-file") continue;
    if (!requiresPass(op.requires, requiresInput)) continue;
    if (op.when && !op.when(ctx)) continue;
    const content = typeof op.content === "function" ? op.content(ctx) : op.content;
    const result = await scaffoldFile(
      target.cwd,
      { path: op.path, content, ...(op.managed === true ? { managed: true } : {}), ...(op.mode !== undefined ? { mode: op.mode } : {}) },
      { ...(dryRun ? { dryRun: true } : {}), ...(opts.force === true ? { force: true } : {}) },
    );
    reporter.onScaffold(result);
    scaffolds.push(result);
  }

  /* ── 3. json patches ───────────────────────────────────── */
  const jsonResults: ApplyResult[] = [];
  const pkgPatches = collectPatches(blueprint, "patch-package-json", requiresInput);
  const tscPatches = collectPatches(blueprint, "patch-tsconfig", requiresInput);
  const jsonOpts = {
    ...(dryRun ? { dryRun: true } : {}),
    ...(opts.force === true ? { force: true } : {}),
  };
  if (pkgPatches.length > 0) {
    const r = await applyJsonPatches(pkgPath, pkgPatches, jsonOpts);
    reporter.onJsonPatch(r);
    jsonResults.push(r);
  }
  if (tscPatches.length > 0) {
    const r = await applyJsonPatches(tscPath, tscPatches, jsonOpts);
    reporter.onJsonPatch(r);
    jsonResults.push(r);
  }
  // F6: turbo patches target the WORKSPACE ROOT, not the per-app cwd.
  const turboPatches = collectPatches(blueprint, "patch-turbo-json", requiresInput);
  if (turboPatches.length > 0) {
    const r = await applyJsonPatches(turboPath, turboPatches, jsonOpts);
    reporter.onJsonPatch(r);
    jsonResults.push(r);
  }

  /* ── 4. verifications ──────────────────────────────────── */
  // In dry-run mode we still run them — caller sees what the post-apply state looks like.
  const verification = await verifyBlueprint(blueprint, target.cwd);
  reporter.onVerification(verification);

  return {
    target,
    plan,
    ...(installRecord ? { install: installRecord } : {}),
    scaffolds,
    jsonPatches: jsonResults,
    verification,
    dryRun,
  };
}

/* ── plan builder ──────────────────────────────────────────────── */

/** F5 (audit-5): inputs to `requires` evaluation, shared across the injector. */
interface RequiresInput {
  readonly env: EnvironmentReport;
  readonly tsconfigExists: boolean;
  readonly createTsconfig: boolean;
}

/** Evaluate an operation's `requires` clause. Empty / undefined = pass. */
function requiresPass(
  req: import("./blueprints/types").OperationRequires | undefined,
  input: RequiresInput,
): boolean {
  if (!req) return true;
  if (req.framework && !req.framework.includes(input.env.framework)) return false;
  if (req.paradigm  && !req.paradigm.includes(input.env.paradigm))   return false;
  if (req.tsconfigExists === true && !input.tsconfigExists && !input.createTsconfig) return false;
  return true;
}

async function buildPlan(
  blueprint: Blueprint,
  ctx: RenderContext,
  paths: { readonly pkgPath: string; readonly tscPath: string; readonly requiresInput: RequiresInput },
): Promise<readonly PlannedOperation[]> {
  const out: PlannedOperation[] = [];

  // Read package.json once for dep-status checks.
  let pkg: Record<string, unknown> = {};
  try {
    pkg = JSON.parse(await fs.readFile(paths.pkgPath, "utf-8")) as Record<string, unknown>;
  } catch { /* missing — fine */ }
  const allDeps = mergeDeps(pkg);

  for (const op of blueprint.operations) {
    // F5: structured requires-filter. Surface unmet prerequisites in the
    // plan output as "filtered-out" so the dry-run report is honest.
    if (!requiresPass(op.requires, paths.requiresInput)) {
      const reason = describeRequiresMiss(op.requires, paths.requiresInput);
      const label  = op.kind === "install-dep" ? `dep ${op.spec.name}` :
                     op.kind === "write-file"  ? `file ${op.path}`     :
                     `${op.kind} ${op.path}`;
      out.push({ op, status: "filtered-out", summary: `${label} (skipped — ${reason})` });
      continue;
    }
    switch (op.kind) {
      case "install-dep": {
        const already = op.spec.name in allDeps;
        out.push({
          op,
          status: already ? "already-applied" : "would-create",
          summary: `dep ${op.spec.name}@${op.spec.version} ${already ? "(already present)" : "(install)"}`,
        });
        break;
      }
      case "write-file": {
        if (op.when && !op.when(ctx)) {
          out.push({ op, status: "filtered-out", summary: `file ${op.path} (skipped — filter)` });
          break;
        }
        const exists = await pathExists(join(ctx.cwd, op.path));
        const status: PlannedOperationStatus = !exists
          ? "would-create"
          : op.managed
            ? "would-update"
            : "user-edited";
        out.push({ op, status, summary: `file ${op.path} (${status.replace("-", " ")})` });
        break;
      }
      case "patch-package-json":
      case "patch-tsconfig":
      case "patch-turbo-json": {
        out.push({ op, status: "would-merge", summary: `${op.kind} ${op.path}` });
        break;
      }
    }
  }
  return out;
}

function describeRequiresMiss(
  req: import("./blueprints/types").OperationRequires | undefined,
  input: RequiresInput,
): string {
  if (!req) return "filter";
  if (req.tsconfigExists && !input.tsconfigExists && !input.createTsconfig) return "no tsconfig.json (pass --create-tsconfig to opt in)";
  if (req.framework && !req.framework.includes(input.env.framework))      return `framework not in [${req.framework.join(",")}] (got ${input.env.framework})`;
  if (req.paradigm  && !req.paradigm.includes(input.env.paradigm))        return `paradigm not in [${req.paradigm.join(",")}] (got ${input.env.paradigm})`;
  return "filter";
}

function collectPatches(
  blueprint: Blueprint,
  kind: "patch-package-json" | "patch-tsconfig" | "patch-turbo-json",
  requiresInput: RequiresInput,
): readonly JsonPatch[] {
  return blueprint.operations
    .filter((o): o is PatchPackageJsonOp | PatchTsconfigOp | PatchTurboJsonOp => o.kind === kind)
    .filter((o) => requiresPass(o.requires, requiresInput))
    .map((o) => ({
      path: o.path,
      value: o.value,
      ...(o.strategy !== undefined ? { strategy: o.strategy } : {}),
    }));
}

/* ── verification (kash doctor) ─────────────────────────────────── */

export interface VerificationReport {
  readonly product: string;
  readonly checks: ReadonlyArray<{
    readonly description: string;
    readonly kind: Verification["kind"];
    readonly passed: boolean;
    readonly detail?: string;
  }>;
  readonly summary: {
    readonly passed: number;
    readonly failed: number;
    readonly total: number;
  };
}

export async function verifyBlueprint(
  blueprint: Blueprint,
  cwd: string,
): Promise<VerificationReport> {
  const checks: VerificationReport["checks"][number][] = [];
  const pkgPath = join(cwd, "package.json");
  let pkg: Record<string, unknown> = {};
  try { pkg = JSON.parse(await fs.readFile(pkgPath, "utf-8")) as Record<string, unknown>; } catch { /* missing */ }
  const allDeps = mergeDeps(pkg);

  for (const v of blueprint.verifications) {
    switch (v.kind) {
      case "file-exists": {
        const passed = await pathExists(join(cwd, v.path));
        checks.push({
          description: v.description,
          kind: v.kind,
          passed,
          ...(passed ? {} : { detail: `Missing: ${v.path}` }),
        });
        break;
      }
      case "dep-present": {
        const ver = allDeps[v.name];
        const matches = ver !== undefined && (
          v.versionStartsWith === undefined || ver.startsWith(v.versionStartsWith)
        );
        checks.push({
          description: v.description,
          kind: v.kind,
          passed: matches,
          ...(matches ? {} : {
            detail: ver === undefined
              ? `Dependency ${v.name} is not in package.json`
              : `Dependency ${v.name}@${ver} does not start with ${v.versionStartsWith ?? "*"}`,
          }),
        });
        break;
      }
      case "package-json-field": {
        const value = getJsonPath(pkg, v.path);
        const passed = value !== undefined;
        checks.push({
          description: v.description,
          kind: v.kind,
          passed,
          ...(passed ? {} : { detail: `package.json.${v.path} is missing` }),
        });
        break;
      }
    }
  }
  const passed = checks.filter((c) => c.passed).length;
  return {
    product: blueprint.id,
    checks,
    summary: { passed, failed: checks.length - passed, total: checks.length },
  };
}

/* ── helpers ────────────────────────────────────────────────────── */

async function pathExists(p: string): Promise<boolean> {
  try { await fs.access(p); return true; } catch { return false; }
}

function mergeDeps(pkg: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const k of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"] as const) {
    const block = pkg[k];
    if (block && typeof block === "object" && !Array.isArray(block)) {
      for (const [n, v] of Object.entries(block)) {
        if (typeof v === "string") out[n] = v;
      }
    }
  }
  return out;
}

function getJsonPath(obj: Record<string, unknown>, path: string): unknown {
  const parts = path.split(".").filter((s) => s.length > 0);
  let cur: unknown = obj;
  for (const p of parts) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

