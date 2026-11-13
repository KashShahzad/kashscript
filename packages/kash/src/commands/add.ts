/**
 * `kash add <product>` — injector orchestration.
 *
 *   1. Scan environment.
 *   2. Look up the product's Blueprint.
 *   3. Run the injector (dry-run unless `--apply`).
 *   4. Print a summary + verification status.
 *   5. Optionally verify the host project's build (F4) and offer rollback.
 *
 * **There is no licence gate.** The SDKs are libre — `bun add
 *   @kashscript/identity-sdk` works with or without this command — and `kash`
 *   no longer holds a login, a session or a registry client (KS-R2, d59: it is
 *   the station kit). The old opt-in `--require-license` check went with them.
 */

import { KashCliError } from "../errors";
import { isProductId, BLUEPRINTS, PRODUCT_IDS, RETIRED_PRODUCTS, type ProductId } from "../inject/blueprints";
import { inject } from "../inject";
import { c, banner, fail, info, step, success, warn } from "../utils/output";
import { scanEnvironment } from "../utils/env";

export interface AddCommandOptions {
  readonly apply?: boolean;
  readonly force?: boolean;
  readonly target?: string;
  readonly skipInstall?: boolean;
  readonly createTsconfig?: boolean;
  /** F4: run the project's own typecheck/build after apply; suggest rollback on failure. */
  readonly verifyBuild?: boolean;
  /**
   * Override the detected package manager. The CLI normally sniffs the
   * project's lockfile (bun.lock / pnpm-lock.yaml / yarn.lock /
   * package-lock.json) and uses the matching manager — set this to force
   * a different one. Useful when running via `npx` from a Bun-installed
   * shell against a pnpm project, for instance.
   */
  readonly manager?: "bun" | "pnpm" | "yarn" | "npm";
}

export async function runAdd(productArg: string, opts: AddCommandOptions = {}): Promise<void> {
  if (!isProductId(productArg)) {
    const retired = Object.prototype.hasOwnProperty.call(RETIRED_PRODUCTS, productArg) ? ` ${RETIRED_PRODUCTS[productArg]}` : "";
    throw new KashCliError(
      `Unknown product "${productArg}".${retired} Choose one of: ${PRODUCT_IDS.join(", ")}.`,
      "INVALID_INPUT",
    );
  }
  const product: ProductId = productArg;
  const runStartedAt = new Date().toISOString();

  banner(`kash · add ${product}`);

  /* ── 1. env scan ────────────────────────────────────────── */
  const rawEnv = await scanEnvironment();
  // Honour --manager override so a user invoking `npx kash add identity` from
  // a Bun shell against a pnpm project can still force `pnpm add`.
  const env = opts.manager !== undefined
    ? { ...rawEnv, manager: opts.manager, signals: [...rawEnv.signals, `manager-override=${opts.manager}`] }
    : rawEnv;
  const mgrSignal = pickManagerSignal(env.signals, env.manager);
  step(`Detected ${c.bold(env.paradigm)} · ${c.bold(env.manager)} · ${c.bold(env.framework)} at ${env.root}`);
  info(`  package manager → ${c.cyan(env.manager)} ${c.gray(`(from ${mgrSignal})`)}`);

  /* ── 2. blueprint + inject ──────────────────────────────── */
  const blueprint = BLUEPRINTS[product];
  step(`Blueprint: ${c.bold(blueprint.title)} v${blueprint.blueprintVersion}`);

  const result = await inject(blueprint, {
    env,
    apply: opts.apply === true,
    ...(opts.force === true ? { force: true } : {}),
    ...(opts.createTsconfig === true ? { createTsconfig: true } : {}),
    ...(opts.target !== undefined ? { target: opts.target } : {}),
    ...(opts.skipInstall === true ? { skipInstall: true } : {}),
    reporter: {
      onPlan: (plan) => {
        process.stdout.write("\nPlan:\n");
        for (const item of plan) {
          const tag = renderStatusTag(item.status);
          process.stdout.write(`  ${tag} ${item.summary}\n`);
        }
        process.stdout.write("\n");
      },
      onInstall:  (line) => step(line),
      onScaffold: (s) => {
        const tag = ({
          "created":             c.green("created"),
          "updated":             c.yellow("updated"),
          "skipped":             c.gray("identical"),
          "skipped-user-edited": c.gray("user-edited"),
        } as const)[s.action];
        step(`${tag} ${s.path}${s.backupPath ? c.gray(`  ← backup ${s.backupPath}`) : ""}`);
      },
      onJsonPatch: (r) => {
        const file = r.file.split(/[\\/]/).pop();
        for (const a of r.applied) {
          if (a.action === "conflict") {
            warn(
              `${c.red("conflict")} ${file} ${c.gray(`(${a.path})`)} ` +
              `— blocked at ${c.bold(`.${a.conflictAt}`)} which holds a ${a.conflictType}. ` +
              `Patch left unapplied; resolve manually or override with strategy: "replace" on the parent.`,
            );
            continue;
          }
          const tag = ({
            "added":    c.green("added"),
            "merged":   c.yellow("merged"),
            "replaced": c.yellow("replaced"),
            "skipped":  c.gray("kept"),
          } as const)[a.action];
          step(`${tag} ${file} ${c.gray(`(${a.path})`)}`);
        }
      },
      onVerification: () => { /* rendered below */ },
    },
  });

  /* ── 3. summary ─────────────────────────────────────────── */
  const conflictCount = result.jsonPatches.reduce(
    (n, r) => n + r.applied.filter((a) => a.action === "conflict").length,
    0,
  );

  process.stdout.write("\n");
  if (result.dryRun) {
    warn(`Dry run — re-run with ${c.cyan("--apply")} to perform the integration.`);
  } else if (conflictCount > 0) {
    warn(
      `${c.bold(blueprint.title)} ${c.red("NOT integrated")}: ${c.red(`${conflictCount} JSON patch conflict(s)`)} ` +
      `aborted the write to protect existing config. Resolve manually (see above) and re-run, ` +
      `or re-run with ${c.cyan("--force")} to clobber the conflicting intermediates.`,
    );
    process.exitCode = 1;
  } else {
    success(`${c.bold(blueprint.title)} integrated into ${c.bold(result.target.workspace ?? result.target.cwd)}.`);
  }

  /* ── 4. verification ────────────────────────────────────── */
  const v = result.verification;
  if (v.summary.failed > 0) {
    warn(`${v.summary.failed} verification check(s) failed. Run \`kash doctor ${product}\` for details.`);
  } else {
    info(`All ${v.summary.passed} verification checks passed.`);
  }

  /* ── 5. F4: post-apply project build check ─────────────── */
  if (opts.verifyBuild === true && opts.apply === true && conflictCount === 0) {
    process.stdout.write("\n");
    step(`Verifying project build at ${c.gray(result.target.cwd)} (--verify)…`);
    const verify = await runPostApplyVerify(result.target.cwd);
    if (verify.ok) {
      success(`Post-apply ${c.bold(verify.via)} passed.`);
    } else {
      fail(`Post-apply ${verify.via} FAILED (exit ${verify.exitCode}).`);
      info(`  ${c.gray("To roll back the files this run touched, run:")}`);
      info(`    ${c.cyan(`kash rollback --all-since "${runStartedAt}" --yes`)}`);
      process.exitCode = 1;
    }
  }
}

/* ── F4 helpers ─────────────────────────────────────────────────── */

interface VerifyOutcome {
  readonly ok: boolean;
  readonly via: string;
  readonly exitCode: number | null;
}

/** Pick the signal that explains why we chose this manager. The env scanner
 *  emits one signal per check (e.g., `pnpm-lock.yaml`, `bun.lock`, or
 *  `no-lockfile`); the user wants to see the lockfile name when one fired. */
function pickManagerSignal(signals: readonly string[], manager: string): string {
  const explicit = signals.find((s) => s.startsWith("manager-override="));
  if (explicit) return explicit;
  const lockfile = signals.find((s) =>
    s === "bun.lock" || s === "bun.lockb" ||
    s === "pnpm-lock.yaml" || s === "yarn.lock" || s === "package-lock.json",
  );
  if (lockfile) return lockfile;
  if (signals.includes("no-lockfile")) return `no-lockfile → defaulted to ${manager}`;
  return `manager=${manager}`;
}

async function runPostApplyVerify(cwd: string): Promise<VerifyOutcome> {
  // Prefer the project's declared scripts in this order:
  //   1. `typecheck` / `tsc` / `tsc --noEmit`
  //   2. `build`
  // Falls back to `bunx tsc --noEmit` when none exists AND tsconfig is present.
  const { promises: fs } = await import("node:fs");
  const { join } = await import("node:path");
  let pkg: { scripts?: Record<string, string> } = {};
  try { pkg = JSON.parse(await fs.readFile(join(cwd, "package.json"), "utf-8")) as typeof pkg; }
  catch { /* missing */ }
  const scripts = pkg.scripts ?? {};
  const npxLike = (scripts.typecheck && "typecheck")
                ?? (scripts.tsc       && "tsc")
                ?? (scripts.build     && "build")
                ?? null;
  const { spawnManager } = await import("../utils/spawn");
  const run = (cmd: string, args: readonly string[]): Promise<VerifyOutcome> =>
    new Promise((resolve) => {
      const child = spawnManager(cmd, args, { cwd, stdio: "inherit" });
      child.on("exit", (code) => resolve({ ok: code === 0, via: `${cmd} ${args.join(" ")}`, exitCode: code }));
      child.on("error", () => resolve({ ok: false, via: `${cmd} ${args.join(" ")}`, exitCode: null }));
    });
  if (npxLike) return run("npm", ["run", "--silent", npxLike]);
  try {
    await fs.access(join(cwd, "tsconfig.json"));
    return run("bunx", ["--bun", "tsc", "--noEmit"]);
  } catch {
    return { ok: true, via: "no-op (no typecheck/build script + no tsconfig.json)", exitCode: 0 };
  }
}

function renderStatusTag(status: string): string {
  switch (status) {
    case "would-create":    return c.green("+");
    case "would-update":    return c.yellow("~");
    case "would-merge":     return c.cyan("≈");
    case "already-applied": return c.gray("·");
    case "user-edited":     return c.gray("!");
    case "filtered-out":    return c.gray("/");
    default:                return c.gray("?");
  }
}
