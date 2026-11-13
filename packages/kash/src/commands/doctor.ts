/**
 * `kash doctor` — verifies that every (selected) blueprint is correctly
 * integrated into the user's project.
 *
 * Renders a per-product table of checks. Exits 1 if any check failed.
 */

import { KashCliError } from "../errors";
import {
  BLUEPRINTS,
  isProductId,
  RETIRED_PRODUCTS,
  type ProductId,
} from "../inject/blueprints";
import { verifyBlueprint, type VerificationReport } from "../inject";
import { resolveTarget } from "../inject/targeting";
import { banner, c, fail, info, success, warn } from "../utils/output";
import { scanEnvironment } from "../utils/env";

export interface DoctorOptions {
  /** Filter to a single product. Default: check every registered blueprint. */
  readonly product?: string;
  /** Target a specific monorepo workspace. */
  readonly target?: string;
}

export async function runDoctor(opts: DoctorOptions = {}): Promise<void> {
  banner("kash · doctor");

  if (opts.product !== undefined && !isProductId(opts.product)) {
    const retired = Object.prototype.hasOwnProperty.call(RETIRED_PRODUCTS, opts.product) ? ` ${RETIRED_PRODUCTS[opts.product]}` : "";
    throw new KashCliError(
      `Unknown product "${opts.product}".${retired} Choose one of: ${Object.keys(BLUEPRINTS).join(", ")}.`,
      "INVALID_INPUT",
    );
  }

  const env    = await scanEnvironment();
  const target = await resolveTarget(env, {
    ...(opts.target !== undefined ? { target: opts.target } : {}),
    nonInteractive: true,
  });

  info(`Checking ${c.bold(target.workspace ?? target.cwd)}.\n`);

  const products: readonly ProductId[] = opts.product
    ? [opts.product as ProductId]
    : (Object.keys(BLUEPRINTS) as readonly ProductId[]);

  const reports: VerificationReport[] = [];
  for (const product of products) {
    const bp = BLUEPRINTS[product];
    const report = await verifyBlueprint(bp, target.cwd);
    reports.push(report);
    renderReport(bp.title, report);
  }

  const totalPassed = reports.reduce((n, r) => n + r.summary.passed, 0);
  const totalFailed = reports.reduce((n, r) => n + r.summary.failed, 0);
  const totalChecks = reports.reduce((n, r) => n + r.summary.total,  0);

  process.stdout.write("\n");
  if (totalFailed === 0) {
    success(`${totalPassed}/${totalChecks} checks passed.`);
  } else {
    warn(`${totalPassed}/${totalChecks} checks passed — ${c.red(`${totalFailed} failed`)}.`);
    info(`Run \`kash add <product>\` to repair missing integrations.`);
    process.exitCode = 1;
  }
}

/* ── presentation ───────────────────────────────────────────────── */

function renderReport(title: string, report: VerificationReport): void {
  process.stdout.write(`${c.bold(title)}\n`);
  for (const check of report.checks) {
    const mark   = check.passed ? c.green("✓") : c.red("✗");
    const status = check.passed ? "" : c.gray(` · ${check.detail ?? "failed"}`);
    process.stdout.write(`  ${mark} ${check.description}${status}\n`);
  }
  const tag = report.summary.failed === 0 ? c.green("ok") : c.red(`${report.summary.failed} failing`);
  process.stdout.write(`  ${c.gray(`${report.summary.passed}/${report.summary.total} · ${tag}`)}\n\n`);
}

void (fail); // referenced indirectly through the catch-all in bin/kash.ts
