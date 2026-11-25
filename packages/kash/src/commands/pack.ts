/**
 * `kash pack build | list | install` — set-up packs (PY-8; ECOSYSTEM d94(b), d86, d96).
 *
 *   kash pack build <dir> [--out <file>]            OFFLINE — checks a pack folder against the floor
 *   kash pack list <dir>                            OFFLINE — lists checked packs in a folder
 *   kash pack install <dir> --host <url> [...]      ONLINE  — installs on a clean practice organisation
 *                                                             and completes its first approval
 */

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";

import { buildPack, installPackOnPractice, listValidPacks } from "../pack";
import { banner, info, step, success } from "../utils/output";

export interface PackBuildCommandOptions {
  readonly dir: string;
  readonly out?: string;
  readonly json?: boolean;
}

export async function runPackBuild(opts: PackBuildCommandOptions): Promise<void> {
  const built = await buildPack(opts.dir);
  const text = `${JSON.stringify(built, null, 2)}\n`;
  if (opts.out !== undefined) {
    writeFileSync(resolve(opts.out), text, "utf8");
  }
  if (opts.json === true) {
    process.stdout.write(text);
    return;
  }
  banner(`kash · pack build · ${built.title}`);
  step(`pack        : ${built.slug} (${built.format})`);
  step(`for         : ${built.forWhom}`);
  step(`cycle       : ${built.cycle}`);
  step(`engine      : ${built.engine} · flow ${built.flow}`);
  step(`open rule   : ${built.rule.id} v${built.rule.version} (${built.rule.criteriaCount} criteria)`);
  step(`rule sha256 : ${built.rule.sha256}`);
  step(`descriptor  : empty — ${built.descriptor.label}`);
  step(`floor       : PASS (${built.floor.routesChecked} routes declared, 0 findings, 0 waivers, no price)`);
  if (opts.out !== undefined) {
    info(`  wrote build manifest → ${resolve(opts.out)}`);
  }
  success("Pack passed open-rule, customer-copy, zero-price and floor checks.");
}

export interface PackListCommandOptions {
  readonly dir: string;
  readonly json?: boolean;
}

export async function runPackList(opts: PackListCommandOptions): Promise<void> {
  const packs = await listValidPacks(opts.dir);
  if (opts.json === true) {
    process.stdout.write(`${JSON.stringify(packs, null, 2)}\n`);
    return;
  }
  banner("kash · pack list");
  if (packs.length === 0) {
    info("  No checked packs found.");
    return;
  }
  for (const p of packs) {
    step(`${p.title} (${p.slug}) — ${p.summary}`);
    info(`    cycle: ${p.cycle}`);
  }
}

export interface PackInstallCommandOptions {
  readonly dir: string;
  readonly host: string;
  readonly orgName?: string;
  readonly orgSlug?: string;
  readonly email?: string;
  readonly out?: string;
  readonly json?: boolean;
}

export async function runPackInstall(opts: PackInstallCommandOptions): Promise<void> {
  process.stderr.write(`ONLINE: connecting to practice host ${opts.host} (practice only; never production).\n`);
  const res = await installPackOnPractice(opts.dir, {
    host: opts.host,
    ...(opts.orgName !== undefined ? { orgName: opts.orgName } : {}),
    ...(opts.orgSlug !== undefined ? { orgSlug: opts.orgSlug } : {}),
    ...(opts.email !== undefined ? { email: opts.email } : {}),
    ...(opts.out !== undefined ? { out: opts.out } : {}),
  });
  if (opts.json === true) {
    // The report only; the record itself is the --out file, which `kash verify` checks offline.
    const { artifactJson: _record, ...report } = res;
    process.stdout.write(`${JSON.stringify({ ...report, ...(opts.out !== undefined ? { out: resolve(opts.out) } : {}) }, null, 2)}\n`);
    return;
  }
  banner(`kash · pack install · ${res.title}`);
  step(`pack               : ${res.packSlug} (${res.flow})`);
  step(`practice host      : ${res.host}`);
  step(`practice org       : ${res.org.name} (${res.org.slug})`);
  step(`organisation key   : ${res.org.did}`);
  step(`first approval ref : ${res.approval.receiptRef}`);
  step(`approver key       : ${res.approval.countersignerDid}`);
  step(`offline check      : PASS (two independent signatures verified)`);
  if (opts.out !== undefined) {
    info(`  saved verified record → ${resolve(opts.out)} (run \`kash verify ${opts.out}\` offline)`);
  }
  success(`${res.title} installed on a clean practice organisation and completed its first approval.`);
}
