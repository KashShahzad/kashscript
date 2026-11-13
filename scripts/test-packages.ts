#!/usr/bin/env bun
/**
 * scripts/test-packages.ts — every open package's own `test` script, one after another.
 *
 * A10-03 (AUDIT-2026-11-11): the kernel every engine pins — attest, identity-core,
 * predicate, wallet and the rest — had suites that gated nothing: not CI, not a
 * publish. This runs each package's `test` exactly as the package defines it
 * (`bun run typecheck:test && bun test …`), in the publish order of
 * scripts/trusted-publishing.json, and fails when any suite fails. ci.yml runs it
 * on every push, publish.yml's gates run it before a publish, and
 * publish-to-npmjs.ts runs each package's `test` again before it builds.
 *
 * Sequential on purpose: attest, kash and identity-server all rebuild
 * packages/attest/dist/bin/attest.js and spawn node and a browser; run in
 * parallel (as `bun run --filter` does) they time each other out.
 *
 *   bun scripts/test-packages.ts                 # the twelve open packages
 *   bun scripts/test-packages.ts --only attest predicate
 *   bun scripts/test-packages.ts --list
 *
 * Exit: 0 when every suite passed — a package whose `test` finds no test files is
 * named as such and does not fail the run; 1 when any suite failed, or a
 * requested slug has no `test` script; 2 on usage.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "..");

type Verdict = "passed" | "failed" | "no-tests" | "no-script";

interface Result {
  readonly slug: string;
  readonly verdict: Verdict;
  readonly seconds: number;
  readonly code: number | null;
}

function openPackages(): string[] {
  const j = JSON.parse(readFileSync(join(ROOT, "scripts", "trusted-publishing.json"), "utf8")) as { moved?: unknown };
  if (!Array.isArray(j.moved) || !j.moved.every((s): s is string => typeof s === "string")) {
    throw new Error("scripts/trusted-publishing.json: `moved` is not a list of slugs");
  }
  return [...j.moved];
}

/** Stream a child's output through to ours while keeping a copy to read. */
async function tee(stream: ReadableStream<Uint8Array>, sink: NodeJS.WriteStream): Promise<string> {
  const dec = new TextDecoder();
  let text = "";
  for await (const chunk of stream) {
    sink.write(chunk);
    text += dec.decode(chunk, { stream: true });
  }
  return text + dec.decode();
}

/** Bun says so in words when a `bun test` path matched no test file, and counts nothing. */
function foundNoTests(output: string): boolean {
  if (/no tests found/i.test(output)) return true;
  return /\b0 pass\b/.test(output) && /\b0 fail\b/.test(output) && !/\(fail\)/.test(output) && !/\b[1-9]\d* pass\b/.test(output);
}

async function runOne(slug: string): Promise<Result> {
  const dir = join(ROOT, "packages", slug);
  const pkgPath = join(dir, "package.json");
  if (!existsSync(pkgPath)) return { slug, verdict: "no-script", seconds: 0, code: null };
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { name?: string; scripts?: Record<string, string> };
  const script = pkg.scripts?.test;
  console.log(`\n===== ${pkg.name ?? slug} — ${script === undefined ? "no test script" : script} =====`);
  if (script === undefined) return { slug, verdict: "no-script", seconds: 0, code: null };

  const started = Date.now();
  // `bun` by name, no shell: the same way publish-to-npmjs.ts starts it.
  const proc = Bun.spawn(["bun", "run", "test"], {
    cwd: dir,
    stdout: "pipe",
    stderr: "pipe",
    env: { ...process.env, FORCE_COLOR: "0", NO_COLOR: "1" },
  });
  const [out, err] = await Promise.all([tee(proc.stdout, process.stdout), tee(proc.stderr, process.stderr)]);
  const code = await proc.exited;
  const seconds = Math.round((Date.now() - started) / 100) / 10;
  const output = `${out}\n${err}`;
  let verdict: Verdict;
  if (foundNoTests(output)) verdict = "no-tests";
  else verdict = code === 0 ? "passed" : "failed";
  console.log(`----- ${pkg.name ?? slug}: ${verdict} (exit ${code}, ${seconds}s) -----`);
  return { slug, verdict, seconds, code };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const all = openPackages();
  if (args.includes("--list")) {
    for (const s of all) console.log(s);
    return;
  }
  const flags = args.filter((a) => a.startsWith("--"));
  const unknownFlag = flags.find((f) => f !== "--only");
  if (unknownFlag !== undefined) {
    console.error(`unknown flag ${unknownFlag}\nusage: bun scripts/test-packages.ts [--list] [--only <slug> [slug ...]]`);
    process.exit(2);
  }
  const named = args.filter((a) => !a.startsWith("--"));
  if (named.length > 0 && !flags.includes("--only")) {
    console.error("name packages after --only\nusage: bun scripts/test-packages.ts [--list] [--only <slug> [slug ...]]");
    process.exit(2);
  }
  const unknown = named.filter((s) => !all.includes(s));
  if (unknown.length > 0) {
    console.error(`not an open package in scripts/trusted-publishing.json: ${unknown.join(", ")}`);
    process.exit(2);
  }
  const slugs = named.length > 0 ? named : all;

  console.log(`packages:  ${slugs.join(" → ")}`);
  console.log(`bun:       ${Bun.version}`);
  const results: Result[] = [];
  for (const slug of slugs) results.push(await runOne(slug));

  const width = Math.max(...results.map((r) => r.slug.length));
  console.log("\n===== summary =====");
  for (const r of results) {
    console.log(`  ${r.slug.padEnd(width)}  ${r.verdict.padEnd(9)}  ${r.verdict === "no-script" ? "" : `${r.seconds}s`}`);
  }
  const failed = results.filter((r) => r.verdict === "failed" || r.verdict === "no-script");
  const noTests = results.filter((r) => r.verdict === "no-tests");
  if (noTests.length > 0) console.log(`  (no test files: ${noTests.map((r) => r.slug).join(", ")} — reported, not failed)`);
  if (failed.length > 0) {
    console.error(`\n✗ ${failed.length} of ${results.length} did not pass: ${failed.map((r) => `${r.slug} (${r.verdict})`).join(", ")}`);
    process.exit(1);
  }
  console.log(`\n✓ ${results.length - noTests.length} suite(s) passed`);
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : String(e));
  process.exit(1);
});
