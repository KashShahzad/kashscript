/**
 * `kash verify <file>` — attest's own verifier, run as attest's own binary.
 *
 * Not a re-implementation and not a re-print: the verdict, the plain layer and
 * the exit code are attest's, unchanged — 0 PASS · 1 verification FAILED · 2
 * usage or IO error (also what this returns when the verifier cannot be found
 * or started) · 3 INTEGRITY ONLY (an audit bundle or report checked with no key;
 * AU-3, A7-06 — never a cohort record, whose keys are self-certifying). Anyone
 * can run `attest verify <file>` and get the same.
 *
 * It never touches the network (d28). `--check-status`, attest's one networked
 * flag, is not passed on and cannot be asked for here; `--offline` is always set.
 * Every key comes out of the file's own did:kash identifiers.
 */

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import { KashCliError } from "../errors";

export interface VerifyOptions {
  readonly file: string;
  /** Publisher DIDs to pin when the file is a trust list. */
  readonly trustPublishers?: readonly string[];
  /** Status lists to hand in, offline. */
  readonly statusLists?: readonly string[];
}

const NAME = "@kashscript/attest";

/** The directory of the installed `@kashscript/attest` package, found from where it resolves. */
function attestPackageDir(): string {
  const require = createRequire(import.meta.url);
  let dir: string;
  try {
    dir = dirname(require.resolve(NAME));
  } catch (err) {
    throw new KashCliError(`${NAME} is not installed next to kash, so there is no verifier to run.`, "VERIFIER_NOT_FOUND", err);
  }
  for (let i = 0; i < 6; i++) {
    const pj = join(dir, "package.json");
    if (existsSync(pj)) {
      try {
        if ((JSON.parse(readFileSync(pj, "utf8")) as { name?: string }).name === NAME) return dir;
      } catch {
        /* keep walking */
      }
    }
    const up = dirname(dir);
    if (up === dir) break;
    dir = up;
  }
  throw new KashCliError(`Found ${NAME} but not its package folder.`, "VERIFIER_NOT_FOUND");
}

/** attest's bin: the built, self-contained one if it is there; its source only under Bun (a workspace checkout). */
export function findAttestBin(): string {
  const dir = attestPackageDir();
  const built = join(dir, "dist", "bin", "attest.js");
  if (existsSync(built)) return built;
  const source = join(dir, "src", "bin", "attest.ts");
  if (existsSync(source) && typeof (globalThis as { Bun?: unknown }).Bun !== "undefined") return source;
  throw new KashCliError(
    `${NAME} has no built verifier at ${built}. Run its build (\`bun run build:bin\` in packages/attest), or install the published package.`,
    "VERIFIER_NOT_FOUND",
  );
}

/** Run attest's verifier; sets the process exit code to attest's. */
export function runVerify(opts: VerifyOptions): void {
  let bin: string;
  try {
    bin = findAttestBin();
  } catch (err) {
    if (err instanceof KashCliError) {
      process.stderr.write(`${err.message}\n`);
      process.exitCode = 2;
      return;
    }
    throw err;
  }

  const args = [bin, "verify", opts.file, "--offline"];
  for (const did of opts.trustPublishers ?? []) args.push("--trust-publisher", did);
  for (const file of opts.statusLists ?? []) args.push("--status-list", file);

  // No shell: a path with a space (this repository's has one) reaches attest intact.
  const r = spawnSync(process.execPath, args, { stdio: "inherit", windowsHide: true });
  // A child that ran and exited has a status, and the status is the verdict. Bun (1.2) also
  // attaches a bogus `error` to a child that exited non-zero, so `error` counts only
  // when there is no status — the verifier never started, or was killed.
  if (r.status === null) {
    const why = r.error instanceof Error && r.error.message ? r.error.message : r.signal ? `killed by ${r.signal}` : "no exit status";
    process.stderr.write(`could not run attest's verifier: ${why}\n`);
    process.exitCode = 2;
    return;
  }
  process.exitCode = r.status;
}
