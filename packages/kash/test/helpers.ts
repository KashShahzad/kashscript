/**
 * Shared test plumbing: run the real CLI two ways, and make a station zero.
 *
 * - "bun-src": `bun run src/bin/kash.ts` — the workspace checkout.
 * - "node-dist": `node dist/bin/kash.js` — the bundled single file that `npx` would run,
 *   under the offline guard (every way a Node process reaches the network throws).
 *   NODE_OPTIONS carries the guard into the child `attest` process `kash verify` spawns.
 *
 * Everything here is a simulation (d11): no real learner, station or teacher.
 */

import { setDefaultTimeout } from "bun:test";
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Most tests here start `node` or `bun` a few times. On a machine busy with another build, one start can take
// seconds; 5s (Bun's default) would then report a slow machine as a failing test.
setDefaultTimeout(30_000);

export const PKG = join(import.meta.dir, "..");
export const ATTEST = join(PKG, "..", "attest");
const WIN = process.platform === "win32";

export interface Run {
  readonly status: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

export type Runner = (args: readonly string[], env?: Record<string, string>) => Run;

let guardCopy: string | null = null;

/** The offline guard, copied to a path with no spaces so NODE_OPTIONS can name it plainly. */
export function offlineGuardPath(): string {
  if (guardCopy === null) {
    const dir = mkdtempSync(join(tmpdir(), "kash-guard-"));
    guardCopy = join(dir, "offline-guard.cjs");
    copyFileSync(join(ATTEST, "test", "offline-guard.cjs"), guardCopy);
  }
  return guardCopy.replace(/\\/g, "/");
}

/** Build the two bundles the node-dist runner needs. Throws with the build's own output on failure. */
export function buildBundles(): void {
  for (const cwd of [ATTEST, PKG]) {
    const r = spawnSync("bun", ["run", "build:bin"], { cwd, encoding: "utf8", shell: WIN });
    if (r.status !== 0) throw new Error(`build:bin failed in ${cwd} (${r.status}):\n${r.stderr || r.stdout}`);
  }
}

export const bunSrc: Runner = (args, env) => {
  const r = spawnSync(process.execPath, ["run", "src/bin/kash.ts", ...args], {
    cwd: PKG,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
};

export const nodeDist: Runner = (args, env) => {
  const r = spawnSync("node", ["dist/bin/kash.js", ...args], {
    cwd: PKG,
    encoding: "utf8",
    env: { ...process.env, NODE_OPTIONS: `--require ${offlineGuardPath()}`, ...env },
  });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
};

export function tempDir(label: string): string {
  return mkdtempSync(join(tmpdir(), `kash-${label}-`));
}

export function removeDir(dir: string): void {
  rmSync(dir, { recursive: true, force: true });
}

/** The `did : ...` line `station init` prints. */
export function didFrom(stdout: string): string {
  const m = /did\s+:\s+(did:kash:\S+)/.exec(stdout);
  if (m === null) throw new Error(`no DID in output:\n${stdout}`);
  return m[1] as string;
}

/** The carried link: the line after the "Carried link" heading in `issue cohort`'s output. */
export function linkFrom(stdout: string): string {
  const lines = stdout.split(/\r?\n/);
  const at = lines.findIndex((l) => l.includes("Carried link"));
  const link = at === -1 ? undefined : lines[at + 1];
  if (link === undefined || link.trim() === "") throw new Error(`no carried link in output:\n${stdout}`);
  return link.trim();
}

export interface StationZero {
  readonly keystore: string;
  readonly work: string;
  readonly teacher: string;
  readonly station: string;
  readonly holder: string;
  readonly syllabusFile: string;
}

/** Three keys in a fresh keystore (teacher's organisation, station, and a stand-in for the learner's relationship key) and a syllabus file. */
export function makeStationZero(run: Runner): StationZero {
  const keystore = join(tempDir("keys"), "keystore");
  const work = tempDir("work");
  const did = (name: string): string => {
    const r = run(["station", "init", "--name", name, "--keystore", keystore]);
    if (r.status !== 0) throw new Error(`station init ${name} failed:\n${r.stdout}\n${r.stderr}`);
    return didFrom(r.stdout);
  };
  const syllabusFile = join(work, "syllabus.txt");
  writeFileSync(syllabusFile, "Web foundations — syllabus, version 1.0 (simulation)\n");
  return { keystore, work, teacher: did("teacher"), station: did("station"), holder: did("learner"), syllabusFile };
}

export function issueArgs(z: StationZero, out: string, extra: readonly string[] = []): string[] {
  return [
    "issue", "cohort",
    "--keystore", z.keystore,
    "--holder", z.holder,
    "--station", z.station,
    "--syllabus-id", `${z.teacher}/syllabus/web-foundations`,
    "--syllabus-version", "1.0",
    "--syllabus-file", z.syllabusFile,
    "--finished", "2026-09-25T12:00:00.000Z",
    "--expires", "2029-09-25T12:00:00.000Z",
    "--out", out,
    ...extra,
  ];
}
