#!/usr/bin/env bun
/**
 * scripts/publish-to-npmjs.ts
 *
 * First-time public publish to registry.npmjs.org. Sibling of
 * `republish-with-dist.ts`, which targets the Verdaccio mirror.
 *
 * Key differences from republish-with-dist.ts:
 *   - Targets registry.npmjs.org explicitly.
 *   - Does NOT bump version. The current package.json version is what gets
 *     published. Bump manually before invoking if a new version is wanted.
 *   - Refuses to run if `npm whoami` against npmjs is not authenticated.
 *   - Refuses to overwrite an already-published version (the registry would
 *     reject this anyway, but we fail fast with a clearer message).
 *   - Same mutate-pack-restore dance so the published shape uses dist/.
 *
 * Safety guards (see ADR-0014):
 *   - Refuses any package that is `private: true` or whose
 *     `publishConfig.registry` is not registry.npmjs.org (e.g. `studio`,
 *     which targets the local Verdaccio and must NEVER reach public npm).
 *   - If the package defines an `artifacts:build` script (trade-sdk's
 *     Foundry contract artifacts), it is run before the build — this
 *     restores the `prepublishOnly` step that publishing from a tarball
 *     bypasses, so stale contract artifacts can't ship silently.
 *     Pass --skip-artifacts to opt out (e.g. forge unavailable AND you
 *     have just built artifacts yourself).
 *
 * Trusted publishing (P6, ECOSYSTEM d84(f); ADR-0014 addendum 2026-10-28):
 *   - scripts/trusted-publishing.json lists the slugs whose trusted publisher is
 *     configured on npmjs.com. Those publish ONLY from .github/workflows/publish.yml
 *     with --trusted (OIDC; no long-lived token). Without --trusted the script
 *     refuses them. With --trusted it refuses any slug not listed, refuses to run
 *     outside GitHub Actions with an OIDC token, and refuses if a token is in the
 *     environment. Dry runs are allowed either way.
 *
 * Provenance, SBOM and the release (RW-2, 2026-11-09; docs/publishing.md):
 *   - --trusted, dry run or not: refuses any npm credential in the environment or an .npmrc
 *     (scripts/publish-checks.ts) before anything else.
 *   - --trusted, real: only from refs/heads/master, and only when the job's OIDC token says the
 *     repository is public — npm generates provenance only from a public repository, and nothing
 *     publishes without it (fail closed, the founder's choice). `--provenance` is passed explicitly,
 *     and after landing each version must show a provenance attestation on the registry.
 *   - --trusted, dry run: after the pack, makes npm's own OIDC token exchange for the package (the
 *     short-lived token is discarded unread) and fails with the stated reason when npmjs.com has no
 *     trusted publisher for it, or when the repository is private.
 *   - Every run writes release/<tarball>.tgz, release/<tarball>.cdx.json (CycloneDX 1.6, scripts/sbom.ts)
 *     and release/published.json; publish.yml uploads them and, after a real publish, signs them
 *     with Sigstore and attaches them to a GitHub release.
 *
 * Tests before anything is built (AU-3, A10-03, AUDIT-2026-11-11):
 *   - Each package's own `test` script (its tests' typecheck, then every test) runs
 *     before its cold rebuild, and a failure halts the run. No flag skips it, and a
 *     package with no `test` script does not publish. publish.yml's gates and ci.yml
 *     run every open package's suite as well (scripts/test-packages.ts).
 *
 * Private packages (ECOSYSTEM d87):
 *   - A package whose publishConfig.access is "restricted" is published as an npm
 *     private package, with `--access restricted`. It publishes only when you pass
 *     --restricted, and never with --trusted: the public publish workflow
 *     (.github/workflows/publish.yml) cannot publish it. Dry runs need the flag too.
 *   - 2026-11-02 (KS-P1, ADR-0024): hudhud and neuron, the two packages this path was
 *     written for, left this repository for Oreoasis's workspace and are published
 *     nowhere. The path stays for a future closed package; no package uses it today.
 *
 * Usage:
 *   bun scripts/publish-to-npmjs.ts [--dry-run] [--stage] [--trusted] [--restricted] [--skip-artifacts] identity-core lexicons identity-sdk identity-zkp whiffin
 */

import { readFileSync, writeFileSync, existsSync, copyFileSync, renameSync, readdirSync, rmSync, mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { resolve, join } from "node:path";
import { confirmLanding, type LandingTarget } from "./confirm-landing";
import {
  escapedName,
  exchangeOutcome,
  npmAuthInEnv,
  npmrcHasAuth,
  oidcClaims,
  provenanceVerdict,
  repositoryVerdict,
  type RepositoryField,
} from "./publish-checks";
import { buildSbom, type PackedManifest } from "./sbom";

const REGISTRY = "https://registry.npmjs.org/";
const ROOT = resolve(import.meta.dir, "..");
/** How long to wait for the registry to show every publish, and how often to look (see confirm-landing.ts). */
const LANDING_DEADLINE_MS = 300_000;
const LANDING_INTERVAL_MS = 10_000;
/** npm's trusted publishing (OIDC) needs the CLI at 11.5.1 or later. */
const MIN_NPM_FOR_OIDC = [11, 5, 1] as const;
/** Where every run leaves its tarballs, SBOMs and published.json (gitignored; publish.yml uploads it). */
const RELEASE_DIR = join(ROOT, "release");
/** The audience npm's OIDC exchange expects for registry.npmjs.org (npm 11, lib/utils/oidc.js). */
const NPM_OIDC_AUDIENCE = "npm:registry.npmjs.org";

/** Slugs that have moved to trusted publishing (scripts/trusted-publishing.json). */
function loadMoved(): ReadonlySet<string> {
  const raw = JSON.parse(readFileSync(join(ROOT, "scripts", "trusted-publishing.json"), "utf8")) as { moved?: unknown };
  if (!Array.isArray(raw.moved) || !raw.moved.every((s) => typeof s === "string")) {
    throw new Error('scripts/trusted-publishing.json: "moved" must be an array of directory slugs');
  }
  return new Set(raw.moved as string[]);
}

interface PkgJson {
  readonly name: string;
  version: string;
  main?: string;
  types?: string;
  bin?: string | Record<string, string>;
  exports?: Record<string, unknown>;
  publishConfig?: Record<string, unknown>;
  readonly private?: boolean;
  readonly scripts?: Record<string, string>;
  readonly [k: string]: unknown;
}

function run(cmd: "npm" | "bun" | "tar", args: string[], cwd: string): { code: number; out: string; err: string } {
  // `cmd` is one of three fixed names; no shell (Bun starts npm's .cmd shim itself on Windows).
  // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process
  const r = spawnSync(cmd, args, { cwd, encoding: "utf8" });
  return { code: r.status ?? -1, out: r.stdout || "", err: r.stderr || "" };
}

function srcToDistJs(s: string): string {
  return s.replace(/^\.\/src\//, "./dist/").replace(/\.tsx?$/, ".js");
}
function srcToDistDts(s: string): string {
  return s.replace(/^\.\/src\//, "./dist/").replace(/\.tsx?$/, ".d.ts");
}

function preflightAuth(): void {
  const r = run("npm", ["whoami", "--registry", REGISTRY], ROOT);
  if (r.code !== 0) {
    console.error("\n✗ Not authenticated against npmjs.org.");
    console.error("   Run: npm login --scope=@kashscript --registry=https://registry.npmjs.org/");
    console.error(`\n   npm error: ${r.err.trim()}`);
    process.exit(1);
  }
  const user = r.out.trim();
  console.log(`✓ Authenticated as: ${user}`);
}

/** True when `have` is at least `want`, comparing major.minor.patch. */
function atLeast(have: string, want: readonly [number, number, number]): boolean {
  const parts = have.split(".").map((p) => Number.parseInt(p, 10));
  for (let i = 0; i < 3; i++) {
    const h = parts[i] ?? 0;
    if (h !== want[i]) return h > want[i]!;
  }
  return true;
}

/**
 * The job's OIDC token for npm's audience. `NPM_ID_TOKEN` takes precedence, as it does in npm itself
 * (lib/utils/oidc.js). Never printed, never written.
 */
async function fetchIdToken(): Promise<string> {
  if (process.env.NPM_ID_TOKEN) return process.env.NPM_ID_TOKEN;
  const url = new URL(process.env.ACTIONS_ID_TOKEN_REQUEST_URL ?? "");
  url.searchParams.set("audience", NPM_OIDC_AUDIENCE);
  const res = await fetch(url, {
    headers: { Accept: "application/json", Authorization: `Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN ?? ""}` },
  });
  if (!res.ok) throw new Error(`GitHub refused an OIDC token (HTTP ${res.status}) — does the job have \`id-token: write\`?`);
  const body = (await res.json()) as { value?: unknown };
  if (typeof body.value !== "string") throw new Error("GitHub's OIDC response carried no token");
  return body.value;
}

/** The .npmrc files npm would read: the user's, the project's and NPM_CONFIG_USERCONFIG's. */
function npmrcPaths(): string[] {
  const paths = [join(homedir(), ".npmrc"), join(ROOT, ".npmrc")];
  for (const v of [process.env.NPM_CONFIG_USERCONFIG, process.env.npm_config_userconfig]) if (v) paths.push(v);
  return [...new Set(paths)];
}

/**
 * --trusted: only inside the publish workflow, on OIDC, with no long-lived credential anywhere in
 * reach — checked on dry runs too (RW-2). A real publish also needs master and a public repository.
 */
async function preflightTrusted(dryRun: boolean): Promise<void> {
  if (process.env.GITHUB_ACTIONS !== "true" || !process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
    console.error("\n✗ --trusted publishes only from GitHub Actions with `permissions: id-token: write`.");
    console.error("   Run the Publish workflow (.github/workflows/publish.yml); there is no local trusted publish.");
    process.exit(1);
  }
  const inEnv = npmAuthInEnv(process.env);
  const inFiles = npmrcPaths().filter((p) => existsSync(p) && npmrcHasAuth(readFileSync(p, "utf8")));
  if (inEnv.length > 0 || inFiles.length > 0) {
    console.error("\n✗ An npm credential is in reach. Trusted publishing never uses a long-lived token (P6, RW-2).");
    for (const n of inEnv) console.error(`   environment: ${n}`);
    for (const f of inFiles) console.error(`   .npmrc with a credential: ${f}`);
    console.error("   Remove it from the workflow and the runner; nothing was built or published.");
    process.exit(1);
  }
  const v = run("npm", ["--version"], ROOT).out.trim();
  if (!atLeast(v, MIN_NPM_FOR_OIDC)) {
    console.error(`\n✗ npm ${v || "(unknown)"} cannot publish with OIDC; need ${MIN_NPM_FOR_OIDC.join(".")} or later.`);
    process.exit(1);
  }
  console.log(`✓ Trusted publishing: GitHub OIDC, npm ${v}, no npm credential in the environment or an .npmrc`);
  if (dryRun) return;

  if (process.env.GITHUB_REF !== "refs/heads/master") {
    console.error(`\n✗ A real publish runs only from refs/heads/master (this run: ${process.env.GITHUB_REF ?? "unknown"}). Dry runs may run from any branch.`);
    process.exit(1);
  }
  const verdict = provenanceVerdict(oidcClaims(await fetchIdToken()));
  if (!verdict.ok) {
    console.error(`\n✗ ${verdict.reason}`);
    process.exit(1);
  }
  console.log("✓ Provenance: the repository is public; npm will sign each version's provenance");
}

/**
 * Dry run, --trusted: npm's own OIDC token exchange for one package — the request `npm publish`
 * makes. A token back means npmjs.com has a trusted publisher matching this repository, workflow
 * and environment; it is discarded unread. Then provenance's precondition. Throws the stated reason.
 */
async function rehearseTrusted(fullName: string): Promise<void> {
  const idToken = await fetchIdToken();
  const res = await fetch(new URL(`/-/npm/v1/oidc/token/exchange/package/${escapedName(fullName)}`, REGISTRY), {
    method: "POST",
    headers: { Accept: "application/json", Authorization: `Bearer ${idToken}` },
  });
  const body: unknown = await res.json().catch(() => null);
  const outcome = exchangeOutcome(res.status, body);
  if (!outcome.configured) {
    throw new Error(`npmjs.com is not yet configured for ${fullName}: the OIDC exchange answered ${outcome.reason} (docs/publishing.md §2)`);
  }
  console.log(`  ✓ npmjs.com: the trusted publisher answers for ${fullName} (a short-lived token was issued and discarded)`);
  const verdict = provenanceVerdict(oidcClaims(idToken));
  if (!verdict.ok) throw new Error(verdict.reason);
  console.log("  ✓ provenance: the repository is public; npm will generate it at publish");
}

let lockText: string | undefined;
/** bun.lock's text, read once — the SBOM's integrity hashes. */
function readLockText(): string {
  lockText ??= readFileSync(join(ROOT, "bun.lock"), "utf8");
  return lockText;
}

function preflightVersionAvailable(name: string, ver: string): void {
  const r = run("npm", ["view", `${name}@${ver}`, "version", "--registry", REGISTRY], ROOT);
  if (r.code === 0 && r.out.trim().length > 0) {
    throw new Error(`${name}@${ver} already published — bump package.json version before retrying`);
  }
}

function mutateAndPack(pkgDir: string): {
  ver: string;
  tarball: string;
  packedMain: string;
  workspaceLeaks: number;
  resolvedDeps: Record<string, string>;
  packedDeps: Record<string, string>;
  /** The package.json as it went into the tarball — what the SBOM describes. */
  packed: PkgJson;
} {
  const pkgPath = join(pkgDir, "package.json");
  const backup = join(pkgDir, "package.json.bak");
  copyFileSync(pkgPath, backup);

  try {
    const raw = readFileSync(pkgPath, "utf8");
    const p = JSON.parse(raw) as PkgJson;

    const oldExports = (p.exports ?? {}) as Record<string, unknown>;
    const newExports: Record<string, unknown> = {};
    const missingDist: string[] = [];

    for (const [key, val] of Object.entries(oldExports)) {
      let srcStr: string | null = null;
      if (typeof val === "string") {
        srcStr = val;
      } else if (val && typeof val === "object") {
        const v = val as { default?: string; import?: string; types?: string };
        srcStr = v.default || v.import || v.types || null;
      }
      if (!srcStr || !srcStr.startsWith("./src/")) {
        newExports[key] = val;
        continue;
      }
      const js = srcToDistJs(srcStr);
      const dts = srcToDistDts(srcStr);
      for (const f of [js, dts]) {
        const abs = join(pkgDir, f);
        if (!existsSync(abs)) missingDist.push(f);
      }
      newExports[key] = { types: dts, import: js, default: js };
    }

    if (missingDist.length > 0) {
      throw new Error(`missing dist files (rebuild first): ${missingDist.join(", ")}`);
    }

    p.exports = newExports;
    const rootEntry = newExports["."] as { import: string; types: string } | undefined;
    if (!rootEntry) throw new Error('no "." export defined');
    p.main = rootEntry.import;
    p.types = rootEntry.types;

    // Resolve `workspace:*` deps from the SIBLING package.json on disk.
    //
    // `bun pm pack` is supposed to do this, and it does — but from stale
    // resolution state, not from the workspace's current version. Observed
    // 2026-09-22: with `packages/attest/package.json` at 0.1.6 and 0.1.6 live
    // on npm, packing identity-server still emitted
    // `"@kashscript/attest": "0.1.5"`. `bun install` and `bun install --force`
    // did not correct it.
    //
    // A wrong-but-well-formed version is the more dangerous half of the bug
    // class that made attest@0.1.5 uninstallable for seven weeks: the
    // `workspaceLeaks` guard below only greps for the literal string
    // `workspace:`, so it passes happily on a dependency pinned to a version
    // that is broken, yanked or nonexistent. Resolving here — from the one
    // source of truth, the sibling's package.json — makes the packed manifest
    // say what the monorepo actually contains.
    const resolvedDeps: Record<string, string> = {};
    for (const field of ["dependencies", "peerDependencies", "optionalDependencies"] as const) {
      const deps = p[field] as Record<string, string> | undefined;
      if (!deps) continue;
      for (const [depName, range] of Object.entries(deps)) {
        if (typeof range !== "string" || !range.startsWith("workspace:")) continue;
        const slug = depName.startsWith("@") ? depName.split("/")[1] : depName;
        const siblingPath = join(ROOT, "packages", slug ?? "", "package.json");
        if (!existsSync(siblingPath)) {
          throw new Error(
            `${depName} is declared "${range}" but no workspace package exists at ` +
            `packages/${slug}. Publishing would emit an unresolvable dependency.`,
          );
        }
        const siblingVer = (JSON.parse(readFileSync(siblingPath, "utf8")) as PkgJson).version;
        if (!siblingVer) throw new Error(`packages/${slug}/package.json has no version`);
        deps[depName] = siblingVer;
        resolvedDeps[depName] = siblingVer;
      }
    }

    // Force registry to npmjs in the published publishConfig.
    const pc = (p.publishConfig ?? {}) as { access?: string; registry?: string };
    p.publishConfig = { access: pc.access ?? "public", registry: REGISTRY };

    // Rewrite bin entries pointing at ./src/*.ts → compiled ./dist/*.js, mirroring
    // the exports rewrite. Without this the published bin points at a TypeScript
    // file that plain `node` cannot execute (publishConfig.bin is dropped above).
    if (typeof p.bin === "string" && p.bin.startsWith("./src/")) {
      const js = srcToDistJs(p.bin);
      if (!existsSync(join(pkgDir, js))) throw new Error(`missing dist file for bin (rebuild first): ${js}`);
      p.bin = js;
    } else if (p.bin && typeof p.bin === "object") {
      const newBin: Record<string, string> = {};
      for (const [name, target] of Object.entries(p.bin)) {
        if (typeof target === "string" && target.startsWith("./src/")) {
          const js = srcToDistJs(target);
          if (!existsSync(join(pkgDir, js))) throw new Error(`missing dist file for bin "${name}" (rebuild first): ${js}`);
          newBin[name] = js;
        } else {
          newBin[name] = target;
        }
      }
      p.bin = newBin;
    }

    writeFileSync(pkgPath, JSON.stringify(p, null, 2) + "\n");

    const pack = run("bun", ["pm", "pack"], pkgDir);
    if (pack.code !== 0) throw new Error(`bun pm pack exit ${pack.code}: ${pack.err}`);

    const tarballs = readdirSync(pkgDir).filter((f) => f.startsWith("kashscript-") && f.endsWith(".tgz"));
    if (tarballs.length === 0) throw new Error("no .tgz produced");
    const tarball = tarballs.sort().reverse()[0]!;

    const inspect = run("tar", ["-xzOf", tarball, "package/package.json"], pkgDir);
    if (inspect.code !== 0) throw new Error(`tar inspect failed: ${inspect.err}`);
    const packedPkg = JSON.parse(inspect.out) as PkgJson;
    const workspaceLeaks = (inspect.out.match(/workspace:/g) || []).length;

    return {
      ver: p.version,
      tarball,
      packedMain: packedPkg.main ?? "(none)",
      workspaceLeaks,
      resolvedDeps,
      packedDeps: (packedPkg.dependencies ?? {}) as Record<string, string>,
      packed: packedPkg,
    };
  } finally {
    renameSync(backup, pkgPath);
  }
}

interface PublishResult {
  readonly slug: string;
  /** The version this run published or validated — never one read back from the registry. */
  readonly version: string;
  /** The dist-tag it was published under; set only for a real (non-staged) publish. */
  readonly tag?: string;
  landedMain: string;
  /** Set by the landing check after all publishes: undefined = not checked (dry run, or staged). */
  landed?: boolean;
  /** Set after landing for a trusted publish: does the registry show a provenance attestation? */
  provenance?: boolean;
  /** File names under release/: the tarball as packed and its CycloneDX SBOM. */
  readonly tarball: string;
  readonly sbom: string;
  readonly timestamp: string;
}

async function publishOne(
  slug: string,
  dryRun: boolean,
  skipArtifacts: boolean,
  stage: boolean,
  trusted: boolean,
  restricted: boolean,
  moved: ReadonlySet<string>,
): Promise<PublishResult> {
  const pkgDir = join(ROOT, "packages", slug);
  const pkgPath = join(pkgDir, "package.json");
  const full = `@kashscript/${slug}`;
  const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as PkgJson;

  console.log(`\n===== ${full}@${pkg.version} =====`);

  // Guard (d87): a private package never goes through the public path. Checked on dry runs too.
  const access = (pkg.publishConfig as { access?: string } | undefined)?.access ?? "public";
  if (access === "restricted") {
    if (trusted) {
      throw new Error(
        `${full} is a private package (publishConfig.access "restricted") — the public publish workflow ` +
        `must never publish it. Publish it from the founder's terminal with --restricted.`,
      );
    }
    if (!restricted) {
      throw new Error(
        `${full} is a private package (publishConfig.access "restricted"). Pass --restricted to publish it ` +
        `as one, once the npm private-package plan is in place.`,
      );
    }
  } else if (restricted) {
    throw new Error(`--restricted was passed but ${full} is public (publishConfig.access "${access}") — refusing to guess.`);
  }

  // Guard (AU-11): provenance names the source repository, and npm refuses a package whose
  // repository.url names another (E422). Checked on dry runs too, before anything is built.
  if (trusted) {
    const rv = repositoryVerdict((pkg as { repository?: RepositoryField }).repository, process.env.GITHUB_REPOSITORY, slug);
    if (!rv.ok) throw new Error(`${full}: ${rv.reason}`);
  }

  // Guard: a package publishes through exactly one path. Dry runs publish nothing, so either mode may rehearse.
  if (!dryRun) {
    if (trusted && !moved.has(slug)) {
      throw new Error(
        `${full} is not listed in scripts/trusted-publishing.json — configure its trusted publisher on ` +
        `npmjs.com (docs/publishing.md), then add "${slug}" there. Until then it publishes by the token path, not from CI.`,
      );
    }
    if (!trusted && moved.has(slug)) {
      throw new Error(
        `${full} has moved to trusted publishing — the long-lived-token path is retired for it. ` +
        `Run the Publish workflow (.github/workflows/publish.yml).`,
      );
    }
  }

  // Guard: never push a private / non-npmjs package to the public registry.
  if (pkg.private === true) {
    throw new Error(`${full} is marked "private": true — it must never be published to npmjs`);
  }
  const declaredRegistry = (pkg.publishConfig as { registry?: string } | undefined)?.registry;
  if (declaredRegistry && !declaredRegistry.startsWith(REGISTRY.slice(0, -1))) {
    throw new Error(
      `${full} declares publishConfig.registry=${declaredRegistry} (not npmjs) — ` +
      `refusing. This package belongs on its own registry, not public npm.`,
    );
  }

  if (!dryRun) {
    preflightVersionAvailable(full, pkg.version);
  }

  // Guard: restore the prepublishOnly step this script bypasses. Packages
  // that generate committed artifacts (trade-sdk's Foundry contract
  // bytecode) must regenerate them or they publish stale.
  if (pkg.scripts?.["artifacts:build"]) {
    if (skipArtifacts) {
      console.log("  ⚠ --skip-artifacts: trusting existing contract artifacts");
    } else {
      console.log("--- artifacts:build (restores bypassed prepublishOnly) ---");
      const art = run("bun", ["run", "artifacts:build"], pkgDir);
      if (art.code !== 0) {
        throw new Error(
          `artifacts:build failed for ${full} (is Foundry/forge installed?). ` +
          `Fix the toolchain or, if artifacts are known-fresh, re-run with --skip-artifacts.\n${art.err}`,
        );
      }
    }
  }

  // Guard (A10-03): the package's own suite — the tests' typecheck, then every test —
  // runs before anything is built or packed, and nothing skips it. A regression in the
  // countersign or SD-JWT verifier must fail here, not in a consumer's pin bump.
  if (pkg.scripts?.test === undefined) {
    throw new Error(`${full} has no "test" script — every published package carries its suite (A10-03)`);
  }
  console.log("--- test (the package's own suite, before the rebuild) ---");
  const tests = run("bun", ["run", "test"], pkgDir);
  if (tests.code !== 0) {
    throw new Error(`tests failed for ${full} (exit ${tests.code}):\n${tests.out.slice(-3000)}\n${tests.err.slice(-3000)}`);
  }
  console.log("  tests:     passed");

  // 1) Clean rebuild
  const distDir = join(pkgDir, "dist");
  if (existsSync(distDir)) rmSync(distDir, { recursive: true, force: true });
  for (const f of readdirSync(pkgDir)) {
    if (f.startsWith("kashscript-") && f.endsWith(".tgz")) rmSync(join(pkgDir, f));
  }
  console.log("--- rebuild dist (cold) ---");
  const build = run("bun", ["run", "build"], pkgDir);
  if (build.code !== 0) {
    throw new Error(`build failed for ${full}: ${build.err}`);
  }

  // 2) Mutate + pack
  const { ver, tarball, packedMain, workspaceLeaks, resolvedDeps, packedDeps, packed } = mutateAndPack(pkgDir);
  console.log(`  version:   ${ver}`);
  console.log(`  tarball:   ${tarball}`);
  console.log(`  main:      ${packedMain}`);
  console.log(`  workspace:* leaks: ${workspaceLeaks} (must be 0)`);
  for (const [dep, range] of Object.entries(packedDeps)) {
    const note = resolvedDeps[dep] !== undefined ? " (resolved from workspace)" : "";
    console.log(`  dep:       ${dep}@${range}${note}`);
  }
  if (!packedMain.startsWith("./dist/")) throw new Error(`packed main does not point at dist: ${packedMain}`);
  if (workspaceLeaks !== 0) throw new Error(`workspace:* literals leaked into tarball`);

  // The packed manifest must agree with the workspace it came from. `bun pm
  // pack` has been observed emitting a stale version here (see mutateAndPack),
  // and a dependency pinned to the wrong version is uninstallable in exactly
  // the way `workspaceLeaks` was written to prevent but does not catch.
  for (const [dep, expected] of Object.entries(resolvedDeps)) {
    const actual = packedDeps[dep];
    if (actual !== expected) {
      throw new Error(
        `packed dependency ${dep}@${actual ?? "(missing)"} does not match the workspace ` +
        `version ${expected}. Refusing to publish a manifest that misstates its own dependencies.`,
      );
    }
  }

  // 2b) The release files (RW-2): the tarball as packed, and its CycloneDX SBOM — dry runs too.
  const tarballPath = join(pkgDir, tarball);
  const sbomFile = tarball.replace(/\.tgz$/, ".cdx.json");
  const sbom = buildSbom({
    root: ROOT,
    pkgDir,
    manifest: packed as unknown as PackedManifest,
    tarballSha512Hex: createHash("sha512").update(readFileSync(tarballPath)).digest("hex"),
    lockText: readLockText(),
    timestamp: new Date().toISOString(),
    serialNumber: `urn:uuid:${randomUUID()}`,
  });
  mkdirSync(RELEASE_DIR, { recursive: true });
  copyFileSync(tarballPath, join(RELEASE_DIR, tarball));
  writeFileSync(join(RELEASE_DIR, sbomFile), JSON.stringify(sbom, null, 2) + "\n");
  console.log(`  sbom:      release/${sbomFile} (CycloneDX 1.6, ${sbom.components.length} components)`);

  if (dryRun) {
    if (trusted) await rehearseTrusted(full);
    console.log("  (dry-run: skipping npm publish)");
    rmSync(tarballPath);
    return {
      slug,
      version: ver,
      landedMain: packedMain,
      tarball,
      sbom: sbomFile,
      timestamp: new Date().toISOString(),
    };
  }

  // 3) Publish
  const isPrerelease = ver.includes("-");
  const tag = isPrerelease ? "alpha" : "latest";
  // --stage: tokens limited to staged publishing (E_STAGE_REQUIRED) get
  // `npm stage publish`; the version is NOT live until `npm stage approve`.
  const pubArgs = [...(stage ? ["stage", "publish"] : ["publish"]), tarball, "--registry", REGISTRY, "--access", access];
  if (isPrerelease) pubArgs.push("--tag", tag);
  // RW-2: provenance on every trusted publish, asked for explicitly (npm's auto-enable is only a default).
  if (trusted) pubArgs.push("--provenance");
  console.log(`--- npm ${pubArgs.join(" ")} ---`);
  const pub = run("npm", pubArgs, pkgDir);
  if (pub.code !== 0) {
    throw new Error(`${stage ? "stage publish" : "publish"} failed: ${pub.err}`);
  }
  if (stage) {
    // Nothing lands until approval, so there is nothing to landing-verify.
    console.log(pub.out.trim());
    rmSync(tarballPath);
    return { slug, version: ver, landedMain: "(staged — not live until approved)", tarball, sbom: sbomFile, timestamp: new Date().toISOString() };
  }

  // 4) Landing is checked once, after every package has been published (see main) — the registry can
  //    lag a couple of minutes, and waiting here would hold up the next publish for nothing.
  rmSync(tarballPath);

  return {
    slug,
    version: ver,
    tag,
    landedMain: "(published; registry not yet checked)",
    tarball,
    sbom: sbomFile,
    timestamp: new Date().toISOString(),
  };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");
  const skipArtifacts = args.includes("--skip-artifacts");
  const stage = args.includes("--stage");
  const trusted = args.includes("--trusted");
  const restricted = args.includes("--restricted");
  const slugs = args.filter((a) => !a.startsWith("--"));
  if (slugs.length === 0) {
    console.error("usage: bun scripts/publish-to-npmjs.ts [--dry-run] [--stage] [--trusted] [--restricted] [--skip-artifacts] <slug> [slug ...]");
    process.exit(1);
  }
  if (trusted && restricted) {
    console.error("--trusted and --restricted cannot be combined: private packages never publish from the public workflow.");
    process.exit(1);
  }
  if (trusted && stage) {
    console.error("--trusted and --stage cannot be combined: staged publishing is a token feature.");
    process.exit(1);
  }

  console.log(`registry:  ${REGISTRY}`);
  console.log(`dry-run:   ${dryRun}`);
  console.log(`stage:     ${stage}`);
  console.log(`trusted:   ${trusted}`);
  console.log(`restricted: ${restricted}`);
  console.log(`order:     ${slugs.join(" → ")}`);

  const moved = loadMoved();
  if (trusted) await preflightTrusted(dryRun);
  else if (!dryRun) preflightAuth();

  // release/ holds only this run's files: it is this script's own, gitignored output.
  rmSync(RELEASE_DIR, { recursive: true, force: true });

  const results: PublishResult[] = [];
  let failed: { slug: string; error: string } | null = null;

  for (const slug of slugs) {
    try {
      const r = await publishOne(slug, dryRun, skipArtifacts, stage, trusted, restricted, moved);
      results.push(r);
    } catch (e) {
      failed = { slug, error: (e as Error).message };
      console.error(`\n✗ HALT at ${slug}: ${(e as Error).message}`);
      break;
    }
  }

  if (!dryRun && !stage && results.length > 0) {
    console.log(`\n--- confirming the registry shows each publish (it can lag a couple of minutes; up to ${LANDING_DEADLINE_MS / 1000}s) ---`);
    const view = (spec: string, field: string): string =>
      run("npm", ["view", spec, field, "--registry", REGISTRY], ROOT).out.trim().split("\n").pop() || "";
    const targets: LandingTarget[] = results.map((r) => ({ name: `@kashscript/${r.slug}`, version: r.version, tag: r.tag ?? "latest" }));
    const checked = await confirmLanding(targets, {
      view,
      sleep: (ms) => new Promise((res) => setTimeout(res, ms)),
      now: () => Date.now(),
      deadlineMs: LANDING_DEADLINE_MS,
      intervalMs: LANDING_INTERVAL_MS,
    });
    results.forEach((r, i) => {
      r.landed = checked[i]!.landed;
      if (r.landed) r.landedMain = checked[i]!.main;
    });
    // RW-2: a trusted publish must carry npm's provenance attestation (SLSA, signed through Sigstore).
    if (trusted) {
      for (const r of results) {
        if (!r.landed) continue;
        r.provenance = view(`@kashscript/${r.slug}@${r.version}`, "dist.attestations.provenance.predicateType").startsWith("https://slsa.dev/provenance/");
      }
    }
  }

  if (results.length > 0) {
    // What publish.yml's release job reads to name the release and the files it signs.
    const published = results.map((r) => ({
      name: `@kashscript/${r.slug}`,
      version: r.version,
      tag: r.tag ?? null,
      tarball: r.tarball,
      sbom: r.sbom,
      provenance: r.provenance ?? null,
    }));
    writeFileSync(join(RELEASE_DIR, "published.json"), JSON.stringify({ dryRun, packages: published }, null, 2) + "\n");
  }

  console.log("\n=== summary ===");
  console.log(`${dryRun ? "validated" : stage ? "staged" : "published"}: ${results.length} / ${slugs.length}`);
  for (const r of results) {
    if (r.landed === false) {
      console.log(
        `  ? @kashscript/${r.slug}@${r.version}  published, but NOT YET VISIBLE on the registry after ${LANDING_DEADLINE_MS / 1000}s — ` +
        `the publish itself succeeded; check \`npm view @kashscript/${r.slug}@${r.version} version\` and \`npm view @kashscript/${r.slug} dist-tags\`  at ${r.timestamp}`,
      );
    } else {
      const seen = r.landed === true ? `  confirmed on the registry under tag ${r.tag}` : "";
      const prov = r.provenance === true ? "  provenance ✓" : r.provenance === false ? "  PROVENANCE MISSING" : "";
      console.log(`  ${r.provenance === false ? "✗" : "✓"} @kashscript/${r.slug}@${r.version}  main=${r.landedMain}${seen}${prov}  sbom=release/${r.sbom}  at ${r.timestamp}`);
    }
  }
  const unproven = results.filter((r) => r.provenance === false);
  if (unproven.length > 0) {
    console.log(
      `\n✗ ${unproven.length} version(s) landed without a provenance attestation — RW-2 requires one. Check ` +
      `\`npm view <pkg>@<ver> --json | jq .dist.attestations\` (docs/publishing.md §4).`,
    );
    process.exit(1);
  }
  if (stage && results.length > 0) {
    console.log("\nNext: `npm stage list`, then `npm stage approve <stage-id>` for each, IN THIS ORDER:");
    console.log(`  ${results.map((r) => `@kashscript/${r.slug}@${r.version}`).join(" → ")}`);
    console.log("  (a dependent approved before its dependency is uninstallable until the dependency is approved)");
  }
  if (failed) {
    console.log(`failed: ${failed.slug} — ${failed.error}`);
    process.exit(1);
  }
}

void main();
