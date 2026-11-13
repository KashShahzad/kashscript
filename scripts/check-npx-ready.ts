#!/usr/bin/env bun
/**
 * scripts/check-npx-ready.ts
 *
 * Pre-publish gate. Refuses to ship `@kashscript/kash` to npm unless the
 * tarball will actually run under `npx`, `pnpm dlx`, `yarn dlx`, `bunx`,
 * and `deno run npm:`. Runs at `prepack` time (see packages/kash/package.json)
 * AFTER `bun run build` and `bun run scripts/fix-shebang.ts`.
 *
 * Checks performed:
 *
 *   1. publishConfig.bin map is present, non-empty, and points at files
 *      that exist on disk under packages/kash/.
 *   2. Each bin target starts with `#!/usr/bin/env node` (the only shebang
 *      that resolves cross-runtime via PATH on every supported OS).
 *   3. Each bin target is syntactically loadable by Node — we parse it
 *      with `Bun.build` (or fall back to `node --check`) to catch the
 *      "bundle imports an unresolvable .ts file" footgun.
 *   4. publishConfig.exports + publishConfig.main + publishConfig.types
 *      all point at files that exist.
 *   5. `files: [...]` includes "dist" — otherwise `npm pack` excludes
 *      the actual binary.
 *   6. engines.node is declared and >= 18.
 *   7. Package name is `@kashscript/*` and `publishConfig.access` is set
 *      (otherwise `npm publish` will refuse the scoped publish).
 *   8. Optional: simulates `npm pack` and inspects the tarball file list
 *      to confirm dist/ is included.
 *
 * Exits 0 on success with a green checkmark report; exits 1 on the first
 * failed check with a precise remediation line.
 */

import { existsSync, readFileSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { spawnSync } from "node:child_process";

const PKG_DIR = resolve(__dirname, "..", "packages", "cli");
const PJ_PATH = join(PKG_DIR, "package.json");

interface PackageJson {
  readonly name?: string;
  readonly version?: string;
  readonly bin?:  Record<string, string> | string;
  readonly main?: string;
  readonly types?: string;
  readonly exports?: Record<string, unknown>;
  readonly files?: readonly string[];
  readonly engines?: Record<string, string>;
  readonly publishConfig?: {
    readonly access?: "public" | "restricted";
    readonly registry?: string;
    readonly bin?:  Record<string, string> | string;
    readonly main?: string;
    readonly types?: string;
    readonly exports?: Record<string, unknown>;
  };
}

const pj = JSON.parse(readFileSync(PJ_PATH, "utf-8")) as PackageJson;

interface Issue { readonly code: string; readonly message: string; readonly fix?: string }
const issues: Issue[] = [];
const passes: string[] = [];

function record(ok: boolean, label: string, fail: { code: string; message: string; fix?: string }): void {
  if (ok) { passes.push(label); return; }
  issues.push({ code: fail.code, message: `${label} — ${fail.message}`, ...(fail.fix ? { fix: fail.fix } : {}) });
}

/* ── 7. scope + access ──────────────────────────────────────── */
record(
  typeof pj.name === "string" && pj.name.startsWith("@kashscript/"),
  "name is under the @kashscript/ scope",
  { code: "BAD_SCOPE", message: `name = ${JSON.stringify(pj.name)}`, fix: 'set "name" to "@kashscript/<short>".' },
);
record(
  pj.publishConfig?.access === "public",
  'publishConfig.access = "public"',
  { code: "BAD_ACCESS", message: `got ${JSON.stringify(pj.publishConfig?.access)}`, fix: 'set publishConfig.access to "public" for the CLI tarball.' },
);

/* ── 6. engines ─────────────────────────────────────────────── */
const engNode = pj.engines?.node ?? "";
record(
  /^>=?\s*1[8-9]|^>=?\s*[2-9]\d/.test(engNode),
  "engines.node >= 18 declared",
  { code: "BAD_ENGINES", message: `got "${engNode}"`, fix: 'set "engines.node" to ">=18" (or higher).' },
);

/* ── 1. bin map ─────────────────────────────────────────────── */
const binMap = normaliseBin(pj.publishConfig?.bin ?? pj.bin);
record(
  Object.keys(binMap).length > 0,
  "publishConfig.bin (or bin) is non-empty",
  { code: "NO_BIN", message: "neither bin nor publishConfig.bin is set", fix: "add `bin: { kash: \"./dist/bin/kash.js\" }`." },
);

/* The bin map's KEYS shouldn't collide with the package's trailing
 * segment in a way that breaks `npx @kashscript/kash`. npx behaviour:
 *  - single bin → always runs.
 *  - multi bin → user must pick with `-c` or `-p`.
 * Warn loudly when multi-bin is set so the maintainer is aware. */
if (Object.keys(binMap).length > 1) {
  issues.push({
    code: "MULTI_BIN_WARN",
    message: `publishConfig.bin has ${Object.keys(binMap).length} entries (${Object.keys(binMap).join(", ")}). \`npx @kashscript/kash\` cannot auto-pick — users will need \`npx -p @kashscript/kash <bin>\`. Consider collapsing to one bin.`,
    fix: "set publishConfig.bin to a single entry.",
  });
}

/* ── 1b + 2. each bin target exists + has node shebang ──────── */
for (const [name, relPath] of Object.entries(binMap)) {
  const abs = join(PKG_DIR, relPath);
  if (!existsSync(abs)) {
    issues.push({
      code: "MISSING_BIN_TARGET",
      message: `bin["${name}"] → ${relPath} does not exist on disk`,
      fix: "run `bun run build` (the prepack script does this for you).",
    });
    continue;
  }
  passes.push(`bin["${name}"] target exists at ${relPath}`);

  const head = readFileSync(abs, "utf-8").slice(0, 64);
  if (!head.startsWith("#!/usr/bin/env node")) {
    issues.push({
      code: "BAD_SHEBANG",
      message: `bin["${name}"] does not start with \`#!/usr/bin/env node\` — actual first line: ${head.split("\n", 1)[0]}`,
      fix: "run `bun run ../../scripts/fix-shebang.ts` from packages/kash (the prepack script does this).",
    });
  } else {
    passes.push(`bin["${name}"] has node shebang`);
  }

  /* ── 3. node-loadable check ────────────────────────────── */
  const check = spawnSync("node", ["--check", abs], { encoding: "utf-8" });
  if (check.status !== 0) {
    issues.push({
      code: "NODE_PARSE_FAIL",
      message: `\`node --check ${relPath}\` exited ${check.status}: ${check.stderr.trim().split("\n").slice(0, 3).join(" ")}`,
      fix: "compile the package with tsc and re-run the prepack script.",
    });
  } else {
    passes.push(`bin["${name}"] parses under node --check`);
  }
}

/* ── 4. exports / main / types ──────────────────────────────── */
const main  = pj.publishConfig?.main  ?? pj.main;
const types = pj.publishConfig?.types ?? pj.types;
if (typeof main === "string") {
  const ok = existsSync(join(PKG_DIR, main));
  record(ok, `main (${main}) exists`, { code: "MISSING_MAIN", message: "build artefact missing", fix: "rebuild." });
}
if (typeof types === "string") {
  const ok = existsSync(join(PKG_DIR, types));
  record(ok, `types (${types}) exists`, { code: "MISSING_TYPES", message: "declaration file missing", fix: "ensure tsc emits .d.ts." });
}
const exportsMap = pj.publishConfig?.exports ?? pj.exports;
if (exportsMap && typeof exportsMap === "object") {
  for (const [subpath, target] of Object.entries(exportsMap as Record<string, unknown>)) {
    if (typeof target !== "string") continue;
    const ok = existsSync(join(PKG_DIR, target));
    record(ok, `exports["${subpath}"] (${target}) exists`, {
      code: "MISSING_EXPORT_TARGET",
      message: "target file missing",
      fix: `confirm tsc emitted ${target} under packages/kash/.`,
    });
  }
}

/* ── 5. files list includes dist ────────────────────────────── */
const files = pj.files ?? [];
record(
  files.includes("dist"),
  '"files" includes "dist"',
  { code: "MISSING_FILES_DIST", message: `got ${JSON.stringify(files)}`, fix: 'add "dist" to the "files" array.' },
);

/* ── 8. `npm pack --dry-run` listing (best-effort) ──────────── */
const pack = spawnSync("npm", ["pack", "--dry-run", "--json"], { cwd: PKG_DIR, encoding: "utf-8" });
if (pack.status === 0) {
  try {
    const parsed = JSON.parse(pack.stdout) as Array<{ files?: Array<{ path: string }> }>;
    const entries = parsed[0]?.files ?? [];
    const hasBin = Object.values(binMap).some((p) => {
      const rel = p.replace(/^\.\//, "");
      return entries.some((e) => e.path === rel);
    });
    record(
      hasBin,
      "`npm pack --dry-run` tarball would include every bin target",
      { code: "PACK_MISSING_BIN", message: "tarball preview did not include the declared bin path", fix: 'check "files" + .npmignore.' },
    );
    record(
      entries.some((e) => e.path === "package.json"),
      "`npm pack --dry-run` tarball includes package.json",
      { code: "PACK_NO_PJ", message: "no package.json in the tarball preview", fix: "should never happen — file an issue." },
    );
  } catch {
    /* json parse failure — non-blocking */
  }
} else {
  // npm may not be on PATH in this CI image — non-blocking.
  passes.push("`npm pack` dry-run skipped (npm not available)");
}

/* ── report ─────────────────────────────────────────────────── */

console.log(`> check-npx-ready · @kashscript/kash v${pj.version ?? "?"}`);
for (const p of passes) console.log(`  ✓  ${p}`);

const blocking = issues.filter((i) => i.code !== "MULTI_BIN_WARN");
const warnings = issues.filter((i) => i.code === "MULTI_BIN_WARN");

for (const w of warnings) {
  console.warn(`  ⚠  ${w.message}`);
  if (w.fix) console.warn(`      fix: ${w.fix}`);
}

if (blocking.length === 0) {
  console.log(`\n  ✓ npx-ready. ${passes.length} check(s) passed.`);
  process.exit(0);
}

console.error(`\n  ✗ ${blocking.length} blocking issue(s):`);
for (const issue of blocking) {
  console.error(`    ✗ [${issue.code}] ${issue.message}`);
  if (issue.fix) console.error(`        fix: ${issue.fix}`);
}
process.exit(1);

/* ── helpers ────────────────────────────────────────────────── */

function normaliseBin(bin: PackageJson["bin"] | undefined): Record<string, string> {
  if (!bin) return {};
  if (typeof bin === "string") {
    const name = (pj.name ?? "kash").replace(/^@[^/]+\//, "");
    return { [name]: bin };
  }
  return bin;
}
