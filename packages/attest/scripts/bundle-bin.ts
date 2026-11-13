// ============================================================================
// scripts/bundle-bin.ts — bundle the attest CLI so it runs under PLAIN NODE.
// ----------------------------------------------------------------------------
// `tsc` alone emits the bin (dist/bin/attest.js) with the SAME extensionless
// relative ESM imports the source uses (`from "../chain"`) — legal under
// `moduleResolution: "Bundler"` and fine for bundler-consumers, but Node's
// native ESM loader rejects them (ERR_MODULE_NOT_FOUND) when the `attest`
// command is run directly. The library is consumed through bundlers so it's
// unaffected; only the directly-executed bin breaks. (ROADMAP M7.1 / Duedale ADR-0018.)
//
// Fix: bundle the bin into ONE self-contained ESM file (only `node:*` builtins
// stay external), so `node dist/bin/attest.js` has nothing to resolve. Runs
// after `tsc` in the `build` script and overwrites tsc's broken bin output.
// ============================================================================

import { join } from "node:path";
import { readFileSync, writeFileSync, chmodSync } from "node:fs";

const PKG = join(import.meta.dir, "..");
const ENTRY = join(PKG, "src", "bin", "attest.ts");
const OUT_DIR = join(PKG, "dist", "bin");
const SHEBANG = "#!/usr/bin/env node";

const result = await Bun.build({
  entrypoints: [ENTRY],
  outdir: OUT_DIR,
  target: "node",
  format: "esm",
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  throw new Error("attest bin bundle failed");
}

const jsOut = result.outputs.find((o) => o.path.endsWith(".js"));
if (jsOut === undefined) throw new Error("attest bin bundle produced no .js output");
const out = jsOut.path;

// Guarantee exactly one shebang line so the published `attest` command is
// directly executable regardless of whether Bun preserved the entry hashbang.
let code = readFileSync(out, "utf8");
if (!code.startsWith("#!")) {
  code = `${SHEBANG}\n${code}`;
  writeFileSync(out, code);
}

// Make it executable on POSIX; a no-op / unsupported on Windows (non-fatal).
try {
  chmodSync(out, 0o755);
} catch {
  /* chmod unsupported on this platform */
}

console.log(`✓ bundled ${out} (node-ready, self-contained ESM)`);
