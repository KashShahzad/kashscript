// ============================================================================
// scripts/bundle-bin.ts — bundle the kash CLI so it runs under PLAIN NODE.
// ----------------------------------------------------------------------------
// `tsc` alone emits dist/bin/kash.js with the same extensionless relative ESM
// imports the source uses (`from "../commands/add"`). Those are legal under
// `moduleResolution: "Bundler"` but Node's native ESM loader rejects them
// (ERR_MODULE_NOT_FOUND), so `npx @kashscript/kash` would not start. The
// libraries kash imports (@kashscript/attest, identity-core, identity-server)
// ship the same shape, so they are bundled in too.
//
// Result: ONE self-contained ESM file; only `node:*` builtins and `enquirer`
// (a lazy, optional import in inject/targeting.ts) stay external. Runs after
// `tsc` in `build` and overwrites tsc's bin output. Same recipe as attest's.
// ============================================================================

import { join } from "node:path";
import { chmodSync, readFileSync, writeFileSync } from "node:fs";

const PKG = join(import.meta.dir, "..");
const ENTRY = join(PKG, "src", "bin", "kash.ts");
const OUT_DIR = join(PKG, "dist", "bin");
const SHEBANG = "#!/usr/bin/env node";

const result = await Bun.build({
  entrypoints: [ENTRY],
  outdir: OUT_DIR,
  target: "node",
  format: "esm",
  external: ["enquirer"],
});

if (!result.success) {
  for (const log of result.logs) console.error(log);
  throw new Error("kash bin bundle failed");
}

const jsOut = result.outputs.find((o) => o.path.endsWith(".js"));
if (jsOut === undefined) throw new Error("kash bin bundle produced no .js output");
const out = jsOut.path;

// Exactly one shebang line, whether or not Bun kept the entry's own.
let code = readFileSync(out, "utf8");
if (!code.startsWith("#!")) {
  code = `${SHEBANG}\n${code}`;
  writeFileSync(out, code);
}

// Executable on POSIX; unsupported (and harmless) on Windows.
try {
  chmodSync(out, 0o755);
} catch {
  /* chmod unsupported on this platform */
}

console.log(`✓ bundled ${out} (node-ready, self-contained ESM)`);
