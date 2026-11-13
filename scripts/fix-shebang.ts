#!/usr/bin/env bun
/**
 * scripts/fix-shebang.ts
 *
 * Run from `packages/kash/prepack`. Ensures every file referenced by the
 * publishConfig.bin map starts with the `#!/usr/bin/env node` shebang
 * AND has the executable bit set on POSIX. tsc preserves shebangs from
 * 3.9+, but the source bin file may be authored with the `bun` shebang
 * for local development — we rewrite to `node` at publish time so the
 * tarball runs cleanly under `npx`, `pnpm dlx`, and so on.
 */

import { existsSync, readFileSync, writeFileSync, chmodSync } from "node:fs";
import { join, resolve } from "node:path";

const PKG_DIR = resolve(__dirname, "..", "packages", "cli");
const pj = JSON.parse(readFileSync(join(PKG_DIR, "package.json"), "utf-8")) as {
  publishConfig?: { bin?: Record<string, string> };
};
const binMap = pj.publishConfig?.bin ?? {};
if (Object.keys(binMap).length === 0) {
  console.error("[fix-shebang] publishConfig.bin is empty — nothing to fix.");
  process.exit(1);
}

const NODE_SHEBANG = "#!/usr/bin/env node\n";
let fixed = 0;

for (const [name, relPath] of Object.entries(binMap)) {
  const abs = join(PKG_DIR, relPath);
  if (!existsSync(abs)) {
    console.error(`[fix-shebang] missing bin target for "${name}": ${abs}`);
    console.error(`[fix-shebang] did you run \`bun run build\` first?`);
    process.exit(2);
  }
  const original = readFileSync(abs, "utf-8");
  let body = original;

  // Strip any existing shebang line.
  if (body.startsWith("#!")) {
    body = body.slice(body.indexOf("\n") + 1);
  }
  const next = NODE_SHEBANG + body;
  if (next !== original) {
    writeFileSync(abs, next, "utf-8");
    fixed++;
    console.log(`[fix-shebang] rewrote shebang in ${relPath}`);
  } else {
    console.log(`[fix-shebang] ${relPath} already has node shebang.`);
  }

  // Best-effort chmod +x on POSIX. On Windows this is a no-op (mode 0o755
  // is meaningless for NTFS), but won't error.
  try { chmodSync(abs, 0o755); } catch { /* swallow */ }
}

console.log(`[fix-shebang] done. ${fixed} file(s) updated.`);
