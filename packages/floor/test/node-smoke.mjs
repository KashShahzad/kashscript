// The floor under plain Node, from its built dist/: the package's own CI runs it on itself (RW-17), on the clean
// fixture, and on every broken fixture. Three of the five repositories run their CI on Node (pnpm), so a dist that
// loads only under Bun would not do. `bun run test` builds first; run alone, build with `bun run build`.

import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const pkg = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(pkg, "dist", "bin", "floor.js");
const failures = [];

if (!existsSync(cli)) {
  console.error(`node-smoke: ${cli} is missing — run \`bun run build\` first`);
  process.exit(1);
}

function floor(args) {
  return spawnSync(process.execPath, [cli, ...args], { cwd: pkg, encoding: "utf8" });
}

function bootLog(fixture) {
  const lines = join(pkg, "test", "fixtures", fixture, "boot-lines.jsonl");
  if (!existsSync(lines)) return [];
  const f = join(mkdtempSync(join(tmpdir(), "floor-smoke-")), "boot.log");
  copyFileSync(lines, f);
  return ["--boot-log", f];
}

const self = floor(["check"]);
if (self.status !== 0) failures.push(`the floor on itself exited ${self.status}:\n${self.stdout}${self.stderr}`);

const clean = floor(["check", "--root", "test/fixtures/clean", ...bootLog("clean")]);
if (clean.status !== 0) failures.push(`the clean fixture exited ${clean.status}:\n${clean.stdout}${clean.stderr}`);

const broken = {
  "person-lookup": "person-lookup",
  "person-score": "person-score",
  "price-per-record": "price-per-record",
  "declined-state": "declined-state",
  "unsuppressed-count": "unsuppressed-count",
  "decision-without-rule": "decision-without-rule",
  "undeclared-route": "undeclared-route",
  waivers: "person-score",
};
for (const [fixture, rule] of Object.entries(broken)) {
  const r = floor(["check", "--root", `test/fixtures/${fixture}`, ...bootLog(fixture)]);
  if (r.status !== 1) failures.push(`${fixture}: exited ${r.status}, not 1:\n${r.stdout}${r.stderr}`);
  if (!r.stdout.includes(`[${rule}]`)) failures.push(`${fixture}: no [${rule}] finding in the output`);
  if (!/decisions: d\d/.test(r.stdout)) failures.push(`${fixture}: no finding names its decisions`);
}

const version = floor(["--version"]);
if (!/^kash-floor \S+ · typescript \d+\.\d+/.test(version.stdout)) failures.push(`--version printed: ${version.stdout}${version.stderr}`);

const runtime = await import(pathToFileURL(join(pkg, "dist", "index.js")).href);
if (runtime.suppress(4) !== null || runtime.suppress(5) !== 5 || runtime.FLOOR_K !== 5) failures.push("the runtime's suppress does not hold under Node");

if (failures.length > 0) {
  for (const f of failures) console.error(`node-smoke: ${f}`);
  process.exit(1);
}
console.log(`node-smoke ok — Node ${process.version}, ${version.stdout.trim()}: the floor on itself, the clean fixture and ${Object.keys(broken).length} broken ones, from dist/`);
