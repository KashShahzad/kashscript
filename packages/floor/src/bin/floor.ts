#!/usr/bin/env node
/**
 * kash-floor — the floor as tests (RW-17).
 *
 *   kash-floor check  [--root <dir>] [--manifest <file>] [--boot-log <file>]… [--json]
 *   kash-floor routes [--root <dir>] [--manifest <file>] [--boot-log <file>]… [--draft]
 *   kash-floor --version
 *
 * Exit 0 when the floor holds, 1 on findings (or a failed self-test), 2 on a usage error or an unreadable manifest.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const USAGE = `kash-floor check  [--root <dir>] [--manifest <file>] [--boot-log <file>]... [--json]
kash-floor routes [--root <dir>] [--manifest <file>] [--boot-log <file>]... [--draft]
kash-floor --version`;

function version(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const up of ["../../package.json", "../package.json"]) {
      try {
        return (JSON.parse(readFileSync(join(here, up), "utf8")) as { version: string }).version;
      } catch {
        // try the next
      }
    }
  } catch {
    // fall through
  }
  return "unknown";
}

async function main(argv: readonly string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  if (cmd === "--version" || cmd === "-v") {
    let tsVersion = "absent";
    try {
      tsVersion = (await import("typescript")).default.version;
    } catch {
      // the scanner's peer is not installed
    }
    process.stdout.write(`kash-floor ${version()} · typescript ${tsVersion}\n`);
    return 0;
  }
  if (cmd !== "check" && cmd !== "routes") {
    process.stderr.write(`${USAGE}\n`);
    return cmd === undefined || cmd === "--help" || cmd === "-h" ? 0 : 2;
  }
  let root = process.cwd();
  let manifest: string | undefined;
  const bootLogs: string[] = [];
  let json = false;
  let draft = false;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const next = (): string | undefined => rest[++i];
    if (a === "--root") root = next() ?? root;
    else if (a === "--manifest") manifest = next();
    else if (a === "--boot-log") {
      const f = next();
      if (f !== undefined) bootLogs.push(f);
    } else if (a === "--json") json = true;
    else if (a === "--draft") draft = true;
    else {
      process.stderr.write(`unknown argument: ${a}\n${USAGE}\n`);
      return 2;
    }
  }
  try {
    await import("typescript");
  } catch {
    process.stderr.write("kash-floor needs the typescript package to read sources (a peer dependency): add typescript (5.x or 6.x) to your devDependencies.\n");
    return 2;
  }
  const { checkFloor, ManifestUnreadable } = await import("../check.js");
  const { formatReport } = await import("../report.js");
  let report;
  try {
    report = checkFloor({ root, ...(manifest !== undefined ? { manifest } : {}), bootLogs });
  } catch (e) {
    if (e instanceof ManifestUnreadable) {
      process.stderr.write(`${e.message}\n`);
      return 2;
    }
    throw e;
  }
  if (cmd === "routes") {
    const undeclared = new Set(report.findings.filter((f) => f.rule === "undeclared-route" && f.at.startsWith("route:")).map((f) => f.at.slice("route:".length)));
    if (draft) {
      const out: Record<string, { subject: string; shape: string }> = {};
      for (const r of report.routes) if (undeclared.has(r.text)) out[r.text] = { subject: "?", shape: "?" };
      process.stdout.write(`${JSON.stringify(out, null, 2)}\n`);
    } else {
      for (const r of report.routes) {
        const state = undeclared.has(r.text) ? "undeclared" : r.closed ? "closed" : "declared";
        process.stdout.write(`${state.padEnd(10)} ${r.text}   (${r.source})\n`);
      }
    }
    return 0;
  }
  process.stdout.write(`${json ? JSON.stringify(report, null, 2) : formatReport(report)}\n`);
  return report.ok ? 0 : 1;
}

// exitCode, not exit(): a long report piped to another program is never cut short.
main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e: unknown) => {
    process.stderr.write(`kash-floor: ${(e as Error).stack ?? String(e)}\n`);
    process.exitCode = 2;
  },
);
