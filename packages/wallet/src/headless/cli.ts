/**
 * `bun run headless [--seed <text>]` — run the wallet's practice scenarios and
 * print the report. Exit 1 if any scenario is red; pending is not a failure,
 * and is always listed. Nothing leaves the process: every host is in-process.
 */

import { formatReport } from "./report";
import { runWalletScenarios } from "./scenarios";

const args = process.argv.slice(2);
const at = args.indexOf("--seed");
const seed = at >= 0 && args[at + 1] !== undefined ? args[at + 1]! : "practice";

const results = await runWalletScenarios({ seed });
console.log(formatReport(results, seed));
process.exit(results.some((r) => r.status === "red") ? 1 : 0);
