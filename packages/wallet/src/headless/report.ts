/** The plain report a practice run prints. Its first line is not optional (d11). */

import { DEFAULT_COPY } from "../copy";
import { WALLET_VERSION } from "../index";
import type { ScenarioResult } from "./scenarios";

export function formatReport(results: readonly ScenarioResult[], seed = "practice"): string {
  const lines = [DEFAULT_COPY.practiceHeading, `@kashscript/wallet ${WALLET_VERSION} · headless · seed "${seed}"`, ""];
  for (const r of results) {
    const all = [...r.checks, ...r.constitution];
    const passed = all.filter((a) => a.ok).length;
    const tag = r.status === "green" ? "GREEN  " : r.status === "pending" ? "PENDING" : "RED    ";
    lines.push(`${r.name.padEnd(8)} ${tag} ${passed}/${all.length} checks${r.status !== "green" && r.reason !== null ? ` — ${r.reason}` : ""}`);
    for (const a of all) if (!a.ok) lines.push(`         ✗ ${a.name}${a.detail ? ` (${a.detail})` : ""}`);
  }
  const red = results.filter((r) => r.status === "red").map((r) => r.name);
  const pending = results.filter((r) => r.status === "pending").map((r) => r.name);
  lines.push("", `red: ${red.length === 0 ? "none" : red.join(", ")} · pending: ${pending.length === 0 ? "none" : pending.join(", ")}`);
  return lines.join("\n");
}
