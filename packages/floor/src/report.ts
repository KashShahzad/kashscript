/**
 * The report, as a person reads it: every finding with the decisions it enforces, every waiver with its reason, and
 * what the floor could not check.
 */

import { RULES } from "./rules.js";
import { citesOf, type Finding, type FloorReport } from "./check.js";

function line(f: Finding): string {
  const rule = f.rule === "manifest" ? "manifest" : f.rule;
  const where = f.where !== undefined ? `  (${f.where})` : "";
  const lines = [`  ✗ [${rule}] ${f.at} — ${f.what}${where}`];
  const cites = citesOf(f);
  if (cites.length > 0) lines.push(`      decisions: ${cites.join(" · ")}`);
  if (!f.waivable && f.rule !== "manifest") lines.push("      this finding cannot be waived");
  return lines.join("\n");
}

export function formatReport(r: FloorReport): string {
  const out: string[] = [];
  out.push(`kash-floor — ${r.repository ?? r.root}`);
  const byOracle = new Map<string, number>();
  for (const route of r.routes) {
    const kind = route.source.split(" ")[0] ?? route.source;
    byOracle.set(kind, (byOracle.get(kind) ?? 0) + 1);
  }
  if (byOracle.size > 0) out.push(`  mounted routes seen: ${[...byOracle].map(([k, n]) => `${k} ${n}`).join(" · ")}`);
  if (r.selftest.length > 0) {
    out.push("", "  ✗ the floor's own detector failed its self-test, so this run proves nothing:");
    for (const s of r.selftest) out.push(`      ${s}`);
  }
  const groups = new Map<string, Finding[]>();
  for (const f of r.findings) groups.set(f.rule, [...(groups.get(f.rule) ?? []), f]);
  for (const [rule, fs] of groups) {
    const title = rule === "manifest" ? "The manifest" : RULES[rule as keyof typeof RULES].title;
    out.push("", `${title} (${fs.length})`);
    for (const f of fs) out.push(line(f));
  }
  if (r.waived.length > 0) {
    out.push("", `Waived (${r.waived.length}) — each with its reason and decision`);
    for (const w of r.waived) out.push(`  ~ [${w.rule}] ${w.at} — ${w.what}`, `      waived: ${w.waiver.reason} (${w.waiver.decision})`);
  }
  for (const n of r.notes) out.push(`  note: ${n}`);
  out.push("");
  out.push(r.ok ? `✓ the floor holds${r.waived.length > 0 ? `, with ${r.waived.length} waiver(s)` : ""}` : `✗ ${r.findings.length} finding(s)${r.selftest.length > 0 ? " and a failed self-test" : ""}`);
  return out.join("\n");
}
