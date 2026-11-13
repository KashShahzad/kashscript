import { describe, expect, test } from "bun:test";
import { formatReport, runWalletScenarios, WALLET_SCENARIOS } from "../src/headless";

describe("the wallet's scenarios in the simulation's set", () => {
  test("receive, present, decline, export and recover — a lost phone, recovered by helpers (PL-2) — are all green", async () => {
    const results = await runWalletScenarios({ seed: "ci" });
    expect(results.map((r) => r.name)).toEqual([...WALLET_SCENARIOS]);
    const status = Object.fromEntries(results.map((r) => [r.name, r.status]));
    expect(status).toEqual({ receive: "green", present: "green", decline: "green", export: "green", recover: "green" });
    for (const r of results) {
      const failed = [...r.checks, ...r.constitution].filter((a) => !a.ok);
      expect({ scenario: r.name, failed }).toEqual({ scenario: r.name, failed: [] });
      expect(r.constitution.length).toBe(7);
    }
    const report = formatReport(results, "ci");
    expect(report.split("\n")[0]).toBe("practice run — not a real-world fact");
    expect(report).toContain("red: none · pending: none");
  }, 120_000);
});
