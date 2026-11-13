import { describe, expect, test } from "bun:test";
import { confirmLanding, type LandingTarget } from "./confirm-landing";

/** A fake registry. `lagPolls`: how many polls answer "nothing there" before a version appears. */
function fakeRegistry(state: {
  versions: Record<string, { lagPolls: number; main?: string }>;
  tags: Record<string, Record<string, string>>;
  latest?: Record<string, string>;
}) {
  const calls: string[] = [];
  const polls: Record<string, number> = {};
  let clock = 0;
  const view = (spec: string, field: string): string => {
    calls.push(`${spec} ${field}`);
    const at = spec.lastIndexOf("@");
    if (at > 0) {
      const v = state.versions[spec];
      polls[spec] = (polls[spec] ?? 0) + (field === "version" ? 1 : 0);
      if (v === undefined || polls[spec]! <= v.lagPolls) return "";
      return field === "version" ? spec.slice(at + 1) : field === "main" ? (v.main ?? "./dist/index.js") : "";
    }
    // A bare package name: only dist-tags.<tag> may be read. `version` here is `latest` — the old bug.
    if (field === "version") return state.latest?.[spec] ?? "";
    if (field.startsWith("dist-tags.")) return state.tags[spec]?.[field.slice("dist-tags.".length)] ?? "";
    return "";
  };
  return { view, calls, now: () => clock, sleep: async (ms: number) => { clock += ms; } };
}

const attest: LandingTarget = { name: "@kashscript/attest", version: "0.2.0-alpha.2", tag: "alpha" };
const core: LandingTarget = { name: "@kashscript/identity-core", version: "0.4.0-alpha.0", tag: "alpha" };

describe("confirmLanding", () => {
  test("an alpha publish lands even though `latest` is an older version — the case the old check could never pass", async () => {
    const reg = fakeRegistry({
      versions: { "@kashscript/attest@0.2.0-alpha.2": { lagPolls: 0 } },
      tags: { "@kashscript/attest": { alpha: "0.2.0-alpha.2", latest: "0.1.8" } },
      latest: { "@kashscript/attest": "0.1.8" },
    });
    const [r] = await confirmLanding([attest], { ...reg, deadlineMs: 60_000, intervalMs: 10_000 });
    expect(r!.landed).toBe(true);
    expect(r!.main).toBe("./dist/index.js");
    // It never read the bare package's `version` (that is `latest`).
    expect(reg.calls).not.toContain("@kashscript/attest version");
  });

  test("a registry that lags is waited for, polling the exact version", async () => {
    const reg = fakeRegistry({
      versions: { "@kashscript/attest@0.2.0-alpha.2": { lagPolls: 3 } },
      tags: { "@kashscript/attest": { alpha: "0.2.0-alpha.2" } },
    });
    const [r] = await confirmLanding([attest], { ...reg, deadlineMs: 300_000, intervalMs: 10_000 });
    expect(r!.landed).toBe(true);
    expect(reg.now()).toBe(30_000); // three empty polls, three waits of 10 s, landed on the fourth
  });

  test("a version that never appears is reported as not landed after the deadline, never as a stale success", async () => {
    const reg = fakeRegistry({
      versions: {},
      tags: { "@kashscript/attest": { alpha: "0.2.0-alpha.1", latest: "0.1.8" } },
      latest: { "@kashscript/attest": "0.1.8" },
    });
    const [r] = await confirmLanding([attest], { ...reg, deadlineMs: 120_000, intervalMs: 10_000 });
    expect(r!.landed).toBe(false);
    expect(r!.main).toBe("");
    expect(reg.now()).toBeGreaterThanOrEqual(120_000);
  });

  test("a visible version whose tag points elsewhere is not confirmed", async () => {
    const reg = fakeRegistry({
      versions: { "@kashscript/attest@0.2.0-alpha.2": { lagPolls: 0 } },
      tags: { "@kashscript/attest": { alpha: "0.2.0-alpha.1" } },
    });
    const [r] = await confirmLanding([attest], { ...reg, deadlineMs: 30_000, intervalMs: 10_000 });
    expect(r!.landed).toBe(false);
  });

  test("a main outside ./dist/ is not confirmed", async () => {
    const reg = fakeRegistry({
      versions: { "@kashscript/attest@0.2.0-alpha.2": { lagPolls: 0, main: "./src/index.ts" } },
      tags: { "@kashscript/attest": { alpha: "0.2.0-alpha.2" } },
    });
    const [r] = await confirmLanding([attest], { ...reg, deadlineMs: 30_000, intervalMs: 10_000 });
    expect(r!.landed).toBe(false);
  });

  test("several packages are judged separately; one slow package does not hide another that landed", async () => {
    const reg = fakeRegistry({
      versions: {
        "@kashscript/identity-core@0.4.0-alpha.0": { lagPolls: 0 },
        "@kashscript/attest@0.2.0-alpha.2": { lagPolls: 1_000 },
      },
      tags: { "@kashscript/identity-core": { alpha: "0.4.0-alpha.0" }, "@kashscript/attest": { alpha: "0.2.0-alpha.2" } },
    });
    const out = await confirmLanding([core, attest], { ...reg, deadlineMs: 60_000, intervalMs: 10_000 });
    expect(out.map((r) => [r.target.name, r.landed])).toEqual([
      ["@kashscript/identity-core", true],
      ["@kashscript/attest", false],
    ]);
  });
});
