/**
 * Signed down the chain, rule version 1 (KS-Q9; ECOSYSTEM d94(c)) — the rulebook's shape.
 * `docs/rulebooks/signed-down-the-chain/v1/rule.json` is content, not code: it is read
 * here from where it is published and validated against `kash.rule@1.1.0`. Its meaning —
 * the floor, the FEEL, the DCQL — is `@kashscript/predicate`'s test of the same file.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { validateBody } from "../src/engine";
import { LexiconRegistry } from "../src/registry";
import { validate } from "../src/schema";
import { DOOR_LEXICONS, GIVENS, KASH_RULE_1_1_ID, KASH_RULE_BODY_SCHEMA, type RuleBody1_1 } from "../src/extensions/door";

const registry = new LexiconRegistry().registerAll(DOOR_LEXICONS);
const RULEBOOK = join(import.meta.dir, "..", "..", "..", "docs", "rulebooks", "signed-down-the-chain", "v1");
const rule = JSON.parse(readFileSync(join(RULEBOOK, "rule.json"), "utf8")) as RuleBody1_1;

describe("Signed down the chain v1 — a kash.rule@1.1.0 record", () => {
  test("rule.json has the 1.1.0 shape", () => {
    const r = validateBody(KASH_RULE_1_1_ID, rule, registry);
    expect(r.ok ? [] : r.errors).toEqual([]);
  });

  test("it is a 1.1.0 rule: the frozen 1.0.0 shape refuses its address and subjects", () => {
    expect(validate(KASH_RULE_BODY_SCHEMA, rule).ok).toBe(false);
  });

  test("its slug, its version and its author", () => {
    expect(rule.id).toBe(`${rule.author}/rule/signed-down-the-chain`);
    expect(rule.version).toBe(1);
    expect(rule.visibility).toBe("public");
    expect(rule.draft).toBeUndefined();
  });

  test("every criterion is about an organisation — never a person", () => {
    expect(rule.criteria.map((c) => c.subject)).toEqual(["organisation", "organisation", "organisation", "organisation", "organisation"]);
  });

  test("its address: computer programming, the work family, KashScript's own rule, earn and spend, all seven givens", () => {
    const a = rule.address!;
    expect(a.sector).toEqual({ classification: "ISIC", revision: "5", code: "62" });
    expect(a.anchorFamily).toBe("work");
    expect(a.authority).toEqual({ kind: "institution", name: "KashScript (the studio)", url: "https://www.kashscript.com" });
    expect(a.journey).toBe("earn-and-spend");
    for (const g of GIVENS) expect((a.givens[g] as { readonly text: string } | undefined)?.text.trim().length ?? 0).toBeGreaterThan(0);
    expect(a.givens.area?.anywhere).toBe(true);
    expect(a.givens.spaces?.kinds).toEqual(["workplace", "online"]);
    expect(a.givens.capitals?.needs?.map((n) => n.kind)).toEqual(["people", "systems"]);
    expect(a.givens.economy?.level).toBe("tertiary");
  });

  test("it ends twelve months after publication, and is renewed before it ends (d43)", () => {
    const published = new Date(rule.dates.published);
    const ends = new Date(rule.dates.endsAt);
    const months = (ends.getUTCFullYear() - published.getUTCFullYear()) * 12 + (ends.getUTCMonth() - published.getUTCMonth());
    expect(months).toBe(12);
    expect(ends.getUTCDate()).toBe(published.getUTCDate());
    expect(Date.parse(rule.dates.renewBy)).toBeGreaterThan(published.getTime());
    expect(Date.parse(rule.dates.renewBy)).toBeLessThan(ends.getTime());
  });
});
