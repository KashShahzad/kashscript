// RW-17's Done-when: fixtures that break each rule fail — each with exactly the findings it was built to produce, each
// finding naming the decisions its rule enforces — and the clean fixture, shaped like the five repositories, passes.

import { describe, expect, test } from "bun:test";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { checkFloor } from "../src/check.js";
import { formatReport } from "../src/report.js";
import { CITE, RULES, type RuleId } from "../src/rules.js";
import { bootLogFor, citesBelong, copyFixture, pairs, runFixture, scratch } from "./helpers.js";

const EXPECTED: Record<string, string[]> = {
  "person-lookup": [
    "person-lookup | noun:GET /api/v1/members/:",
    "person-lookup | param:GET /api/v1/me/:#userId",
    "person-lookup | query:GET /api/v1/receipts?holderEmail",
    "person-lookup | route:GET /api/v1/dump",
    "person-lookup | route:GET /api/v1/find",
    "person-lookup | route:GET /api/v1/people/search",
    "person-lookup | route:GET /api/v1/users",
    "person-lookup | route:POST /api/v1/nudges",
  ],
  "person-score": [
    "person-score | lexicon:lexicons/review.schema.json#/properties/score",
    "person-score | lexicon:lexicons/transcript.ts#KASH_EDU_TRANSCRIPT_BODY_SCHEMA.grade",
    "person-score | prisma:Rating",
    "person-score | prisma:User.loginCount",
    "person-score | prisma:User.trustScore",
    "person-score | sql:profiles.reputation",
    "person-score | sql:trip_members.streak",
  ],
  "price-per-record": [
    'manifest | manifest.prices.fields["PRICES.legacy"]',
    "price-per-record | figure:src/page.tsx#USD 2.00",
    "price-per-record | price-name:src/billing.ts#Fees.perRequest",
    "price-per-record | price-name:src/prices.ts#PRICES.commissionPct",
    "price-per-record | price-name:src/prices.ts#PRICES.perCheck",
    "price-per-record | price-object:src/prices.ts#PRICES.outcome.link",
    "price-per-record | price-source:src/billing.ts#CHECK_FEE_USD",
    "price-per-record | price-tier:src/prices.ts#PRICES.tiers[].price",
    "price-per-record | price:src/prices.ts#PRICES.monthly",
  ],
  "declined-state": [
    "declined-state | filter:GET /api/v1/packets?outcome",
    "declined-state | prisma:Invite.status=DECLINED",
    "declined-state | sql:approvals.state=refused",
    "declined-state | state:GET /api/v1/asks/:id=declined",
    "declined-state | state:GET /api/v1/bookings=not_come",
    "declined-state | state:GET /api/v1/decisions=no",
  ],
  "unsuppressed-count": [
    'manifest | manifest.routes["GET /api/v1/stats"]',
    "unsuppressed-count | alias:tsconfig.json#paths",
    "unsuppressed-count | cast:src/cast.ts#fake",
    "unsuppressed-count | count:src/stores.ts#receiptsFor",
    "unsuppressed-count | k:src/k.ts#lowK",
    "unsuppressed-count | k:src/k.ts#varK",
    "unsuppressed-count | sql-aggregate:region",
    "unsuppressed-count | suppress:src/local.ts#<module>",
    "unsuppressed-count | suppress:src/shadow.ts#sneaky",
    "unsuppressed-count | type:north-star#[].receipts",
    "unsuppressed-count | type:untyped",
  ],
  "decision-without-rule": [
    "decision-without-rule | decision:lexicon:lexicons/decision.schema.json",
    "decision-without-rule | decision:lexicon:lexicons/decision.ts#DECISION_BODY",
    "decision-without-rule | decision:prisma:DoorDecision",
    "decision-without-rule | decision:prisma:Ruling",
    "decision-without-rule | decision:sql:decisions",
  ],
  "undeclared-route": [
    "undeclared-route | oracle:boot-log:boot.log",
    "undeclared-route | route:GET /b",
    "undeclared-route | route:GET /x",
    "undeclared-route | route:REST /rest/v1/people_directory",
    "undeclared-route | stale:GET /c",
  ],
  waivers: [
    "manifest | manifest.waivers[1]",
    "manifest | manifest.waivers[2]",
    "manifest | manifest.waivers[3]",
    "manifest | manifest.waivers[4].decision",
    "person-lookup | route:GET /api/v1/users",
    "person-score | prisma:User.streak",
  ],
};

describe("the clean fixture, shaped like the five repositories", () => {
  test("holds: no finding, no waiver, the self-test passes", () => {
    const r = runFixture("clean");
    expect(r.selftest).toEqual([]);
    expect(pairs(r)).toEqual([]);
    expect(r.waived).toEqual([]);
    expect(r.ok).toBe(true);
  });

  test("its oracles see every kind of mounted route", () => {
    const r = runFixture("clean");
    const texts = r.routes.map((x) => x.text).sort();
    expect(texts).toContain("GET /api/v1/receipts/:");
    expect(texts).toContain("PAGE web:/pricing"); // a route group is not a segment
    expect(texts).toContain("ACTION web/actions.ts#subscribe");
    expect(texts).toContain("ANY /functions/v1/hello");
    expect(texts).toContain("TOOL host.read_queue");
    expect(texts.some((t) => t.includes("_lib") || t.includes("_shared"))).toBe(false);
    const audit = r.routes.find((x) => x.text === "REST /rest/v1/audit_log");
    expect(audit?.closed).toBe(true); // row-level security and no policy: closed, and declared by the floor itself
    expect(r.routes.find((x) => x.text === "REST /rest/v1/profiles")?.self).toBe(true);
  });
});

describe("each broken fixture fails with exactly its findings", () => {
  for (const [name, expected] of Object.entries(EXPECTED)) {
    test(name, () => {
      const r = runFixture(name);
      expect(r.selftest).toEqual([]);
      expect(pairs(r)).toEqual([...expected].sort());
      expect(r.ok).toBe(false);
      expect(citesBelong(r)).toEqual([]);
      const printed = formatReport(r);
      for (const f of r.findings) for (const c of f.cites) expect(printed).toContain(CITE[c]);
    });
  }

  test("every rule has a fixture that breaks it", () => {
    const broken = new Set<string>();
    for (const name of Object.keys(EXPECTED)) for (const f of runFixture(name).findings) broken.add(f.rule);
    for (const id of Object.keys(RULES) as RuleId[]) expect(broken.has(id)).toBe(true);
  });

  test("what cannot be waived is marked so", () => {
    const lookup = runFixture("person-lookup");
    expect(lookup.findings.filter((f) => f.waivable).map((f) => f.at)).toEqual(["noun:GET /api/v1/members/:"]);
    const counts = runFixture("unsuppressed-count");
    const fixed = counts.findings.filter((f) => f.rule === "unsuppressed-count" && !f.waivable).map((f) => f.at.split(":")[0]);
    expect(new Set(fixed)).toEqual(new Set(["type", "cast", "k", "suppress", "count", "alias"]));
    expect(runFixture("undeclared-route").findings.every((f) => !f.waivable)).toBe(true);
  });

  test("a good waiver moves its finding to the waived list, which the report prints", () => {
    const r = runFixture("waivers");
    expect(r.waived.map((w) => `${w.rule} | ${w.at}`)).toEqual(["person-score | prisma:User.karma"]);
    expect(formatReport(r)).toContain("waived: the fixture's one good waiver (d64(g))");
  });
});

describe("changing one thing in the clean fixture is caught", () => {
  test("a raw count with no reason in the manifest", () => {
    const root = copyFixture("clean");
    const file = join(root, "floor.manifest.json");
    const m = JSON.parse(readFileSync(file, "utf8")) as { aggregates: Record<string, { raw?: unknown }> };
    delete m.aggregates["north-star"]!.raw;
    writeFileSync(file, JSON.stringify(m));
    const r = checkFloor({ root, bootLogs: bootLogFor(root) });
    expect(pairs(r)).toEqual(["unsuppressed-count | type:north-star#[].receiptsSignedByOthers"]);
  });

  test("a route the engine mounts that the manifest does not name", () => {
    const root = copyFixture("clean");
    const log = join(scratch(), "boot.log");
    writeFileSync(log, readFileSync(join(root, "boot-lines.jsonl"), "utf8").replace('"POST /api/v1/receipts"]', '"POST /api/v1/receipts","DELETE /api/v1/receipts/:receiptNo"]').replace('"endpoints":5', '"endpoints":6'));
    const r = checkFloor({ root, bootLogs: [log] });
    expect(pairs(r)).toEqual(["undeclared-route | route:DELETE /api/v1/receipts/:"]);
  });

  test("a person's table whose row policy lets anyone read it, declared as the caller's own", () => {
    const root = copyFixture("clean");
    const sql = join(root, "supabase", "migrations", "001_init.sql");
    writeFileSync(sql, readFileSync(sql, "utf8").replace("using (id = (select auth.uid()))", "using (true)"));
    const r = checkFloor({ root, bootLogs: bootLogFor(root) });
    expect(pairs(r)).toEqual(["person-lookup | policy:REST /rest/v1/profiles"]);
  });

  test("a price per check added to the price file", () => {
    const root = copyFixture("clean");
    const file = join(root, "src", "prices.ts");
    writeFileSync(file, readFileSync(file, "utf8").replace('asOf: "2026-11-15",', 'asOf: "2026-11-15",\n  perCheck: 0.05,'));
    const r = checkFloor({ root, bootLogs: bootLogFor(root) });
    expect(pairs(r)).toEqual(["price-per-record | price-name:src/prices.ts#PRICES.perCheck", "price-per-record | price:src/prices.ts#PRICES.perCheck"]);
  });
});
