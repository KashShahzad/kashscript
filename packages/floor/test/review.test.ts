// The fresh-session review of 5ddecaf (RW-17, run on Opus 2026-11-24): each bypass it confirmed is pinned shut here.

import { describe, expect, test } from "bun:test";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { checkFloor } from "../src/check.js";
import { scratch } from "./helpers.js";

function repo(files: Record<string, string | object>): string {
  const root = scratch("floor-review-");
  for (const [rel, body] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, typeof body === "string" ? body : JSON.stringify(body));
  }
  return root;
}

const ats = (root: string): string[] => checkFloor({ root }).findings.map((f) => `${f.rule} | ${f.at}`).sort();

describe("1. coverage is not opt-in", () => {
  test("an almost empty manifest fails: the floor finds the routes, schemas and sources itself", () => {
    const root = repo({
      "floor.manifest.json": { floor: 1 },
      "web/next.config.mjs": "export default {};",
      "web/app/api/users/search/route.ts": "export async function GET() { return new Response(); }",
      "web/pages/api/legacy.ts": "export default function h() {}",
      "prisma/schema.prisma": "model User {\n  id String @id\n  trustScore Int\n}",
      "db/migrations/001.sql": "create table t (a int);",
      "supabase/migrations/001.sql": "create table s (a int);",
      "worker/wrangler.toml": 'name = "go"',
      "src/stats.ts": "export const n = 1;",
    });
    expect(ats(root)).toEqual([
      "manifest | coverage:next-app:web/app",
      "manifest | coverage:next-pages:web/pages",
      "manifest | coverage:oracles",
      "manifest | coverage:prisma:prisma/schema.prisma",
      "manifest | coverage:sources:src",
      "manifest | coverage:sources:web",
      "manifest | coverage:sources:web/app",
      "manifest | coverage:sources:web/pages",
      "manifest | coverage:sql:db/migrations/001.sql",
      "manifest | coverage:supabase:supabase",
      "manifest | coverage:worker:worker/wrangler.toml",
    ]);
  });

  test("what is excluded says why, and then is not looked for", () => {
    const root = repo({
      "floor.manifest.json": { floor: 1, serves: "none", excluded: { "scripts/**": "the founder's local tools, never deployed" } },
      "scripts/x.ts": "export const x = 1;",
    });
    expect(ats(root)).toEqual([]);
  });
});

describe("2. no catch-all route keys", () => {
  test("GET /** declares nothing; a two-segment prefix and pages are allowed", () => {
    const root = repo({
      "floor.manifest.json": {
        floor: 1,
        serves: "none",
        routes: {
          "GET /**": { subject: "organisation", shape: "one", outsideOracle: "x" },
          "GET /api/v1/*": { subject: "organisation", shape: "one", outsideOracle: "x" },
          "TOOL *": { subject: "record", shape: "one", outsideOracle: "x" },
          "PAGE /**": { subject: "public", shape: "one", outsideOracle: "x" },
        },
      },
    });
    expect(ats(root)).toEqual(['manifest | manifest.routes["GET /**"]', 'manifest | manifest.routes["TOOL *"]']);
  });
});

describe("3. waivers name one finding and cite what allows the exception", () => {
  test("a wildcard waiver is refused and waives nothing; a percentage needs d63(a)", () => {
    const root = repo({
      "floor.manifest.json": {
        floor: 1,
        serves: "none",
        schemas: { prisma: ["schema.prisma"] },
        sources: ["src/*.ts"],
        waivers: [
          { rule: "person-score", at: "*", reason: "a signing grade", decision: "d91(e)" },
          { rule: "price-per-record", at: "price-source:src/c.ts#COMMISSION_RATE_BPS", reason: "the marketplace's commission", decision: "d96(b), d64(g)" },
        ],
      },
      "schema.prisma": "model User {\n  id String @id\n  trustScore Int\n}",
      "src/c.ts": "export const COMMISSION_RATE_BPS = 500;",
    });
    expect(ats(root)).toEqual([
      "manifest | manifest.waivers[0].at",
      "manifest | manifest.waivers[1]",
      "person-score | prisma:User.trustScore",
      "price-per-record | price-source:src/c.ts#COMMISSION_RATE_BPS",
    ]);
  });
});

describe("4–5. counts do not escape", () => {
  test("glob count keys, Supabase's count option, a cast to any, an average, served counter columns, a counterfeit floor_suppress", () => {
    const root = repo({
      "floor.manifest.json": {
        floor: 1,
        oracles: [{ kind: "supabase", dir: "supabase" }],
        routes: {
          "REST /rest/v1/kumak_reports": { subject: "record", shape: "list" },
          "RPC /rest/v1/rpc/floor_suppress": { subject: "public", shape: "action" },
          "RPC /rest/v1/rpc/stars": { subject: "place", shape: "aggregate", aggregates: ["stars"] },
        },
        aggregates: { people: { file: "src/agg.ts", export: "people" }, stars: { sql: "stars" } },
        counts: { "src/*.ts#*": { kind: "own", why: "ours" } },
        sources: ["src/*.ts", "supabase/functions/**/*.ts"],
      },
      "src/agg.ts": 'import type { FloorCount } from "@kashscript/floor";\nexport async function people(rows: unknown[]): Promise<{ people: FloorCount }> { return { people: rows.length } as any; }\n',
      "src/q.ts": 'export async function visits(db: any) { return db.from("visits").select("*", { count: "exact", head: true }); }\n',
      "supabase/migrations/001.sql": [
        "create table public.kumak_reports (id uuid primary key, reporter_id uuid, endorsement_count int not null default 0);",
        "alter table public.kumak_reports enable row level security;",
        'create policy "read" on public.kumak_reports for select using (true);',
        "create function public.floor_suppress(n numeric, k integer default 5) returns numeric language sql as $$ select n $$;",
        "create function public.stars() returns numeric language sql as $$ select floor_suppress(count(*)), avg(r.stars) from reviews r $$;",
      ].join("\n"),
    });
    expect(ats(root)).toEqual([
      'manifest | manifest.counts["src/*.ts#*"]',
      "unsuppressed-count | cast-any:people",
      "unsuppressed-count | count:sql:kumak_reports.endorsement_count",
      "unsuppressed-count | count:src/q.ts#visits",
      "unsuppressed-count | counterfeit:sql:public.floor_suppress",
      "unsuppressed-count | sql-aggregate:stars",
    ]);
  });
});

describe("6. person lookups", () => {
  test("an email in the path, a DID in the path, a noun not on the old list, an RPC by email, an RPC that returns persons, a policy that only checks sign-in", () => {
    const root = repo({
      "floor.manifest.json": {
        floor: 1,
        oracles: [{ kind: "supabase", dir: "supabase" }],
        routes: {
          "GET /api/records/[email]": { subject: "record", shape: "one", outsideOracle: "x" },
          "GET /api/receipts/by-did/[did]": { subject: "record", shape: "list", outsideOracle: "x" },
          "GET /api/candidates/search": { subject: "record", shape: "search", outsideOracle: "x" },
          "RPC /rest/v1/rpc/who": { subject: "record", shape: "one" },
          "REST /rest/v1/profiles": { subject: "person", shape: "self" },
        },
      },
      "supabase/migrations/001.sql": [
        "create table public.profiles (id uuid primary key, name text);",
        "alter table public.profiles enable row level security;",
        'create policy "signed in" on public.profiles for select using (auth.uid() is not null);',
        "create function public.who(p_email text) returns setof public.profiles language sql security definer as $$ select * from profiles $$;",
      ].join("\n"),
    });
    expect(ats(root)).toEqual([
      "person-lookup | arg:RPC /rest/v1/rpc/who#p_email",
      "person-lookup | noun:GET /api/candidates/search",
      "person-lookup | param:GET /api/receipts/by-did/:#did",
      "person-lookup | param:GET /api/records/:#email",
      "person-lookup | policy:REST /rest/v1/profiles",
      "person-lookup | returns:RPC /rest/v1/rpc/who",
    ]);
  });

  test("a person's own aggregate is refused: totals are of many", () => {
    const root = repo({
      "floor.manifest.json": {
        floor: 1,
        serves: "none",
        routes: { "GET /api/users/[id]/stats": { subject: "person", shape: "aggregate", aggregates: ["s"], outsideOracle: "x" } },
        aggregates: { s: { sql: "s" } },
        schemas: { sql: ["db/*.sql"] },
      },
      "db/001.sql": "create function s() returns numeric language sql as $$ select floor_suppress(count(*)) from t $$;",
    });
    expect(ats(root)).toEqual(["person-lookup | route:GET /api/users/[id]/stats"]);
  });
});

describe("7–8. scores and declines the first lists missed", () => {
  test("an operator's error count, an assignee's lateness, a driver's on-time rate; an RSVP's decline; a rejection kept on a person's row", () => {
    const root = repo({
      "floor.manifest.json": { floor: 1, serves: "none", schemas: { prisma: ["schema.prisma"], sql: ["db/*.sql"] } },
      "schema.prisma": [
        "model Handoff {\n  id String @id\n  operatorDid String\n  errorCount Int\n}",
        "model Driver {\n  id String @id\n  onTimeRate Float\n}",
      ].join("\n"),
      "db/001.sql": [
        "create table rsvps (id uuid, user_id uuid, status text check (status in ('going', 'declined')));",
        "create table applications (id uuid, user_id uuid, status text check (status in ('accepted', 'rejected')));",
      ].join("\n"),
    });
    expect(ats(root)).toEqual([
      "decision-without-rule | refusal:sql:applications.status=rejected",
      "declined-state | sql:rsvps.status=declined",
      "person-score | prisma:Driver.onTimeRate",
      "person-score | prisma:Handoff.errorCount",
    ]);
  });
});

describe("9. prices the first lists missed", () => {
  test("a price per credential, an API call's price, a host's share and a royalty", () => {
    const root = repo({
      "floor.manifest.json": {
        floor: 1,
        serves: "none",
        sources: ["prices.ts"],
        prices: { files: ["prices.ts"], fields: { "P.pricePerCredential": "outcome", "P.apiCallPrice": "outcome", "P.hostShare": "flat", "P.royalty": "flat" } },
      },
      "prices.ts": "export const P = { pricePerCredential: 1, apiCallPrice: 0.1, hostShare: 0.95, royalty: 0.07 };",
    });
    expect(ats(root)).toEqual([
      "price-per-record | price-name:prices.ts#P.apiCallPrice",
      "price-per-record | price-name:prices.ts#P.hostShare",
      "price-per-record | price-name:prices.ts#P.pricePerCredential",
      "price-per-record | price-name:prices.ts#P.royalty",
      "price-per-record | price-object:prices.ts#P",
    ]);
  });
});

describe("12. false positives the review measured", () => {
  test("a regex replacement is not a price figure; a kebab-case data key is not a commission; a deliverable's outcome is not a decision", () => {
    const root = repo({
      "floor.manifest.json": { floor: 1, serves: "none", sources: ["src/*.ts"], schemas: { prisma: ["schema.prisma"] } },
      "src/log.ts": 'export const redact = (s: string) => s.replace(/(token=)\\S+/, "$1[secret]");\nexport const PLACES = { "pakistan-atomic-energy-commission-headquarters": { lat: 33.7 } };\n',
      "schema.prisma": "model WorkItem {\n  id String @id\n  outcome String\n}",
    });
    expect(ats(root)).toEqual([]);
  });
});

describe("11. the Pages Router", () => {
  test("pages/api routes are API routes; _app is not a route", () => {
    const root = repo({
      "floor.manifest.json": { floor: 1, oracles: [{ kind: "next-pages", dir: "web/pages" }], sources: ["web/**/*.{ts,tsx,mjs}"] },
      "web/next.config.mjs": "export default {};",
      "web/pages/api/users.ts": "export default function h() {}",
      "web/pages/index.tsx": "export default function P() { return null; }",
      "web/pages/_app.tsx": "export default function A() { return null; }",
    });
    expect(checkFloor({ root }).routes.map((r) => r.text).sort()).toEqual(["ANY /api/users", "PAGE /"]);
  });
});
