/**
 * The detector proves itself on every run (Indusland's check-desk does the same): a handful of cases each rule must
 * catch, and a few it must let pass. A TypeScript version, a parser change or a word list edited by mistake that
 * stops a rule from finding anything fails the run instead of passing it quietly.
 *
 * The cases are strings, never files; the SQL among them is classified in the package's own manifest.
 */

import { normalizePath, parseRouteKey, covers } from "./manifest.js";
import { globToRegExp } from "./scan/files.js";
import { schemaObjects } from "./scan/json-schema.js";
import { emptySchema, readPrisma, resolveRelations } from "./scan/prisma.js";
import { emptySqlModel, everyCountWrapped, readSql, relationClosed, columnValues, functionClosed } from "./scan/sql.js";
import { Sources, leaves, typeTree, valueTree, ts } from "./scan/ts.js";
import { countSites, dslObjects, exportedFunction, routeMethods, suppressHits, tableEntries } from "./scan/ts-scans.js";
import { declineKind, forbiddenPrice, isPersonIdentifier, isSubjectRef, scoreShaped, tokens } from "./scan/words.js";

export function runSelftest(): string[] {
  const failures: string[] = [];
  const expect = (ok: boolean, what: string): void => {
    if (!ok) failures.push(what);
  };
  try {
    // words
    expect(tokens("COMMISSION_RATE_BPS").join(" ") === "commission rate bps", "tokens: COMMISSION_RATE_BPS");
    expect(scoreShaped("trustScore", "User") && scoreShaped("loginCount", "Account"), "a score and a count on a person are score-shaped");
    expect(!scoreShaped("grade", "Acceptance") && scoreShaped("grade", "Transcript"), "a signing grade passes; another grade does not");
    expect(!scoreShaped("totalPkr", "Booking"), "a money total is not a count");
    expect(declineKind("DECLINED") === "decline" && declineKind("not_come") === "no-show" && declineKind("no") === "refusal" && declineKind("not-yet") === undefined, "decline words");
    expect(forbiddenPrice("perCheck", true) !== undefined && forbiddenPrice("maxPerRequest", false) === undefined && forbiddenPrice("COMMISSION_RATE_BPS", false) !== undefined, "price words");
    expect(isPersonIdentifier("holderDid", "record") && !isPersonIdentifier("id", "record") && isPersonIdentifier("email", "public"), "person identifiers");
    expect(isSubjectRef("user_id") && !isSubjectRef("reporter_id") && !isSubjectRef("ownerAccountId"), "subject and actor columns");

    // globs and route keys
    expect(globToRegExp("apps/*/src/**/*.{ts,tsx}").test("apps/web/src/a/b.tsx") && !globToRegExp("apps/*/src/**/*.ts").test("apps/web/lib/a.ts"), "globs");
    expect(normalizePath("/a/[id]/:b/{c}/[...rest]") === "/a/:/:/:/:*", "route parameters normalise");
    const glob = parseRouteKey("PAGE web:/**");
    const page = parseRouteKey("PAGE web:/explore/places");
    expect(glob !== undefined && page !== undefined && covers(glob, page), "a glob key covers a page");

    // Prisma
    const schema = emptySchema();
    readPrisma(schema, "self.prisma", "model User {\n  id String @id // a comment, with \"quotes\"\n  trustScore Float\n  posts Post[]\n}\nmodel Post {\n  id String @id\n  user User @relation(fields: [userId], references: [id])\n  userId String\n}\nenum S { SENT DECLINED }");
    resolveRelations(schema);
    expect(schema.models.get("User")?.fields.some((f) => f.name === "trustScore") === true && schema.models.get("Post")?.fields.find((f) => f.name === "user")?.relation === true && schema.enums.get("S")?.includes("DECLINED") === true, "Prisma models, relations and enums");

    // SQL
    const sql = emptySqlModel();
    readSql(
      sql,
      "self.sql",
      [
        "create table public.invites (id uuid primary key, user_id uuid references profiles(id), status text not null check (status in ('sent', 'declined')));",
        "alter table invites enable row level security;",
        "create or replace function public.tally() returns bigint language sql as $$ select count(*) from invites; create table hidden (a int); $$;",
        "revoke execute on function public.tally() from public, anon, authenticated;",
        "-- create table commented_out (a int);",
      ].join("\n"),
    );
    const inv = sql.relations.get("public.invites");
    const status = inv?.columns.get("status");
    expect(inv !== undefined && status !== undefined && columnValues(sql, inv, status).includes("declined"), "SQL check values");
    expect(inv !== undefined && relationClosed(inv), "row-level security with no policy closes a table");
    expect(!sql.relations.has("public.hidden") && !sql.relations.has("public.commented_out"), "SQL in a body or a comment is not read");
    const tally = sql.functions.get("public.tally");
    expect(tally !== undefined && functionClosed(tally) && !everyCountWrapped(tally.body).wrapped, "SQL functions, revokes and counts");
    expect(everyCountWrapped("select floor_suppress(count(*)) from t").wrapped, "floor_suppress wraps a count");

    // JSON Schema
    expect(schemaObjects({ properties: { a: { type: "object", properties: { b: {} } } } }).length === 2, "lexicon objects");

    // TypeScript
    const sources = new Sources("/selftest");
    const floor = { self: false };
    const notFloor = sources.put("/selftest/a.ts", "const suppress = (n: number) => n;\nexport const x = suppress(3);\n");
    expect(suppressHits(notFloor, "/selftest/a.ts", floor, false).some((h) => h.kind === "not-floor"), "a local suppress is not the floor's");
    const lowK = sources.put("/selftest/b.ts", 'import { suppress as s } from "@kashscript/floor";\nexport const y = s(3, 2);\nexport const z = s(9);\n');
    const lowHits = suppressHits(lowK, "/selftest/b.ts", floor, false);
    expect(lowHits.length === 1 && lowHits[0]?.kind === "k", "k below 5 is caught through a renamed import, and only there");
    const shadow = sources.put("/selftest/c.ts", 'import { suppress } from "@kashscript/floor";\nexport function f() { const suppress = (n: number) => n; return suppress(1); }\n');
    expect(suppressHits(shadow, "/selftest/c.ts", floor, false).some((h) => h.kind === "not-floor"), "a shadowing suppress is caught");
    const cast = sources.put("/selftest/d.ts", 'import type { FloorCount } from "@kashscript/floor";\nexport const c = 3 as FloorCount;\n');
    expect(suppressHits(cast, "/selftest/d.ts", floor, false).some((h) => h.kind === "cast"), "a cast to FloorCount is caught");
    const types = sources.put("/selftest/e.ts", 'import type { FloorCount } from "@kashscript/floor";\nexport interface V { a: FloorCount; b: number; c: { d: number | null }[] }\nexport async function agg(): Promise<V> { return null as never; }\n');
    const fn = exportedFunction(types, "agg");
    const tree = fn?.returnType === undefined ? undefined : typeTree(fn.returnType, "/selftest/e.ts", { sources, floor, seen: new Set() });
    const ls = tree === undefined ? [] : leaves(tree);
    expect(ls.find((l) => l.path === "a")?.cls === "floor" && ls.find((l) => l.path === "b")?.cls === "number" && ls.find((l) => l.path === "c[].d")?.cls === "number", "an aggregate's return type is read through Promise, arrays and unions");
    const prices = sources.put("/selftest/f.ts", 'export const P = { link: { price: "1.00", perCheck: 2 } } as const;\n');
    const decl = prices.statements[0];
    const init = decl !== undefined && ts.isVariableStatement(decl) ? decl.declarationList.declarations[0]?.initializer : undefined;
    const vls = init === undefined ? [] : leaves(valueTree(init, prices));
    expect(vls.some((l) => l.path === "link.price" && l.cls === "str") && vls.some((l) => l.path === "link.perCheck" && l.cls === "num"), "price values are read");
    const route = sources.put("/selftest/route.ts", "export async function GET() {}\nexport const POST = () => null;\n");
    expect(routeMethods(route).join(",") === "GET,POST", "route handler methods");
    const table = sources.put("/selftest/g.ts", 'export const TOOLS = { a: def({ name: "host.read_queue" }) } as const satisfies Record<string, unknown>;\n');
    const entries = tableEntries(table, "TOOLS", "name");
    expect("entries" in entries && entries.entries[0]?.name === "host.read_queue", "a tool table written as an object of def() calls");
    const dsl = sources.put("/selftest/h.ts", 'export const X = S.object({ studentDid: S.string(), score: S.number() }, ["studentDid"]);\n');
    expect(dslObjects(dsl)[0]?.props.has("score") === true, "the lexicon DSL");
    const counted = sources.put("/selftest/i.ts", 'export function f() { return db.receipt.count(); }\nexport const q = "select count(*) from receipts";\n');
    const sites = countSites(counted);
    expect(sites.some((s) => s.fn === "f") && sites.some((s) => s.what === "a count in SQL"), "count sites");
  } catch (e) {
    failures.push(`the self-test threw: ${(e as Error).message}`);
  }
  return failures;
}
