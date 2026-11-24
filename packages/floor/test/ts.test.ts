import { describe, expect, test } from "bun:test";
import { join } from "node:path";
import { Sources, leaves, typeTree, valueTree, ts, type LeafAt } from "../src/scan/ts.js";
import { countSites, exportedFunction, memberNames, serverActions, suppressHits, tableEntries } from "../src/scan/ts-scans.js";
import { FIXTURES } from "./helpers.js";

const TYPES = join(FIXTURES, "types");

function returnLeaves(file: string, name: string): LeafAt[] {
  const sources = new Sources(TYPES);
  const abs = join(TYPES, file);
  const sf = sources.get(abs)!;
  const fn = exportedFunction(sf, name)!;
  return leaves(typeTree(fn.returnType!, abs, { sources, floor: { self: false }, seen: new Set() }));
}

const byPath = (ls: LeafAt[]): Record<string, string> => Object.fromEntries(ls.map((l) => [l.path, l.cls]));

describe("an aggregate's return type, read through relative imports", () => {
  test("Promise, interfaces with heritage, arrays, records and unions", () => {
    expect(byPath(returnLeaves("agg.ts", "visits"))).toEqual({
      "months[].count": "floor",
      "months[].label": "ok",
      "byDoor.*.count": "floor",
      "byDoor.*.label": "ok",
      note: "ok",
      k: "number",
    });
  });

  test("Pick and Omit keep and drop members; an arrow function's annotation is read", () => {
    expect(Object.keys(byPath(returnLeaves("agg.ts", "picked"))).sort()).toEqual(["months[].count", "months[].label", "note"]);
    expect(byPath(returnLeaves("agg.ts", "omitted")).k).toBeUndefined();
  });

  test("a type from another package is one the floor cannot see", () => {
    expect(byPath(returnLeaves("agg.ts", "external"))).toEqual({ e: "unresolved" });
  });

  test("export { local as renamed } is found", () => {
    expect(byPath(returnLeaves("agg.ts", "renamed")).k).toBe("number");
  });
});

describe("values", () => {
  test("spreads, shorthand, Object.freeze and as const", () => {
    const sources = new Sources("/v");
    const sf = sources.put("/v/p.ts", 'const base = { usd: 1 };\nconst pkr = 100;\nexport const P = Object.freeze({ ...base, pkr, label: "x", n: -2 } as const);\n');
    const init = (sf.statements[2] as ts.VariableStatement).declarationList.declarations[0]!.initializer!;
    expect(byPath(leaves(valueTree(init, sf)))).toEqual({ usd: "num", pkr: "num", label: "str", n: "num" });
  });

  test("what cannot be read is marked computed", () => {
    const sf = new Sources("/v").put("/v/q.ts", "export const Q = { a: compute(), ...other() };\n");
    const init = (sf.statements[0] as ts.VariableStatement).declarationList.declarations[0]!.initializer!;
    expect(byPath(leaves(valueTree(init, sf)))).toEqual({ a: "computed", "...": "computed" });
  });
});

describe("suppress through a namespace import", () => {
  test("k and casts are read through floor.suppress and floor.FloorCount", () => {
    const sources = new Sources("/n");
    const sf = sources.put("/n/a.ts", 'import * as floor from "@kashscript/floor";\nexport const a = floor.suppress(3, 4);\nexport const b = floor.suppress(3, floor.FLOOR_K);\nexport const c = 1 as floor.FloorCount;\n');
    expect(suppressHits(sf, "/n/a.ts", { self: false }, false).map((h) => h.kind).sort()).toEqual(["cast", "k"]);
  });

  test("suppressSeries' k is read from the call", () => {
    const sf = new Sources("/n").put("/n/b.ts", 'import { suppressSeries } from "@kashscript/floor";\nconst o = { k: 9 };\nexport const a = suppressSeries([1], { k: 3 });\nexport const b = suppressSeries([1], o);\nexport const c = suppressSeries([1], { k: 9 });\n');
    expect(suppressHits(sf, "/n/b.ts", { self: false }, false).map((h) => h.kind)).toEqual(["k", "k"]);
  });

  test("an unrelated method named suppress is not the floor's business", () => {
    const sf = new Sources("/n").put("/n/c.ts", "export const a = console.suppress?.(1);\nexport const b = logger.suppress(2);\n");
    expect(suppressHits(sf, "/n/c.ts", { self: false }, false)).toEqual([]);
  });
});

describe("count sites, actions, tables and names", () => {
  test("Prisma counts, groupBy, _count and SQL in a tagged template", () => {
    const sf = new Sources("/c").put("/c/a.ts", 'export async function a() { return db.x.groupBy({ by: ["k"], _count: true }); }\nexport const b = () => sql`select count(distinct holder) from receipts`;\n');
    const sites = countSites(sf).map((s) => `${s.fn}:${s.what}`);
    expect(sites).toContain("a:.groupBy()");
    expect(sites).toContain("a:_count");
    expect(sites).toContain("b:a count in SQL");
  });

  test("server actions: a use server file's exports, and an inline directive", () => {
    const sources = new Sources("/s");
    expect(serverActions(sources.put("/s/a.ts", '"use server";\nexport async function save() {}\nexport const remove = async () => {};\nfunction helper() {}\n'))).toEqual(["remove", "save"]);
    expect(serverActions(sources.put("/s/b.tsx", 'export default function Page() {\n  async function submit() {\n    "use server";\n  }\n  return null;\n}\n'))).toEqual(["submit"]);
  });

  test("tables: an array of routes with method and path; a spread cannot be read", () => {
    const sources = new Sources("/t");
    const ok = tableEntries(sources.put("/t/a.ts", 'export const ROUTES = [\n  { method: "POST", path: "/api/desk/decisions", who: "desk" },\n];\n'), "ROUTES", "name");
    expect("entries" in ok && ok.entries[0]).toMatchObject({ method: "POST", path: "/api/desk/decisions" });
    const bad = tableEntries(sources.put("/t/b.ts", "export const ROUTES = [...OTHER];\n"), "ROUTES", "name");
    expect("error" in bad).toBe(true);
  });

  test("member names say whether they can hold a price", () => {
    const sf = new Sources("/m").put("/m/a.ts", 'export const RULES = { "price-per-record": { title: "x" } };\nexport interface Fees { perCheck: number; perPage: { size: number }; declineCosts: string }\nexport const F = { perCheck: 1 };\n');
    const names = memberNames(sf).map((m) => `${m.container}.${m.member}:${m.priceLike}`);
    expect(names).toContain("RULES.price-per-record:false");
    expect(names).toContain("Fees.perCheck:true");
    expect(names).toContain("F.perCheck:true");
    expect(names).toContain("Fees.declineCosts:false"); // copy text, not a price
  });
});
