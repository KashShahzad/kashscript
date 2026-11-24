import { describe, expect, test } from "bun:test";
import { covers, looseGlob, normalizePath, parseRouteKey, specificity, validateManifest } from "../src/manifest.js";

const problems = (raw: unknown): string[] => validateManifest(raw).problems.map((p) => `${p.at}: ${p.what}`);

describe("the manifest", () => {
  test("a minimal manifest is valid", () => {
    expect(problems({ floor: 1 })).toEqual([]);
  });

  test("the format version is required", () => {
    expect(problems({})).toEqual(["manifest.floor: must be 1, the manifest format this floor reads"]);
  });

  test("unknown keys, words outside the vocabulary and a draft's ? are problems", () => {
    const p = problems({ floor: 1, extra: true, routes: { "GET /a": { subject: "?", shape: "list", color: "red" } } });
    expect(p.some((x) => x.startsWith("manifest.extra: an unknown key"))).toBe(true);
    expect(p.some((x) => x.includes(".color: an unknown key"))).toBe(true);
    expect(p.some((x) => x.includes(".subject: must be one of") && x.includes("a draft's ? is not an answer"))).toBe(true);
  });

  test("a route key must be METHOD /path", () => {
    expect(problems({ floor: 1, routes: { "/a": { subject: "public", shape: "one" } } }).length).toBe(1);
    expect(problems({ floor: 1, routes: { "FETCH /a": { subject: "public", shape: "one" } } }).length).toBe(1);
  });

  test("shape rules: aggregate names existing aggregates, closed says why, export says where", () => {
    const p = problems({
      floor: 1,
      routes: {
        "GET /a": { subject: "organisation", shape: "aggregate", aggregates: ["missing"] },
        "GET /b": { subject: "record", shape: "closed" },
        "GET /c": { subject: "record", shape: "export" },
      },
    });
    expect(p).toEqual([
      'manifest.routes["GET /a"].aggregates: names "missing", which manifest.aggregates does not declare',
      'manifest.routes["GET /b"]: a closed route says why ("why")',
      'manifest.routes["GET /c"]: an export says where it goes ("to": "own-book")',
    ]);
  });

  test("aggregates are TypeScript or SQL, not both and not neither", () => {
    expect(problems({ floor: 1, aggregates: { a: { file: "x.ts" } } }).length).toBe(1);
    expect(problems({ floor: 1, aggregates: { a: { file: "x.ts", export: "f", sql: "g" } } }).length).toBe(1);
    expect(problems({ floor: 1, aggregates: { a: { sql: "g" } } })).toEqual([]);
  });

  test("counts carry a kind and a why; a waiver carries a reason and a decision of the log", () => {
    const p = problems({ floor: 1, counts: { "a.ts#f": { kind: "own" }, nohash: { kind: "internal", why: "w" } }, waivers: [{ rule: "person-score", at: "x", reason: "r", decision: "a good reason" }] });
    expect(p.some((x) => x.startsWith('manifest.counts["a.ts#f"].why: is required'))).toBe(true);
    expect(p.some((x) => x.startsWith('manifest.counts["nohash"]: a count key is'))).toBe(true);
    expect(p.some((x) => x.startsWith("manifest.waivers[0].decision: cites a decision of the log"))).toBe(true);
    expect(validateManifest({ floor: 1, waivers: [{ rule: "person-score", at: "x", reason: "r", decision: "a good reason" }] }).manifest.waivers).toEqual([]);
  });
});

describe("route keys", () => {
  test("parameters compare equal whatever they are called", () => {
    expect(normalizePath("/r/:receiptNo")).toBe("/r/:");
    expect(normalizePath("/r/[id]/")).toBe("/r/:");
    expect(normalizePath("/r/{id}")).toBe("/r/:");
    expect(normalizePath("/r/:id{[0-9]+}")).toBe("/r/:");
    expect(normalizePath("/docs/[...slug]")).toBe("/docs/:*");
    expect(normalizePath("/docs/[[...slug]]")).toBe("/docs/:*?");
    expect(normalizePath("/files/:path*")).toBe("/files/:*");
  });

  test("hosts, tools and actions", () => {
    expect(parseRouteKey("PAGE web:/about")).toMatchObject({ method: "PAGE", host: "web", norm: "/about" });
    expect(parseRouteKey("TOOL host.read_queue")).toMatchObject({ method: "TOOL", host: undefined, target: "host.read_queue" });
    expect(parseRouteKey("TOOL mcp:find_listings")).toMatchObject({ host: "mcp", target: "find_listings" });
    expect(parseRouteKey("ACTION app/actions.ts#save")).toMatchObject({ target: "app/actions.ts#save" });
    expect(parseRouteKey("ALL /x")?.method).toBe("ANY");
  });

  test("globs cover, and the most specific wins", () => {
    const all = parseRouteKey("PAGE web:/**")!;
    const explore = parseRouteKey("PAGE web:/explore/*")!;
    const page = parseRouteKey("PAGE web:/explore/places")!;
    const root = parseRouteKey("PAGE web:/")!;
    expect(covers(all, page) && covers(explore, page) && covers(all, root)).toBe(true);
    expect(covers(explore, root)).toBe(false);
    expect(specificity(explore)).toBeGreaterThan(specificity(all));
    expect(covers(parseRouteKey("TOOL host.*")!, parseRouteKey("TOOL host.read_queue")!)).toBe(true);
    expect(covers(parseRouteKey("GET /a")!, parseRouteKey("POST /a")!)).toBe(false);
  });

  test("waiver keys: * matches anything", () => {
    expect(looseGlob("price:src/*#PRICES.*").test("price:src/prices.ts#PRICES.monthly")).toBe(true);
    expect(looseGlob("prisma:User.karma").test("prisma:User.karmaX")).toBe(false);
  });
});
