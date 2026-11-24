import { describe, expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { checkFloor } from "../src/check.js";
import { scratch } from "./helpers.js";

function repo(files: Record<string, string>): string {
  const root = scratch();
  for (const [rel, text] of Object.entries(files)) {
    const abs = join(root, rel);
    mkdirSync(dirname(abs), { recursive: true });
    writeFileSync(abs, text);
  }
  return root;
}

const git = spawnSync("git", ["--version"], { encoding: "utf8" });
const hasGit = git.error === undefined && git.status === 0;

describe("next-app", () => {
  test("dynamic segments, catch-alls, groups, slots, intercepts, metadata and route methods", () => {
    const root = repo({
      "floor.manifest.json": JSON.stringify({ floor: 1, oracles: [{ kind: "next-app", app: "web/app" }] }),
      "web/app/blog/[slug]/page.tsx": "export default function P() { return null; }",
      "web/app/docs/[[...path]]/page.tsx": "export default function P() { return null; }",
      "web/app/(shop)/cart/page.tsx": "export default function P() { return null; }",
      "web/app/@modal/(.)photo/page.tsx": "export default function P() { return null; }",
      "web/app/@modal/default.tsx": "export default function D() { return null; }",
      "web/app/sitemap.ts": "export default function sitemap() { return []; }",
      "web/app/blog/opengraph-image.tsx": "export default function I() { return null; }",
      "web/app/api/hook/route.ts": "async function handler() { return new Response(); }\nexport { handler as POST, handler as PUT };",
      "web/app/api/any/route.ts": 'export * from "./impl";',
    });
    const texts = checkFloor({ root }).routes.map((r) => r.text).sort();
    expect(texts).toEqual([
      "ANY /api/any",
      "GET /blog/opengraph-image",
      "GET /sitemap.xml",
      "PAGE /blog/:",
      "PAGE /cart",
      "PAGE /docs/:*?",
      "POST /api/hook",
      "PUT /api/hook",
    ]);
  });
});

describe("boot-log", () => {
  test("text lines are read; a log with no route is a finding", () => {
    const root = repo({ "floor.manifest.json": JSON.stringify({ floor: 1, oracles: [{ kind: "boot-log" }], routes: { "GET /a": { subject: "public", shape: "one" } } }) });
    const ok = join(scratch(), "boot.log");
    writeFileSync(ok, "starting\nGET /a\n");
    expect(checkFloor({ root, bootLogs: [ok] }).findings).toEqual([]);
    const empty = join(scratch(), "boot.log");
    writeFileSync(empty, '{"phase":"SERVING","routes":{"paths":1,"endpoints":1}}\n');
    expect(checkFloor({ root, bootLogs: [empty] }).findings.map((f) => f.what)).toContain("names no routes: the engine must print mountedRoutes().list on its boot line");
  });

  test("with no log given, the oracle says how to give one", () => {
    const root = repo({ "floor.manifest.json": JSON.stringify({ floor: 1, oracles: [{ kind: "boot-log" }] }) });
    expect(checkFloor({ root }).findings.map((f) => f.at)).toEqual(["oracle:boot-log"]);
  });

  test.skipIf(!hasGit)("a boot log tracked by git is refused", () => {
    const root = repo({
      "floor.manifest.json": JSON.stringify({ floor: 1, oracles: [{ kind: "boot-log", files: ["boot.log"] }], routes: { "GET /a": { subject: "public", shape: "one" } } }),
      "boot.log": "GET /a\n",
    });
    spawnSync("git", ["init", "-q"], { cwd: root });
    spawnSync("git", ["add", "boot.log"], { cwd: root });
    const r = checkFloor({ root });
    expect(r.findings.map((f) => `${f.at} — ${f.what.split(":")[0]}`)).toContain("oracle:boot-log:boot.log — is tracked by git");
  });
});

describe("ts-table", () => {
  test("an array of routes with method and path, under a host", () => {
    const root = repo({
      "floor.manifest.json": JSON.stringify({ floor: 1, oracles: [{ kind: "ts-table", file: "routes.ts", export: "ROUTES", host: "desk" }] }),
      "routes.ts": 'export const ROUTES = [\n  { method: "POST", path: "/api/desk/decisions" },\n  { method: "get", path: "/api/desk/doors/:id/packets" },\n] as const;\n',
    });
    expect(checkFloor({ root }).routes.map((r) => r.text).sort()).toEqual(["GET desk:/api/desk/doors/:/packets", "POST desk:/api/desk/decisions"]);
  });
});

describe("supabase", () => {
  test("exposed schemas only; served counts must be an aggregate or classified", () => {
    const root = repo({
      "floor.manifest.json": JSON.stringify({ floor: 1, oracles: [{ kind: "supabase", dir: "supabase" }], routes: { "RPC /rest/v1/rpc/stats": { subject: "place", shape: "one" } } }),
      "supabase/migrations/001.sql": "create schema private;\ncreate table private.hidden (x int);\ncreate function public.stats() returns bigint language sql as $$ select count(*) from listings $$;\n",
    });
    const r = checkFloor({ root });
    expect(r.routes.map((x) => x.text)).toEqual(["RPC /rest/v1/rpc/stats"]);
    expect(r.findings.map((f) => f.at)).toEqual(["count:sql:stats"]);
  });
});
