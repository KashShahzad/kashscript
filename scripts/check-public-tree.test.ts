import { afterAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { checkTarball, checkTree, denied, markdownLinks } from "./check-public-tree";

const roots: string[] = [];
afterAll(() => { for (const r of roots) rmSync(r, { recursive: true, force: true }); });

function tree(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "public-tree-"));
  roots.push(root);
  for (const [p, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, p)), { recursive: true });
    writeFileSync(join(root, p), text);
  }
  return root;
}

const open = (slug: string): Record<string, string> => ({
  [`packages/${slug}/package.json`]: JSON.stringify({ name: `@kashscript/${slug}`, license: "Apache-2.0" }),
});
const trusted = (...slugs: string[]): Record<string, string> => ({
  "scripts/trusted-publishing.json": JSON.stringify({ moved: slugs }),
});

describe("denied", () => {
  test("refuses closed code, private apps and credential files wherever they sit", () => {
    for (const p of [
      "apps/kashscript/app/page.tsx",
      "services/muffler-pds/src/index.ts",
      "packages/trade-core/src/kernel/fsm.ts",
      "packages/hudhud/src/index.ts",
      "packages/attest/src/neuron/x.ts",
      "specs/hudhud.md",
      "specs/trade-sdk.md",
      "docs/legal/SSLA.md",
      "packages/kash/.npmrc",
      ".env.local",
      "packages/wallet/test/server.pem",
      "docs/policy-door/run.json",
    ]) expect(denied(p)).toBeDefined();
  });

  test("lets the open protocol through", () => {
    for (const p of [
      "packages/attest/src/bundle.ts",
      "packages/terms/README.md",
      "specs/countersign.md",
      "specs/schemas/rule.schema.json",
      "docs/rulebooks/signed-down-the-chain/rule.json",
      ".github/workflows/publish.yml",
      "packages/wallet/android/build.gradle",
    ]) expect(denied(p)).toBeUndefined();
  });
});

describe("markdownLinks", () => {
  test("finds relative targets, skips URLs, anchors and code", () => {
    const md = [
      "See [the spec](specs/a.md#part) and [b](<../b c.md>).",
      "[web](https://example.com) [mail](mailto:x@y.z) [top](#top)",
      "`[not](a-link.md)`",
      "```",
      "[also not](fenced.md)",
      "```",
    ].join("\n");
    expect(markdownLinks(md)).toEqual(["specs/a.md#part", "../b c.md"]);
  });
});

describe("checkTree", () => {
  test("a clean tree passes", () => {
    const root = tree({
      ...open("terms"),
      ...trusted("terms"),
      "README.md": "[terms](packages/terms) [spec](specs/x.md#one)",
      "specs/x.md": "# x",
      "packages/internal/package.json": JSON.stringify({ name: "@kashscript/internal", private: true }),
    });
    expect(checkTree(root).violations).toEqual([]);
  });

  test("a closed path, a broken link and a trusted-publishing mismatch are each reported", () => {
    const root = tree({
      ...open("terms"),
      ...open("wallet"),
      ...trusted("terms", "hudhud"),
      "README.md": "[gone](services/muffler-pds) [out](../elsewhere.md)",
      "packages/trade-sdk/package.json": "{}",
    });
    const v = checkTree(root).violations;
    const kinds = v.map((x) => `${x.check}:${x.where}`);
    expect(kinds).toContain("deny:packages/trade-sdk/package.json");
    expect(kinds).toContain("link:README.md");
    expect(v.filter((x) => x.check === "link")).toHaveLength(2);
    expect(kinds).toContain("trusted:packages/wallet");
    expect(kinds).toContain("trusted:scripts/trusted-publishing.json");
  });
});

describe("checkTarball", () => {
  const manifest = JSON.stringify({ files: ["dist", "src", "README.md", "LICENSE"] });

  test("entries the files field admits pass", () => {
    const r = checkTarball("kashscript-terms-0.1.0.tgz", [
      "package/package.json", "package/README.md", "package/LICENSE", "package/dist/index.js", "package/src/index.ts",
    ], manifest);
    expect(r.violations).toEqual([]);
    expect(r.count).toBe(5);
  });

  test("closed, stray and unadmitted entries are reported", () => {
    const r = checkTarball("x.tgz", [
      "package/src/hudhud/runtime.ts",
      "package/.npmrc",
      "package/test/secret.test.ts",
      "other/file.txt",
    ], manifest);
    const where = r.violations.map((v) => v.where);
    expect(where).toContain("x.tgz:src/hudhud/runtime.ts");
    expect(where).toContain("x.tgz:.npmrc");
    expect(where).toContain("x.tgz:test/secret.test.ts");
    expect(where).toContain("x.tgz:other/file.txt");
  });
});
