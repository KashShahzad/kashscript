import { afterAll, beforeAll, describe, expect, test } from "bun:test";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildSbom, lockIntegrity, npmPurl, sriToHash, stripTrailingCommas, type PackedManifest } from "./sbom";

let root = "";

function pkg(dir: string, manifest: Record<string, unknown>): void {
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "package.json"), JSON.stringify(manifest));
}

// A fixture workspace: two siblings, hoisted and nested externals, a dev dependency, an absent peer.
beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), "sbom-test-"));
  pkg(join(root, "packages", "terms"), {
    name: "@kashscript/terms",
    version: "0.1.0",
    dependencies: { "@kashscript/identity-core": "workspace:*", "@noble/hashes": "^1.7.0" },
    devDependencies: { typescript: "^5" },
  });
  pkg(join(root, "packages", "identity-core"), {
    name: "@kashscript/identity-core",
    version: "0.4.0-alpha.0",
    license: "Apache-2.0",
    dependencies: { enquirer: "^2" },
    optionalDependencies: { fsevents: "*" }, // not installed: left out
  });
  pkg(join(root, "node_modules", "@noble", "hashes"), { name: "@noble/hashes", version: "1.7.1", license: "MIT" });
  pkg(join(root, "node_modules", "enquirer"), { name: "enquirer", version: "2.4.1", license: "MIT", dependencies: { "ansi-colors": "^4" } });
  // A nested copy wins over the hoisted one, as Node resolves it.
  pkg(join(root, "node_modules", "enquirer", "node_modules", "ansi-colors"), { name: "ansi-colors", version: "4.1.3", license: "MIT" });
  pkg(join(root, "node_modules", "ansi-colors"), { name: "ansi-colors", version: "3.0.0", license: "MIT" });
  pkg(join(root, "node_modules", "fflate"), { name: "fflate", version: "0.8.2", license: { type: "MIT" } });
  pkg(join(root, "node_modules", "typescript"), { name: "typescript", version: "5.6.3", license: "Apache-2.0" });
});

afterAll(() => {
  if (root) rmSync(root, { recursive: true, force: true });
});

const LOCK = `{
  "lockfileVersion": 1,
  "workspaces": { "": { "name": "root", }, },
  "packages": {
    "@kashscript/identity-core": ["@kashscript/identity-core@workspace:packages/identity-core"],
    "@noble/hashes": ["@noble/hashes@1.7.1", "", {}, "sha512-AAECAw=="],
    "enquirer": ["enquirer@2.4.1", "", { "dependencies": { "ansi-colors": "^4.1.1", }, }, "sha512-BAUG"],
    "enquirer/ansi-colors": ["ansi-colors@4.1.3", "", {}, "sha512-BwgJ"],
    "ansi-colors": ["ansi-colors@3.0.0", "", {}, "sha512-CgsM"],
  },
}
`;

const packed: PackedManifest = {
  name: "@kashscript/terms",
  version: "0.1.0",
  license: "Apache-2.0",
  dependencies: { "@kashscript/identity-core": "0.4.0-alpha.0", "@noble/hashes": "^1.7.0" },
  optionalDependencies: { fflate: "*" },
  peerDependencies: { react: "*" }, // not installed: left out
};

function build(manifest: PackedManifest = packed) {
  return buildSbom({
    root,
    pkgDir: join(root, "packages", "terms"),
    manifest,
    tarballSha512Hex: "ab".repeat(64),
    lockText: LOCK,
    timestamp: "2026-11-09T00:00:00.000Z",
    serialNumber: "urn:uuid:00000000-0000-4000-8000-000000000000",
  });
}

describe("bun.lock", () => {
  test("trailing commas are stripped outside strings only", () => {
    expect(JSON.parse(stripTrailingCommas('{"a": [1, 2,], "b": "x,}",}'))).toEqual({ a: [1, 2], b: "x,}" });
    expect(JSON.parse(stripTrailingCommas('{"q": "say \\"hi,\\"",}'))).toEqual({ q: 'say "hi,"' });
  });

  test("integrity by name@version; workspace entries carry none", () => {
    const m = lockIntegrity(LOCK);
    expect(m.get("@noble/hashes@1.7.1")).toBe("sha512-AAECAw==");
    expect(m.get("ansi-colors@4.1.3")).toBe("sha512-BwgJ");
    expect(m.has("@kashscript/identity-core@workspace:packages/identity-core")).toBe(false);
  });

  test("SRI becomes a hex CycloneDX hash", () => {
    expect(sriToHash("sha512-AAECAw==")).toEqual({ alg: "SHA-512", content: "00010203" });
    expect(sriToHash("md5-xx")).toBeUndefined();
  });
});

test("purls encode the scope and the version", () => {
  expect(npmPurl("@kashscript/terms", "0.1.0")).toBe("pkg:npm/%40kashscript/terms@0.1.0");
  expect(npmPurl("fflate", "1.0.0+build.1")).toBe("pkg:npm/fflate@1.0.0%2Bbuild.1");
});

describe("buildSbom", () => {
  test("the document's frame is CycloneDX 1.6, the package itself its subject", () => {
    const bom = build();
    expect(bom.bomFormat).toBe("CycloneDX");
    expect(bom.specVersion).toBe("1.6");
    expect(bom.version).toBe(1);
    expect(bom.metadata.component).toEqual({
      type: "library",
      "bom-ref": "pkg:npm/%40kashscript/terms@0.1.0",
      group: "@kashscript",
      name: "terms",
      version: "0.1.0",
      purl: "pkg:npm/%40kashscript/terms@0.1.0",
      licenses: [{ expression: "Apache-2.0" }],
      hashes: [{ alg: "SHA-512", content: "ab".repeat(64) }],
    });
  });

  test("the runtime closure, transitively, with Node's resolution — and nothing else", () => {
    const refs = build().components.map((c) => `${c.purl} ${c.scope}`);
    expect(refs).toEqual([
      "pkg:npm/%40kashscript/identity-core@0.4.0-alpha.0 required",
      "pkg:npm/%40noble/hashes@1.7.1 required",
      "pkg:npm/ansi-colors@4.1.3 required", // the nested copy, not the hoisted 3.0.0
      "pkg:npm/enquirer@2.4.1 required",
      "pkg:npm/fflate@0.8.2 optional",
    ]);
    // typescript (a devDependency), react (an absent peer) and fsevents (an absent optional) are out.
  });

  test("hashes come from bun.lock; a sibling has none; licences in either shape", () => {
    const by = new Map(build().components.map((c) => [c.name, c]));
    expect(by.get("hashes")!.hashes).toEqual([{ alg: "SHA-512", content: "00010203" }]);
    expect(by.get("identity-core")!.hashes).toBeUndefined();
    expect(by.get("fflate")!.licenses).toEqual([{ expression: "MIT" }]);
    expect(by.get("fflate")!.hashes).toBeUndefined(); // not in the lock
  });

  test("the dependency graph, root first", () => {
    const deps = build().dependencies;
    expect(deps[0]).toEqual({
      ref: "pkg:npm/%40kashscript/terms@0.1.0",
      dependsOn: ["pkg:npm/%40kashscript/identity-core@0.4.0-alpha.0", "pkg:npm/%40noble/hashes@1.7.1", "pkg:npm/fflate@0.8.2"],
    });
    expect(deps.find((d) => d.ref === "pkg:npm/enquirer@2.4.1")!.dependsOn).toEqual(["pkg:npm/ansi-colors@4.1.3"]);
    expect(deps.find((d) => d.ref === "pkg:npm/%40kashscript/identity-core@0.4.0-alpha.0")!.dependsOn).toEqual([
      "pkg:npm/enquirer@2.4.1",
    ]);
  });

  test("a required dependency that is not installed fails the SBOM", () => {
    expect(() => build({ ...packed, dependencies: { ...packed.dependencies, "left-pad": "^1" } })).toThrow(
      "left-pad (a dependency of pkg:npm/%40kashscript/terms@0.1.0) is not installed",
    );
  });

  test("deterministic: the same inputs give the same document", () => {
    expect(JSON.stringify(build())).toBe(JSON.stringify(build()));
  });
});
