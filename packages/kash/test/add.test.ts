/**
 * `kash add` and `kash doctor`: which products exist, what the retired ones answer, and what the
 * scaffolds say. Everything here is a simulation (d11): a throwaway project in a temp directory.
 */

import { describe, it, expect } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import {
  BLUEPRINTS,
  PRODUCT_IDS,
  RETIRED_PRODUCTS,
  type RenderContext,
} from "../src/inject/blueprints";
import { bunSrc, PKG, removeDir, tempDir } from "./helpers";

const KASH = join(PKG, "src", "bin", "kash.ts");

/** Run `kash` from inside a throwaway project, as a user would. */
function inProject(dir: string, args: readonly string[]) {
  const r = spawnSync(process.execPath, ["run", KASH, ...args], { cwd: dir, encoding: "utf8" });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

function scaffoldOf(product: keyof typeof BLUEPRINTS, path: string): string {
  for (const op of BLUEPRINTS[product].operations) {
    if (op.kind === "write-file" && op.path === path) {
      return typeof op.content === "function" ? op.content({} as RenderContext) : op.content;
    }
  }
  throw new Error(`${product} has no scaffold at ${path}`);
}

describe("the products", () => {
  it("are identity, terms, muffler and whiffin, each with a blueprint of its own id", () => {
    expect([...PRODUCT_IDS]).toEqual(["identity", "terms", "muffler", "whiffin"]);
    expect(Object.keys(BLUEPRINTS).sort()).toEqual([...PRODUCT_IDS].sort());
    for (const id of PRODUCT_IDS) expect(BLUEPRINTS[id].id).toBe(id);
  });

  it("no longer include trade, neuron or hudhud, and the retired list points at what replaced them", () => {
    expect(Object.keys(BLUEPRINTS)).not.toContain("trade");
    expect(Object.keys(BLUEPRINTS)).not.toContain("neuron");
    expect(Object.keys(BLUEPRINTS)).not.toContain("hudhud");
    expect(RETIRED_PRODUCTS.trade).toContain("kash add terms");
    // hudhud and neuron are Indorania's closed code inside Oreoasis since 2026-11-02 (KS-P1, ADR-0024).
    expect(RETIRED_PRODUCTS.neuron).toContain("Oreoasis");
    expect(RETIRED_PRODUCTS.hudhud).toContain("Oreoasis");
  });

  it("install the packages as they are on npm today (whiffin ^0.2.0, terms ^0.1.0)", () => {
    const spec = (product: keyof typeof BLUEPRINTS, name: string) => {
      const op = BLUEPRINTS[product].operations.find((o) => o.kind === "install-dep" && o.spec.name === name);
      return op?.kind === "install-dep" ? op.spec.version : undefined;
    };
    expect(spec("whiffin", "@kashscript/whiffin")).toBe("^0.2.0");
    expect(spec("terms", "@kashscript/terms")).toBe("^0.1.0");
  });
});

describe("the whiffin scaffold", () => {
  const text = scaffoldOf("whiffin", "lib/whiffin-mandate.ts");

  it("describes a mandate protocol that never moves money", () => {
    expect(text).toContain("NEVER MOVES MONEY");
    expect(text).toContain("second signature");
    expect(text).toContain("REQUIRED end date");
  });

  it("carries nothing that settles, holds or calls a rail", () => {
    expect(text).not.toMatch(/settle|escrow|refund|payout|custody/i);
    // Rail names are an enum a declaration cites; the scaffold must not import an adapter for one.
    expect(text).not.toMatch(/import\s*\{[^}]*\b(raast|emvco|safepay|softpos)\b/i);
  });

  it("does not claim the licence of a version that is not on npm yet", () => {
    expect(text).not.toContain("COMMERCIAL");
    expect(text).toContain("Apache-2.0 from 0.2.1");
  });
});

describe("the terms scaffold", () => {
  const text = scaffoldOf("terms", "lib/agreement.ts");

  it("declares a split and says it holds no balance", () => {
    expect(text).toContain("declaredSplit");
    expect(text).toContain("moves nothing and holds no");
    expect(text).not.toMatch(/escrow|refund|trust.?score|reputation|onchain/i);
  });
});

describe("kash add", () => {
  it("answers a retired product by name and points to its replacement", () => {
    const trade = bunSrc(["add", "trade"]);
    expect(trade.status).not.toBe(0);
    expect(trade.stderr).toContain("Unknown product");
    expect(trade.stderr).toContain("kash add terms");

    const neuron = bunSrc(["add", "neuron"]);
    expect(neuron.status).not.toBe(0);
    expect(neuron.stderr).toContain("Oreoasis");

    const hudhud = bunSrc(["add", "hudhud"]);
    expect(hudhud.status).not.toBe(0);
    expect(hudhud.stderr).toContain("Oreoasis");
  });

  it("lists the products it does install when it does not know one", () => {
    const r = bunSrc(["add", "nonsense"]);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain("identity, terms, muffler, whiffin");
    expect(r.stderr).not.toContain("hudhud");
    expect(r.stderr).not.toContain("kash add terms"); // no retired hint for a name that was never a product
  });

  it("does not name a prototype property as a retired product", () => {
    const r = bunSrc(["add", "constructor"]);
    expect(r.status).not.toBe(0);
    expect(r.stderr).not.toContain("undefined");
  });

  it("is a dry run until --apply, and --apply scaffolds terms and whiffin", () => {
    const dir = tempDir("add");
    try {
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "demo", version: "0.0.0", private: true }, null, 2));

      const dry = inProject(dir, ["add", "terms", "--skip-install"]);
      expect(dry.status).toBe(0);
      expect(existsSync(join(dir, "lib", "agreement.ts"))).toBe(false);

      for (const product of ["terms", "whiffin"]) {
        const done = inProject(dir, ["add", product, "--apply", "--skip-install"]);
        expect(done.status).toBe(0);
      }
      expect(readFileSync(join(dir, "lib", "agreement.ts"), "utf8")).toContain("declareShares");
      expect(readFileSync(join(dir, "lib", "whiffin-mandate.ts"), "utf8")).toContain("createMandateIssuer");
    } finally {
      removeDir(dir);
    }
  });
});

describe("kash doctor", () => {
  it("answers a retired product the same way", () => {
    const r = bunSrc(["doctor", "trade"]);
    expect(r.status).not.toBe(0);
    expect(r.stderr).toContain("kash add terms");
  });
});
