/**
 * The command surface and the package's shape: what was asked to go is gone,
 * what was asked to stay is there, and the version is written once.
 */

import { describe, it, expect } from "bun:test";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { VERSION } from "../src/version";
import { bunSrc, PKG } from "./helpers";

const pkg = JSON.parse(readFileSync(join(PKG, "package.json"), "utf8"));

describe("the command surface", () => {
  it("lists the station kit, plus the kept commands — and nothing that was removed", () => {
    const help = bunSrc(["--help"]);
    expect(help.status).toBe(0);
    const names = [...help.stdout.matchAll(/^ {2}([a-z]+)\b/gm)].map((m) => m[1]);
    for (const kept of ["station", "issue", "countersign", "verify", "trust", "status", "doctor", "add", "rollback"]) {
      expect(names).toContain(kept);
    }
    for (const gone of ["trade", "neuron", "login", "logout", "sync", "browse"]) {
      expect(names).not.toContain(gone);
    }
  });

  it("an old command is simply unknown", () => {
    for (const gone of ["login", "logout", "trade", "neuron", "sync", "browse"]) {
      const r = bunSrc([gone]);
      expect(r.status).toBe(1);
      expect(r.stderr).toContain("unknown command");
    }
  });

  it("status reports the keystore without needing a session", () => {
    const r = bunSrc(["status", "--keystore", join(PKG, "no-such-keystore")]);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("No keys");
    expect(r.stdout).not.toMatch(/authenticated|kash login/i);
  });
});

describe("the package", () => {
  it("writes its version once: src/version.ts equals package.json, and is 0.5.0", () => {
    expect(VERSION).toBe(pkg.version);
    expect(pkg.version).toBe("0.5.0");
    expect(bunSrc(["--version"]).stdout.trim()).toBe("0.5.0");
  });

  it("no longer depends on the packages behind the removed commands, and exports no auth or paywall", () => {
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    for (const gone of ["@kashscript/trade-core", "@kashscript/trade-sdk", "@kashscript/neuron"]) {
      expect(deps[gone]).toBeUndefined();
    }
    expect(Object.keys(pkg.exports)).toEqual([".", "./utils/env"]);
    expect(Object.keys(pkg.publishConfig.exports)).toEqual([".", "./utils/env"]);
    for (const gone of ["src/auth", "src/registry", "src/paywall", "src/commands/login.ts", "src/commands/trade.ts", "src/commands/neuron.ts",
                         // AU-11: the old phase-1 entry, unreachable from the bin, wrote a silo depending on trade-core and neuron
                         "src/index.ts", "src/commands/scaffold.ts", "src/templates/silo.ts"]) {
      expect(existsSync(join(PKG, gone))).toBe(false);
    }
  });

  it("keeps the verifier a real dependency, and says Node 20 (WebCrypto Ed25519)", () => {
    expect(pkg.dependencies["@kashscript/attest"]).toBe("workspace:*");
    expect(pkg.engines.node).toBe(">=20");
  });
});
