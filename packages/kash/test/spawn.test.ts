/**
 * How kash hands arguments to a package manager (src/utils/spawn.ts): unchanged
 * off Windows; on Windows each one double-quoted for cmd.exe, so a version range
 * keeps its caret and >= never redirects, and anything unquotable is refused.
 */

import { describe, it, expect } from "bun:test";

import { KashCliError } from "../src/errors";
import { managerArgs, spawnManager } from "../src/utils/spawn";

const SPECS = ["install", "@kashscript/muffler@^0.1.0", "pkg@>=1.0 <2", "a&b", "p|q"];

describe("managerArgs", () => {
  it("passes arguments unchanged off Windows", () => {
    expect(managerArgs(SPECS, "linux")).toEqual(SPECS);
    expect(managerArgs(SPECS, "darwin")).toEqual(SPECS);
  });

  it("double-quotes every argument on Windows", () => {
    expect(managerArgs(SPECS, "win32")).toEqual(SPECS.map((a) => `"${a}"`));
  });

  it("refuses what cmd.exe would still read inside quotes", () => {
    for (const bad of ['a"b', "%PATH%", "a!b", "a\nb", "a\rb", "dir\\"]) {
      expect(() => managerArgs([bad], "win32")).toThrow(KashCliError);
    }
  });
});

describe("spawnManager", () => {
  it("refuses a command that is not a plain name", () => {
    for (const bad of ["npm & calc", "C:\\tools\\npm.cmd", "../npm", ""]) {
      expect(() => spawnManager(bad, [])).toThrow(KashCliError);
    }
  });
});
