// KS-R4 — the rails are NAMES a declaration can cite, and nothing else. Whiffin
// makes no rail call (DECLARE → PAY on the payer's own rail → CONFIRM): there is
// no adapter, no dispatch, and no function in this module beyond a name check.

import { describe, expect, it } from "bun:test";

import * as rails from "../src/rails";
import { RAIL, RAILS, isRail } from "../src/rails";

describe("rails — names only", () => {
  it("the names a declaration can cite are pinned (they sit inside signed bytes)", () => {
    expect([...RAILS]).toEqual(["RAAST", "EMVCO", "SAFEPAY", "SOFTPOS", "CHAIN"]);
    expect(RAIL.RAAST).toBe("RAAST");
    expect(Object.isFrozen(RAILS) || Array.isArray(RAILS)).toBe(true);
  });

  it("isRail accepts a name and nothing else", () => {
    for (const name of RAILS) expect(isRail(name)).toBe(true);
    for (const bad of ["raast", "PARTNER_LEDGER", "", " RAAST", null, undefined, 7, {}]) expect(isRail(bad)).toBe(false);
  });

  it("exports no rail call: the whole module is RAIL, RAILS and isRail", () => {
    expect(Object.keys(rails).sort()).toEqual(["RAIL", "RAILS", "isRail"]);
    // The only function is the pure name check; there is nothing to dispatch to.
    const fns = Object.entries(rails).filter(([, v]) => typeof v === "function").map(([k]) => k);
    expect(fns).toEqual(["isRail"]);
  });
});
