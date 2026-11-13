/**
 * M1 acceptance (ROADMAP done-when): the verifier verifies, OFFLINE, a real
 * Oreoasis exported bundle, Duedale's report.json, and an Indusland IVFC1 sample.
 * The Oreoasis fixture is genuine venture output (its own export script); the
 * Duedale/Indus fixtures reproduce each venture's exact signing construction.
 * Regenerate with `bun test/fixtures/gen-fixtures.ts`.
 */

import { describe, it, expect } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { verifyAuditBundle } from "../src/bundle";
import { verifyDuedaleReport } from "../src/compat/duedale-report";
import { verifyIndusTokenWithJwks } from "../src/compat/indus-token";

const F = join(import.meta.dir, "fixtures");
const read = (p: string): string => readFileSync(join(F, p), "utf8");

describe("M1 acceptance — verify real venture artifacts offline", () => {
  it("verifies a REAL Oreoasis exported audit bundle (DSSE + chain + anchor)", async () => {
    const env = JSON.parse(read("oreoasis-audit-bundle.dsse.json"));
    const [did, hex] = read("oreoasis-host-public-key.txt").trim().split(/\s+/);
    const report = await verifyAuditBundle(env, {
      trustedKeysByDid: new Map([[did!, hex!]]),
      requireSignerDid: did!,
    });
    expect(report.ok).toBe(true);
    expect(report.dsseOk).toBe(true);
    expect(report.requiredSignerVerified).toBe(true);
    expect(report.forensic.ok).toBe(true);
    expect(report.anchorRootMatches).toBe(true);
    expect(report.anchorBindsChain).toBe(true);
  });

  it("verifies Duedale's every-rupee report.json (envelope signature + hash-chain)", async () => {
    const signed = JSON.parse(read("duedale-report.json"));
    const report = await verifyDuedaleReport(signed);
    expect(report.ok).toBe(true);
    expect(report.signatureOk).toBe(true);
    expect(report.chain.ok).toBe(true);
  });

  it("verifies an Indusland IVFC1 certificate against its JWKS (signature + certId)", async () => {
    const token = read("indus-ivfc1.token.txt").trim();
    const jwks = JSON.parse(read("indus-keys.json"));
    const report = await verifyIndusTokenWithJwks(token, jwks);
    expect(report.ok).toBe(true);
    expect(report.signatureOk).toBe(true);
    expect(report.certIdOk).toBe(true);
  });
});
