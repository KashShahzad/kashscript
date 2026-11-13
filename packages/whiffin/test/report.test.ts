// M4 acceptance (ROADMAP done-when): the 9 report-behavior tests, ported from
// Duedale's report.unit.spec against @kashscript/whiffin's reconciliation module
// with an example program (not DEMO_PROGRAMS). Covers reconciliation totals +
// vendor breakdown, the render-time hash-chain (determinism + tamper-detection +
// independent re-verification), the report signature (+ domain separation vs
// grants), and the shadow paths (empty ledger, malformed record).

import { describe, expect, it } from "bun:test";
import { canonicalizeBytes, encodeHex } from "@kashscript/identity-core";

import { buildVendorAllowlist, generateGrantAuthorityKeyPair, verifyGrant } from "../src/mandate/grant";
import { InMemoryGrantLedger, InMemoryNonceStore, issueGrant, markDelivered, redeemGrant } from "../src/mandate/lifecycle";
import type { GrantRecord, IssueRequest } from "../src/mandate/types";
import { assembleSignedReport, computeChainSummary, signReport, verifyReportSignature } from "../src/report";
import { buildReconciliationReport } from "../src/report/builder";
import { exampleProgram, EXAMPLE_VENDORS } from "./fixtures";

const NOW = 1_800_000_000;
const DAY = 86_400;
const program = exampleProgram();
const VENDOR = EXAMPLE_VENDORS[0];

async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return encodeHex(new Uint8Array(digest));
}

function concatFor(prevHex: string, rowBytes: Uint8Array): Uint8Array {
  const prev = new TextEncoder().encode(prevHex);
  const out = new Uint8Array(prev.length + rowBytes.length);
  out.set(prev, 0);
  out.set(rowBytes, prev.length);
  return out;
}

const issueReq = (beneficiary: string, amountPaisa: number): IssueRequest => ({
  programId: program.programId,
  beneficiaryDid: beneficiary,
  purposeTag: "MEAL",
  amountPaisa,
});

/** Issue 3 grants: one redeemed, one live, one issued-then-expired. */
async function seedLedger() {
  const kp = await generateGrantAuthorityKeyPair();
  const ledger = new InMemoryGrantLedger();
  const nonces = new InMemoryNonceStore();

  const redeemed = await issueGrant(issueReq("did:kash:ben-1", 250_000), program, kp.privateKey, ledger, { nowUnix: NOW });
  await issueGrant(issueReq("did:kash:ben-2", 100_000), program, kp.privateKey, ledger, { nowUnix: NOW });
  await issueGrant({ ...issueReq("did:kash:ben-3", 50_000), expiryUnix: NOW + DAY }, program, kp.privateKey, ledger, { nowUnix: NOW });

  const allowlist = await buildVendorAllowlist(program.approvedVendorDids);
  await markDelivered(redeemed.signed.grant.grantId, ledger, { nowUnix: NOW + 60 });
  await redeemGrant(
    { grantId: redeemed.signed.grant.grantId, vendorDid: VENDOR, beneficiaryDid: "did:kash:ben-1", purposeTag: "MEAL", vendorProof: allowlist.proofByDid.get(VENDOR)! },
    kp.publicKey,
    ledger,
    nonces,
    { nowUnix: NOW + 120 },
  );

  return { kp, ledger };
}

describe("assembleSignedReport — happy path + reconciliation", () => {
  it("reconciles totals, breaks down by vendor, and marks every signature valid", async () => {
    const { kp, ledger } = await seedLedger();
    const signed = await assembleSignedReport(await ledger.list(), program, kp, { nowUnix: NOW + 2 * DAY });
    const { report } = signed;

    expect(report.meta.simulation).toBe(true);
    expect(report.totals.issuedCount).toBe(3);
    expect(report.totals.issuedPaisa).toBe(400_000);
    expect(report.totals.redeemedCount).toBe(1);
    expect(report.totals.redeemedPaisa).toBe(250_000);
    expect(report.totals.redeemedPaisa + report.totals.unspentPaisa).toBe(report.totals.issuedPaisa);
    expect(report.totals.unspentPaisa).toBe(150_000);
    // Whiffin holds and moves nothing, so a report has no totals for value paid out or returned.
    expect(Object.keys(report.totals).sort()).toEqual(
      ["expiredCount", "issuedCount", "issuedPaisa", "redeemedCount", "redeemedPaisa", "unspentPaisa"],
    );
    expect(report.totals.expiredCount).toBe(1);
    expect(report.grants.map((g) => g.state).sort()).toEqual(["EXPIRED", "ISSUED", "REDEEMED"]);

    expect(report.vendors).toHaveLength(1);
    expect(report.vendors[0]).toMatchObject({ vendorDid: VENDOR, redeemedCount: 1, redeemedPaisa: 250_000 });

    expect(report.grants.every((g) => g.signatureValid)).toBe(true);
  });
});

describe("chain summary — determinism, tamper-detection, independent re-verification", () => {
  it("produces a stable head hash across two builds of the same ledger", async () => {
    const { ledger } = await seedLedger();
    const records = await ledger.list();
    const a = await computeChainSummary(records);
    const b = await computeChainSummary(records);
    expect(a.headHashHex).toBe(b.headHashHex);
    expect(a.transitionCount).toBe(b.transitionCount);
    expect(a.durablyAnchored).toBe(false);
    expect(a.computedAtRender).toBe(true);
  });

  it("re-verifies the whole chain from the report JSON alone (genesis → head)", async () => {
    const { ledger } = await seedLedger();
    const chain = await computeChainSummary(await ledger.list());
    let prev = await sha256Hex(new TextEncoder().encode(chain.genesisLabel));
    for (const link of chain.links) {
      expect(link.prevHashHex).toBe(prev);
      const recomputed = await sha256Hex(concatFor(prev, canonicalizeBytes(link.row)));
      expect(recomputed).toBe(link.rowHashHex);
      prev = link.rowHashHex;
    }
    expect(chain.headHashHex).toBe(prev);
  });

  it("changes the head hash when a single transition is mutated", async () => {
    const { ledger } = await seedLedger();
    const records = await ledger.list();
    const before = await computeChainSummary(records);
    const tampered: GrantRecord[] = records.map((r, i) =>
      i !== 0 ? r : { ...r, transitions: r.transitions.map((t) => ({ ...t, reason: "TAMPERED" })) },
    );
    const after = await computeChainSummary(tampered);
    expect(after.headHashHex).not.toBe(before.headHashHex);
  });
});

describe("report signature — validity + domain separation", () => {
  it("verifies a genuine report signature and rejects a tampered payload", async () => {
    const { kp, ledger } = await seedLedger();
    const signed = await assembleSignedReport(await ledger.list(), program, kp, { nowUnix: NOW + DAY });
    expect(await verifyReportSignature(signed, kp.publicKey)).toBe(true);
    expect(signed.operatorPublicKeyHex).toBe(encodeHex(kp.publicKey));

    const tampered = { ...signed, report: { ...signed.report, totals: { ...signed.report.totals, redeemedPaisa: 999_999 } } };
    expect(await verifyReportSignature(tampered, kp.publicKey)).toBe(false);
  });

  it("does not verify under a foreign operator key", async () => {
    const { kp, ledger } = await seedLedger();
    const signed = await assembleSignedReport(await ledger.list(), program, kp, { nowUnix: NOW + DAY });
    const other = await generateGrantAuthorityKeyPair();
    expect(await verifyReportSignature(signed, other.publicKey)).toBe(false);
  });

  it("a report signature does not verify as a grant (kash-report-v1 vs kash-grant-v1 DST)", async () => {
    const { kp, ledger } = await seedLedger();
    const records = await ledger.list();
    const signed = await assembleSignedReport(records, program, kp, { nowUnix: NOW + DAY });
    const forged = { grant: records[0]!.signed.grant, signature: signed.signature };
    expect(await verifyGrant(forged, kp.publicKey)).toBe(false);
  });
});

describe("report — shadow paths", () => {
  it("empty ledger → valid all-zero report, null chain head, no throw", async () => {
    const kp = await generateGrantAuthorityKeyPair();
    const ledger = new InMemoryGrantLedger();
    const signed = await assembleSignedReport(await ledger.list(), program, kp, { nowUnix: NOW });
    expect(signed.report.grants).toHaveLength(0);
    expect(signed.report.totals.issuedPaisa).toBe(0);
    expect(signed.report.chain.headHashHex).toBeNull();
    expect(signed.report.chain.transitionCount).toBe(0);
    expect(await verifyReportSignature(signed, kp.publicKey)).toBe(true);
  });

  it("a record with zero transitions is skipped and counted as an anomaly (no throw)", async () => {
    const { kp, ledger } = await seedLedger();
    const records = await ledger.list();
    const malformed = { ...records[0]!, transitions: [] };
    const chain = await computeChainSummary(records);
    const report = (
      await signReport(
        buildReconciliationReport([...records, malformed], program, {
          nowUnix: NOW + DAY,
          signatureValidByGrantId: new Map(records.map((r) => [r.signed.grant.grantId, true])),
          chainSummary: chain,
        }),
        kp.privateKey,
        kp.publicKey,
      )
    ).report;
    expect(report.meta.anomalies).toBe(1);
    expect(report.grants).toHaveLength(3);
  });
});
