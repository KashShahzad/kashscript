// M4 — the mandate lifecycle (ISSUE·DELIVER·REDEEM) + the config-driven policy
// gate. Happy path, then each gate rule rejected with its neutral code.

import { describe, expect, it } from "bun:test";
import { ARRIVAL_CLAUSE, buildVendorAllowlist, generateGrantAuthorityKeyPair, isArrivalClause, verifyGrant } from "../src/mandate/grant";
import type { MerkleInclusionProof } from "../src/mandate/grant";
import { GRANT_LIFECYCLE_STATES } from "../src/mandate/types";
import type { SignedGrant } from "../src/mandate/types";
import { InMemoryGrantLedger, InMemoryNonceStore, issueGrant, markDelivered, redeemGrant } from "../src/mandate/lifecycle";
import type { RedeemRequest } from "../src/policy";
import { WhiffinPolicyError } from "../src/errors";
import { EXAMPLE_VENDORS, exampleProgram } from "./fixtures";

const NOW = 1_800_000_000;
const program = exampleProgram();
const VENDOR = EXAMPLE_VENDORS[0];

async function setup() {
  const kp = await generateGrantAuthorityKeyPair();
  const ledger = new InMemoryGrantLedger();
  const nonces = new InMemoryNonceStore();
  const allowlist = await buildVendorAllowlist(program.approvedVendorDids);
  return { kp, ledger, nonces, allowlist };
}

const req = (over = {}) => ({
  programId: program.programId,
  beneficiaryDid: "did:kash:ben-1",
  purposeTag: "MEAL",
  amountPaisa: 250_000,
  ...over,
});

const redeemReq = (grantId: string, vendorProof: MerkleInclusionProof, over: Partial<RedeemRequest> = {}): RedeemRequest => ({
  grantId,
  vendorDid: VENDOR,
  beneficiaryDid: "did:kash:ben-1",
  purposeTag: "MEAL",
  vendorProof,
  ...over,
});

async function issueAndDeliver(kp: Awaited<ReturnType<typeof generateGrantAuthorityKeyPair>>, ledger: InMemoryGrantLedger, over = {}) {
  const issued = await issueGrant(req(over), program, kp.privateKey, ledger, { nowUnix: NOW });
  await markDelivered(issued.signed.grant.grantId, ledger, { nowUnix: NOW + 60 });
  return issued;
}

describe("mandate lifecycle — happy path", () => {
  it("issues, delivers, and redeems a grant", async () => {
    const { kp, ledger, nonces, allowlist } = await setup();
    const issued = await issueAndDeliver(kp, ledger);
    const result = await redeemGrant(
      redeemReq(issued.signed.grant.grantId, allowlist.proofByDid.get(VENDOR)!),
      kp.publicKey,
      ledger,
      nonces,
      { nowUnix: NOW + 120 },
    );
    expect(result.record.state).toBe("REDEEMED");
  });

  it("rejects an out-of-program purpose at ISSUE", async () => {
    const { kp, ledger } = await setup();
    await expect(issueGrant(req({ purposeTag: "CASINO" }), program, kp.privateKey, ledger, { nowUnix: NOW })).rejects.toMatchObject({ code: "PURPOSE_MISMATCH" });
  });
});

describe("policy gate — each rule rejects with a neutral code", () => {
  it("PURPOSE_MISMATCH when the sale purpose differs", async () => {
    const { kp, ledger, nonces, allowlist } = await setup();
    const issued = await issueAndDeliver(kp, ledger);
    await expect(
      redeemGrant(redeemReq(issued.signed.grant.grantId, allowlist.proofByDid.get(VENDOR)!, { purposeTag: "GROCERY" }), kp.publicKey, ledger, nonces, { nowUnix: NOW + 120 }),
    ).rejects.toMatchObject({ code: "PURPOSE_MISMATCH" });
  });

  it("BENEFICIARY_BINDING_FAILED for the wrong presenter", async () => {
    const { kp, ledger, nonces, allowlist } = await setup();
    const issued = await issueAndDeliver(kp, ledger);
    await expect(
      redeemGrant(redeemReq(issued.signed.grant.grantId, allowlist.proofByDid.get(VENDOR)!, { beneficiaryDid: "did:kash:impostor" }), kp.publicKey, ledger, nonces, { nowUnix: NOW + 120 }),
    ).rejects.toMatchObject({ code: "BENEFICIARY_BINDING_FAILED" });
  });

  it("EXPIRED past the grant's expiry", async () => {
    const { kp, ledger, nonces, allowlist } = await setup();
    const issued = await issueAndDeliver(kp, ledger, { expiryUnix: NOW + 100 });
    await expect(
      redeemGrant(redeemReq(issued.signed.grant.grantId, allowlist.proofByDid.get(VENDOR)!), kp.publicKey, ledger, nonces, { nowUnix: NOW + 1000 }),
    ).rejects.toMatchObject({ code: "EXPIRED" });
  });

  it("VENDOR_NOT_IN_ALLOWLIST for a vendor outside the signed set", async () => {
    const { kp, ledger, nonces, allowlist } = await setup();
    const issued = await issueAndDeliver(kp, ledger);
    // A valid proof for VENDOR, but claim a different vendorDid → recovered root won't match.
    await expect(
      redeemGrant(redeemReq(issued.signed.grant.grantId, allowlist.proofByDid.get(VENDOR)!, { vendorDid: "did:kash:not-a-vendor" }), kp.publicKey, ledger, nonces, { nowUnix: NOW + 120 }),
    ).rejects.toMatchObject({ code: "VENDOR_NOT_IN_ALLOWLIST" });
  });

  it("SIGNATURE_INVALID under the wrong operator key", async () => {
    const { kp, ledger, nonces, allowlist } = await setup();
    const issued = await issueAndDeliver(kp, ledger);
    const wrong = await generateGrantAuthorityKeyPair();
    await expect(
      redeemGrant(redeemReq(issued.signed.grant.grantId, allowlist.proofByDid.get(VENDOR)!), wrong.publicKey, ledger, nonces, { nowUnix: NOW + 120 }),
    ).rejects.toMatchObject({ code: "SIGNATURE_INVALID" });
  });

  it("NOT_REDEEMABLE on a double-spend (already redeemed)", async () => {
    const { kp, ledger, nonces, allowlist } = await setup();
    const issued = await issueAndDeliver(kp, ledger);
    const r = redeemReq(issued.signed.grant.grantId, allowlist.proofByDid.get(VENDOR)!);
    await redeemGrant(r, kp.publicKey, ledger, nonces, { nowUnix: NOW + 120 });
    await expect(redeemGrant(r, kp.publicKey, ledger, nonces, { nowUnix: NOW + 130 })).rejects.toMatchObject({ code: "NOT_REDEEMABLE" });
  });

  it("NOT_FOUND for an unknown grant", async () => {
    const { kp, ledger, nonces, allowlist } = await setup();
    await expect(
      redeemGrant(redeemReq("grant_missing", allowlist.proofByDid.get(VENDOR)!), kp.publicKey, ledger, nonces, { nowUnix: NOW }),
    ).rejects.toMatchObject({ code: "NOT_FOUND" });
  });

  it("errors are WhiffinPolicyError (neutral, no DD_*)", async () => {
    const { kp, ledger } = await setup();
    try {
      await issueGrant(req({ purposeTag: "CASINO" }), program, kp.privateKey, ledger, { nowUnix: NOW });
      throw new Error("should have thrown");
    } catch (err) {
      expect(err).toBeInstanceOf(WhiffinPolicyError);
      expect((err as WhiffinPolicyError).message).not.toContain("DD_");
    }
  });
});

describe("the mandate carries its purpose, limits, end date and arrival clause (KS-R4)", () => {
  it("every new grant states who confirms arrival: the recipient, two signatures (d41)", async () => {
    const { kp, ledger } = await setup();
    const { signed } = await issueGrant(req(), program, kp.privateKey, ledger, { nowUnix: NOW });
    expect(signed.grant.arrival).toEqual({ confirmedBy: "RECIPIENT", signatures: 2 });
    expect(isArrivalClause(signed.grant.arrival)).toBe(true);
    expect(await verifyGrant(signed, kp.publicKey)).toBe(true);
  });

  it("the arrival clause is part of the signed bytes — weakening it breaks the signature", async () => {
    const { kp, ledger } = await setup();
    const { signed } = await issueGrant(req(), program, kp.privateKey, ledger, { nowUnix: NOW });
    const weakened = { ...signed, grant: { ...signed.grant, arrival: { confirmedBy: "RECIPIENT", signatures: 1 } } } as unknown as SignedGrant;
    expect(await verifyGrant(weakened, kp.publicKey)).toBe(false);
  });

  it("isArrivalClause accepts exactly the d41 clause and nothing weaker or wider", () => {
    expect(isArrivalClause(ARRIVAL_CLAUSE)).toBe(true);
    expect(isArrivalClause({ confirmedBy: "RECIPIENT", signatures: 1 })).toBe(false);
    expect(isArrivalClause({ confirmedBy: "PAYER", signatures: 2 })).toBe(false);
    expect(isArrivalClause({ confirmedBy: "RECIPIENT", signatures: 2, extra: true })).toBe(false);
    expect(isArrivalClause(null)).toBe(false);
  });

  it("a mandate always has an end date: the program default fills one, an explicit one wins", async () => {
    const { kp, ledger } = await setup();
    const byDefault = await issueGrant(req(), program, kp.privateKey, ledger, { nowUnix: NOW });
    expect(byDefault.signed.grant.expiryUnix).toBe(NOW + program.defaultExpirySeconds);
    const explicit = await issueGrant(req({ expiryUnix: NOW + 500 }), program, kp.privateKey, ledger, { nowUnix: NOW });
    expect(explicit.signed.grant.expiryUnix).toBe(NOW + 500);
  });

  it("no mandate can be issued without a future end date (d43: every rule expires)", async () => {
    const { kp, ledger } = await setup();
    // An end date in the past, or exactly now, is refused.
    await expect(issueGrant(req({ expiryUnix: NOW - 1 }), program, kp.privateKey, ledger, { nowUnix: NOW })).rejects.toMatchObject({ code: "VALIDATION" });
    await expect(issueGrant(req({ expiryUnix: NOW }), program, kp.privateKey, ledger, { nowUnix: NOW })).rejects.toMatchObject({ code: "VALIDATION" });
    // So is a program whose default would leave no end date at all.
    const noDefault = { ...program, defaultExpirySeconds: undefined } as unknown as typeof program;
    await expect(issueGrant(req(), noDefault, kp.privateKey, ledger, { nowUnix: NOW })).rejects.toMatchObject({ code: "VALIDATION" });
    const zeroDefault = { ...program, defaultExpirySeconds: 0 };
    await expect(issueGrant(req(), zeroDefault, kp.privateKey, ledger, { nowUnix: NOW })).rejects.toMatchObject({ code: "VALIDATION" });
  });

  it("an EXPIRED grant cannot be redeemed", async () => {
    const { kp, ledger, nonces, allowlist } = await setup();
    const issued = await issueAndDeliver(kp, ledger);
    await ledger.recordTransition(issued.signed.grant.grantId, {
      grantId: issued.signed.grant.grantId,
      toState: "EXPIRED",
      actorDid: "did:kash:funder-example",
      actorClass: "PROTOCOL",
      reason: "end date passed",
      code: null,
      atUnix: NOW + 1,
    });
    await expect(
      redeemGrant(redeemReq(issued.signed.grant.grantId, allowlist.proofByDid.get(VENDOR)!), kp.publicKey, ledger, nonces, { nowUnix: NOW + 2 }),
    ).rejects.toMatchObject({ code: "NOT_REDEEMABLE" });
  });

  it("the lifecycle vocabulary is closed: nothing to hold, return or claw back (d41)", () => {
    expect([...GRANT_LIFECYCLE_STATES]).toEqual(["ISSUED", "DELIVERED", "REDEEMED", "EXPIRED"]);
  });
});
