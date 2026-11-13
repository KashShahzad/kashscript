// Red-team audit round 1 — whiffin regression tests (specs/whiffin-audit-r1.md).
// F3: verifyGrant PINS the grant DST. F5: verifyVendorInclusion bounds proof
// depth. (F6/F7 — the EMVCo amount and CRC fixes — went with the EMVCo encoder
// when the rail adapters were removed in 0.2.0; the encoder is in git history.)

import { describe, expect, it } from "bun:test";
import { generateGrantAuthorityKeyPair, verifyGrant, verifyVendorInclusion } from "../src/mandate/grant";
import type { MerkleInclusionProof } from "../src/mandate/grant";
import { InMemoryGrantLedger, issueGrant } from "../src/mandate/lifecycle";
import { exampleProgram } from "./fixtures";

describe("audit r1 F3 — verifyGrant pins the grant DST", () => {
  it("accepts a genuine grant but rejects one whose signature DST is swapped", async () => {
    const kp = await generateGrantAuthorityKeyPair();
    const program = exampleProgram();
    const ledger = new InMemoryGrantLedger();
    const { signed } = await issueGrant(
      { programId: program.programId, beneficiaryDid: "did:kash:ben-1", purposeTag: "MEAL", amountPaisa: 5000 },
      program,
      kp.privateKey,
      ledger,
      { nowUnix: 1_800_000_000 },
    );
    expect(await verifyGrant(signed, kp.publicKey)).toBe(true);
    const tampered = { ...signed, signature: { ...signed.signature, dst: "kash-record-v1\n" } };
    expect(await verifyGrant(tampered, kp.publicKey)).toBe(false);
  });
});

describe("audit r1 F5 — merkle hardening", () => {
  it("F5: verifyVendorInclusion rejects an over-long proof (no unbounded hashing)", async () => {
    const fakeProof = {
      siblings: Array.from({ length: 33 }, () => new Uint8Array(32)),
      positions: Array.from({ length: 33 }, () => 0),
    } as unknown as MerkleInclusionProof;
    expect(await verifyVendorInclusion("did:kash:v", fakeProof, "00".repeat(32))).toBe(false);
  });
});
