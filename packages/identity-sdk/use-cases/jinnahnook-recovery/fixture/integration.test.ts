/**
 * Jinnahnook identity recovery — integration tests.
 *
 * Five layers:
 *   1. Enrolment — student sets a 2-of-3 advisor quorum
 *   2. Loss + claim — new device generates fresh keypair, claims DID
 *   3. Advisor attestation — each advisor signs the same claim
 *   4. Verification — quorum threshold reached → accept; otherwise reject
 *   5. Adversarial cases — single-advisor fraud, duplicate attestations,
 *      out-of-quorum advisor, weak threshold
 */

import { describe, expect, test } from "bun:test";
import { Signer } from "@kashscript/identity-core/signer";
import { encodeBase58 } from "@kashscript/identity-core/base58";

// Recovery primitives were promoted upstream from this fixture into
// the SDK proper after the persona audit. The use case now exercises
// the published API directly.
import {
  setRecoveryQuorum,
  buildRecoveryClaim,
  advisorAttestRecovery,
  verifyRecovery,
  advisorRefFromSigner,
  type AdvisorRef,
} from "@kashscript/identity-sdk/recovery";

async function makeStudent() {
  return await Signer.generate();
}

async function makeAdvisors(n = 3): Promise<{
  signers: Signer[];
  refs: AdvisorRef[];
}> {
  const signers: Signer[] = [];
  const refs: AdvisorRef[] = [];
  for (let i = 0; i < n; i++) {
    const s = await Signer.generate();
    signers.push(s);
    refs.push({ did: s.did, publicKeyB58: encodeBase58(s.publicKey) });
  }
  return { signers, refs };
}

/* ─────────────────────────────────────────────────────────────────
 *  Layer 1 — Enrolment
 * ───────────────────────────────────────────────────────────────── */

describe("Jinnahnook recovery · Enrolment", () => {
  test("student signs a 2-of-3 quorum envelope", async () => {
    const student = await makeStudent();
    const { refs } = await makeAdvisors(3);
    const env = await setRecoveryQuorum(student, refs, 2);
    expect(env.header.did).toBe(student.did);
    expect(env.signature.dst).toBe("kash-recovery-v1\n");
    const body = env.body as { advisors: AdvisorRef[]; threshold: number };
    expect(body.threshold).toBe(2);
    expect(body.advisors).toHaveLength(3);
  });

  test("setRecoveryQuorum refuses a threshold that's not a strict majority", async () => {
    const student = await makeStudent();
    const { refs } = await makeAdvisors(3);
    // 1-of-3 is not strict majority (1*2 = 2 ≤ 3).
    await expect(setRecoveryQuorum(student, refs, 1)).rejects.toThrow(/strict majority/);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 2 — Recovery claim
 * ───────────────────────────────────────────────────────────────── */

describe("Jinnahnook recovery · Claim", () => {
  test("new device builds a claim referencing the original quorum envelope", async () => {
    const student = await makeStudent();
    const { refs } = await makeAdvisors(3);
    const quorumEnv = await setRecoveryQuorum(student, refs, 2);

    const newDevice = await Signer.generate();
    const claim = buildRecoveryClaim(
      student.did,
      newDevice.publicKey,
      "sha256:quorum-envelope-content-hash-placeholder",
    );
    expect(claim.subjectDid).toBe(student.did);
    expect(claim.newPublicKeyB58).toBe(encodeBase58(newDevice.publicKey));
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 3 + 4 — Attestation + verification (happy path)
 * ───────────────────────────────────────────────────────────────── */

describe("Jinnahnook recovery · Happy-path verification", () => {
  test("2 of 3 advisors attest → verification succeeds", async () => {
    const student = await makeStudent();
    const { signers, refs } = await makeAdvisors(3);
    const quorumEnv = await setRecoveryQuorum(student, refs, 2);

    const newDevice = await Signer.generate();
    const claim = buildRecoveryClaim(student.did, newDevice.publicKey, "sha256:ref");

    const att0 = await advisorAttestRecovery(signers[0]!, claim);
    const att1 = await advisorAttestRecovery(signers[1]!, claim);

    const result = await verifyRecovery({
      quorumEnvelope: quorumEnv,
      userOriginalPublicKey: student.publicKey,
      claim,
      attestations: [att0, att1],
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.newPublicKeyB58).toBe(encodeBase58(newDevice.publicKey));
    }
  });

  test("3 of 3 advisors attest → still succeeds (over-quorum is fine)", async () => {
    const student = await makeStudent();
    const { signers, refs } = await makeAdvisors(3);
    const quorumEnv = await setRecoveryQuorum(student, refs, 2);

    const newDevice = await Signer.generate();
    const claim = buildRecoveryClaim(student.did, newDevice.publicKey, "sha256:ref");

    const atts = await Promise.all(signers.map((s) => advisorAttestRecovery(s, claim)));
    const result = await verifyRecovery({
      quorumEnvelope: quorumEnv,
      userOriginalPublicKey: student.publicKey,
      claim,
      attestations: atts,
    });
    expect(result.ok).toBe(true);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 5 — Adversarial cases
 * ───────────────────────────────────────────────────────────────── */

describe("Jinnahnook recovery · Adversarial", () => {
  test("only 1 advisor attests → rejects (under-quorum)", async () => {
    const student = await makeStudent();
    const { signers, refs } = await makeAdvisors(3);
    const quorumEnv = await setRecoveryQuorum(student, refs, 2);

    const newDevice = await Signer.generate();
    const claim = buildRecoveryClaim(student.did, newDevice.publicKey, "sha256:ref");
    const att0 = await advisorAttestRecovery(signers[0]!, claim);

    const result = await verifyRecovery({
      quorumEnvelope: quorumEnv,
      userOriginalPublicKey: student.publicKey,
      claim,
      attestations: [att0],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/distinct attestations/);
  });

  test("duplicate advisor attestation only counts once", async () => {
    const student = await makeStudent();
    const { signers, refs } = await makeAdvisors(3);
    const quorumEnv = await setRecoveryQuorum(student, refs, 2);

    const newDevice = await Signer.generate();
    const claim = buildRecoveryClaim(student.did, newDevice.publicKey, "sha256:ref");
    const att0a = await advisorAttestRecovery(signers[0]!, claim);
    const att0b = await advisorAttestRecovery(signers[0]!, claim); // same advisor twice

    const result = await verifyRecovery({
      quorumEnvelope: quorumEnv,
      userOriginalPublicKey: student.publicKey,
      claim,
      attestations: [att0a, att0b],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/duplicate attestation/);
  });

  test("attestation from a non-quorum signer → rejects", async () => {
    const student = await makeStudent();
    const { signers, refs } = await makeAdvisors(3);
    const quorumEnv = await setRecoveryQuorum(student, refs, 2);

    const newDevice = await Signer.generate();
    const imposter = await Signer.generate();
    const claim = buildRecoveryClaim(student.did, newDevice.publicKey, "sha256:ref");
    const att0 = await advisorAttestRecovery(signers[0]!, claim);
    const attImposter = await advisorAttestRecovery(imposter, claim);

    const result = await verifyRecovery({
      quorumEnvelope: quorumEnv,
      userOriginalPublicKey: student.publicKey,
      claim,
      attestations: [att0, attImposter],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/not in the quorum/);
  });

  test("advisor signs a different claim than the proposed one → rejects", async () => {
    const student = await makeStudent();
    const { signers, refs } = await makeAdvisors(3);
    const quorumEnv = await setRecoveryQuorum(student, refs, 2);

    const newDevice = await Signer.generate();
    const realClaim  = buildRecoveryClaim(student.did, newDevice.publicKey, "sha256:ref");
    const otherKey   = await Signer.generate();
    const wrongClaim = buildRecoveryClaim(student.did, otherKey.publicKey, "sha256:ref");

    const att0 = await advisorAttestRecovery(signers[0]!, realClaim);
    const att1 = await advisorAttestRecovery(signers[1]!, wrongClaim); // signs the WRONG claim

    const result = await verifyRecovery({
      quorumEnvelope: quorumEnv,
      userOriginalPublicKey: student.publicKey,
      claim: realClaim,
      attestations: [att0, att1],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/different claim body/);
  });

  test("forged quorum envelope (signed by an imposter) → rejects", async () => {
    const realStudent = await makeStudent();
    const imposter    = await makeStudent();
    const { signers, refs } = await makeAdvisors(3);
    // The forger signs a quorum envelope claiming to be the real student.
    // (For this test we pass imposter's pubkey into setRecoveryQuorum's
    //  inner sign by using the imposter as the signer.)
    const forgedEnv = await setRecoveryQuorum(imposter, refs, 2);

    const newDevice = await Signer.generate();
    const claim = buildRecoveryClaim(realStudent.did, newDevice.publicKey, "sha256:ref");
    const atts = await Promise.all(signers.slice(0, 2).map((s) => advisorAttestRecovery(s, claim)));

    // Verifier holds the REAL student's pubkey, the forged envelope
    // doesn't verify under it.
    const result = await verifyRecovery({
      quorumEnvelope: forgedEnv,
      userOriginalPublicKey: realStudent.publicKey,
      claim,
      attestations: atts,
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/quorum envelope signature does not verify/);
  });
});
