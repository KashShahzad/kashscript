/**
 * Paceplug co-founder multi-sig — integration tests.
 *
 *   1. Constitution invariants — strict-majority threshold required
 *   2. Happy path — 2 of 3 founders sign a board action; verifier accepts
 *   3. Over-quorum (3 of 3) — still accepts
 *   4. Adversarial — under-quorum, duplicate signer, outsider, body drift
 */

import { describe, expect, test } from "bun:test";
import { Signer } from "@kashscript/identity-core/signer";

import {
  buildConstitution,
  founderCoSign,
  verifyBoardAction,
  founderRefFromSigner,
} from "./multisig";

async function makeStartup(founderCount = 3, threshold = 2) {
  const founders: Signer[] = [];
  for (let i = 0; i < founderCount; i++) founders.push(await Signer.generate());
  const constitution = buildConstitution(
    "Paceplug Inc.",
    "did:kash:CompanyDidPlaceholder12345678901234567890123",
    founders.map(founderRefFromSigner),
    threshold,
  );
  return { founders, constitution };
}

const SAMPLE_BOARD_ACTION = {
  action: "grant-equity",
  grantee: "did:kash:NewHireDidPlaceholder12345678901234567890123",
  optionsCount: 10_000,
  vestingMonths: 48,
  cliffMonths: 12,
};

/* ─────────────────────────────────────────────────────────────────
 *  Layer 1 — Constitution invariants
 * ───────────────────────────────────────────────────────────────── */

describe("Paceplug multi-sig · Constitution", () => {
  test("buildConstitution accepts a strict-majority threshold", async () => {
    const { constitution } = await makeStartup(3, 2);
    expect(constitution.threshold).toBe(2);
    expect(constitution.founders).toHaveLength(3);
    expect(constitution.companyName).toBe("Paceplug Inc.");
  });

  test("buildConstitution refuses non-majority thresholds", async () => {
    const founders = [
      await Signer.generate(),
      await Signer.generate(),
      await Signer.generate(),
    ].map(founderRefFromSigner);
    // 1-of-3 → 1*2 = 2 ≤ 3 → not strict majority
    expect(() =>
      buildConstitution("Bad Co", "did:kash:x".padEnd(48, "x"), founders, 1),
    ).toThrow(/strict majority/);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 2 — Happy path
 * ───────────────────────────────────────────────────────────────── */

describe("Paceplug multi-sig · Happy path", () => {
  test("2 of 3 co-sign a board action → quorum accepts", async () => {
    const { founders, constitution } = await makeStartup(3, 2);
    const co0 = await founderCoSign(founders[0]!, SAMPLE_BOARD_ACTION);
    const co1 = await founderCoSign(founders[1]!, SAMPLE_BOARD_ACTION);

    const result = await verifyBoardAction({
      constitution,
      proposedBody: SAMPLE_BOARD_ACTION,
      cosignatures: [co0, co1],
    });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.approvedBy).toHaveLength(2);
  });

  test("3 of 3 still accepts (over-quorum is fine)", async () => {
    const { founders, constitution } = await makeStartup(3, 2);
    const all = await Promise.all(
      founders.map((f) => founderCoSign(f, SAMPLE_BOARD_ACTION)),
    );
    const result = await verifyBoardAction({
      constitution,
      proposedBody: SAMPLE_BOARD_ACTION,
      cosignatures: all,
    });
    expect(result.ok).toBe(true);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 3 — Adversarial
 * ───────────────────────────────────────────────────────────────── */

describe("Paceplug multi-sig · Adversarial", () => {
  test("only 1 of 3 → rejects (under-quorum)", async () => {
    const { founders, constitution } = await makeStartup(3, 2);
    const co0 = await founderCoSign(founders[0]!, SAMPLE_BOARD_ACTION);
    const result = await verifyBoardAction({
      constitution,
      proposedBody: SAMPLE_BOARD_ACTION,
      cosignatures: [co0],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/distinct co-signatures/);
  });

  test("same founder twice → only counts once → under-quorum", async () => {
    const { founders, constitution } = await makeStartup(3, 2);
    const co0a = await founderCoSign(founders[0]!, SAMPLE_BOARD_ACTION);
    const co0b = await founderCoSign(founders[0]!, SAMPLE_BOARD_ACTION);
    const result = await verifyBoardAction({
      constitution,
      proposedBody: SAMPLE_BOARD_ACTION,
      cosignatures: [co0a, co0b],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/duplicate co-signature/);
  });

  test("outsider co-signs → rejects (not in founder set)", async () => {
    const { founders, constitution } = await makeStartup(3, 2);
    const outsider = await Signer.generate();
    const co0 = await founderCoSign(founders[0]!, SAMPLE_BOARD_ACTION);
    const coOut = await founderCoSign(outsider, SAMPLE_BOARD_ACTION);
    const result = await verifyBoardAction({
      constitution,
      proposedBody: SAMPLE_BOARD_ACTION,
      cosignatures: [co0, coOut],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/not in the founder set/);
  });

  test("founder signs a different body than the one being verified → rejects", async () => {
    const { founders, constitution } = await makeStartup(3, 2);
    const co0 = await founderCoSign(founders[0]!, SAMPLE_BOARD_ACTION);
    const tampered = { ...SAMPLE_BOARD_ACTION, optionsCount: 50_000 }; // grant 5x more
    const co1 = await founderCoSign(founders[1]!, tampered);
    const result = await verifyBoardAction({
      constitution,
      proposedBody: SAMPLE_BOARD_ACTION, // verifier proposes the ORIGINAL action
      cosignatures: [co0, co1],
    });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toMatch(/signs a different body/);
  });
});
