/**
 * manifest.test.ts — compileManifest: deterministic sealing, and the
 * invariants a draft must meet before it can be sealed.
 */

import { expect, test } from "bun:test";

import { deriveDid, generateKeyPair } from "@kashscript/identity-core";
import { keccak_256, sha3_256 } from "@noble/hashes/sha3";
import { bytesToHex } from "@noble/hashes/utils";

import { compileManifest, type ManifestDraft } from "../src/manifest";
import { MIN_LOCKOUT_SECONDS, type PartyRef, type ShareLeg } from "../src/types";

const mkParty = async (): Promise<PartyRef> => {
  const did = deriveDid((await generateKeyPair()).publicKey);
  return { did, didCommitment: ("0x" + "cc".repeat(32)) as `0x${string}`, kid: `${did}#sig-1` };
};

const [buyer, seller, attestor, attestor2] = [await mkParty(), await mkParty(), await mkParty(), await mkParty()];

const SPLITS: ShareLeg[] = [
  { did: seller.did, bps: 9_000 },
  { did: buyer.did, bps: 1_000, sweepFinal: true },
];

const DRAFT: ManifestDraft = {
  v: 3,
  blueprint: "otdc",
  parties: { buyer, seller, attestors: [attestor] },
  price: { amount: "250000", currency: "PKR" },
  splits: SPLITS,
  validation: { classThresholds: { 1: 1, 2: 0, 3: 0 }, priorityClasses: [1], threshold: 1 },
  softTimeoutAt: 1_760_086_400,     // Unix seconds
  hardTimeoutAt: 1_760_090_000,
  disputeTimeoutAt: 1_761_000_000,
  witnesses: { set: [attestor], threshold: 1 },
  payload: { kind: "otdc", otdc: { deliveryClaim: "0x00", description: "a booking", buyerExpectation: "arrive on the day" } },
  metadata: {},
};

const code = (draft: unknown) => compileManifest(draft as ManifestDraft);

/* ── sealing ── */

test("compile is deterministic and content-addressed", async () => {
  const a = await compileManifest(DRAFT);
  const b = await compileManifest({ ...DRAFT });
  expect(a.manifestId).toBe(b.manifestId);
  expect(a.manifestId).toMatch(/^kash-trade:0x[0-9a-f]{64}$/);
  expect(Array.from(a.jcsBytes)).toEqual(Array.from(b.jcsBytes));
  const changed = await compileManifest({ ...DRAFT, price: { amount: "250001", currency: "PKR" } });
  expect(changed.manifestId).not.toBe(a.manifestId);
});

test("the id is keccak-256 of the canonical bytes — not NIST SHA3-256", async () => {
  // Pin the algorithm: keccak-256("") is a published vector, and SHA3-256("") differs.
  expect(bytesToHex(keccak_256(new Uint8Array()))).toBe("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  const { manifestId, jcsBytes } = await compileManifest(DRAFT);
  expect(manifestId).toBe(`kash-trade:0x${bytesToHex(keccak_256(jcsBytes))}`);
  expect(manifestId).not.toBe(`kash-trade:0x${bytesToHex(sha3_256(jcsBytes))}`);
});

test("key order does not change the id (canonical JSON)", async () => {
  const reversed = Object.fromEntries(Object.entries(DRAFT).reverse()) as ManifestDraft;
  expect((await compileManifest(reversed)).manifestId).toBe((await compileManifest(DRAFT)).manifestId);
});

/* ── invariants ── */

test("rejects a wrong version and a dropped blueprint", async () => {
  await expect(code({ ...DRAFT, v: 2 })).rejects.toMatchObject({ code: "WRONG_VERSION" });
  await expect(code({ ...DRAFT, blueprint: "escrow" })).rejects.toMatchObject({ code: "UNKNOWN_BLUEPRINT" });
  await expect(code({ ...DRAFT, blueprint: "auction" })).rejects.toMatchObject({ code: "UNKNOWN_BLUEPRINT" });
  await expect(code({ ...DRAFT, blueprint: "subscription" })).rejects.toMatchObject({ code: "INVALID_BLUEPRINT_PAYLOAD" });
});

test("rejects a bad price", async () => {
  await expect(code({ ...DRAFT, price: { amount: "-1", currency: "PKR" } })).rejects.toMatchObject({ code: "INVALID_MANIFEST" });
  await expect(code({ ...DRAFT, price: { amount: "1", currency: "" } })).rejects.toMatchObject({ code: "INVALID_MANIFEST" });
});

test("rejects splits that leave dust or do not name a did:kash", async () => {
  await expect(code({ ...DRAFT, splits: [{ did: seller.did, bps: 9_000 }, { did: buyer.did, bps: 1_000 }] })).rejects.toMatchObject({ code: "NO_SWEEP_LEG" });
  await expect(code({ ...DRAFT, splits: [{ did: seller.did, bps: 9_000, sweepFinal: true }, { did: buyer.did, bps: 900 }] })).rejects.toMatchObject({ code: "BPS_SUM" });
  await expect(code({ ...DRAFT, splits: [{ did: seller.did, bps: 5_000, sweepFinal: true }, { did: buyer.did, bps: 5_000, sweepFinal: true }] })).rejects.toMatchObject({ code: "DUPLICATE_SWEEP" });
  await expect(code({ ...DRAFT, splits: [{ did: "0x" + "11".repeat(20), bps: 10_000, sweepFinal: true }] })).rejects.toMatchObject({ code: "WRONG_DID" });
});

test("a roundingHolder stands in for a sweep leg", async () => {
  const noSweep = [{ did: seller.did, bps: 9_000 }, { did: buyer.did, bps: 1_000 }];
  await expect(compileManifest({ ...DRAFT, splits: noSweep, roundingHolder: seller.did })).resolves.toBeDefined();
});

test("rejects timeouts that leave less than the lockout floor between soft and hard", async () => {
  const soft = DRAFT.softTimeoutAt;
  await expect(code({ ...DRAFT, hardTimeoutAt: soft })).rejects.toMatchObject({ code: "PRE_HARD_TIMEOUT" });
  await expect(code({ ...DRAFT, hardTimeoutAt: soft + MIN_LOCKOUT_SECONDS - 1 })).rejects.toMatchObject({ code: "PRE_HARD_TIMEOUT" });
  await expect(compileManifest({ ...DRAFT, hardTimeoutAt: soft + MIN_LOCKOUT_SECONDS })).resolves.toBeDefined(); // exactly the floor is fine
});

test("timeouts must be Unix seconds — milliseconds are refused", async () => {
  const ms = Date.UTC(2026, 9, 9);                       // a millisecond timestamp
  await expect(code({ ...DRAFT, softTimeoutAt: ms, hardTimeoutAt: ms + 3_600_000 })).rejects.toMatchObject({ code: "INVALID_MANIFEST" });
  await expect(code({ ...DRAFT, disputeTimeoutAt: 1.5 })).rejects.toMatchObject({ code: "INVALID_MANIFEST" });
  await expect(code({ ...DRAFT, softTimeoutAt: -1 })).rejects.toMatchObject({ code: "INVALID_MANIFEST" });
});

test("rejects a sub-majority quorum and a class-count mismatch", async () => {
  const two = { ...DRAFT, parties: { buyer, seller, attestors: [attestor, attestor2] }, validation: { ...DRAFT.validation, priorityClasses: [1, 1] as [1, 1] } };
  await expect(code(two)).rejects.toMatchObject({ code: "SUB_MAJORITY_QUORUM" }); // 1-of-2
  await expect(code({ ...DRAFT, validation: { ...DRAFT.validation, priorityClasses: [1, 1] } })).rejects.toMatchObject({ code: "INVALID_MANIFEST" });
});

test("a subscription with cascade-on-N-failures needs a positive N", async () => {
  const sub = (max?: number): ManifestDraft => ({
    ...DRAFT,
    blueprint: "subscription",
    payload: {
      kind: "subscription",
      subscription: {
        periodSeconds: 604_800, maxPeriods: 3, perPeriodSplits: SPLITS, perPeriodAmount: "1000",
        cancellation: { leadTimeSeconds: 86_400, owedPolicy: "pro-rata" }, autoRenew: false,
        periodRevertPolicy: "cascade-on-N-failures", ...(max !== undefined ? { maxSequentialFailedPeriods: max } : {}),
      },
    },
  });
  await expect(code(sub())).rejects.toMatchObject({ code: "INVALID_BLUEPRINT_PAYLOAD" });
  await expect(compileManifest(sub(2))).resolves.toBeDefined();
});

test("a milestone schedule's step shares must total 10000 and each step must be dust-free", async () => {
  const step = (bps: number, sweep = true) => ({
    stepId: "0x01" as const, bps, triggerClaim: "0x02" as const,
    recipients: [{ did: seller.did, bps: 10_000, ...(sweep ? { sweepFinal: true } : {}) }],
  });
  const ms = (steps: ReturnType<typeof step>[]): ManifestDraft => ({ ...DRAFT, blueprint: "milestone", payload: { kind: "milestone", milestone: { steps } } });
  await expect(compileManifest(ms([step(6_000), step(4_000)]))).resolves.toBeDefined();
  await expect(code(ms([step(6_000), step(3_000)]))).rejects.toMatchObject({ code: "BPS_SUM" });
  await expect(code(ms([step(10_000, false)]))).rejects.toMatchObject({ code: "NO_SWEEP_LEG" });
  await expect(code(ms([]))).rejects.toMatchObject({ code: "INVALID_BLUEPRINT_PAYLOAD" });
});
