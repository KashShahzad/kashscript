/**
 * completion-receipt.test.ts — a signed record that an agreement concluded:
 * round-trip, the review gate, the security properties (DST scoping, tamper,
 * wrong issuer, cross-manifest replay), and the pinned tag.
 */

import { expect, test } from "bun:test";

import { deriveDid, generateKeyPair, signEvent, type KashDid } from "@kashscript/identity-core";

import { TermsError } from "../src/errors";
import {
  RECEIPT_DST,
  buildCompletionReceipt,
  canReview,
  completionReceiptId,
  receiptBlueprint,
  signCompletionReceipt,
  verifyCompletionReceipt,
  type BuildCompletionReceiptInput,
} from "../src/completion-receipt";

// Fresh keypairs: the issuer + the two parties.
const issuer = await generateKeyPair();
const buyer = await generateKeyPair();
const seller = await generateKeyPair();
const issuerDid = deriveDid(issuer.publicKey);
const buyerDid = deriveDid(buyer.publicKey);
const sellerDid = deriveDid(seller.publicKey);

const INPUT: BuildCompletionReceiptInput = {
  issuer: issuerDid,
  manifestId: ("kash-trade:0x" + "ab".repeat(32)) as `kash-trade:${string}`,
  blueprint: "OTDC",
  state: "Resolved",
  concludedAt: 1_760_000_000,
  buyer: { did: buyerDid, didCommitment: ("0x" + "aa".repeat(32)) as `0x${string}` },
  seller: { did: sellerDid, didCommitment: ("0x" + "bb".repeat(32)) as `0x${string}` },
};

/* ── the tag never changes ── */

test("the tag is pinned: header type, header version, DST and id prefix", async () => {
  expect(RECEIPT_DST).toBe("kash-trade-receipt-v1\n");
  const receipt = buildCompletionReceipt(INPUT);
  expect(receipt.header).toEqual({ type: "kash.trade.completion", v: 1, issuer: issuerDid });
  expect((await completionReceiptId(receipt)).startsWith("kash-receipt:0x")).toBe(true);
  const signed = await signCompletionReceipt(receipt, issuer.privateKey);
  expect(signed.signature.dst).toBe("kash-trade-receipt-v1\n");
});

/* ── build ── */

test("terminal states map to outcomes; non-terminal is rejected", () => {
  expect(buildCompletionReceipt(INPUT).body.outcome).toBe("resolved");
  expect(buildCompletionReceipt({ ...INPUT, state: "Reverted" }).body.outcome).toBe("reverted");
  expect(buildCompletionReceipt({ ...INPUT, state: "Cancelled" }).body.outcome).toBe("cancelled");
  expect(() => buildCompletionReceipt({ ...INPUT, state: "Active" })).toThrow(TermsError);
  expect(() => buildCompletionReceipt({ ...INPUT, state: "Committed" })).toThrow(TermsError);
});

test("build validates issuer/party DIDs, blueprint and the concluded-at instant", () => {
  expect(() => buildCompletionReceipt({ ...INPUT, issuer: "nope" as unknown as KashDid })).toThrow(TermsError);
  expect(() => buildCompletionReceipt({ ...INPUT, buyer: { ...INPUT.buyer, did: "x" as unknown as KashDid } })).toThrow(TermsError);
  expect(() => buildCompletionReceipt({ ...INPUT, blueprint: "AUCTION" as never })).toThrow(TermsError);
  expect(() => buildCompletionReceipt({ ...INPUT, concludedAt: -1 })).toThrow(TermsError);
  expect(() => buildCompletionReceipt({ ...INPUT, concludedAt: 1.5 })).toThrow(TermsError);
  // Milliseconds are refused rather than read as a date in the year 57,000.
  expect(() => buildCompletionReceipt({ ...INPUT, concludedAt: 1_760_000_000_000 })).toThrow(TermsError);
});

test("the claim names the agreement and its parties — it carries no price or chain field", () => {
  const body = buildCompletionReceipt(INPUT).body;
  expect(Object.keys(body).sort()).toEqual(["blueprint", "concludedAt", "manifestId", "outcome", "parties", "v"]);
  expect(JSON.stringify(body)).not.toMatch(/amount|currency|price|chainId|cloneAddress/);
});

test("build rejects buyer === seller (no self-dealing)", () => {
  expect(() => buildCompletionReceipt({ ...INPUT, seller: { ...INPUT.seller, did: buyerDid } })).toThrow(TermsError);
});

test("receiptBlueprint lifts a manifest blueprint to the receipt form", () => {
  expect(receiptBlueprint("otdc")).toBe("OTDC");
  expect(receiptBlueprint("subscription")).toBe("SUBSCRIPTION");
  expect(receiptBlueprint("milestone")).toBe("MILESTONE");
});

/* ── round-trip ── */

test("a signed receipt verifies; issuer pubkey derives from the DID", async () => {
  const receipt = buildCompletionReceipt(INPUT);
  const signed = await signCompletionReceipt(receipt, issuer.privateKey);
  const v = await verifyCompletionReceipt(signed);
  expect(v.valid).toBe(true);
  expect(v.issuer).toBe(issuerDid);
  expect(v.claim.outcome).toBe("resolved");
  expect(v.claim.v).toBe(2);
  expect(signed.signature.dst).toBe(RECEIPT_DST);
});

test("verify rejects a signed-but-malformed body (build/verify symmetry)", async () => {
  // The issuer signs a garbage body under the RIGHT DST — verify must still
  // reject it structurally, so a valid:true receipt always carries a real claim.
  const header = { type: "kash.trade.completion", v: 1, issuer: issuerDid } as const;
  const garbage = { evil: true } as unknown as never;
  const signature = await signEvent(header, garbage, issuer.privateKey, { dst: RECEIPT_DST });
  await expect(verifyCompletionReceipt({ header, body: garbage, signature } as never)).rejects.toMatchObject({ code: "INVALID_RECEIPT" });
});

test("a signed claim with a millisecond instant is rejected on verify, not just on build", async () => {
  const good = buildCompletionReceipt(INPUT);
  const body = { ...good.body, concludedAt: 1_760_000_000_000 };
  const signature = await signEvent(good.header, body, issuer.privateKey, { dst: RECEIPT_DST });
  await expect(verifyCompletionReceipt({ header: good.header, body, signature } as never)).rejects.toMatchObject({ code: "INVALID_RECEIPT" });
});

test("a v1 claim is rejected, even when correctly signed under the tag", async () => {
  // The shape the retired trade-core issued. Signed properly; still not accepted here.
  const header = { type: "kash.trade.completion", v: 1, issuer: issuerDid } as const;
  const v1Body = {
    v: 1,
    manifestId: INPUT.manifestId,
    blueprint: "ESCROW",
    chainId: 8453,
    cloneAddress: "0x" + "11".repeat(20),
    outcome: "settled",
    settledAtBlock: 123,
    parties: { buyer: INPUT.buyer, seller: INPUT.seller },
    escrow: { token: "native", amount: "1000000" },
  } as unknown as never;
  const signature = await signEvent(header, v1Body, issuer.privateKey, { dst: RECEIPT_DST });
  await expect(verifyCompletionReceipt({ header, body: v1Body, signature } as never)).rejects.toMatchObject({ code: "INVALID_RECEIPT" });
});

test("malformed signature fields return valid:false, never a raw throw", async () => {
  const signed = await signCompletionReceipt(buildCompletionReceipt(INPUT), issuer.privateKey);
  expect((await verifyCompletionReceipt({ ...signed, signature: { ...signed.signature, sig: "!!!not-base58!!!" } })).valid).toBe(false);
  expect((await verifyCompletionReceipt({ ...signed, signature: { ...signed.signature, alg: "rsa" as never } })).valid).toBe(false);
});

/* ── security ── */

test("DST scoping: a record-DST signature is NOT a valid receipt", async () => {
  const receipt = buildCompletionReceipt(INPUT);
  // Sign with the DEFAULT (record) DST, then masquerade it as a receipt signature.
  const recordSig = await signEvent(receipt.header, receipt.body, issuer.privateKey); // default kash-record-v1\n
  const masquerade = { ...receipt, signature: recordSig };
  const v = await verifyCompletionReceipt(masquerade);
  expect(v.valid).toBe(false);
  expect(v.reason).toContain("DST");
});

test("tamper: mutating the body after signing breaks verification", async () => {
  const signed = await signCompletionReceipt(buildCompletionReceipt(INPUT), issuer.privateKey);
  const tampered = { ...signed, body: { ...signed.body, outcome: "cancelled" as const } };
  expect((await verifyCompletionReceipt(tampered)).valid).toBe(false);
});

test("wrong issuer: header says issuer but signed by another key → invalid", async () => {
  const receipt = buildCompletionReceipt(INPUT); // header.issuer = issuerDid
  const signedByOther = await signCompletionReceipt(receipt, seller.privateKey); // but signed with seller's key
  const v = await verifyCompletionReceipt(signedByOther); // derives pubkey from issuerDid
  expect(v.valid).toBe(false);
});

test("cross-manifest replay: swapping manifestId breaks the signature", async () => {
  const signed = await signCompletionReceipt(buildCompletionReceipt(INPUT), issuer.privateKey);
  const replayed = { ...signed, body: { ...signed.body, manifestId: ("kash-trade:0x" + "cd".repeat(32)) as `kash-trade:${string}` } };
  expect((await verifyCompletionReceipt(replayed)).valid).toBe(false);
});

test("a structurally malformed receipt throws INVALID_RECEIPT", async () => {
  await expect(verifyCompletionReceipt({} as never)).rejects.toMatchObject({ code: "INVALID_RECEIPT" });
  await expect(verifyCompletionReceipt({ header: { type: "x" }, body: {}, signature: {} } as never)).rejects.toThrow(TermsError);
});

/* ── content id ── */

test("receiptId is deterministic and content-addressed", async () => {
  const id1 = await completionReceiptId(buildCompletionReceipt(INPUT));
  const id1b = await completionReceiptId(buildCompletionReceipt(INPUT));
  const id2 = await completionReceiptId(buildCompletionReceipt({ ...INPUT, concludedAt: 999 }));
  expect(id1).toBe(id1b);
  expect(id1).not.toBe(id2);
  expect(id1.startsWith("kash-receipt:0x")).toBe(true);
});

/* ── review gate ── */

test("review gate is two-sided; strangers are ineligible", () => {
  const claim = buildCompletionReceipt(INPUT).body;
  expect(canReview(claim, buyerDid)).toMatchObject({ eligible: true, role: "buyer", subject: { did: sellerDid } });
  expect(canReview(claim, sellerDid)).toMatchObject({ eligible: true, role: "seller", subject: { did: buyerDid } });
  expect(canReview(claim, issuerDid).eligible).toBe(false);
  expect(canReview(claim, deriveDid((globalThis.crypto.getRandomValues(new Uint8Array(32))))).eligible).toBe(false);
});

test("canReview guards a malformed claim and refuses a self-dealing agreement", () => {
  expect(() => canReview({ outcome: "resolved" } as never, buyerDid)).toThrow(TermsError); // no parties
  const selfClaim = { ...buildCompletionReceipt(INPUT).body, parties: { buyer: INPUT.buyer, seller: { ...INPUT.seller, did: buyerDid } } };
  expect(canReview(selfClaim as never, buyerDid).eligible).toBe(false);
});
