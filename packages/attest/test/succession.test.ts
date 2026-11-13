/**
 * Key succession across algorithms, and recovery by a helper quorum (PL-2,
 * specs/recovery.md). A succession is not a takeover: it needs the old key or
 * a strict majority of the helpers the old key named in advance, the
 * successor must sign too, and two successors for one key are trusted by
 * nobody.
 */

import { describe, expect, it } from "bun:test";
import {
  deriveDid,
  deriveDidP256,
  generateKeyPair,
  generateP256KeyPair,
  signEvent,
  signEventWith,
  type KashKeyPair,
  type P256KeyPair,
} from "@kashscript/identity-core";
import { base64ToBytes, bytesToBase64 } from "../src/ed25519";
import { pae, signEnvelope } from "../src/dsse";
import { signBytes } from "../src/signing";
import {
  COUNTERSIGN_BUNDLE_FORMAT,
  DST_COUNTERSIGN_ACCEPTANCE,
  DST_COUNTERSIGN_REQUEST,
  countersignRequestDigest,
  verifyCountersignBundle,
} from "../src/countersign";
import { sha256Hex } from "../src/chain";
import {
  DST_KEY_CLAIM,
  DST_RECOVERY_HELPERS,
  HELPERS_MAX,
  approveKeyClaim,
  draftHelperClaim,
  helperSetSha256,
  signHelperSet,
  signKeyClaim,
  verifyHelperSet,
  verifyKeyClaim,
  verifySuccessionSet,
  withApprovals,
  type HelperKeyClaim,
  type SignedHelperSet,
  type SuccessionSigner,
} from "../src/succession";

const T = 1_790_812_800;
type Ed = KashKeyPair & { did: string };
type P = P256KeyPair & { did: string };
const ed = async (): Promise<Ed> => {
  const k = await generateKeyPair();
  return { ...k, did: deriveDid(k.publicKey) };
};
const p = async (): Promise<P> => {
  const k = await generateP256KeyPair();
  return { ...k, did: deriveDidP256(k.publicKey) };
};
const sE = (k: Ed): SuccessionSigner => ({ alg: "ed25519", did: k.did, privateKey: k.privateKey });
const sP = (k: P): SuccessionSigner => ({ alg: "es256", did: k.did, privateKey: k.privateKey, publicKey: k.publicKey });

async function setFor(subject: SuccessionSigner, helpers: string[], need = 2, sequence = 1, issuedAtUnix = T - 1000, expiresAtUnix: number | null = null) {
  return signHelperSet({ subject, helpers, need, sequence, issuedAtUnix, expiresAtUnix });
}

/** Sign a helper set's body as-is — no rule check — to test that the VERIFIER enforces the rules. */
async function rawSet(subject: SuccessionSigner, body: Record<string, unknown>): Promise<SignedHelperSet> {
  const header = { typ: "recovery-helpers", v: 1 };
  return { header, body: body as never, signature: await signEventWith(header, body, subject, { dst: DST_RECOVERY_HELPERS }) };
}

describe("the prior-key path, across algorithms", () => {
  it("Ed25519 → P-256 and P-256 → Ed25519, with a hardware-style signer on either side", async () => {
    const [a, b] = [await ed(), await p()];
    const hw: SuccessionSigner = {
      alg: "es256",
      did: b.did,
      sign: async (payload) => ({ signature: await signBytes({ alg: "ES256", privateKey: b.privateKey, publicKey: b.publicKey }, payload, "der"), format: "der" }),
    };
    const up = await signKeyClaim({ prior: sE(a), successor: hw, claimedAtUnix: T });
    const down = await signKeyClaim({ prior: sP(b), successor: sE(await ed()), claimedAtUnix: T });
    for (const [c, from, to] of [[up, "Ed25519", "P-256"], [down, "P-256", "Ed25519"]] as const) {
      const r = await verifyKeyClaim(c);
      expect(r.ok).toBe(true);
      expect(r.path).toBe("prior-key");
      expect([r.priorKeyType, r.successorKeyType]).toEqual([from, to]);
      expect(r.notes.join(" ")).toContain("across algorithms");
    }
  });

  it("is byte-for-byte ADR-0018's claim: no `by`, the same header, both signatures", async () => {
    const c = await signKeyClaim({ prior: sE(await ed()), successor: sE(await ed()), claimedAtUnix: T });
    expect(c.header).toEqual({ typ: "key-claim", v: 1 });
    expect(Object.keys(c.body).sort()).toEqual(["act", "claimedAtUnix", "priorDid", "successorDid", "successorKeyCustody"]);
  });

  it("a claim without the prior key's signature, or without the successor's, is no succession", async () => {
    const [a, b, x] = [await ed(), await p(), await ed()];
    const c = await signKeyClaim({ prior: sE(a), successor: sP(b), claimedAtUnix: T });
    const forgedPrior = { ...c, signatures: { ...c.signatures, prior: await signEvent(c.header, c.body, x.privateKey, { dst: DST_KEY_CLAIM }) } };
    expect((await verifyKeyClaim(forgedPrior)).reason).toBe("PRIOR_SIGNATURE_INVALID");
    const noSuccessor = { ...c, signatures: { ...c.signatures, successor: c.signatures.prior } };
    expect((await verifyKeyClaim(noSuccessor)).reason).toBe("SUCCESSOR_SIGNATURE_INVALID");
  });

  it("an es256 signature relabelled ed25519 (or the reverse) fails — the key decides", async () => {
    const [a, b] = [await ed(), await p()];
    const c = await signKeyClaim({ prior: sE(a), successor: sP(b), claimedAtUnix: T });
    const relabel = { ...c, signatures: { prior: { ...c.signatures.prior, alg: "es256" as const }, successor: { ...c.signatures.successor, alg: "ed25519" as const } } };
    const r = await verifyKeyClaim(relabel);
    expect(r.ok).toBe(false);
    expect(r.priorSignatureOk).toBe(false);
    expect(r.successorSignatureOk).toBe(false);
  });
});

describe("helper sets — the rules, at signing and at verifying", () => {
  it("refuses a quorum of one, a non-majority, a repeated key, the subject as its own helper, and a crowd", async () => {
    const subject = sE(await ed());
    const hs = await Promise.all(Array.from({ length: 17 }, () => ed()));
    const ids = hs.map((h) => h.did);
    await expect(setFor(subject, ids.slice(0, 3), 1)).rejects.toThrow(/one key alone/);
    await expect(setFor(subject, ids.slice(0, 4), 2)).rejects.toThrow(/strict majority/);
    await expect(setFor(subject, [ids[0]!, ids[0]!, ids[1]!], 2)).rejects.toThrow(/listed twice/);
    await expect(setFor(subject, [subject.did, ids[0]!, ids[1]!], 2)).rejects.toThrow(/names itself/);
    await expect(setFor(subject, ids.slice(0, HELPERS_MAX + 1), 9)).rejects.toThrow(/more than/);
    // 2 of 3, 3 of 5 and 2 of 2 are majorities
    for (const [n, need] of [[3, 2], [5, 3], [2, 2]] as const) {
      expect((await verifyHelperSet(await setFor(subject, ids.slice(0, n), need))).ok).toBe(true);
    }
  });

  it("the verifier enforces the same rules on a set signed without the check", async () => {
    const s = await ed();
    const h = await Promise.all([ed(), ed(), ed(), ed()]);
    const r = await verifyHelperSet(await rawSet(sE(s), { act: "name-helpers", subjectDid: s.did, helpers: h.map((x) => x.did), need: 2, sequence: 1, issuedAtUnix: T, expiresAtUnix: null }));
    expect(r.reason).toBe("RULES_BROKEN");
    expect(r.problems.join(" ")).toContain("strict majority");
  });

  it("a set signed by any key but its subject is not a set", async () => {
    const [s, other] = [await ed(), await ed()];
    const h = await Promise.all([ed(), ed(), ed()]);
    const r = await verifyHelperSet(await rawSet(sE(other), { act: "name-helpers", subjectDid: s.did, helpers: h.map((x) => x.did), need: 2, sequence: 1, issuedAtUnix: T, expiresAtUnix: null }));
    expect(r.reason).toBe("SIGNATURE_INVALID");
  });
});

describe("the helper path — a lost key, a quorum, a successor that signs", () => {
  async function scene() {
    const prior = await ed(); // on the lost phone
    const successor = await p(); // the new phone's secure chip
    const helpers = [await p(), await ed(), await ed()];
    const set = await setFor(sE(prior), helpers.map((h) => h.did));
    const draft = await draftHelperClaim({ helperSet: set, successor: sP(successor), claimedAtUnix: T });
    const signers = [sP(helpers[0]!), sE(helpers[1]!), sE(helpers[2]!)];
    return { prior, successor, helpers, set, draft, signers };
  }

  it("two of three helpers and the successor move the key; the report counts them", async () => {
    const { draft, signers } = await scene();
    const claim = withApprovals(draft, [await approveKeyClaim(draft, signers[0]!), await approveKeyClaim(draft, signers[2]!)]);
    const r = await verifyKeyClaim(claim);
    expect(r.ok).toBe(true);
    expect(r.helpers).toMatchObject({ need: 2, of: 3, counted: 2 });
    expect(r.notes.join(" ")).toContain("keys, not people");
  });

  it("one helper is below the quorum; the same helper twice still counts once", async () => {
    const { draft, signers } = await scene();
    const a = await approveKeyClaim(draft, signers[1]!);
    expect((await verifyKeyClaim(withApprovals(draft, [a]))).reason).toBe("BELOW_QUORUM");
    const twice = { ...draft, signatures: { ...draft.signatures, helpers: [a, a] } };
    const r = await verifyKeyClaim(twice);
    expect(r.reason).toBe("BELOW_QUORUM");
    expect(r.helpers?.counted).toBe(1);
  });

  it("a key the set does not name never counts, even with a valid signature", async () => {
    const { draft, signers } = await scene();
    const stranger = await ed();
    const forged = { did: stranger.did, signature: await signEvent(draft.header, draft.body, stranger.privateKey, { dst: DST_KEY_CLAIM }) };
    const r = await verifyKeyClaim(withApprovals(draft, [await approveKeyClaim(draft, signers[0]!), forged]));
    expect(r.reason).toBe("BELOW_QUORUM");
    await expect(approveKeyClaim(draft, sE(stranger))).rejects.toThrow(/does not name/);
  });

  it("without the successor's own signature there is no succession — a quorum cannot name a key nobody holds", async () => {
    const { draft, signers } = await scene();
    const full = withApprovals(draft, [await approveKeyClaim(draft, signers[0]!), await approveKeyClaim(draft, signers[1]!)]);
    const noSuccessor = { ...full, signatures: { ...full.signatures, successor: full.signatures.helpers[0]!.signature } };
    expect((await verifyKeyClaim(noSuccessor)).reason).toBe("SUCCESSOR_SIGNATURE_INVALID");
  });

  it("the claim must rest on THIS key's set, and on the very set it names", async () => {
    const { prior, helpers, draft, signers } = await scene();
    // a different set (sequence 2) swapped in under the same claim
    const other = await setFor(sE(prior), helpers.map((h) => h.did), 2, 2);
    const swapped: HelperKeyClaim = { ...draft, helperSet: other };
    expect((await verifyKeyClaim(swapped)).reason).toBe("HELPER_SET_MISMATCH");
    // a set for another key entirely
    const elsewhere = await ed();
    const foreign = await setFor(sE(elsewhere), helpers.map((h) => h.did));
    const moved = withApprovals(draft, [await approveKeyClaim(draft, signers[0]!), await approveKeyClaim(draft, signers[1]!)]);
    expect((await verifyKeyClaim({ ...moved, helperSet: foreign })).reason).toBe("HELPER_SET_NOT_FOR_PRIOR");
    expect(await helperSetSha256(other)).not.toBe(draft.body.helperSetSha256);
  });

  it("a helper cannot be the successor; a claim dated before its set, or after its expiry, is outside it", async () => {
    const prior = await ed();
    const hs = [await ed(), await ed(), await ed()];
    const set = await setFor(sE(prior), hs.map((h) => h.did), 2, 1, T, T + 1000);
    await expect(draftHelperClaim({ helperSet: set, successor: sE(hs[0]!), claimedAtUnix: T })).rejects.toThrow(/helper key cannot be the successor/);
    for (const at of [T - 1, T + 1001]) {
      const d = await draftHelperClaim({ helperSet: set, successor: sP(await p()), claimedAtUnix: at });
      const c = withApprovals(d, [await approveKeyClaim(d, sE(hs[0]!)), await approveKeyClaim(d, sE(hs[1]!))]);
      expect((await verifyKeyClaim(c)).reason).toBe("OUTSIDE_HELPER_SET_WINDOW");
    }
  });
});

describe("a succession is not a takeover — forks and superseded sets", () => {
  it("two successors for one key: each verifies alone, together neither is trusted, and the helper who signed both is named", async () => {
    const prior = await ed();
    const hs = [await ed(), await ed(), await ed()];
    const set = await setFor(sE(prior), hs.map((h) => h.did));
    const mk = async (i: number, j: number) => {
      const d = await draftHelperClaim({ helperSet: set, successor: sP(await p()), claimedAtUnix: T });
      return withApprovals(d, [await approveKeyClaim(d, sE(hs[i]!)), await approveKeyClaim(d, sE(hs[j]!))]);
    };
    const r = await verifySuccessionSet([await mk(0, 1), await mk(1, 2)]);
    expect(r.claims.every((c) => c.ok)).toBe(true);
    expect(r.ok).toBe(false);
    expect(r.conflicts[0]!.signedBoth).toEqual([hs[1]!.did]);
  });

  it("the old key and the helpers naming different successors is a fork too", async () => {
    const prior = await ed();
    const hs = [await ed(), await ed(), await ed()];
    const set = await setFor(sE(prior), hs.map((h) => h.did));
    const byKey = await signKeyClaim({ prior: sE(prior), successor: sP(await p()), claimedAtUnix: T });
    const d = await draftHelperClaim({ helperSet: set, successor: sP(await p()), claimedAtUnix: T });
    const byHelpers = withApprovals(d, [await approveKeyClaim(d, sE(hs[0]!)), await approveKeyClaim(d, sE(hs[2]!))]);
    const r = await verifySuccessionSet([byKey, byHelpers]);
    expect(r.ok).toBe(false);
    expect(r.conflicts.length).toBe(1);
  });

  it("a claim on a set the key itself later replaced does not count, once the newer set is shown", async () => {
    const prior = await ed();
    const old = [await ed(), await ed(), await ed()];
    const fresh = [await ed(), await ed(), await ed()];
    const set1 = await setFor(sE(prior), old.map((h) => h.did), 2, 1, T - 2000);
    const set2 = await setFor(sE(prior), fresh.map((h) => h.did), 2, 2, T - 1000);
    const d = await draftHelperClaim({ helperSet: set1, successor: sP(await p()), claimedAtUnix: T });
    const c = withApprovals(d, [await approveKeyClaim(d, sE(old[0]!)), await approveKeyClaim(d, sE(old[1]!))]);
    expect((await verifySuccessionSet([c])).ok).toBe(true); // shown alone, offline, it stands…
    const r = await verifySuccessionSet([c], [set2]); // …and the replacement, once shown, retires it
    expect(r.ok).toBe(false);
    expect(r.superseded[0]).toMatchObject({ sequence: 1, newerSequence: 2 });
    expect(r.notes.join(" ")).toContain("absence of a conflicting claim is not proof");
  });

  it("KNOWN LIMIT (specs/recovery.md §3): a replaced quorum that dates its claim before the newer set was issued is not retired — the claim's time is its signers' own word", async () => {
    const prior = await ed();
    const old = [await ed(), await ed(), await ed()];
    const fresh = [await ed(), await ed(), await ed()];
    const set1 = await setFor(sE(prior), old.map((h) => h.did), 2, 1, T - 2000);
    const set2 = await setFor(sE(prior), fresh.map((h) => h.did), 2, 2, T - 1000); // the key replaced its helpers at T - 1000
    const claimAt = async (at: number) => {
      const d = await draftHelperClaim({ helperSet: set1, successor: sP(await p()), claimedAtUnix: at });
      return withApprovals(d, [await approveKeyClaim(d, sE(old[0]!)), await approveKeyClaim(d, sE(old[1]!))]);
    };
    const honest = await verifySuccessionSet([await claimAt(T)], [set2]); // dated after the replacement
    expect(honest.ok).toBe(false);
    expect(honest.superseded.length).toBe(1);
    const backdated = await verifySuccessionSet([await claimAt(T - 1500)], [set2]); // dated between the two sets, by the old helpers themselves
    expect(backdated.ok).toBe(true); // shown BOTH sets, the verifier still accepts it
    expect(backdated.superseded.length).toBe(0);
    // If this starts failing, a fix has landed: update the limit paragraph in specs/recovery.md and this test together.
  });
});

describe("a delegated-mint key stays labelled after any succession (ADR-0018)", () => {
  it("a counterparty on a minted Ed25519 key claims a P-256 phone key by helpers; the acceptance stays delegated-mint", async () => {
    const requester = await ed();
    const minted = await ed(); // a key someone else made for the counterparty
    const subject1 = await signEnvelope({ delivered: 1 }, "application/vnd.example.delivery+json", { keyid: requester.did, privateKey: requester.privateKey, publicKey: requester.publicKey }, { canonical: true });
    const payloadBytes = base64ToBytes(subject1.payload);
    const requestBody = {
      requestId: `csr_${"a".repeat(32)}`, requesterDid: requester.did, subjectPayloadType: subject1.payloadType, subjectDigestSha256: await sha256Hex(payloadBytes),
      statement: "A practice delivery.", disclosures: [], nonceB64: bytesToBase64(new Uint8Array(32)), issuedAtUnix: T, expiresAtUnix: T + 86_400, relationshipContext: "", withdrawalFeed: null,
    };
    const request = { header: { typ: "countersign-request", v: 1 }, body: requestBody, signature: await signEvent({ typ: "countersign-request", v: 1 }, requestBody, requester.privateKey, { dst: DST_COUNTERSIGN_REQUEST }) };
    const sig = await signBytes({ privateKey: minted.privateKey, publicKey: minted.publicKey }, pae(subject1.payloadType, payloadBytes), "der");
    const accBody = {
      act: "countersign" as const, requestId: requestBody.requestId, requestDigestSha256: await countersignRequestDigest(request), subjectPayloadType: subject1.payloadType,
      subjectDigestSha256: requestBody.subjectDigestSha256, countersignerDid: minted.did, keyCustody: "delegated-mint" as const, signedAtUnix: T + 60,
    };
    const acceptance = { header: { typ: "countersign", v: 1 }, body: accBody, signature: await signEvent({ typ: "countersign", v: 1 }, accBody, minted.privateKey, { dst: DST_COUNTERSIGN_ACCEPTANCE }) };
    const hs = [await ed(), await ed(), await ed()];
    const set = await setFor(sE(minted), hs.map((h) => h.did));
    const d = await draftHelperClaim({ helperSet: set, successor: sP(await p()), claimedAtUnix: T + 120 });
    const claim = withApprovals(d, [await approveKeyClaim(d, sE(hs[0]!)), await approveKeyClaim(d, sE(hs[1]!))]);
    const r = await verifyCountersignBundle({
      formatVersion: COUNTERSIGN_BUNDLE_FORMAT,
      subject: { ...subject1, signatures: [...subject1.signatures, { keyid: minted.did, sig: bytesToBase64(sig) }] },
      request, acceptances: [acceptance], withdrawal: null, keyClaims: [claim],
    });
    expect(r.ok).toBe(true);
    expect(r.acceptances[0]!.keyCustody).toBe("delegated-mint");
    expect(r.acceptances[0]!.subjectHeldKey).toBe(false);
    expect(r.keyClaims[0]!.ok).toBe(true);
    expect(r.notes.join(" ")).toContain("could have made this claim too, and named its helpers");
  });
});
