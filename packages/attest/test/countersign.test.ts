/**
 * The countersign bundle, built and checked with attest + identity-core ALONE.
 *
 * This file deliberately does not import `@kashscript/identity-server`. The
 * ceremony package is convenience; the artifact is the contract, and a stranger
 * holding only the free Apache-2.0 package must be able to construct one,
 * verify one, and break one. If these tests ever need the ceremony to pass,
 * decision 27 rule 4 has been quietly broken.
 */

import { describe, it, expect } from "bun:test";
import { deriveDid, generateKeyPair, signEvent, type KashKeyPair } from "@kashscript/identity-core";
import { sha256Hex } from "../src/chain";
import { bytesToBase64, base64ToBytes, signRaw } from "../src/ed25519";
import { pae, signEnvelope, type DsseEnvelope } from "../src/dsse";
import { isRegisteredDst, lookupDst } from "../src/dst";
import {
  COUNTERSIGN_BUNDLE_FORMAT,
  DST_COUNTERSIGN_ACCEPTANCE,
  DST_COUNTERSIGN_REQUEST,
  DST_COUNTERSIGN_WITHDRAWAL,
  DST_KEY_CLAIM,
  countersignRequestDigest,
  isCountersignBundle,
  verifyCountersignBundle,
  type CountersignBundle,
  type KeyCustody,
  type SignedCountersignAcceptance,
  type SignedCountersignRequest,
} from "../src/countersign";

const TYPE = "application/vnd.example.thing+json";
const T0 = 1_700_000_000;

type Party = KashKeyPair & { did: string };

async function party(): Promise<Party> {
  const kp = await generateKeyPair();
  return { ...kp, did: deriveDid(kp.publicKey) };
}

async function subjectFor(holder: Party, payload: unknown = { thing: 1 }): Promise<DsseEnvelope> {
  return signEnvelope(
    payload,
    TYPE,
    { keyid: holder.did, privateKey: holder.privateKey, publicKey: holder.publicKey },
    { canonical: true },
  );
}

async function requestFor(
  holder: Party,
  subject: DsseEnvelope,
  over: Partial<SignedCountersignRequest["body"]> = {},
): Promise<SignedCountersignRequest> {
  const body = {
    requestId: "csr_00000000000000000000000000000001",
    requesterDid: holder.did,
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256: await sha256Hex(base64ToBytes(subject.payload)),
    statement: "Confirm you received this.",
    disclosures: [],
    nonceB64: bytesToBase64(new Uint8Array(32).fill(9)),
    issuedAtUnix: T0,
    expiresAtUnix: T0 + 3600,
    relationshipContext: "ctx",
    withdrawalFeed: null,
    ...over,
  };
  const header = { typ: "countersign-request", v: 1 };
  return {
    header,
    body,
    signature: await signEvent(header, body, holder.privateKey, { dst: DST_COUNTERSIGN_REQUEST }),
  };
}

/** Countersign: the SAME PAE bytes, a second key — plus the acceptance that
 *  gives the raw signature its time and its context. */
async function countersign(
  signer: Party,
  subject: DsseEnvelope,
  request: SignedCountersignRequest,
  opts: { signedAtUnix?: number; keyCustody?: KeyCustody } = {},
): Promise<{ envelope: DsseEnvelope; acceptance: SignedCountersignAcceptance }> {
  const payloadBytes = base64ToBytes(subject.payload);
  const sig = await signRaw(
    pae(subject.payloadType, payloadBytes),
    signer.privateKey,
    signer.publicKey,
  );
  const envelope: DsseEnvelope = {
    ...subject,
    signatures: [...subject.signatures, { keyid: signer.did, sig: bytesToBase64(sig) }],
  };
  const body = {
    act: "countersign" as const,
    requestId: request.body.requestId,
    requestDigestSha256: await countersignRequestDigest(request),
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256: await sha256Hex(payloadBytes),
    countersignerDid: signer.did,
    keyCustody: opts.keyCustody ?? ("subject-generated" as KeyCustody),
    signedAtUnix: opts.signedAtUnix ?? T0 + 60,
  };
  const header = { typ: "countersign", v: 1 };
  return {
    envelope,
    acceptance: {
      header,
      body,
      signature: await signEvent(header, body, signer.privateKey, {
        dst: DST_COUNTERSIGN_ACCEPTANCE,
      }),
    },
  };
}

function bundle(
  subject: DsseEnvelope,
  request: SignedCountersignRequest,
  acceptances: SignedCountersignAcceptance[],
  extra: Partial<CountersignBundle> = {},
): CountersignBundle {
  return {
    formatVersion: COUNTERSIGN_BUNDLE_FORMAT,
    subject,
    request,
    acceptances,
    withdrawal: null,
    ...extra,
  };
}

async function happyBundle(): Promise<{ holder: Party; signer: Party; bundle: CountersignBundle }> {
  const holder = await party();
  const signer = await party();
  const subject = await subjectFor(holder);
  const request = await requestFor(holder, subject);
  const { envelope, acceptance } = await countersign(signer, subject, request);
  return { holder, signer, bundle: bundle(envelope, request, [acceptance]) };
}

describe("countersign — the DSTs are registered before anything signs under them", () => {
  it("registers all four, owned by the ceremony package", () => {
    for (const tag of [
      DST_COUNTERSIGN_REQUEST,
      DST_COUNTERSIGN_ACCEPTANCE,
      DST_COUNTERSIGN_WITHDRAWAL,
      DST_KEY_CLAIM,
    ]) {
      expect(isRegisteredDst(tag)).toBe(true);
      expect(lookupDst(tag)!.family).toBe("kash-event");
      expect(lookupDst(tag)!.owner).toBe("@kashscript/identity-server");
      expect(lookupDst(tag)!.reserved).toBeUndefined();
    }
  });

  it("adds NO new payloadType — an existing DSSE envelope is countersignable as it stands", async () => {
    const { bundle: b } = await happyBundle();
    expect(b.subject.payloadType).toBe(TYPE);
    expect(isRegisteredDst(TYPE)).toBe(false);
    const report = await verifyCountersignBundle(b);
    expect(report.ok).toBe(true);
  });
});

describe("countersign — verifying with nothing but the file", () => {
  it("passes on two independent keys over the same bytes, with no key material supplied", async () => {
    const { holder, signer, bundle: b } = await happyBundle();
    const report = await verifyCountersignBundle(b);
    expect(report.ok).toBe(true);
    expect(report.reason).toBeNull();
    expect(report.twoSignatureProof).toBe(true);
    expect(report.independentSignatureCount).toBe(2);
    expect([...report.subjectVerifiedKeyids].sort()).toEqual([holder.did, signer.did].sort());
    expect(report.acceptances[0]!.countersignedSubject).toBe(true);
  });

  it("resolves both public keys out of the did:kash strings — no registry, no lookup", async () => {
    const { bundle: b } = await happyBundle();
    // Nothing is passed to the verifier but the artifact itself.
    expect(verifyCountersignBundle.length).toBe(1);
    const report = await verifyCountersignBundle(b);
    for (const keyid of report.subjectVerifiedKeyids) {
      expect(keyid).toMatch(/^did:kash:[1-9A-HJ-NP-Za-km-z]+$/);
    }
  });

  it("always states what it cannot know", async () => {
    const { bundle: b } = await happyBundle();
    const report = await verifyCountersignBundle(b);
    const notes = report.notes.join(" ");
    expect(notes).toContain("not evidence that none exists");
    expect(notes).toContain("signers' own claims");
  });

  it("detects a bundle as a bundle, and leaves other artifacts alone", async () => {
    const { bundle: b } = await happyBundle();
    expect(isCountersignBundle(b)).toBe(true);
    expect(isCountersignBundle(b.subject)).toBe(false);
    expect(isCountersignBundle(null)).toBe(false);
    expect(isCountersignBundle({ formatVersion: "something-else/1" })).toBe(false);
  });
});

describe("countersign — a one-sided claim never passes as proof (d26, d41)", () => {
  it("fails a subject carrying only the holder's signature", async () => {
    const holder = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const report = await verifyCountersignBundle(bundle(subject, request, []));
    expect(report.ok).toBe(false);
    expect(report.reason).toBe("NOT_COUNTERSIGNED");
    expect(report.twoSignatureProof).toBe(false);
  });

  it("fails when one key signs twice — two signatures, one signer, no independence", async () => {
    const holder = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const { envelope, acceptance } = await countersign(holder, subject, request);
    // The holder countersigning their own claim: the envelope now has two
    // entries and exactly one distinct verified key.
    const report = await verifyCountersignBundle(bundle(envelope, request, [acceptance]));
    expect(report.independentSignatureCount).toBe(1);
    expect(report.twoSignatureProof).toBe(false);
    expect(report.ok).toBe(false);
  });

  it("fails an acceptance whose DID never signed the envelope", async () => {
    const holder = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const { acceptance } = await countersign(signer, subject, request);
    // The acceptance is genuine; the countersignature was dropped from the
    // envelope. An assertion about bytes nobody signed is not a countersignature.
    const report = await verifyCountersignBundle(bundle(subject, request, [acceptance]));
    expect(report.ok).toBe(false);
    expect(report.acceptances[0]!.countersignedSubject).toBe(false);
  });
});

describe("countersign — tamper and replay", () => {
  it("rejects a mutated payload", async () => {
    const { bundle: b } = await happyBundle();
    const mutated = bundle(
      { ...b.subject, payload: bytesToBase64(new TextEncoder().encode('{"thing":2}')) },
      b.request,
      [...b.acceptances],
    );
    const report = await verifyCountersignBundle(mutated);
    expect(report.ok).toBe(false);
    expect(report.subjectSignatureOk).toBe(false);
  });

  it("rejects an acceptance re-pointed at a different request", async () => {
    const holder = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const requestA = await requestFor(holder, subject);
    const requestB = await requestFor(holder, subject, {
      requestId: "csr_00000000000000000000000000000002",
      nonceB64: bytesToBase64(new Uint8Array(32).fill(7)),
    });
    const { envelope, acceptance } = await countersign(signer, subject, requestA);
    const report = await verifyCountersignBundle(bundle(envelope, requestB, [acceptance]));
    expect(report.ok).toBe(false);
    expect(report.acceptances[0]!.bindingOk).toBe(false);
  });

  it("rejects a re-labelled DST (the cross-family replay)", async () => {
    const { bundle: b } = await happyBundle();
    const relabelled = bundle(b.subject, b.request, [
      {
        ...b.acceptances[0]!,
        signature: { ...b.acceptances[0]!.signature, dst: DST_COUNTERSIGN_WITHDRAWAL },
      },
    ]);
    const report = await verifyCountersignBundle(relabelled);
    expect(report.ok).toBe(false);
    expect(report.acceptances[0]!.reason).toBe("ACCEPTANCE_DST_MISMATCH");
  });

  it("rejects a request signed by someone other than the named requester", async () => {
    const holder = await party();
    const impostor = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const genuine = await requestFor(holder, subject);
    const header = genuine.header;
    const forged: SignedCountersignRequest = {
      header,
      body: genuine.body,
      signature: await signEvent(header, genuine.body, impostor.privateKey, {
        dst: DST_COUNTERSIGN_REQUEST,
      }),
    };
    const { envelope, acceptance } = await countersign(signer, subject, forged);
    const report = await verifyCountersignBundle(bundle(envelope, forged, [acceptance]));
    expect(report.ok).toBe(false);
    expect(report.requestSignatureOk).toBe(false);
  });

  it("detects a signature outside the window — a verifier who was not there", async () => {
    const holder = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const { envelope, acceptance } = await countersign(signer, subject, request, {
      signedAtUnix: T0 + 999_999,
    });
    const report = await verifyCountersignBundle(bundle(envelope, request, [acceptance]));
    expect(report.ok).toBe(false);
    expect(report.acceptances[0]!.inWindow).toBe(false);
    expect(report.acceptances[0]!.reason).toBe("SIGNED_OUTSIDE_WINDOW");
  });

  it("returns a report, never a throw, for structurally junk input", async () => {
    for (const junk of [null, 42, "nope", {}, { formatVersion: "x" }, { formatVersion: COUNTERSIGN_BUNDLE_FORMAT }]) {
      const report = await verifyCountersignBundle(junk as unknown as CountersignBundle);
      expect(report.ok).toBe(false);
      expect(report.reason).toBe("MALFORMED_BUNDLE");
    }
  });
});

describe("countersign — key custody is a fact in the file (ADR-0018)", () => {
  it("verifies a delegated-mint signature AND labels it not-subject-held", async () => {
    const holder = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const { envelope, acceptance } = await countersign(signer, subject, request, {
      keyCustody: "delegated-mint",
    });
    const report = await verifyCountersignBundle(bundle(envelope, request, [acceptance]));
    expect(report.ok).toBe(true);
    expect(report.acceptances[0]!.keyCustody).toBe("delegated-mint");
    expect(report.acceptances[0]!.subjectHeldKey).toBe(false);
    expect(report.notes.join(" ")).toContain("NOT subject-held");
  });

  it("cannot be upgraded to subject-held by editing the label", async () => {
    const holder = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const { envelope, acceptance } = await countersign(signer, subject, request, {
      keyCustody: "delegated-mint",
    });
    // Custody is INSIDE the signed bytes, so promoting it to subject-generated
    // breaks the acceptance signature rather than laundering the record.
    const relabelled: SignedCountersignAcceptance = {
      ...acceptance,
      body: { ...acceptance.body, keyCustody: "subject-generated" as KeyCustody },
    };
    const report = await verifyCountersignBundle(bundle(envelope, request, [relabelled]));
    expect(report.ok).toBe(false);
    expect(report.acceptances[0]!.acceptanceSignatureOk).toBe(false);
    expect(report.acceptances[0]!.reason).toBe("ACCEPTANCE_SIGNATURE_INVALID");
  });
});

describe("countersign — withdrawal is presented, never looked up (d28)", () => {
  it("reports the ordering when a valid withdrawal predates the signing", async () => {
    const holder = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const { envelope, acceptance } = await countersign(signer, subject, request, {
      signedAtUnix: T0 + 600,
    });
    const wBody = {
      act: "withdraw" as const,
      requestId: request.body.requestId,
      requestDigestSha256: await countersignRequestDigest(request),
      withdrawnAtUnix: T0 + 300,
    };
    const wHeader = { typ: "countersign-withdrawal", v: 1 };
    const withdrawal = {
      header: wHeader,
      body: wBody,
      signature: await signEvent(wHeader, wBody, holder.privateKey, {
        dst: DST_COUNTERSIGN_WITHDRAWAL,
      }),
    };
    const report = await verifyCountersignBundle(
      bundle(envelope, request, [acceptance], { withdrawal }),
    );
    expect(report.ok).toBe(false);
    expect(report.withdrawalSignatureOk).toBe(true);
    expect(report.withdrawnBeforeSigning).toBe(true);
    expect(report.acceptances[0]!.reason).toBe("WITHDRAWN_BEFORE_SIGNING");
  });

  it("does not let a withdrawal dated AFTER the signing invalidate it", async () => {
    const holder = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const { envelope, acceptance } = await countersign(signer, subject, request, {
      signedAtUnix: T0 + 100,
    });
    const wBody = {
      act: "withdraw" as const,
      requestId: request.body.requestId,
      requestDigestSha256: await countersignRequestDigest(request),
      withdrawnAtUnix: T0 + 900,
    };
    const wHeader = { typ: "countersign-withdrawal", v: 1 };
    const withdrawal = {
      header: wHeader,
      body: wBody,
      signature: await signEvent(wHeader, wBody, holder.privateKey, {
        dst: DST_COUNTERSIGN_WITHDRAWAL,
      }),
    };
    const report = await verifyCountersignBundle(
      bundle(envelope, request, [acceptance], { withdrawal }),
    );
    expect(report.ok).toBe(true);
    expect(report.withdrawalPresented).toBe(true);
    expect(report.withdrawnBeforeSigning).toBe(false);
  });
});

/* ── AU-3 (AUDIT-2026-11-11): the verifier counts signers by key, never by spelling ── */

describe("countersign — signers are counted by the key they resolve to (AU-3, A7-02)", () => {
  it("one key under two spellings is one signer: did:kash:X and did:kash:X#c never make a two-signature proof", async () => {
    const holder = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    // The holder countersigns its own claim under an alias of its own key.
    const alias: Party = { ...holder, did: `${holder.did}#c` };
    const { envelope, acceptance } = await countersign(alias, subject, request);
    expect(envelope.signatures.map((s) => s.keyid)).toEqual([holder.did, `${holder.did}#c`]);
    const report = await verifyCountersignBundle(bundle(envelope, request, [acceptance]));
    expect(report.independentSignatureCount).toBe(1);
    expect(report.twoSignatureProof).toBe(false);
    expect(report.ok).toBe(false);
    expect(report.reason).toBe("COUNTERSIGNER_IS_REQUESTER");
    // Reported in canonical form, so every downstream string check compares keys.
    expect(report.subjectVerifiedKeyids).toEqual([holder.did]);
    expect(report.acceptances[0]!.countersignerDid).toBe(holder.did);
    expect(report.acceptances[0]!.independent).toBe(false);
  });

  it("the requester's own acceptance is a signature, never a countersignature: beside an independent one the bundle stands, alone it does not", async () => {
    const holder = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const own = await countersign(holder, subject, request); // the requester accepts its own request (the cohort profile's shape)
    const theirs = await countersign(signer, own.envelope, request); // an independent key over the same bytes
    const both = await verifyCountersignBundle(bundle(theirs.envelope, request, [own.acceptance, theirs.acceptance]));
    expect(both.ok).toBe(true);
    expect(both.twoSignatureProof).toBe(true);
    expect(both.independentSignatureCount).toBe(2);
    expect(both.acceptances.map((a) => [a.countersignerDid, a.ok, a.independent])).toEqual([
      [holder.did, true, false],
      [signer.did, true, true],
    ]);
    const alone = await verifyCountersignBundle(bundle(own.envelope, request, [own.acceptance]));
    expect(alone.ok).toBe(false);
    expect(alone.reason).toBe("COUNTERSIGNER_IS_REQUESTER");
    expect(alone.twoSignatureProof).toBe(false);
    expect(alone.acceptances[0]!.ok).toBe(true);
  });

  it("whether the requester signed the subject is a fact in the report, never a failure", async () => {
    const { bundle: b } = await happyBundle();
    expect((await verifyCountersignBundle(b)).requesterSignedSubject).toBe(true);
    // An organisation requests a countersignature on its doer's record: the doer signed the bytes, the organisation did not.
    const org = await party();
    const doer = await party();
    const client = await party();
    const subject = await subjectFor(doer);
    const request = await requestFor(org, subject);
    const { envelope, acceptance } = await countersign(client, subject, request);
    const r = await verifyCountersignBundle(bundle(envelope, request, [acceptance]));
    expect(r.ok).toBe(true);
    expect(r.requesterSignedSubject).toBe(false);
    expect([...r.subjectVerifiedKeyids].sort()).toEqual([doer.did, client.did].sort());
    expect(r.notes.join(" ")).toContain("did not sign the subject");
  });
});

describe("countersign — a verifier of untrusted input returns a report, never a throw (AU-3, A7-04)", () => {
  it("a junk sibling signature anyone can append neither denies the record nor crashes the check", async () => {
    const { bundle: b } = await happyBundle();
    const withJunk = bundle({ ...b.subject, signatures: [...b.subject.signatures, { keyid: "x", sig: "%%%" }] }, b.request, [...b.acceptances]);
    const report = await verifyCountersignBundle(withJunk);
    expect(report.ok).toBe(true);
    expect(report.independentSignatureCount).toBe(2);
  });

  it("a subject whose payload is not JSON is judged as bytes, with a note — not an exception", async () => {
    const holder = await party();
    const signer = await party();
    const bytes = new TextEncoder().encode("not json");
    const sig = await signRaw(pae(TYPE, bytes), holder.privateKey, holder.publicKey);
    const subject: DsseEnvelope = { payloadType: TYPE, payload: bytesToBase64(bytes), signatures: [{ keyid: holder.did, sig: bytesToBase64(sig) }] };
    const request = await requestFor(holder, subject);
    const { envelope, acceptance } = await countersign(signer, subject, request);
    const report = await verifyCountersignBundle(bundle(envelope, request, [acceptance]));
    expect(report.ok).toBe(true);
    expect(report.notes.join(" ")).toContain("not JSON");
  });

  it("a request whose body cannot be canonicalised is a malformed bundle, not an exception", async () => {
    const { bundle: b } = await happyBundle();
    const body: Record<string, unknown> = { ...b.request.body };
    body.loop = body; // JCS cannot write this; neither could any signer have signed it
    const bad = { ...b, request: { ...b.request, body } } as unknown as CountersignBundle;
    const report = await verifyCountersignBundle(bad);
    expect(report.ok).toBe(false);
    expect(report.reason).toBe("MALFORMED_BUNDLE");
  });
});

describe("countersign — custody that is not stated is unknown, never subject-held (AU-3, A7-05)", () => {
  /** An acceptance with `keyCustody` set to anything at all, or left out. */
  async function acceptWithCustody(signer: Party, subject: DsseEnvelope, request: SignedCountersignRequest, custody: unknown) {
    const payloadBytes = base64ToBytes(subject.payload);
    const sig = await signRaw(pae(subject.payloadType, payloadBytes), signer.privateKey, signer.publicKey);
    const envelope: DsseEnvelope = { ...subject, signatures: [...subject.signatures, { keyid: signer.did, sig: bytesToBase64(sig) }] };
    const body: Record<string, unknown> = {
      act: "countersign",
      requestId: request.body.requestId,
      requestDigestSha256: await countersignRequestDigest(request),
      subjectPayloadType: subject.payloadType,
      subjectDigestSha256: await sha256Hex(payloadBytes),
      countersignerDid: signer.did,
      signedAtUnix: T0 + 60,
    };
    if (custody !== undefined) body.keyCustody = custody;
    const header = { typ: "countersign", v: 1 };
    const acceptance = { header, body, signature: await signEvent(header, body, signer.privateKey, { dst: DST_COUNTERSIGN_ACCEPTANCE }) } as unknown as SignedCountersignAcceptance;
    return { envelope, acceptance };
  }

  it("an acceptance with keyCustody missing, null or misspelt reports unknown and is not subject-held", async () => {
    for (const custody of [undefined, null, "subject_generated", 7]) {
      const holder = await party();
      const signer = await party();
      const subject = await subjectFor(holder);
      const request = await requestFor(holder, subject);
      const { envelope, acceptance } = await acceptWithCustody(signer, subject, request, custody);
      const report = await verifyCountersignBundle(bundle(envelope, request, [acceptance]));
      const a = report.acceptances[0]!;
      expect(a.keyCustody).toBe("unknown");
      expect(a.subjectHeldKey).toBe(false);
      expect(a.ok).toBe(true); // the signature stands; only the claim about its custody is missing
      expect(report.notes.join(" ")).toContain("NOT subject-held");
    }
  });

  it("only the exact word subject-generated is subject-held", async () => {
    const holder = await party();
    const signer = await party();
    const subject = await subjectFor(holder);
    const request = await requestFor(holder, subject);
    const { envelope, acceptance } = await acceptWithCustody(signer, subject, request, "subject-generated");
    const report = await verifyCountersignBundle(bundle(envelope, request, [acceptance]));
    expect(report.acceptances[0]!.keyCustody).toBe("subject-generated");
    expect(report.acceptances[0]!.subjectHeldKey).toBe(true);
  });
});
