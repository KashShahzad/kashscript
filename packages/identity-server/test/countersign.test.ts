/**
 * The countersign ceremony (ADR-0018) — a link, one click, signed.
 *
 * Four of these tests are constitutional rather than functional, and they are
 * marked as such: declining leaves nothing aggregatable (d27.3, d41), two
 * requesters get unlinkable signing identities (d41), the ceremony page names
 * nobody (d44), and nothing here can answer "what has this counterparty
 * signed" (d41). A regression in any of them is a breach, not a bug.
 */

import { describe, it, expect, beforeAll } from "bun:test";
import { spawnSync } from "node:child_process";
import { rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import { signEnvelope, verifyCountersignBundle, type DsseEnvelope } from "@kashscript/attest";

import * as identityServer from "../src/index";
import {
  acceptCountersignRequest,
  assembleCountersignBundle,
  adoptDelegatedSigningKey,
  claimCountersignKey,
  createCountersignRequest,
  decodeCompactCountersignRequest,
  decodeCrockford32,
  declineCountersignRequest,
  deriveRelationshipSalt,
  deriveRelationshipSigningKey,
  encodeCrockford32,
  generateOneTimeSigningKey,
  requestIdForCapability,
  withdrawCountersignRequest,
  COUNTERSIGN_MAX_TTL_SECONDS,
} from "../src/countersign";
import { renderCountersignPage } from "../src/countersign-page";
import { createIdentityServer, InMemoryCountersignRequestStore } from "../src/stores";

const SUBJECT_TYPE = "application/vnd.example.delivery+json";

async function holderKey(): Promise<KashKeyPair & { did: string }> {
  const kp = await generateKeyPair();
  return { ...kp, did: deriveDid(kp.publicKey) };
}

/** A holder signs something ordinary. No new format, no new DST. */
async function signedSubject(
  holder: KashKeyPair & { did: string },
  payload: unknown = { order: "A-77", delivered: true },
): Promise<DsseEnvelope> {
  return signEnvelope(
    payload,
    SUBJECT_TYPE,
    { keyid: holder.did, privateKey: holder.privateKey, publicKey: holder.publicKey },
    { canonical: true },
  );
}

async function fullCeremony(over: { nowSec?: number; ttlSeconds?: number } = {}) {
  const holder = await holderKey();
  const subject = await signedSubject(holder);
  const created = await createCountersignRequest({
    subject,
    requesterDid: holder.did,
    requesterPrivateKey: holder.privateKey,
    statement: "Confirm you received the delivery for order A-77.",
    disclosures: [{ label: "Order", value: "A-77" }],
    relationshipContext: "book-1",
    ...over,
  });
  const signingKey = await generateOneTimeSigningKey();
  const accepted = await acceptCountersignRequest({
    request: created.request,
    subject,
    signingKey,
    ...(over.nowSec !== undefined ? { nowSec: over.nowSec } : {}),
  });
  return { holder, subject, created, signingKey, accepted };
}

describe("countersign — the ceremony round-trip", () => {
  it("produces a second signature over the SAME canonical bytes the first covered", async () => {
    const { subject, accepted } = await fullCeremony();
    if (!accepted.ok) throw new Error(`ceremony failed: ${accepted.reason}`);

    // Same payloadType, same payload bytes — only the signature list grew.
    expect(accepted.envelope.payloadType).toBe(subject.payloadType);
    expect(accepted.envelope.payload).toBe(subject.payload);
    expect(accepted.envelope.signatures).toHaveLength(2);
    expect(accepted.envelope.signatures[0]).toEqual(subject.signatures[0]!);
  });

  it("verifies as a two-signature bundle under the attest verifier", async () => {
    const { subject, created, accepted } = await fullCeremony();
    if (!accepted.ok) throw new Error("ceremony failed");
    const bundle = assembleCountersignBundle({
      subject: accepted.envelope,
      request: created.request,
      acceptances: [accepted.acceptance],
    });

    const report = await verifyCountersignBundle(bundle);
    expect(report.ok).toBe(true);
    expect(report.twoSignatureProof).toBe(true);
    expect(report.independentSignatureCount).toBe(2);
    expect(report.acceptances[0]!.keyCustody).toBe("subject-generated");
    expect(report.acceptances[0]!.subjectHeldKey).toBe(true);
    expect(report.subjectVerifiedKeyids).toContain(subject.signatures[0]!.keyid);
  });

  it("refuses to sign the same envelope twice with one key", async () => {
    const { subject, created, signingKey, accepted } = await fullCeremony();
    if (!accepted.ok) throw new Error("ceremony failed");
    const again = await acceptCountersignRequest({
      request: created.request,
      subject: accepted.envelope,
      signingKey,
    });
    expect(again.ok).toBe(false);
    if (again.ok) throw new Error("unreachable");
    expect(again.reason).toBe("ALREADY_COUNTERSIGNED");
    expect(subject.signatures).toHaveLength(1);
  });

  it("refuses a request that does not describe this envelope", async () => {
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const other = await signedSubject(holder, { order: "B-12", delivered: true });
    const created = await createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
    });
    const result = await acceptCountersignRequest({
      request: created.request,
      subject: other,
      signingKey: await generateOneTimeSigningKey(),
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error("unreachable");
    expect(result.reason).toBe("SUBJECT_MISMATCH");
  });
});

describe("countersign — replay and expiry (d28: a stranger must detect both)", () => {
  it("refuses to sign outside the request's window", async () => {
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const nowSec = 1_700_000_000;
    const created = await createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
      ttlSeconds: 3600,
      nowSec,
    });
    const signingKey = await generateOneTimeSigningKey();

    const late = await acceptCountersignRequest({
      request: created.request,
      subject,
      signingKey,
      nowSec: nowSec + 3601,
    });
    expect(late.ok).toBe(false);
    if (!late.ok) expect(late.reason).toBe("REQUEST_EXPIRED");

    const early = await acceptCountersignRequest({
      request: created.request,
      subject,
      signingKey,
      nowSec: nowSec - 1,
    });
    expect(early.ok).toBe(false);
    if (!early.ok) expect(early.reason).toBe("REQUEST_NOT_YET_VALID");
  });

  it("caps the window, so no request becomes a standing claim", async () => {
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const created = await createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
      ttlSeconds: COUNTERSIGN_MAX_TTL_SECONDS * 10,
      nowSec: 1_700_000_000,
    });
    expect(created.request.body.expiresAtUnix - created.request.body.issuedAtUnix).toBe(
      COUNTERSIGN_MAX_TTL_SECONDS,
    );
  });

  it("gives each request a fresh nonce, so two requests never share a digest", async () => {
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const args = {
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
      nowSec: 1_700_000_000,
    };
    const a = await createCountersignRequest(args);
    const b = await createCountersignRequest(args);
    expect(a.request.body.nonceB64).not.toBe(b.request.body.nonceB64);
    expect(a.requestId).not.toBe(b.requestId);
  });

  it("answers a hosted request once — a replayed link resolves to nothing", async () => {
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const server = createIdentityServer();
    const created = await server.createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
    });

    expect(await server.resolveCountersignRequest(created.capabilitySecretB32)).not.toBeNull();
    expect(await server.markCountersignRequestAnswered(created.requestId)).toBe(true);
    // Replayed: same link, same secret, nothing to sign.
    expect(await server.resolveCountersignRequest(created.capabilitySecretB32)).toBeNull();
    expect(await server.markCountersignRequestAnswered(created.requestId)).toBe(false);
  });

  it("a verifier who was not there detects a signature outside the window", async () => {
    const nowSec = 1_700_000_000;
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const created = await createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
      ttlSeconds: 3600,
      nowSec,
    });
    const accepted = await acceptCountersignRequest({
      request: created.request,
      subject,
      signingKey: await generateOneTimeSigningKey(),
      nowSec: nowSec + 60,
    });
    if (!accepted.ok) throw new Error("ceremony failed");

    // Re-issue the same request with a window that ends before the signature —
    // the acceptance is cryptographically fine and still must not pass.
    const narrowed = await createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
      ttlSeconds: 10,
      nowSec,
    });
    const report = await verifyCountersignBundle(
      assembleCountersignBundle({
        subject: accepted.envelope,
        request: narrowed.request,
        acceptances: [accepted.acceptance],
      }),
    );
    expect(report.ok).toBe(false);
    expect(report.acceptances[0]!.inWindow).toBe(false);
  });
});

describe("countersign — tamper", () => {
  it("rejects a rewritten statement", async () => {
    const { created, accepted } = await fullCeremony();
    if (!accepted.ok) throw new Error("ceremony failed");
    const tampered = {
      ...created.request,
      body: { ...created.request.body, statement: "Confirm you received a used car." },
    };
    const report = await verifyCountersignBundle(
      assembleCountersignBundle({
        subject: accepted.envelope,
        request: tampered,
        acceptances: [accepted.acceptance],
      }),
    );
    expect(report.ok).toBe(false);
    expect(report.requestSignatureOk).toBe(false);
  });

  it("rejects an acceptance moved onto a different subject", async () => {
    const { holder, created, accepted } = await fullCeremony();
    if (!accepted.ok) throw new Error("ceremony failed");
    const otherSubject = await signedSubject(holder, { order: "C-99", delivered: true });
    const report = await verifyCountersignBundle(
      assembleCountersignBundle({
        subject: otherSubject,
        request: created.request,
        acceptances: [accepted.acceptance],
      }),
    );
    expect(report.ok).toBe(false);
  });

  it("rejects an envelope carrying only the holder's signature", async () => {
    const { subject, created } = await fullCeremony();
    const report = await verifyCountersignBundle(
      assembleCountersignBundle({ subject, request: created.request, acceptances: [] }),
    );
    expect(report.ok).toBe(false);
    expect(report.twoSignatureProof).toBe(false);
    expect(report.reason).toBe("NOT_COUNTERSIGNED");
  });
});

describe("countersign — declining is safe and free (d27.3, d42)", () => {
  it("produces no artifact and returns nothing durable", () => {
    const result = declineCountersignRequest();
    expect(result).toEqual({ ok: true, recorded: false });
    expect(Object.keys(result).sort()).toEqual(["ok", "recorded"]);
  });

  it("zeroises the local secret and leaves the stored state byte-identical", async () => {
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const store = new InMemoryCountersignRequestStore();
    const server = createIdentityServer({ countersignStore: store });
    const created = await server.createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
    });

    const before = store.inspectForTest(created.requestId);
    const secret = decodeCrockford32(created.capabilitySecretB32);
    declineCountersignRequest({ capabilitySecret: secret });

    // The counterparty's own copy is gone...
    expect([...secret]).toEqual(new Array(secret.length).fill(0));
    // ...and nothing the requester can see has changed. A decline is
    // indistinguishable from silence and from an unopened link.
    expect(store.inspectForTest(created.requestId)).toEqual(before!);
    expect(await server.resolveCountersignRequest(created.capabilitySecretB32)).not.toBeNull();
  });

  it("CONSTITUTIONAL: nothing in the package can enumerate requests, declines or signers", () => {
    // d41's never-build list includes "a report naming the individuals who have
    // not confirmed". It is unbuildable from this surface: there is no call that
    // returns more than the one request you already hold the secret for.
    const enumerating = /^(list|find|search|query|getAll|scan|export)/i;
    const offenders = Object.keys(identityServer).filter((name) => enumerating.test(name));
    expect(offenders).toEqual([]);

    // The store contract itself is two reads and two marks — all by a known id.
    const storeMethods = Object.getOwnPropertyNames(
      InMemoryCountersignRequestStore.prototype,
    ).filter((n) => n !== "constructor" && n !== "inspectForTest");
    expect(storeMethods.sort()).toEqual(["get", "markAnswered", "markWithdrawn", "put"]);

    // And no acceptance is ever persisted — the ceremony hands it back instead.
    expect(storeMethods.some((m) => /accept|signature|countersign/i.test(m))).toBe(false);
  });
});

describe("countersign — separate identifiers per relationship (d41)", () => {
  it("CONSTITUTIONAL: two requesters get unlinkable signing identities", async () => {
    const wallet = crypto.getRandomValues(new Uint8Array(32));
    const requesterA = (await holderKey()).did;
    const requesterB = (await holderKey()).did;

    const keyA = await deriveRelationshipSigningKey({
      masterSeed: wallet,
      relationshipSalt: await deriveRelationshipSalt({
        requesterDid: requesterA,
        contextLabel: "book-1",
      }),
    });
    const keyB = await deriveRelationshipSigningKey({
      masterSeed: wallet,
      relationshipSalt: await deriveRelationshipSalt({
        requesterDid: requesterB,
        contextLabel: "book-1",
      }),
    });

    expect(keyA.did).not.toBe(keyB.did);
    expect([...keyA.publicKey]).not.toEqual([...keyB.publicKey]);
    // Nothing shared: neither DID is derivable from the other without the seed,
    // which is what stops a second book from recognising the first book's
    // counterparty.
    expect([...keyA.privateKey]).not.toEqual([...keyB.privateKey]);
  });

  it("is stable WITHIN one relationship, so a holder's own book sees one counterparty", async () => {
    const wallet = crypto.getRandomValues(new Uint8Array(32));
    const requester = (await holderKey()).did;
    const salt = await deriveRelationshipSalt({ requesterDid: requester, contextLabel: "book-1" });
    const first = await deriveRelationshipSigningKey({ masterSeed: wallet, relationshipSalt: salt });
    const second = await deriveRelationshipSigningKey({ masterSeed: wallet, relationshipSalt: salt });
    expect(second.did).toBe(first.did);

    // A different context under the SAME requester separates too — one book
    // does not link its own two corridors unless it is told to.
    const other = await deriveRelationshipSigningKey({
      masterSeed: wallet,
      relationshipSalt: await deriveRelationshipSalt({
        requesterDid: requester,
        contextLabel: "book-2",
      }),
    });
    expect(other.did).not.toBe(first.did);
  });

  it("the salt is derived from the requester only — the counterparty contributes nothing stable", async () => {
    const requester = (await holderKey()).did;
    const a = await deriveRelationshipSalt({ requesterDid: requester, contextLabel: "book-1" });
    const b = await deriveRelationshipSalt({ requesterDid: requester, contextLabel: "book-1" });
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("without a wallet, every request gets a fresh key — unlinkable by construction", async () => {
    const one = await generateOneTimeSigningKey();
    const two = await generateOneTimeSigningKey();
    expect(one.did).not.toBe(two.did);
    expect(one.custody).toBe("subject-generated");
  });

  it("two full ceremonies from different requesters yield unlinkable countersigners", async () => {
    const a = await fullCeremony();
    const b = await fullCeremony();
    if (!a.accepted.ok || !b.accepted.ok) throw new Error("ceremony failed");
    expect(a.accepted.countersignerDid).not.toBe(b.accepted.countersignerDid);
    expect(a.created.request.body.requesterDid).not.toBe(b.created.request.body.requesterDid);
  });
});

describe("countersign — key custody and the claim path (ADR-0018)", () => {
  it("labels a delegated mint inside the signed bytes, not in a footnote", async () => {
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const created = await createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
    });
    // The shape a relay or issueGuestDid produces: somebody else made the key.
    const minted = await generateKeyPair();
    const delegated = adoptDelegatedSigningKey(minted);
    expect(delegated.custody).toBe("delegated-mint");

    const accepted = await acceptCountersignRequest({
      request: created.request,
      subject,
      signingKey: delegated,
    });
    if (!accepted.ok) throw new Error("ceremony failed");
    expect(accepted.acceptance.body.keyCustody).toBe("delegated-mint");

    const report = await verifyCountersignBundle(
      assembleCountersignBundle({
        subject: accepted.envelope,
        request: created.request,
        acceptances: [accepted.acceptance],
      }),
    );
    // It still verifies — the signature is real. It is simply not subject-held,
    // and the verifier says so every time rather than letting the claim pass.
    expect(report.ok).toBe(true);
    expect(report.acceptances[0]!.subjectHeldKey).toBe(false);
    expect(report.notes.join(" ")).toContain("NOT subject-held");
  });

  it("carries a verifiable prior → successor claim", async () => {
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const created = await createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "Confirm the delivery.",
    });
    const prior = adoptDelegatedSigningKey(await generateKeyPair());
    const accepted = await acceptCountersignRequest({
      request: created.request,
      subject,
      signingKey: prior,
    });
    if (!accepted.ok) throw new Error("ceremony failed");

    const successor = await generateOneTimeSigningKey();
    const claim = await claimCountersignKey({
      priorDid: prior.did,
      priorPrivateKey: prior.privateKey,
      successor,
    });

    const report = await verifyCountersignBundle(
      assembleCountersignBundle({
        subject: accepted.envelope,
        request: created.request,
        acceptances: [accepted.acceptance],
        keyClaims: [claim],
      }),
    );
    expect(report.ok).toBe(true);
    expect(report.keyClaims[0]!.ok).toBe(true);
    expect(report.keyClaims[0]!.priorDid).toBe(prior.did);
    expect(report.keyClaims[0]!.successorDid).toBe(successor.did);

    // The qualification holds: claiming does not relabel the record behind it.
    expect(report.acceptances[0]!.subjectHeldKey).toBe(false);
  });

  it("rejects a claim the prior key did not sign", async () => {
    const prior = await generateOneTimeSigningKey();
    const impostor = await generateOneTimeSigningKey();
    const successor = await generateOneTimeSigningKey();
    const claim = await claimCountersignKey({
      priorDid: prior.did,
      priorPrivateKey: impostor.privateKey,
      successor,
    });
    const { subject, created, accepted } = await fullCeremony();
    if (!accepted.ok) throw new Error("ceremony failed");
    void subject;
    const report = await verifyCountersignBundle(
      assembleCountersignBundle({
        subject: accepted.envelope,
        request: created.request,
        acceptances: [accepted.acceptance],
        keyClaims: [claim],
      }),
    );
    expect(report.ok).toBe(false);
    expect(report.keyClaims[0]!.priorSignatureOk).toBe(false);
  });
});

describe("countersign — withdrawal without a centre (d28)", () => {
  it("is a signed artifact a stranger checks offline, not a service", async () => {
    const { holder, created, accepted } = await fullCeremony({ nowSec: 1_700_000_000 });
    if (!accepted.ok) throw new Error("ceremony failed");
    const withdrawal = await withdrawCountersignRequest({
      request: created.request,
      requesterPrivateKey: holder.privateKey,
      nowSec: 1_700_000_000 - 1, // withdrawn before the counterparty signed
    });

    const report = await verifyCountersignBundle(
      assembleCountersignBundle({
        subject: accepted.envelope,
        request: created.request,
        acceptances: [accepted.acceptance],
        withdrawal,
      }),
    );
    expect(report.ok).toBe(false);
    expect(report.withdrawalPresented).toBe(true);
    expect(report.withdrawnBeforeSigning).toBe(true);
  });

  it("says 'none presented', never 'none exists', when no withdrawal is shown", async () => {
    const { created, accepted } = await fullCeremony();
    if (!accepted.ok) throw new Error("ceremony failed");
    const report = await verifyCountersignBundle(
      assembleCountersignBundle({
        subject: accepted.envelope,
        request: created.request,
        acceptances: [accepted.acceptance],
      }),
    );
    expect(report.withdrawalPresented).toBe(false);
    expect(report.notes.join(" ")).toContain("not evidence that none exists");
  });

  it("a withdrawal signed by anyone but the requester does not bite", async () => {
    const { created, accepted } = await fullCeremony();
    if (!accepted.ok) throw new Error("ceremony failed");
    const impostor = await holderKey();
    const forged = await withdrawCountersignRequest({
      request: created.request,
      requesterPrivateKey: impostor.privateKey,
    });
    const report = await verifyCountersignBundle(
      assembleCountersignBundle({
        subject: accepted.envelope,
        request: created.request,
        acceptances: [accepted.acceptance],
        withdrawal: forged,
      }),
    );
    expect(report.withdrawalSignatureOk).toBe(false);
    expect(report.withdrawnBeforeSigning).toBe(false);
  });
});

describe("countersign — the link, and the no-device path", () => {
  it("addresses by capability: the id is public, the secret is the key", async () => {
    const { created } = await fullCeremony();
    const derived = await requestIdForCapability(decodeCrockford32(created.capabilitySecretB32));
    expect(derived).toBe(created.requestId);
    expect(created.requestId).toMatch(/^csr_[0-9a-f]{32}$/);
    // The id is a one-way function of the secret, so publishing it gives nothing.
    expect(created.requestId).not.toContain(created.capabilitySecretB32);
  });

  it("puts the secret in the URL fragment, which browsers do not send to a host", async () => {
    const { created } = await fullCeremony();
    const link = created.linkFor("https://example.org/");
    expect(link).toBe(
      `https://example.org/c/${created.requestId}#${created.capabilitySecretB32}`,
    );
    expect(link.split("#")[0]).not.toContain(created.capabilitySecretB32);
  });

  it("renders a short code a person can read down a phone line", async () => {
    const { created } = await fullCeremony();
    expect(created.capabilitySecretB32).toMatch(/^[0-9A-HJKMNP-TV-Z]{26}$/);
  });

  it("survives the substitutions a person makes when reading a code aloud", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    const code = encodeCrockford32(bytes);
    for (const spoken of [code, code.toLowerCase(), code.replace(/(.{4})/g, "$1-")]) {
      expect([...decodeCrockford32(spoken)]).toEqual([...bytes]);
    }
  });

  it("travels whole, with no server anywhere, in carried mode", async () => {
    const { created, subject } = await fullCeremony();
    const carried = decodeCompactCountersignRequest(created.compactB64u);
    expect(carried.body).toEqual(created.request.body);
    expect(carried.signature).toEqual(created.request.signature);

    // And a ceremony run off the carried copy produces the same artifact a
    // hosted one does — which is what lets an SMS/USSD path be added later
    // without a second protocol.
    const accepted = await acceptCountersignRequest({
      request: carried,
      subject,
      signingKey: await generateOneTimeSigningKey(),
    });
    expect(accepted.ok).toBe(true);
  });
});

/**
 * d44's rule, as a list. It lives here and not in `src/` on purpose: a package
 * a stranger installs should not ship a roster of the ecosystem's names, and
 * the guard belongs with the test that enforces it.
 */
const FORBIDDEN_IN_CEREMONY_COPY: readonly string[] = [
  "Indorania",
  "proof economy",
  "standing",
  "KashScript",
  "Kashscript",
  "Duedale",
  "Oreoasis",
  "Indusland",
];

describe("countersign — the ceremony page (d44)", () => {
  const page = async (): Promise<string> => {
    const { created, subject } = await fullCeremony();
    return renderCountersignPage(created.request, {
      requesterLabel: "Rahim General Store",
      submitUrl: "https://example.org/c/submit",
      ceremonyModuleUrl: "https://example.org/c/ceremony.js",
      subject,
    });
  };

  it("CONSTITUTIONAL: names nobody — not the parent entity, not a member, not the vocabulary", async () => {
    const html = await page();
    for (const word of FORBIDDEN_IN_CEREMONY_COPY) {
      expect(html.toLowerCase()).not.toContain(word.toLowerCase());
    }
  });

  it("shows the statement and the disclosures, and asks for nothing else", async () => {
    const html = await page();
    expect(html).toContain("Confirm you received the delivery for order A-77.");
    expect(html).toContain("Rahim General Store");
    expect(html).toContain("A-77");
    // No account, no password, no session — d26's whole point. The page asks
    // for nothing: there is not a single input on it, only two buttons.
    expect(html.toLowerCase()).not.toContain("password");
    expect(html.toLowerCase()).not.toContain("<input");
    expect(html.toLowerCase()).not.toContain("<form");
    expect(html.toLowerCase()).not.toContain("cookie");
    expect(html.match(/<button/g)).toHaveLength(2);
  });

  it("tells the reader that declining records nothing", async () => {
    const html = await page();
    expect(html).toContain("records nothing at all");
  });

  it("escapes requester-supplied copy — the label is shown, never trusted", async () => {
    const holder = await holderKey();
    const subject = await signedSubject(holder);
    const created = await createCountersignRequest({
      subject,
      requesterDid: holder.did,
      requesterPrivateKey: holder.privateKey,
      statement: "<img src=x onerror=alert(1)>",
      disclosures: [{ label: "</dt><script>", value: "\"'&" }],
    });
    const html = renderCountersignPage(created.request, {
      requesterLabel: "<script>alert(2)</script>",
      submitUrl: "https://example.org/c/submit",
      ceremonyModuleUrl: "https://example.org/c/ceremony.js",
      subject,
    });
    expect(html).not.toContain("<img src=x");
    expect(html).not.toContain("<script>alert(2)</script>");
    expect(html).toContain("&lt;img src=x");
  });
});

// ============================================================================
// Consumer-as-acceptance for the mechanic (ROADMAP / ADR-0016 rule).
// ----------------------------------------------------------------------------
// The tests above prove the ceremony's output satisfies the verifier LIBRARY.
// This one proves it satisfies the published verifier BINARY, under plain Node,
// driven the way a counterparty's auditor would drive it: a file, a command, no
// key material, no service. Nothing that passes here needed us to be reachable.
// ============================================================================

describe("countersign — the stranger path: real ceremony output through the published binary", () => {
  const ATTEST = join(import.meta.dir, "..", "..", "attest");
  const WIN = process.platform === "win32";

  beforeAll(() => {
    const build = spawnSync("bun", ["run", "build:bin"], { cwd: ATTEST, encoding: "utf8", shell: WIN });
    if (build.status !== 0) {
      throw new Error(`attest build:bin failed (${build.status}):\n${build.stderr || build.stdout}`);
    }
  });

  it("a ceremony-produced bundle verifies offline, with no --key and no service", async () => {
    const { created, accepted } = await fullCeremony();
    if (!accepted.ok) throw new Error("ceremony failed");
    const bundle = assembleCountersignBundle({
      subject: accepted.envelope,
      request: created.request,
      acceptances: [accepted.acceptance],
    });

    const path = join(tmpdir(), `countersign-ceremony-${process.pid}.json`);
    writeFileSync(path, JSON.stringify(bundle, null, 2));
    try {
      // Run from the attest package with a relative bin path: the repo path
      // contains a space, which `shell: true` would split on Windows.
      const r = spawnSync("node", ["dist/bin/attest.js", "verify", path], {
        cwd: ATTEST,
        encoding: "utf8",
        shell: WIN,
      });
      expect(`${r.stdout}${r.stderr}`).toContain("two-signature proof: yes");
      expect(r.stdout).toContain("RESULT: PASS");
      expect(r.status).toBe(0);
    } finally {
      rmSync(path, { force: true });
    }
  });
});
