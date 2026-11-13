// M4 — mandates as W3C Verifiable Credentials with AP2 semantics. Conformance
// (@context/type/issuer/validFrom/credentialSubject/proof) + round-trip verify
// + tamper/wrong-key rejection, for both Intent (grant) and Cart mandates.

import { describe, expect, it } from "bun:test";
import { deriveDid } from "@kashscript/identity-core";

import {
  MANDATE_CONTEXT,
  VC_CONTEXT_V2,
  forgeCartMandate,
  grantFromMandateCredential,
  toCartMandateCredential,
  toMandateCredential,
  verifyMandateCredential,
} from "../src/credential";
import type { Cart, IntentMandateSubject } from "../src/credential";
import { forgeGrant, generateGrantAuthorityKeyPair } from "../src/mandate/grant";
import type { Grant } from "../src/mandate/types";
import { InMemoryGrantLedger, issueGrant } from "../src/mandate/lifecycle";
import { exampleProgram } from "./fixtures";

const NOW = 1_800_000_000;

describe("credential — AP2 Intent Mandate (grant) as a W3C VC", () => {
  it("expresses a conformant VC and verifies its proof", async () => {
    const kp = await generateGrantAuthorityKeyPair();
    const issuer = deriveDid(kp.publicKey);
    const ledger = new InMemoryGrantLedger();
    const { signed } = await issueGrant(
      { programId: "prog_example", beneficiaryDid: "did:kash:ben-1", purposeTag: "MEAL", amountPaisa: 250_000 },
      exampleProgram(),
      kp.privateKey,
      ledger,
      { nowUnix: NOW },
    );

    const vc = toMandateCredential(signed, { issuer });
    // W3C VC 2.0 conformance.
    expect(vc["@context"]).toEqual([VC_CONTEXT_V2, MANDATE_CONTEXT]);
    expect(vc.type).toContain("VerifiableCredential");
    expect(vc.type).toContain("MandateCredential");
    expect(vc.type).toContain("IntentMandate");
    expect(vc.issuer).toBe(issuer);
    expect(typeof vc.validFrom).toBe("string");
    expect(vc.validUntil).toBe(new Date(signed.grant.expiryUnix * 1000).toISOString());
    expect(vc.credentialSubject.mandateType).toBe("IntentMandate");
    // AP2 Intent Mandate constraints.
    const subject = vc.credentialSubject as IntentMandateSubject;
    expect(subject.constraints.maxAmountPaisa).toBe(250_000);
    expect(subject.constraints.singleUseNonce).toBe(signed.grant.singleUseNonce);
    // Proof embeds the kash-grant-v1 Ed25519 signature.
    expect(vc.proof.type).toBe("KashEventSignature2026");
    expect(vc.proof.domainSeparationTag).toBe("kash-grant-v1\n");

    const res = await verifyMandateCredential(vc, kp.publicKey);
    expect(res.ok).toBe(true);
    expect(res.mandateType).toBe("IntentMandate");
  });

  it("rejects a tampered credential and a wrong key", async () => {
    const kp = await generateGrantAuthorityKeyPair();
    const issuer = deriveDid(kp.publicKey);
    const ledger = new InMemoryGrantLedger();
    const { signed } = await issueGrant(
      { programId: "prog_example", beneficiaryDid: "did:kash:ben-1", purposeTag: "MEAL", amountPaisa: 250_000 },
      exampleProgram(),
      kp.privateKey,
      ledger,
      { nowUnix: NOW },
    );
    const vc = toMandateCredential(signed, { issuer });

    const subject = vc.credentialSubject as IntentMandateSubject;
    const tampered = {
      ...vc,
      credentialSubject: { ...subject, constraints: { ...subject.constraints, maxAmountPaisa: 1 } },
    };
    expect((await verifyMandateCredential(tampered, kp.publicKey)).ok).toBe(false);

    const other = await generateGrantAuthorityKeyPair();
    expect((await verifyMandateCredential(vc, other.publicKey)).ok).toBe(false);

    expect((await verifyMandateCredential({ not: "a credential" }, kp.publicKey)).reason).toBe("MALFORMED_CREDENTIAL");
  });
});

describe("credential — AP2 Cart Mandate (offer → receipt) as a W3C VC", () => {
  it("signs, expresses, and verifies a cart mandate", async () => {
    const kp = await generateGrantAuthorityKeyPair();
    const issuer = deriveDid(kp.publicKey);
    const cart: Cart = {
      cartId: "cart_1",
      payerDid: "did:kash:payer",
      merchantDid: "did:kash:merchant",
      items: [{ sku: "coffee", amountPaisa: 45_000, qty: 2 }],
      totalPaisa: 90_000,
      currency: "PKR",
      expiryUnix: NOW + 3600,
      nonce: "cart-nonce-1",
    };
    const signedCart = await forgeCartMandate(cart, kp.privateKey);
    const vc = toCartMandateCredential(signedCart, { issuer });
    expect(vc.type).toContain("CartMandate");
    expect(vc.credentialSubject.mandateType).toBe("CartMandate");

    const res = await verifyMandateCredential(vc, kp.publicKey);
    expect(res.ok).toBe(true);
    expect(res.mandateType).toBe("CartMandate");

    const other = await generateGrantAuthorityKeyPair();
    expect((await verifyMandateCredential(vc, other.publicKey)).ok).toBe(false);
  });
});

describe("credential — every mandate expires, and says who confirms arrival (KS-R4)", () => {
  async function issued() {
    const kp = await generateGrantAuthorityKeyPair();
    const issuer = deriveDid(kp.publicKey);
    const { signed } = await issueGrant(
      { programId: "prog_example", beneficiaryDid: "did:kash:ben-1", purposeTag: "MEAL", amountPaisa: 250_000 },
      exampleProgram(),
      kp.privateKey,
      new InMemoryGrantLedger(),
      { nowUnix: NOW },
    );
    return { kp, issuer, signed, vc: toMandateCredential(signed, { issuer }) };
  }

  it("carries the arrival clause into the VC, and it verifies", async () => {
    const { kp, vc } = await issued();
    const subject = vc.credentialSubject as IntentMandateSubject;
    expect(subject.constraints.arrival).toEqual({ confirmedBy: "RECIPIENT", signatures: 2 });
    expect((await verifyMandateCredential(vc, kp.publicKey)).ok).toBe(true);
  });

  it("a credential with no validUntil is malformed — it has no end date", async () => {
    const { kp, vc } = await issued();
    const { validUntil: _dropped, ...noEnd } = vc;
    const res = await verifyMandateCredential(noEnd, kp.publicKey);
    expect(res).toMatchObject({ ok: false, reason: "MALFORMED_CREDENTIAL" });
  });

  it("a validUntil stretched past the signed expiry is refused (the ISO view cannot outlive the signature)", async () => {
    const { kp, vc } = await issued();
    const stretched = { ...vc, validUntil: new Date((NOW + 400 * 86_400) * 1000).toISOString() };
    expect(await verifyMandateCredential(stretched, kp.publicKey)).toMatchObject({ ok: false, reason: "EXPIRY_MISMATCH" });
    const subject = vc.credentialSubject as IntentMandateSubject;
    const viewOnly = { ...vc, credentialSubject: { ...subject, constraints: { ...subject.constraints, expiry: "2099-01-01T00:00:00.000Z" } } };
    expect(await verifyMandateCredential(viewOnly, kp.publicKey)).toMatchObject({ ok: false, reason: "EXPIRY_MISMATCH" });
  });

  it("altering the signed expiry or the arrival clause breaks the signature", async () => {
    const { kp, vc } = await issued();
    const subject = vc.credentialSubject as IntentMandateSubject;
    const later = { ...vc, credentialSubject: { ...subject, constraints: { ...subject.constraints, expiryUnix: subject.constraints.expiryUnix + 86_400 } } };
    expect((await verifyMandateCredential(later, kp.publicKey)).reason).toBe("SIGNATURE_INVALID");
    const weaker = { ...vc, credentialSubject: { ...subject, constraints: { ...subject.constraints, arrival: { confirmedBy: "RECIPIENT", signatures: 1 } } } };
    expect((await verifyMandateCredential(weaker, kp.publicKey)).reason).toBe("SIGNATURE_INVALID");
  });

  it("a properly signed mandate asking for fewer than two signatures is still refused (d41 floor)", async () => {
    const { kp, issuer, signed } = await issued();
    const weakGrant = { ...signed.grant, arrival: { confirmedBy: "RECIPIENT", signatures: 1 } } as unknown as Grant;
    const weakSigned = await forgeGrant(weakGrant, kp.privateKey); // genuine signature over a clause d41 forbids
    const vc = toMandateCredential(weakSigned, { issuer });
    expect(await verifyMandateCredential(vc, kp.publicKey)).toMatchObject({ ok: false, reason: "ARRIVAL_CLAUSE_INVALID" });
  });

  it("a mandate signed under 0.1.0 (no arrival clause) still verifies and round-trips byte for byte", async () => {
    const { kp, issuer, signed } = await issued();
    const { arrival: _none, ...legacyGrant } = signed.grant;
    const legacySigned = await forgeGrant(legacyGrant, kp.privateKey);
    const vc = toMandateCredential(legacySigned, { issuer });
    expect((vc.credentialSubject as IntentMandateSubject).constraints).not.toHaveProperty("arrival");
    expect(await verifyMandateCredential(vc, kp.publicKey)).toMatchObject({ ok: true, reason: null });
    expect(grantFromMandateCredential(vc.credentialSubject as IntentMandateSubject)).toEqual(legacyGrant);
  });

  it("a cart mandate's validUntil must match its signed expiry too", async () => {
    const kp = await generateGrantAuthorityKeyPair();
    const issuer = deriveDid(kp.publicKey);
    const cart: Cart = {
      cartId: "cart_2", payerDid: "did:kash:payer", merchantDid: "did:kash:merchant",
      items: [{ sku: "tea", amountPaisa: 10_000, qty: 1 }], totalPaisa: 10_000, currency: "PKR",
      expiryUnix: NOW + 3600, nonce: "cart-nonce-2",
    };
    const vc = toCartMandateCredential(await forgeCartMandate(cart, kp.privateKey), { issuer });
    expect((await verifyMandateCredential(vc, kp.publicKey)).ok).toBe(true);
    const stretched = { ...vc, validUntil: new Date((NOW + 999_999) * 1000).toISOString() };
    expect(await verifyMandateCredential(stretched, kp.publicKey)).toMatchObject({ ok: false, reason: "EXPIRY_MISMATCH" });
  });
});
