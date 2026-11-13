/**
 * Age-proof — integration tests for selective disclosure.
 */

import { describe, expect, test } from "bun:test";
import { Signer } from "@kashscript/identity-core/signer";

import { Registrar, StudentWallet, AdultLibrary, type StudentIdBody } from "./age-proof";

function adultStudentBody(): StudentIdBody {
  return {
    legalName:   "Ayesha Khan",
    dateOfBirth: "2005-04-15",   // ≥ 18 as of 2026
    cnic:        "42101-1234567-8",
    citizenship: "Pakistan",
    isOver18:    true,
  };
}

function minorStudentBody(): StudentIdBody {
  return {
    legalName:   "Hassan Ali",
    dateOfBirth: "2012-09-03",
    cnic:        "42101-9876543-2",
    citizenship: "Pakistan",
    isOver18:    false,
  };
}

/* ─────────────────────────────────────────────────────────────────
 *  Layer 1 — Issuance produces a valid signed envelope
 * ───────────────────────────────────────────────────────────────── */

describe("Age-proof · Issuance", () => {
  test("registrar issues an envelope whose cid is the body commitment root", async () => {
    const registrarSigner = await Signer.generate();
    const registrar = new Registrar(registrarSigner);
    const issued = await registrar.issue(adultStudentBody());

    expect(issued.event.header.did).toBe(registrar.did);
    expect(issued.event.header.lexicon).toBe("kash.education.student-id@1.0.0");
    expect(issued.event.header.cid).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
    expect(issued.commitment.fieldOrder).toEqual([
      "citizenship", "cnic", "dateOfBirth", "isOver18", "legalName",
    ]);
  });

  test("the issued event has a salt for every field", async () => {
    const registrar = new Registrar(await Signer.generate());
    const issued = await registrar.issue(adultStudentBody());
    for (const k of ["legalName", "dateOfBirth", "cnic", "citizenship", "isOver18"]) {
      expect(issued.commitment.salts[k]).toBeDefined();
      expect(issued.commitment.salts[k]!.length).toBe(32);
    }
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 2 — Selective disclosure reveals only what's asked
 * ───────────────────────────────────────────────────────────────── */

describe("Age-proof · Selective disclosure", () => {
  test("discloseAgeOnly reveals isOver18 and redacts the other four", async () => {
    const registrar = new Registrar(await Signer.generate());
    const issued = await registrar.issue(adultStudentBody());
    const wallet = new StudentWallet(issued);
    const disclosure = await wallet.discloseAgeOnly();

    expect(Object.keys(disclosure.disclosed)).toEqual(["isOver18"]);
    expect(disclosure.disclosed["isOver18"]?.value).toBe(true);
    expect(Object.keys(disclosure.redacted).sort()).toEqual([
      "citizenship", "cnic", "dateOfBirth", "legalName",
    ]);
  });

  test("the redacted fields contain only leaf hashes — no values leak", async () => {
    const registrar = new Registrar(await Signer.generate());
    const issued = await registrar.issue(adultStudentBody());
    const wallet = new StudentWallet(issued);
    const disclosure = await wallet.discloseAgeOnly();

    // Redacted entries have leafB58 + siblingsB58 + positions; no `value`.
    for (const k of ["legalName", "dateOfBirth", "cnic", "citizenship"]) {
      const r = disclosure.redacted[k]!;
      expect(r.leafB58).toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
      expect(r.siblingsB58.length).toBeGreaterThan(0);
      expect((r as unknown as Record<string, unknown>)["value"]).toBeUndefined();
    }
  });

  test("discloseCitizenshipAndAge reveals two fields, hides three", async () => {
    const registrar = new Registrar(await Signer.generate());
    const issued = await registrar.issue(adultStudentBody());
    const wallet = new StudentWallet(issued);
    const disclosure = await wallet.discloseCitizenshipAndAge();

    expect(Object.keys(disclosure.disclosed).sort()).toEqual(["citizenship", "isOver18"]);
    expect(disclosure.disclosed["citizenship"]?.value).toBe("Pakistan");
    expect(disclosure.disclosed["isOver18"]?.value).toBe(true);
    expect(Object.keys(disclosure.redacted).sort()).toEqual(["cnic", "dateOfBirth", "legalName"]);
  });
});

/* ─────────────────────────────────────────────────────────────────
 *  Layer 3 — Library verification
 * ───────────────────────────────────────────────────────────────── */

describe("Age-proof · Library verification", () => {
  test("adult student → library accepts the disclosure", async () => {
    const registrar = new Registrar(await Signer.generate());
    const issued = await registrar.issue(adultStudentBody());
    const wallet = new StudentWallet(issued);
    const library = new AdultLibrary(registrar.publicKey);

    const disclosure = await wallet.discloseAgeOnly();
    expect(await library.accepts(disclosure)).toBe(true);
  });

  test("minor student → library rejects (isOver18 === false)", async () => {
    const registrar = new Registrar(await Signer.generate());
    const issued = await registrar.issue(minorStudentBody());
    const wallet = new StudentWallet(issued);
    const library = new AdultLibrary(registrar.publicKey);

    const disclosure = await wallet.discloseAgeOnly();
    expect(await library.accepts(disclosure)).toBe(false);
  });

  test("GAP-ZKP-001 (CLOSED): wrong registrar public key → library rejects", async () => {
    // Previously this test pinned a Phase-5-v1 limitation: with any field
    // redacted, `verifySelectiveDisclosure` did NOT actually verify the
    // event signature against the supplied public key — a verifier
    // holding the WRONG key would still accept.
    //
    // Closed by adding a `headerAttestation` signature at issuance time
    // (under DST `kash-header-attestation-v1\n`). The disclosure carries
    // it through; `verifySelectiveDisclosure` verifies it against the
    // supplied public key whenever it's present. The body slot of the
    // attestation is constant-empty, so the signature stays verifiable
    // regardless of which fields the holder later chooses to redact.
    //
    // See packages/identity-zkp/src/disclosure.ts:
    //   - export const KASH_HEADER_ATTESTATION_DST
    //   - export async function signHeaderAttestation(...)
    //   - SelectiveDisclosure.headerAttestation (optional field)
    //   - verifySelectiveDisclosure now branches on the optional field
    const realRegistrar = new Registrar(await Signer.generate());
    const fakeRegistrar = new Registrar(await Signer.generate());
    const issued = await realRegistrar.issue(adultStudentBody());
    const wallet = new StudentWallet(issued);
    const library = new AdultLibrary(fakeRegistrar.publicKey);

    const disclosure = await wallet.discloseAgeOnly();
    expect(await library.accepts(disclosure)).toBe(false);
  });

  test("tampered disclosed value → verifier rejects", async () => {
    const registrar = new Registrar(await Signer.generate());
    const issued = await registrar.issue(minorStudentBody());
    const wallet = new StudentWallet(issued);
    const library = new AdultLibrary(registrar.publicKey);

    const disclosure = await wallet.discloseAgeOnly();
    // Holder lies: claim isOver18 = true when the registrar issued false.
    const tampered = {
      ...disclosure,
      disclosed: {
        ...disclosure.disclosed,
        isOver18: { ...disclosure.disclosed["isOver18"]!, value: true },
      },
    };
    expect(await library.accepts(tampered)).toBe(false);
  });
});
