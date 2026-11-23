/**
 * RW-15 — salted references: two verifiers' copies share nothing to join on (`specs/attestation/README.md`
 * §2.4a–§2.4b, §3 G1). The copy of a countersigned record already in use, the opened commitment, the page's rule
 * and its seal, the references already salted, the worked example and the conformance cases.
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { signEvent } from "@kashscript/identity-core";
import { DST_COUNTERSIGN_WITHDRAWAL, countersignRequestDigest, verifyCountersignBundle, type CountersignBundle } from "../src/countersign";
import type { DsseEnvelope } from "../src/dsse";
import { bytesToBase64Url } from "../src/ed25519";
import { RESTS_ON_SLOTS, issuePredicateCredential, restsOnDecoys } from "../src/exchange";
import { makeKeyResolver } from "../src/holder";
import { decodeDisclosure, decodeJws, issueSdJwt, linkabilityBetween, parseSdJwt, presentSdJwt, sharedValues, verifySdJwt } from "../src/sd-jwt";
import {
  ATTESTATION_VCT,
  COPY_LIFETIME_DAYS,
  COPY_SD_SLOTS,
  NOT_DISCLOSED,
  PAGE_SEAL_HEADER,
  copyClaimsOf,
  copyClaimsOfCountersigned,
  openArtefact,
  openPage,
  openRecordCommitment,
  pageOf,
  projectVc,
  readCountersigned,
  recordDisclosureOf,
  recordHashOf,
  shownOnPage,
  viewOfCopy,
  viewerCopyOf,
  type CountersignedCopyInput,
} from "../src/attestation";
import { DAY, bookingDelivered, clientSignoff, countersigned, iso, party, type Party } from "./helpers/countersigned";

const SPECS = join(import.meta.dir, "..", "..", "..", "specs", "attestation");
const EXAMPLE = join(SPECS, "examples", "receipt-booking-countersigned");
const read = (...p: string[]): string => readFileSync(join(...p), "utf8");
const readJson = <T = unknown>(...p: string[]): T => JSON.parse(read(...p)) as T;
const resolver = makeKeyResolver(new Map(), new Map());
const enc = new TextEncoder();

const T0 = Date.parse("2026-11-16T10:00:00Z") / 1000;
const ISSUED = Date.parse("2026-11-23T00:00:00Z") / 1000;
const PRESENTED = ISSUED + 9 * 3600 + 1800;
const PROFILE = "booking.delivered/1";

/** What every copy of a kind shows by construction — the class (§3 G1; the founder's reading of 2026-11-20). */
function classOf(issuer: string, profile: string, iat: number, grade?: number): Set<string> {
  const c = new Set<string>([issuer, ATTESTATION_VCT, "dc+sd-jwt", "kb+jwt", "EdDSA", "sha-256", "receipt", "accepted", profile, String(iat), String(iat + COPY_LIFETIME_DAYS * DAY), "OKP", "Ed25519", "true"]);
  if (grade !== undefined) c.add(String(grade));
  return c;
}

async function copyOf(bundle: CountersignBundle, issuer: Party, holder: Party | null, over: Partial<CountersignedCopyInput> = {}): Promise<string> {
  const { claims, sdProperties, decoys } = await copyClaimsOfCountersigned(bundle, { issuer: issuer.did, ...(holder !== null ? { holderKey: holder.publicKey } : {}), iatUnix: ISSUED, ...over });
  return issueSdJwt({ header: { kid: issuer.did }, claims, sdProperties, decoys, signer: issuer });
}
const presentTo = (held: string, holder: Party, aud: string, nonce: string, iatUnix: number, disclose: readonly string[] = []): Promise<string> =>
  presentSdJwt(held, (d) => d.name !== null && disclose.includes(d.name), holder, { aud, nonce, iatUnix });
const visibleOf = (sdJwt: string): Record<string, unknown> => decodeJws(parseSdJwt(sdJwt)!.issuerJwt)!.payload;
const disclosedNames = async (sdJwt: string): Promise<string[]> => (await Promise.all(parseSdJwt(sdJwt)!.disclosures.map(decodeDisclosure))).map((d) => d?.name ?? "?");
const disclosuresOf = (sdJwt: string): string[] => [...parseSdJwt(sdJwt)!.disclosures];
async function digestOfString(s: string): Promise<string> {
  return bytesToBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s))));
}
/** Every file under a folder, recursively. */
function filesUnder(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => (statSync(join(dir, f)).isDirectory() ? filesUnder(join(dir, f)) : [join(dir, f)]));
}

let host: Party;
let guest: Party;
let holderA: Party;
let holderB: Party;
let booking: CountersignBundle;

beforeAll(async () => {
  [host, guest, holderA, holderB] = await Promise.all([party(), party(), party(), party()]);
  booking = await bookingDelivered(host, guest, { start: T0 - 2 * DAY, end: T0 });
});

describe("the copy of a countersigned record (§2.4a)", () => {
  test("a booking's copy: the class visible, the record and the rest behind fresh salts, eight digests, the counterparty nowhere", async () => {
    const held = await copyOf(booking, host, holderA, { grade: 1 });
    const r = await verifySdJwt(held, { resolveKey: resolver, requireKeyBinding: false, nowSec: ISSUED });
    expect(r.ok).toBe(true);
    expect(r.vct).toBe(ATTESTATION_VCT);
    expect(r.issuer).toBe(host.did);
    const v = visibleOf(held);
    const { _sd, _sd_alg, cnf, ...rest } = v;
    expect(rest).toEqual({ iss: host.did, iat: ISSUED, exp: ISSUED + COPY_LIFETIME_DAYS * DAY, vct: ATTESTATION_VCT, attestation: { kind: "receipt", outcome: "accepted", profile: PROFILE, grade: 1 } });
    expect(cnf).toBeDefined();
    expect(_sd_alg).toBe("sha-256");
    expect((_sd as string[]).length).toBe(COPY_SD_SLOTS);
    // The reference the acceptance bound is what the copy commits to; a keccak agreement reference cannot be carried.
    expect(new Set(await disclosedNames(held))).toEqual(new Set(["record", "statement", "claimedAt"]));
    const view = viewOfCopy(r.claims!);
    expect(view.record).toBe(booking.request.body.subjectDigestSha256);
    expect(await recordHashOf(booking)).toBe(view.record!);
    expect(view.claimedAt).toBe(iso(booking.acceptances[0]!.body.signedAtUnix));
    expect(view.statement).toBe("Delivered a booking under the agreement this record names.");
    expect(view.reference).toBeUndefined();
    expect(held).not.toContain(guest.did);
    expect(JSON.stringify(await Promise.all(disclosuresOf(held).map(decodeDisclosure)))).not.toContain(guest.did);
  });

  test("a SHA-256 agreement reference is carried, behind its own disclosure; practice comes from the record", async () => {
    const terms = "c".repeat(64);
    const b = await bookingDelivered(host, guest, { start: T0 - 2 * DAY, end: T0, reference: terms, practice: true });
    const held = await copyOf(b, host, holderA);
    expect(new Set(await disclosedNames(held))).toEqual(new Set(["reference", "record", "statement", "claimedAt"]));
    expect((visibleOf(held)._sd as string[]).length).toBe(COPY_SD_SLOTS);
    const seen = await verifySdJwt(held, { resolveKey: resolver, requireKeyBinding: false, nowSec: ISSUED });
    const view = viewOfCopy(seen.claims!);
    expect(view.reference).toEqual({ kind: "agreement", sha256: terms });
    expect(view.practice).toBe(true);
  });

  test("only from a record that checks: a one-signature claim, a withdrawn request, a stopped record and a record that ends sooner get no copy", async () => {
    const want = { issuer: host.did, holderKey: holderA.publicKey, iatUnix: ISSUED };
    await expect(copyClaimsOfCountersigned({ ...booking, acceptances: [] }, want)).rejects.toThrow("a copy is made only from a record that checks");
    const header = { typ: "countersign-withdrawal", v: 1 };
    const body = { act: "withdraw" as const, requestId: booking.request.body.requestId, requestDigestSha256: await countersignRequestDigest(booking.request), withdrawnAtUnix: booking.acceptances[0]!.body.signedAtUnix - 10 };
    const withdrawn = { ...booking, withdrawal: { header, body, signature: await signEvent(header, body, host.privateKey, { dst: DST_COUNTERSIGN_WITHDRAWAL }) } };
    expect((await verifyCountersignBundle(withdrawn)).reason).toBe("WITHDRAWN_BEFORE_SIGNING");
    await expect(copyClaimsOfCountersigned(withdrawn, want)).rejects.toThrow("a copy is made only from a record that checks");
    const [doer, agency, client] = await Promise.all([party(), party(), party()]);
    const stopped = await clientSignoff(doer, agency, client, { at: T0, status: "stopped" });
    await expect(copyClaimsOfCountersigned(stopped, { issuer: agency.did, iatUnix: ISSUED })).rejects.toThrow("a stopped record gets no copy");
    const ending = await countersigned(host, guest, { spec: "oreoasis.work-record/1", actor: { class: "organisation", id: host.did }, shape: "accepted", status: "completed", expiresAt: iso(ISSUED + 10 * DAY) }, T0);
    await expect(copyClaimsOfCountersigned(ending, want)).rejects.toThrow("the record ends before a copy's lifetime would");
    await expect(copyClaimsOfCountersigned({ not: "a bundle" } as unknown as CountersignBundle, want)).rejects.toThrow("kashscript-countersign/1");
  });

  test("the issuer is a party to the record — a subject signer or the requester — and never the counterparty", async () => {
    const [doer, agency, client] = await Promise.all([party(), party(), party()]);
    const signoff = await clientSignoff(doer, agency, client, { at: T0 });
    const reading = await readCountersigned(signoff);
    expect([...reading.eligibleIssuers].sort()).toEqual([agency.did, doer.did].sort());
    expect(reading.countersigners).toEqual([client.did]);
    for (const issuer of [agency, doer]) {
      const held = await copyOf(signoff, issuer, holderA, { profile: "client-signoff/1" });
      expect((await verifySdJwt(held, { resolveKey: resolver, requireKeyBinding: false, nowSec: ISSUED })).ok).toBe(true);
    }
    await expect(copyOf(signoff, client, holderA)).rejects.toThrow("never the counterparty");
    await expect(copyOf(booking, guest, holderA)).rejects.toThrow("never the counterparty");
    // Without a profile of its own or from the record, the copy carries none; one that is not name/version is refused.
    const bare = await copyOf(signoff, agency, holderA);
    expect((visibleOf(bare).attestation as Record<string, unknown>).profile).toBeUndefined();
    await expect(copyOf(signoff, agency, holderA, { profile: "Client Sign-off" })).rejects.toThrow("name/version");
  });

  test("a copy signed by a key that is not the issuer's is refused by every checker", async () => {
    const stranger = await party();
    const { claims, sdProperties, decoys } = await copyClaimsOfCountersigned(booking, { issuer: host.did, holderKey: holderA.publicKey, iatUnix: ISSUED });
    const kidWrong = await issueSdJwt({ header: { kid: stranger.did }, claims, sdProperties, decoys, signer: stranger });
    expect((await verifySdJwt(kidWrong, { resolveKey: resolver, requireKeyBinding: false, nowSec: ISSUED })).reason).toBe("KID_NOT_ISSUER");
    const sigWrong = await issueSdJwt({ header: { kid: host.did }, claims, sdProperties, decoys, signer: stranger });
    expect((await verifySdJwt(sigWrong, { resolveKey: resolver, requireKeyBinding: false, nowSec: ISSUED })).reason).toBe("ISSUER_SIGNATURE_INVALID");
    expect((await shownOnPage(sigWrong, [booking], { nowSec: ISSUED })).ok).toBe(false);
  });

  test("grade 0 is practice only", async () => {
    await expect(copyOf(booking, host, holderA, { grade: 0 })).rejects.toThrow("practice only");
    const practice = await bookingDelivered(host, guest, { start: T0 - 2 * DAY, end: T0, practice: true });
    expect((visibleOf(await copyOf(practice, host, holderA, { grade: 0 })).attestation as Record<string, unknown>).grade).toBe(0);
  });

  test("a page copy has no key, so nobody can present it — it is only ever shown", async () => {
    const pageCopy = await copyOf(booking, host, null);
    expect(visibleOf(pageCopy).cnf).toBeUndefined();
    const held = await verifySdJwt(pageCopy, { resolveKey: resolver, requireKeyBinding: false, nowSec: ISSUED });
    expect(held.ok).toBe(true);
    expect(held.holder).toBeNull();
    const tried = await presentSdJwt(pageCopy, () => false, holderA, { aud: "https://a.example", nonce: "n", iatUnix: PRESENTED });
    expect((await verifySdJwt(tried, { resolveKey: resolver, requireKeyBinding: true, audience: "https://a.example", nonce: "n", nowSec: PRESENTED })).reason).toBe("HOLDER_KEY_MISSING");
  });

  test("RW-14's copy of an attestation record of truth also makes a page copy without a key", async () => {
    const record = readJson<DsseEnvelope>(SPECS, "examples", "receipt-booking", "record.dsse.json");
    const { claims } = await copyClaimsOf(record, { iatUnix: ISSUED });
    expect(claims.cnf).toBeUndefined();
    expect(claims.attestation).toEqual({ kind: "receipt", outcome: "accepted", profile: PROFILE, grade: 1, practice: true });
  });
});

describe("two verifiers' copies share nothing to join on (RW-15's test, read with the class — §3 G1)", () => {
  test("two presentations of one receipt to two verifiers share no common string beyond the issuer's key and the profile name; the checker accepts both", async () => {
    const a = await copyOf(booking, host, holderA, { grade: 1 });
    const b = await copyOf(booking, host, holderB, { grade: 1 });
    const pa = await presentTo(a, holderA, "https://a.example", "nonce-a", PRESENTED);
    const pb = await presentTo(b, holderB, "https://b.example", "nonce-b", PRESENTED + 1234);
    const cls = classOf(host.did, PROFILE, ISSUED, 1);
    const shared = await sharedValues(pa, pb);
    expect(shared.filter((s) => !cls.has(s.value))).toEqual([]);
    // Not vacuous: the issuer's key and the profile name are shared, as the prompt allows.
    expect(shared.map((s) => s.value)).toEqual(expect.arrayContaining([host.did, PROFILE]));
    expect(await linkabilityBetween(pa, pb)).toEqual([]);
    const sdA = new Set(visibleOf(a)._sd as string[]);
    expect((visibleOf(b)._sd as string[]).some((d) => sdA.has(d))).toBe(false);
    // The checker accepts each at its own verifier, and refuses it at the other's.
    expect((await verifySdJwt(pa, { resolveKey: resolver, requireKeyBinding: true, audience: "https://a.example", nonce: "nonce-a", nowSec: PRESENTED + 60 })).ok).toBe(true);
    expect((await verifySdJwt(pb, { resolveKey: resolver, requireKeyBinding: true, audience: "https://b.example", nonce: "nonce-b", nowSec: PRESENTED + 1234 + 60 })).ok).toBe(true);
    expect((await verifySdJwt(pa, { resolveKey: resolver, requireKeyBinding: true, audience: "https://b.example", nonce: "nonce-a", nowSec: PRESENTED + 60 })).reason).toBe("AUDIENCE_MISMATCH");
  });

  test("disclosing the record to both verifiers links them — the holder's choice, and the diagnostic says where", async () => {
    const a = await copyOf(booking, host, holderA);
    const b = await copyOf(booking, host, holderB);
    const pa = await presentTo(a, holderA, "https://a.example", "nonce-a", PRESENTED, ["record"]);
    const pb = await presentTo(b, holderB, "https://b.example", "nonce-b", PRESENTED + 7, ["record"]);
    expect((await linkabilityBetween(pa, pb)).map((c) => c.kind)).toEqual(["disclosed-value"]);
    const hit = (await sharedValues(pa, pb)).find((s) => s.value === booking.request.body.subjectDigestSha256);
    expect(hit?.inA).toEqual(["disclosure[0].value"]);
    expect(hit?.inB).toEqual(["disclosure[0].value"]);
  });

  test("copies of two records of one class differ only in their keys, digests and signatures", async () => {
    const guest2 = await party();
    const other = await bookingDelivered(host, guest2, { start: T0 - 3 * DAY, end: T0 - DAY });
    const strip = (held: string) => {
      const { cnf, _sd, ...rest } = visibleOf(held);
      void cnf;
      return { rest, sdCount: (_sd as string[]).length };
    };
    const x = strip(await copyOf(booking, host, holderA, { grade: 1 }));
    const y = strip(await copyOf(other, host, holderB, { grade: 1 }));
    expect(y.rest).toEqual(x.rest);
    expect([x.sdCount, y.sdCount]).toEqual([COPY_SD_SLOTS, COPY_SD_SLOTS]);
  });
});

describe("the checker verifies the commitment, and the page shows the artefact only to the holder of the disclosure (§2.4b)", () => {
  test("openRecordCommitment: committed, uncommitted, the record, and whether it opens the artefact", async () => {
    const a = await copyOf(booking, host, holderA);
    const b = await copyOf(booking, host, holderB);
    const sd = visibleOf(a)._sd as string[];
    const hash = (await recordHashOf(booking))!;
    const opened = await openRecordCommitment({ sd, disclosures: disclosuresOf(a), artefactSha256: hash });
    expect(new Set(opened.committed)).toEqual(new Set(["record", "statement", "claimedAt"]));
    expect(opened.uncommitted).toEqual([]);
    expect(opened.record).toBe(hash);
    expect(opened.opens).toBe(true);
    const wrong = await openRecordCommitment({ sd, disclosures: disclosuresOf(a), artefactSha256: "f".repeat(64) });
    expect(wrong.opens).toBe(false);
    const foreign = await openRecordCommitment({ sd, disclosures: disclosuresOf(b) });
    expect(foreign.committed).toEqual([]);
    expect(foreign.uncommitted.length).toBe(3);
    expect(foreign.record).toBeNull();
    expect(foreign.opens).toBeNull();
  });

  test("recordHashOf names a bundle by its subject's payload, an envelope by its payload, and nothing else", async () => {
    const hash = await recordHashOf(booking);
    expect(hash).toBe(booking.request.body.subjectDigestSha256);
    expect(await recordHashOf(booking.subject)).toBe(hash);
    expect(await recordHashOf({ not: "a record" })).toBeNull();
    expect(await recordHashOf("text")).toBeNull();
    expect(await recordHashOf({ ...booking, subject: { ...booking.subject, payload: "not base64!" } })).toBeNull();
  });

  test("shownOnPage: nothing without the disclosure; the artefact with it; the wrong artefact, the bare subject, a forged record and another issuer's copy are refused", async () => {
    const held = await copyOf(booking, host, null);
    const stored = `${parseSdJwt(held)!.issuerJwt}~`;
    const closed = await shownOnPage(stored, [booking], { nowSec: ISSUED });
    expect(closed.ok).toBe(true);
    expect(closed.shown).toBeNull();
    expect(closed.why).toBe(NOT_DISCLOSED);
    expect(closed.view?.record).toBeUndefined();

    const open = await shownOnPage(held, [{ junk: true }, booking], { nowSec: ISSUED });
    expect(open.ok).toBe(true);
    expect(open.shown?.index).toBe(1);
    expect(open.why).toContain("shown");

    const guest2 = await party();
    const other = await bookingDelivered(host, guest2, { start: T0 - 3 * DAY, end: T0 - DAY });
    expect((await shownOnPage(held, [other], { nowSec: ISSUED })).why).toBe("the disclosed record names no artefact here");
    expect((await shownOnPage(held, [booking.subject], { nowSec: ISSUED })).why).toContain("one signature is a request, not a record");
    const forged = structuredClone(booking) as CountersignBundle & { acceptances: { signature: { sig: string } }[] };
    forged.acceptances[0]!.signature.sig = "A".repeat(forged.acceptances[0]!.signature.sig.length);
    expect((await shownOnPage(held, [forged], { nowSec: ISSUED })).why).toContain("does not check");

    const stranger = await party();
    const claimed = await issueSdJwt({
      header: { kid: stranger.did },
      claims: { iss: stranger.did, iat: ISSUED, exp: ISSUED + COPY_LIFETIME_DAYS * DAY, vct: ATTESTATION_VCT, attestation: { kind: "receipt", outcome: "accepted" } },
      sdProperties: { record: booking.request.body.subjectDigestSha256 },
      decoys: COPY_SD_SLOTS - 1,
      signer: stranger,
    });
    const notTheirs = await shownOnPage(claimed, [booking], { nowSec: ISSUED });
    expect(notTheirs.ok).toBe(true);
    expect(notTheirs.shown).toBeNull();
    expect(notTheirs.why).toContain("issuer is not the copy's");

    const predicate = await issueSdJwt({ header: { kid: host.did }, claims: { iss: host.did, iat: ISSUED, exp: ISSUED + DAY, vct: "https://practice.invalid/vct/x/1" }, signer: host });
    expect((await shownOnPage(predicate, [booking], { nowSec: ISSUED })).reason).toBe("NOT_AN_ATTESTATION_COPY");
  });

  test("the seal opens only under its own disclosure; the page opens with the fragment and not without", async () => {
    const pageCopy = await copyOf(booking, host, null);
    const page = await pageOf(pageCopy, booking);
    expect(page.copy.endsWith("~")).toBe(true);
    expect(parseSdJwt(page.copy)!.disclosures).toEqual([]);
    expect(page.fragment.split("~").filter((d) => d.length > 0).length).toBe(3);
    expect(PAGE_SEAL_HEADER).toEqual({ alg: "dir", enc: "A256GCM" });
    expect(page.artefact.split(".").length).toBe(5);

    const disclosure = (await recordDisclosureOf(viewerCopyOf(page.copy, page.fragment)))!;
    expect(await openArtefact(disclosure, page.artefact)).toEqual(JSON.parse(JSON.stringify(booking)));
    // Another copy's record disclosure opens to the same hash under another salt — and does not open this seal.
    const otherDisclosure = (await recordDisclosureOf(await copyOf(booking, host, holderA)))!;
    expect(await openArtefact(otherDisclosure, page.artefact)).toBeNull();
    const parts = page.artefact.split(".");
    parts[3] = `${parts[3]![0] === "A" ? "B" : "A"}${parts[3]!.slice(1)}`;
    expect(await openArtefact(disclosure, parts.join("."))).toBeNull();
    const otherHeader = `${bytesToBase64Url(enc.encode(JSON.stringify({ alg: "dir", enc: "A128GCM" })))}${page.artefact.slice(page.artefact.indexOf("."))}`;
    expect(await openArtefact(disclosure, otherHeader)).toBeNull();
    expect(await openArtefact(disclosure, "not.a.jwe")).toBeNull();

    const opened = await openPage(page, { nowSec: PRESENTED });
    expect(opened.shown?.artefact).toEqual(JSON.parse(JSON.stringify(booking)));
    const without = await openPage({ ...page, fragment: "" }, { nowSec: PRESENTED });
    expect(without.ok).toBe(true);
    expect(without.shown).toBeNull();
    expect(without.why).toBe(NOT_DISCLOSED);
    const foreign = await openPage({ ...page, fragment: disclosuresOf(await copyOf(booking, host, holderB)).map((d) => `${d}~`).join("") }, { nowSec: PRESENTED });
    expect(foreign.ok).toBe(false);
    expect(foreign.reason).toBe("UNREFERENCED_DISCLOSURE");
    await expect(pageOf(await presentTo(await copyOf(booking, host, holderA), holderA, "https://a.example", "n", PRESENTED), booking)).rejects.toThrow("never from a presentation");
  });

  test("two pages of one record share nothing beyond the class, and their seals differ", async () => {
    const one = await pageOf(await copyOf(booking, host, null), booking);
    const two = await pageOf(await copyOf(booking, host, null), booking);
    const cls = classOf(host.did, PROFILE, ISSUED);
    expect((await sharedValues(one.copy, two.copy)).filter((s) => !cls.has(s.value))).toEqual([]);
    expect(one.artefact).not.toBe(two.artefact);
    expect(one.fragment).not.toBe(two.fragment);
  });
});

describe("the references already salted keep their counts to themselves (§3 G1)", () => {
  test("a predicate's restsOn is padded to a multiple of eight, and its _sd carries no decoys", async () => {
    const [issuer, holder] = await Promise.all([party(), party()]);
    const predicate = { kind: "projects", answer: true, rule: { id: `${issuer.did}/rule/hiring`, version: "1", hash: "a".repeat(64) }, window: { from: "2024-11-01T00:00:00Z", to: "2026-11-01T00:00:00Z" } };
    const lengths: number[] = [];
    for (const n of [0, 3, 8]) {
      const restsOn = Array.from({ length: n }, (_, i) => String.fromCharCode(97 + i).repeat(64));
      const held = await issuePredicateCredential({ issuer, holderPublicKey: holder.publicKey, predicate, restsOn, credentialStatus: null, iatUnix: ISSUED, expUnix: ISSUED + 90 * DAY });
      const v = visibleOf(held);
      lengths.push((v.restsOn as unknown[]).length);
      expect(v._sd).toBeUndefined();
      const seen = await verifySdJwt(held, { resolveKey: resolver, requireKeyBinding: false, nowSec: ISSUED });
      expect(seen.ok).toBe(true);
    }
    expect(lengths).toEqual([8, 8, 16]);
    expect(RESTS_ON_SLOTS).toBe(8);
    expect([restsOnDecoys(0), restsOnDecoys(7), restsOnDecoys(8), restsOnDecoys(9)]).toEqual([8, 1, 8, 7]);
  });
});

describe("the worked example (specs/attestation/examples/receipt-booking-countersigned)", () => {
  interface Presentation {
    readonly audience: string;
    readonly nonce: string;
    readonly iatUnix: number;
    readonly disclosed: readonly string[];
    readonly copyKey: string;
  }
  interface Context {
    readonly issuer: string;
    readonly counterparty: string;
    readonly record: string;
    readonly profile: string;
    readonly grade: number;
    readonly presentations: { readonly a: Presentation; readonly b: Presentation };
    readonly page: { readonly disclosed: readonly string[] };
    readonly checkAt: number;
  }
  const ctx = readJson<Context>(EXAMPLE, "context.json");
  const record = readJson<CountersignBundle>(EXAMPLE, "record.countersign.json");
  const copies = { a: read(EXAMPLE, "copy-a.sd-jwt.txt").trim(), b: read(EXAMPLE, "copy-b.sd-jwt.txt").trim() };
  const presentations = { a: read(EXAMPLE, "presentation-a.sd-jwt.txt").trim(), b: read(EXAMPLE, "presentation-b.sd-jwt.txt").trim() };
  const page = { copy: read(EXAMPLE, "page", "copy.sd-jwt.txt").trim(), fragment: read(EXAMPLE, "page", "fragment.txt").trim(), artefact: read(EXAMPLE, "page", "artefact.jwe.txt").trim() };

  test("the record of truth is the old form — a countersign bundle — and it still verifies as it did", async () => {
    const r = await verifyCountersignBundle(record);
    expect(r.ok).toBe(true);
    expect(r.twoSignatureProof).toBe(true);
    expect(r.requesterDid).toBe(ctx.issuer);
    expect(r.acceptances.map((a) => a.countersignerDid)).toEqual([ctx.counterparty]);
    expect(await recordHashOf(record)).toBe(ctx.record);
    expect(record.subject.payloadType).toBe("application/vnd.oreoasis.work-record+json");
  });

  test("each copy is the issuer's own word: its key, the class, the record behind a disclosure, eight digests, the counterparty nowhere", async () => {
    for (const [name, copy] of [["a", copies.a], ["b", copies.b], ["page", viewerCopyOf(page.copy, page.fragment)]] as const) {
      const held = await verifySdJwt(copy, { resolveKey: resolver, requireKeyBinding: false, nowSec: ctx.checkAt });
      expect(held.ok).toBe(true);
      expect(held.vct).toBe(ATTESTATION_VCT);
      expect(held.issuer).toBe(ctx.issuer);
      const v = visibleOf(copy);
      expect(v.attestation).toEqual({ kind: "receipt", outcome: "accepted", profile: ctx.profile, grade: ctx.grade, practice: true });
      expect((v.iat as number) % DAY).toBe(0);
      expect(v.exp).toBe((v.iat as number) + COPY_LIFETIME_DAYS * DAY);
      expect((v._sd as string[]).length).toBe(COPY_SD_SLOTS);
      expect(v.credentialStatus).toBeUndefined();
      if (name === "page") expect(v.cnf).toBeUndefined();
      else expect(held.holder).toBe(ctx.presentations[name].copyKey);
      expect(new Set(await disclosedNames(copy))).toEqual(new Set(ctx.page.disclosed));
      expect(viewOfCopy(held.claims!).record).toBe(ctx.record);
      expect(copy).not.toContain(ctx.counterparty);
      expect(JSON.stringify(await Promise.all(disclosuresOf(copy).map(decodeDisclosure)))).not.toContain(ctx.counterparty);
    }
  });

  test("the two presentations share no common string beyond the issuer's key and the profile name, read with the class; the checker accepts both and refuses each at the other's door", async () => {
    const iat = visibleOf(copies.a).iat as number;
    const cls = classOf(ctx.issuer, ctx.profile, iat, ctx.grade);
    const shared = await sharedValues(presentations.a, presentations.b);
    expect(shared.filter((s) => !cls.has(s.value))).toEqual([]);
    expect(shared.map((s) => s.value)).toEqual(expect.arrayContaining([ctx.issuer, ctx.profile]));
    expect(await linkabilityBetween(presentations.a, presentations.b)).toEqual([]);
    for (const k of ["a", "b"] as const) {
      const p = ctx.presentations[k];
      const r = await verifySdJwt(presentations[k], { resolveKey: resolver, requireKeyBinding: true, audience: p.audience, nonce: p.nonce, nowSec: p.iatUnix + 60 });
      expect(r.ok).toBe(true);
      expect(r.disclosed).toEqual([]);
      expect(r.holder).toBe(p.copyKey);
    }
    const crossed = await verifySdJwt(presentations.a, { resolveKey: resolver, requireKeyBinding: true, audience: ctx.presentations.b.audience, nonce: ctx.presentations.a.nonce, nowSec: ctx.presentations.a.iatUnix + 60 });
    expect(crossed.reason).toBe("AUDIENCE_MISMATCH");
  });

  test("the projection is projectVc of what verifier A saw, and never names the counterparty", async () => {
    const p = ctx.presentations.a;
    const r = await verifySdJwt(presentations.a, { resolveKey: resolver, requireKeyBinding: true, audience: p.audience, nonce: p.nonce, nowSec: p.iatUnix + 60 });
    const projection = readJson<Record<string, unknown>>(EXAMPLE, "projection.vc.json");
    expect(projection).toEqual(JSON.parse(JSON.stringify(projectVc(viewOfCopy(r.claims!)))));
    expect(JSON.stringify(projection)).not.toContain(ctx.counterparty);
    expect(projection.relatedResource).toBeUndefined();
  });

  test("the page: the stored copy carries no key and no disclosure; it opens with the fragment and shows nothing without it; the seal is the record", async () => {
    expect(parseSdJwt(page.copy)!.disclosures).toEqual([]);
    expect(visibleOf(page.copy).cnf).toBeUndefined();
    const opened = await openPage(page, { nowSec: ctx.checkAt });
    expect(opened.ok).toBe(true);
    expect(opened.shown?.artefact).toEqual(record);
    const closed = await openPage({ ...page, fragment: "" }, { nowSec: ctx.checkAt });
    expect(closed.ok).toBe(true);
    expect(closed.shown).toBeNull();
    expect(closed.why).toBe(NOT_DISCLOSED);
    const disclosure = (await recordDisclosureOf(viewerCopyOf(page.copy, page.fragment)))!;
    expect(await openArtefact(disclosure, page.artefact)).toEqual(record);
    expect(await openArtefact((await recordDisclosureOf(copies.a))!, page.artefact)).toBeNull();
    const holder = await party();
    const tried = await presentSdJwt(viewerCopyOf(page.copy, page.fragment), () => false, holder, { aud: "https://a.example", nonce: "n", iatUnix: ctx.checkAt });
    expect((await verifySdJwt(tried, { resolveKey: resolver, requireKeyBinding: true, audience: "https://a.example", nonce: "n", nowSec: ctx.checkAt })).reason).toBe("HOLDER_KEY_MISSING");
  });

  test("no example file carries key material", () => {
    for (const f of filesUnder(EXAMPLE)) expect(readFileSync(f, "utf8")).not.toMatch(/privateKey|secretKey|"seed"|"d":|BEGIN [A-Z ]*PRIVATE KEY/);
  });
});

describe("the conformance cases (specs/attestation/tck/attestation-copy@1)", () => {
  interface Copy {
    readonly record: string | null;
    readonly sd: readonly string[];
    readonly preimages: { readonly record: string; readonly statement?: string; readonly claimedAt?: string; readonly decoys: readonly string[] };
  }
  interface Case {
    readonly name: string;
    readonly copy: string;
    readonly disclosures: readonly string[];
    readonly artefactSha256?: string;
    readonly expect: { readonly committed: readonly string[]; readonly uncommitted: readonly string[]; readonly record: string | null; readonly opens: boolean | null };
  }
  interface File {
    readonly type: string;
    readonly copies: Readonly<Record<string, Copy>>;
    readonly cases: readonly Case[];
    readonly pairs: readonly { readonly name: string; readonly a: string; readonly b: string }[];
  }
  const file = readJson<File>(SPECS, "tck", "attestation-copy@1", "cases.json");

  test("the file names the copy's type, and every digest is recomputable from the preimage written beside it", async () => {
    expect(file.type).toBe(ATTESTATION_VCT);
    for (const copy of Object.values(file.copies)) {
      for (const d of [copy.preimages.record, copy.preimages.statement, copy.preimages.claimedAt].filter((x): x is string => typeof x === "string")) {
        expect(copy.sd).toContain((await decodeDisclosure(d))!.digest);
      }
      for (const decoy of copy.preimages.decoys) expect(copy.sd).toContain(await digestOfString(decoy));
      expect([...copy.sd].sort()).toEqual([...copy.sd]);
    }
  });
  for (const c of file.cases) {
    test(c.name, async () => {
      const copy = file.copies[c.copy]!;
      const r = await openRecordCommitment({ sd: copy.sd, disclosures: c.disclosures, ...(c.artefactSha256 !== undefined ? { artefactSha256: c.artefactSha256 } : {}) });
      expect(r).toEqual(c.expect);
    });
  }
  for (const p of file.pairs) {
    test(p.name, async () => {
      const a = file.copies[p.a]!;
      const b = file.copies[p.b]!;
      expect(a.sd.filter((d) => b.sd.includes(d))).toEqual([]);
      for (const copy of [a, b]) {
        const r = await openRecordCommitment({ sd: copy.sd, disclosures: [copy.preimages.record], artefactSha256: copy.record! });
        expect(r.opens).toBe(true);
      }
    });
  }
});
