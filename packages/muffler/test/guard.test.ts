// KS-N1 — the guard ECOSYSTEM d59 asks for: muffler publishes public, organisation-authored records, never a
// person's. Every planted violation here is refused with a report, and every public record kind refines.
// The attest round trip shows the trust list this shape describes is the one attest signs and the wallet
// verifies today, unchanged — and that the record's CID names the signed bytes.

import { describe, expect, it } from "bun:test";
import { canonicalizeBytes, deriveDid, generateKeyPair } from "@kashscript/identity-core";
import { base64ToBytes } from "@kashscript/attest/ed25519";
import {
  DST_TRUST_LIST,
  ISSUER_CLASSES as ATTEST_ISSUER_CLASSES,
  STANDINGS as ATTEST_STANDINGS,
  STATUS_LIST_FORMAT,
  STATUS_PURPOSES as ATTEST_STATUS_PURPOSES,
  TRUST_LIST_FORMAT,
  createStatusBitstring,
  encodeStatusList,
  findListing,
  lookupListing,
  makeKeyResolver,
  signStatusList,
  signTrustList,
  verifyStatusList,
  verifyTrustList,
  type StatusListPayload,
  type TrustListPayload,
} from "@kashscript/attest/holder";
import { ISSUER_CLASSES, STANDINGS, STATUS_PURPOSES } from "@kashscript/lexicons/extensions/lists";
import { cidForBytes } from "../src/cid";
import { composeRefiners, createPublicRecordGuard } from "../src/guard";
import { RefineError } from "../src/refine";
import { EXAMPLE, exampleRefiner } from "./example-lexicons";
import { DAY, NOW, OTHER, PUB, guide, hunza, listing, pointer, rule, skardu, statusList, trustList } from "./public-records";

const guard = createPublicRecordGuard();

async function refused(collection: string, record: unknown): Promise<RefineError> {
  try {
    await guard.refine(collection, record);
  } catch (err) {
    if (err instanceof RefineError) return err;
    throw err;
  }
  throw new Error(`${collection} was not refused`);
}

describe("the guard — by kind", () => {
  it("handles every collection under the protocol's namespace, and the admitted kinds", () => {
    for (const c of ["kash.place", "kash.place.pointer", "kash.listing", "kash.guide", "kash.trust-list", "kash.status-list", "kash.rule", "kash.adoption"]) {
      expect(guard.handles(c)).toBe(true);
    }
    expect(guard.handles("kash.id.profile")).toBe(true); // handled, so it is refused with a report — never skipped in silence
    expect(guard.handles("app.indusland.provider.profile")).toBe(false); // a venture's own collection is its own refiner's
  });

  it("refuses a person's own records — the profile, a post, a decision receipt — as PERSON_RECORD", async () => {
    expect((await refused("kash.id.profile", { displayName: "Amina" })).code).toBe("PERSON_RECORD");
    expect((await refused("kash.social.post", { text: "hello" })).code).toBe("PERSON_RECORD");
    expect((await refused("kash.decision", { outcome: "yes" })).code).toBe("PERSON_RECORD");
    expect((await refused("kash.anything.else", {})).code).toBe("PERSON_RECORD");
  });

  it("refines every public record kind, and the rule's older body as the newest version", async () => {
    for (const [c, r] of [
      ["kash.place", skardu],
      ["kash.place", hunza],
      ["kash.place.pointer", pointer],
      ["kash.listing", listing],
      ["kash.guide", guide],
      ["kash.rule", rule],
      ["kash.trust-list", trustList(PUB, OTHER)],
    ] as const) {
      const refined = await guard.refine(c, r);
      expect(refined.collection).toBe(c);
      expect(refined.cid).toBe(await cidForBytes(canonicalizeBytes(r)));
    }
  });
});

describe("the guard — by content", () => {
  it("a listing with a contact field is refused by the closed shape", async () => {
    expect((await refused("kash.listing", { ...listing, contact: "amina@karavan.example" })).code).toBe("INVALID_RECORD");
    expect((await refused("kash.listing", { ...listing, phone: "+92 300 1234567" })).code).toBe("INVALID_RECORD");
    expect((await refused("kash.listing", { ...listing, rating: 4.8 })).code).toBe("INVALID_RECORD");
  });
  it("a place with a coordinate is refused by the closed shape (d60, d69(c))", async () => {
    expect((await refused("kash.place", { ...skardu, lat: 35.3, lon: 75.63 })).code).toBe("INVALID_RECORD");
  });
  it("a person's identity in words is refused as PERSON_IDENTITY — a phone number in a summary, a DID in a guide's text", async () => {
    const phone = await refused("kash.listing", { ...listing, summary: "Three hours through the walled city. Call +92 300 1234567 to book." });
    expect(phone.code).toBe("PERSON_IDENTITY");
    expect(phone.detail).toMatchObject({ path: ["summary"], what: "a phone number" });
    const did = await refused("kash.guide", { ...guide, sections: [{ heading: "Skardu", text: `Written with ${OTHER}, who walked it.` }] });
    expect(did.code).toBe("PERSON_IDENTITY");
    expect(did.detail).toMatchObject({ what: "a DID" });
    const email = await refused("kash.place", { ...skardu, source: "Told to us by amina.k@tours.example" });
    expect(email.code).toBe("PERSON_IDENTITY");
  });
  it("a cross-field rule is refused as INVALID_ATTRIBUTES, with the faults", async () => {
    const other = await refused("kash.place", { ...skardu, publisher: OTHER });
    expect(other.code).toBe("INVALID_ATTRIBUTES");
    expect(other.detail).toMatchObject([{ code: "ID_PUBLISHER" }]);
    const list = trustList(PUB, OTHER);
    const stillOpen = { ...list, issuers: [list.issuers[0], { ...list.issuers[1], validUntilUnix: NOW + DAY }] };
    expect((await refused("kash.trust-list", stillOpen)).detail).toMatchObject([{ code: "STANDING_WINDOW" }]);
  });
});

describe("the record and the checker name the same values (KS-Q4)", () => {
  it("issuer classes, standings and status purposes are one list in lexicons and attest", () => {
    expect([...ISSUER_CLASSES]).toEqual([...ATTEST_ISSUER_CLASSES]);
    expect([...STANDINGS]).toEqual([...ATTEST_STANDINGS]);
    expect([...STATUS_PURPOSES]).toEqual([...ATTEST_STATUS_PURPOSES]);
  });
});

describe("the guard — with attest: the list this shape describes is the one attest signs and the wallet verifies", () => {
  it("a d91-shaped trust list signs, verifies and lists under attest unchanged; the record's CID names the signed bytes", async () => {
    const pub = await generateKeyPair();
    const pubDid = deriveDid(pub.publicKey);
    const issuer = await generateKeyPair();
    const issuerDid = deriveDid(issuer.publicKey);
    const payload = trustList(pubDid, issuerDid);
    expect(payload.format).toBe(TRUST_LIST_FORMAT);

    // The record refines: shape, cross-field rules, no person.
    const refined = await guard.refine("kash.trust-list", payload);

    // attest signs the same clear document, canonical — and verifies it, class, standing, grade and floor included.
    const envelope = await signTrustList(payload as unknown as TrustListPayload, { keyid: pubDid, privateKey: pub.privateKey, publicKey: pub.publicKey });
    expect(envelope.payloadType).toBe(DST_TRUST_LIST);
    const report = await verifyTrustList(envelope, { pinnedPublishers: [pubDid], nowSec: NOW });
    expect(report.ok).toBe(true);
    expect(report.pinned).toBe(true);
    expect(report.current).toBe(true);
    expect(report.issuers).toHaveLength(2);

    // The listed issuer is listed; the removed assessor, whose window ended, lists nobody — a checker that reads windows only agrees with the standing.
    expect(findListing(issuerDid, "application/vnd.oreoasis.work-record+json", [report], NOW)?.issuerId).toBe(issuerDid);
    expect(findListing("assessor-7#k1", "application/vnd.oreoasis.predicate+json", [report], NOW)).toBeNull();
    // KS-Q4: attest now reads the standing itself, and says why — removed, never a silent "unlisted".
    expect(lookupListing("assessor-7#k1", "application/vnd.oreoasis.predicate+json", [report], NOW).refused?.why).toBe("removed");
    expect(findListing(issuerDid, "application/vnd.oreoasis.work-record+json", [report], NOW)?.standing).toBe("listed");

    // One document, two forms: the signed bytes are the record's canonical bytes, so its CID names them.
    const signedBytes = base64ToBytes(envelope.payload);
    expect(new TextDecoder().decode(signedBytes)).toBe(refined.canonical);
    expect(await cidForBytes(signedBytes)).toBe(refined.cid);
  });

  it("a status list signs, verifies and refines the same way", async () => {
    const issuer = await generateKeyPair();
    const issuerDid = deriveDid(issuer.publicKey);
    const payload = statusList(issuerDid, await encodeStatusList(createStatusBitstring()));
    expect(payload.format).toBe(STATUS_LIST_FORMAT);
    const refined = await guard.refine("kash.status-list", payload);
    const envelope = await signStatusList(payload as unknown as StatusListPayload, { keyid: issuerDid, privateKey: issuer.privateKey, publicKey: issuer.publicKey });
    const report = await verifyStatusList(envelope, { resolveKey: makeKeyResolver(new Map(), new Map()), nowSec: NOW });
    expect(report.ok).toBe(true);
    expect(report.entries).toBe(131_072);
    expect(await cidForBytes(base64ToBytes(envelope.payload))).toBe(refined.cid);
  });

  it("KS-Q4: a withdrawal list (kash.status-list@1.1.0) refines, signs and verifies; a purpose d91 does not name is refused", async () => {
    const issuer = await generateKeyPair();
    const issuerDid = deriveDid(issuer.publicKey);
    const payload = { ...statusList(issuerDid, await encodeStatusList(createStatusBitstring())), statusPurpose: "withdrawal" };
    await guard.refine("kash.status-list", payload);
    const envelope = await signStatusList(payload as unknown as StatusListPayload, { keyid: issuerDid, privateKey: issuer.privateKey, publicKey: issuer.publicKey });
    expect((await verifyStatusList(envelope, { resolveKey: makeKeyResolver(new Map(), new Map()), nowSec: NOW })).statusPurpose).toBe("withdrawal");
    await expect(guard.refine("kash.status-list", { ...payload, statusPurpose: "expired" })).rejects.toBeInstanceOf(RefineError);
  });
});

describe("composeRefiners — the public records beside a venture's own", () => {
  it("routes each collection to the first refiner that handles it", async () => {
    const both = composeRefiners(guard, exampleRefiner());
    expect(both.handles("kash.place")).toBe(true);
    expect(both.handles(EXAMPLE.profile)).toBe(true);
    expect(both.handles("com.other.thing")).toBe(false);
    expect((await both.refine("kash.place", skardu)).collection).toBe("kash.place");
    expect((await both.refine(EXAMPLE.profile, { displayName: "Karavan Tours" })).collection).toBe(EXAMPLE.profile);
    await expect(both.refine("com.other.thing", {})).rejects.toMatchObject({ code: "UNKNOWN_COLLECTION" });
    // The guard still answers for the protocol's namespace, whatever else is composed beside it.
    await expect(both.refine("kash.id.profile", { displayName: "Amina" })).rejects.toMatchObject({ code: "PERSON_RECORD" });
  });
});
