/**
 * KS-Q4 — the checker reads d91's three assertions on a trust list: identity
 * (class, grade), standing (listed · suspended · removed) and scope (the exact
 * tag, and the references it may attest against), each entry citing its floor.
 * A suspension or removal in a pinned list stands, and the report says so —
 * never a silent "unlisted".
 */

import { describe, expect, it } from "bun:test";
import { deriveDid, generateKeyPair, type KashKeyPair } from "@kashscript/identity-core";
import { signEnvelope, type DsseEnvelope } from "../src/dsse";
import {
  ISSUER_CLASSES,
  STANDINGS,
  TRUST_LIST_FORMAT,
  findListing,
  lookupListing,
  makeKeyResolver,
  signTrustList,
  verifyHeldRecord,
  verifyTrustList,
  type HoldingManifest,
  type TrustListIssuer,
  type TrustListPayload,
} from "../src/holder";

const T = 1_800_000_000;
const DAY = 86_400;
const TAG = "application/vnd.oreoasis.work-record+json";
const RULE = { id: "rule:internship-hours", hash: "a".repeat(64) };
const kjs = (k: KashKeyPair) => ({ privateKey: k.privateKey, publicKey: k.publicKey });

async function party() {
  const k = await generateKeyPair();
  return { ...k, did: deriveDid(k.publicKey) };
}

function entry(issuerId: string, over: Partial<TrustListIssuer> = {}): TrustListIssuer {
  return { issuerId, label: "An issuer (sample)", keys: [], dsts: [TAG], validFromUnix: T - DAY, validUntilUnix: T + DAY, ...over };
}

async function listOf(publisher: Awaited<ReturnType<typeof party>>, issuers: TrustListIssuer[], over: Partial<TrustListPayload> = {}, listId = "sample-list") {
  const payload: TrustListPayload = {
    format: TRUST_LIST_FORMAT,
    listId,
    version: 1,
    publisher: publisher.did,
    issuedAtUnix: T - 10,
    validFromUnix: T - DAY,
    validUntilUnix: T + DAY,
    floor: { version: "VISION §4 draft, 2026-10-18" },
    issuers,
    ...over,
  };
  return signTrustList(payload, { keyid: publisher.did, ...kjs(publisher) });
}

describe("identity — class and grade, read and reported", () => {
  it("a listed entry's class, grade and floor ride on the match; an entry written before d91 reads as listed, with none", async () => {
    const [pub, a, b] = [await party(), await party(), await party()];
    const env = await listOf(pub, [entry(a.did, { class: "counterparty", standing: "listed", grade: 1, floor: { version: "floor v0.1", hash: "b".repeat(64) } }), entry(b.did)]);
    const report = await verifyTrustList(env, { pinnedPublishers: [pub.did], nowSec: T });
    expect(report.ok).toBe(true);
    expect(report.floor).toEqual({ version: "VISION §4 draft, 2026-10-18" });
    const ma = findListing(a.did, TAG, [report], T)!;
    expect([ma.class, ma.grade, ma.standing, ma.scope, ma.pinned]).toEqual(["counterparty", 1, "listed", "unscoped", true]);
    expect(ma.floor).toEqual({ version: "floor v0.1", hash: "b".repeat(64) });
    const mb = findListing(b.did, TAG, [report], T)!;
    expect([mb.class, mb.grade, mb.standing, mb.scope]).toEqual([null, null, "listed", "unscoped"]);
    expect(mb.floor).toEqual({ version: "VISION §4 draft, 2026-10-18" }); // the list's floor, when the entry names none
  });

  it("the classes and standings are d91's, and nothing else verifies", async () => {
    expect(ISSUER_CLASSES).toEqual(["self-issuer", "counterparty", "assessor", "accredited-body", "insurer"]);
    expect(STANDINGS).toEqual(["listed", "suspended", "removed"]);
    const [pub, a] = [await party(), await party()];
    for (const bad of [{ class: "friend" }, { standing: "paused" }, { grade: 4 }, { grade: 1.5 }, { references: [{}] }, { references: [{ id: "r", hash: "nothex" }] }, { floor: { version: "" } }, { floor: { version: "v", extra: 1 } }]) {
      const payload = { format: TRUST_LIST_FORMAT, listId: "l", version: 1, publisher: pub.did, issuedAtUnix: T, validFromUnix: T - DAY, validUntilUnix: T + DAY, issuers: [{ ...entry(a.did), ...bad }] };
      const env = await signEnvelope(payload, "application/vnd.kash.trust-list+json", { keyid: pub.did, ...kjs(pub) }, { canonical: true });
      expect({ bad, reason: (await verifyTrustList(env, { pinnedPublishers: [pub.did], nowSec: T })).reason }).toEqual({ bad, reason: "TRUST_LIST_BAD_ASSERTION" });
    }
    // The signer refuses the same values before anything is made.
    await expect(listOf(pub, [entry(a.did, { class: "friend" as never })])).rejects.toThrow("TRUST_LIST_BAD_ASSERTION");
    const badFloor = { format: TRUST_LIST_FORMAT, listId: "l", version: 1, publisher: pub.did, issuedAtUnix: T, validFromUnix: T - DAY, validUntilUnix: T + DAY, issuers: [], floor: { version: 7 } };
    const env = await signEnvelope(badFloor, "application/vnd.kash.trust-list+json", { keyid: pub.did, ...kjs(pub) }, { canonical: true });
    expect((await verifyTrustList(env, { pinnedPublishers: [pub.did], nowSec: T })).reason).toBe("TRUST_LIST_BAD_ASSERTION");
  });
});

describe("standing — only listed lists; a sanction in a pinned list stands", () => {
  it("a suspended or removed entry lists nothing, whatever its window says, and the lookup says why", async () => {
    const [pub, a, b] = [await party(), await party(), await party()];
    // Written without lexicons' guard: a suspended entry whose window is still open. attest reads the standing anyway.
    const env = await listOf(pub, [entry(a.did, { standing: "suspended" }), entry(b.did, { standing: "removed", validUntilUnix: T - 20 })]);
    const report = await verifyTrustList(env, { pinnedPublishers: [pub.did], nowSec: T });
    expect(report.notes.join(" ")).toContain("2 entries are suspended or removed");
    for (const [did, why] of [[a.did, "suspended"], [b.did, "removed"]] as const) {
      const l = lookupListing(did, TAG, [report], T);
      expect(l.listing).toBeNull();
      expect(l.refused?.why).toBe(why);
      expect(findListing(did, TAG, [report], T)).toBeNull();
    }
  });

  it("a suspension in any pinned list stands over a listing in another; an unpinned list's suspension is only its word", async () => {
    const [pubA, pubB, stranger, issuer] = [await party(), await party(), await party(), await party()];
    const lists = await Promise.all([
      verifyTrustList(await listOf(pubA, [entry(issuer.did, { class: "counterparty" })], {}, "a"), { pinnedPublishers: [pubA.did, pubB.did], nowSec: T }),
      verifyTrustList(await listOf(pubB, [entry(issuer.did, { standing: "suspended", validUntilUnix: T - 10 })], {}, "b"), { pinnedPublishers: [pubA.did, pubB.did], nowSec: T }),
    ]);
    const l = lookupListing(issuer.did, TAG, lists, T);
    expect(l.listing).toBeNull();
    expect(l.refused?.why).toBe("suspended");
    expect(l.refused?.listId).toBe("b");
    const strangers = await verifyTrustList(await listOf(stranger, [entry(issuer.did, { standing: "removed", validUntilUnix: T - 10 })], {}, "c"), { pinnedPublishers: [pubA.did], nowSec: T });
    const withStranger = lookupListing(issuer.did, TAG, [lists[0]!, strangers], T);
    expect(withStranger.listing?.listId).toBe("a");
    expect(withStranger.refused).toBeNull();
  });
});

describe("scope — the exact tag, and the references it may attest against", () => {
  it("in scope, out of scope, not checked, unscoped", async () => {
    const [pub, scoped, open] = [await party(), await party(), await party()];
    const report = await verifyTrustList(await listOf(pub, [entry(scoped.did, { references: [RULE] }), entry(open.did)]), { pinnedPublishers: [pub.did], nowSec: T });
    expect(findListing(scoped.did, TAG, [report], T, { reference: RULE })?.scope).toBe("in-scope");
    expect(findListing(scoped.did, TAG, [report], T, { reference: { id: RULE.id } })?.scope).toBe("in-scope"); // the id alone matches
    const other = lookupListing(scoped.did, TAG, [report], T, { reference: { id: "rule:something-else" } });
    expect(other.listing).toBeNull();
    expect(other.refused?.why).toBe("out-of-scope");
    const otherVersion = lookupListing(scoped.did, TAG, [report], T, { reference: { id: RULE.id, hash: "c".repeat(64) } });
    expect(otherVersion.refused?.why).toBe("out-of-scope"); // the same rule, another version
    expect(findListing(scoped.did, TAG, [report], T)?.scope).toBe("not-checked");
    expect(findListing(open.did, TAG, [report], T, { reference: RULE })?.scope).toBe("unscoped");
    // Scope part one is unchanged: another tag lists nobody.
    expect(findListing(open.did, "application/vnd.oreoasis.predicate+json", [report], T)).toBeNull();
  });
});

describe("the held record's report carries the listing's assertions, and says why a pinned list does not list", () => {
  async function recordBy(issuer: Awaited<ReturnType<typeof party>>): Promise<{ kind: "dsse"; value: DsseEnvelope }> {
    return { kind: "dsse", value: await signEnvelope({ v: 1, job: "SAMPLE", expiresAtUnix: T + 30 * DAY }, TAG, { keyid: issuer.did, ...kjs(issuer) }, { canonical: true }) };
  }
  const probe = (issuer: string): HoldingManifest => ({
    recordId: "",
    issuer,
    relationship: null,
    type: { tag: TAG, family: "dsse-type", attestation: "issuer-signed" },
    receivedAtUnix: T,
    expiresAtUnix: null,
    retentionSource: "none-declared",
    status: null,
    listing: "unlisted",
    keptUnlistedAtUnix: T,
  });

  it("listed: class, grade, scope and floor; suspended: refused, with a note", async () => {
    const [pub, listed, held] = [await party(), await party(), await party()];
    const lists = [
      await verifyTrustList(await listOf(pub, [entry(listed.did, { class: "assessor", grade: 3 }), entry(held.did, { standing: "suspended", validUntilUnix: T - 10 })]), { pinnedPublishers: [pub.did], nowSec: T }),
    ];
    const ctx = { resolveKey: makeKeyResolver(new Map(), new Map()), trustLists: lists, statusLists: [], revocations: [], nowSec: T, exportedAtUnix: null };
    const a = await verifyHeldRecord({ manifest: probe(listed.did), artifact: await recordBy(listed) }, ctx);
    expect(a.trusted).toBe(true);
    expect(a.listing).toMatchObject({ evidence: "pinned-list", class: "assessor", grade: 3, scope: "unscoped", refused: null });
    expect(a.listing.floor).toEqual({ version: "VISION §4 draft, 2026-10-18" });
    const b = await verifyHeldRecord({ manifest: probe(held.did), artifact: await recordBy(held) }, ctx);
    expect(b.trusted).toBe(false);
    expect(b.listing).toMatchObject({ evidence: "none", refused: "suspended" });
    expect(b.notes.join(" ")).toContain("marks this issuer suspended");
  });
});
