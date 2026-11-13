import { describe, expect, test } from "bun:test";
import { issueSdJwt, jwkOf } from "@kashscript/attest/sd-jwt";
import { verifyTrustList } from "@kashscript/attest/holder";
import { DECISION_VCT } from "@kashscript/predicate";
import { cpdRule, PRACTICE_VCT, registerPracticeTypes } from "@kashscript/predicate/fixtures";
import { createHeadlessWallet, PracticeDesk, PracticeIssuer, PracticeNetwork, PracticePublisher, PRACTICE_T0 } from "../src/headless";
import { isWalletError } from "../src/errors";
import { sha256Hex } from "@kashscript/attest/chain";
import { COUNTERSIGN_BUNDLE_FORMAT, countersignRequestDigest, DST_COUNTERSIGN_ACCEPTANCE, DST_COUNTERSIGN_REQUEST, type CountersignBundle } from "@kashscript/attest/countersign";
import { pae, signEnvelope } from "@kashscript/attest/dsse";
import { base64ToBytes, bytesToBase64 } from "@kashscript/attest/ed25519";
import type { HeldArtifact, HeldRecord } from "@kashscript/attest/holder";
import { signBytes } from "@kashscript/attest/signing";
import { deriveDid, generateKeyPair, signEvent, signEventWith } from "@kashscript/identity-core";
import { bookingReviewRule, WORK_RECORD_TYPE } from "@kashscript/predicate/fixtures";

const DAY = 86_400;
const iso = (t: number): string => new Date(t * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");
const dateOf = (t: number): string => iso(t).slice(0, 10);

interface Activity {
  readonly recordId: string;
  readonly hours: number;
  readonly structured: boolean;
  readonly completedOn: string;
}

/** A practice world: a CPD provider and two professional bodies' doors, all listed by one pinned publisher, and a person's wallet. */
async function doorWorld() {
  registerPracticeTypes();
  const clock = { t: PRACTICE_T0 };
  const now = () => clock.t;
  const net = new PracticeNetwork();
  const publisher = await PracticePublisher.create(now);
  const provider = await PracticeIssuer.create({
    origin: "https://cpd.practice.invalid",
    name: "A practice CPD provider",
    now,
    extra: {
      "cpd-record": {
        vct: PRACTICE_VCT.cpdRecord,
        // The same record in every copy; a fresh holder key in each.
        issue: async ({ holder, now: t, context, signer }) =>
          issueSdJwt({
            header: { kid: signer.did },
            claims: { iss: signer.did, iat: t - (t % DAY), exp: t + 365 * DAY, vct: PRACTICE_VCT.cpdRecord, cnf: { jwk: jwkOf(holder) }, practice: true },
            sdProperties: { ...(context as Activity) },
            decoys: 2,
            signer,
          }),
      },
    },
  });
  const deskA = await PracticeDesk.create({ origin: "https://body.practice.invalid", name: "A practice professional body", now });
  const deskB = await PracticeDesk.create({ origin: "https://other-body.practice.invalid", name: "Another practice body", now });
  for (const h of [provider, deskA, deskB]) net.mount(h.origin, h.handler);
  const list = await publisher.list([
    { did: provider.did, label: provider.name, dsts: [PRACTICE_VCT.cpdRecord] },
    { did: deskA.did, label: deskA.name, dsts: [DECISION_VCT] },
    { did: deskB.did, label: deskB.name, dsts: [DECISION_VCT] },
  ]);
  const report = await verifyTrustList(list, { pinnedPublishers: [publisher.did], nowSec: now() });
  const dates = { published: iso(PRACTICE_T0 - 10 * DAY), renewBy: iso(PRACTICE_T0 + 300 * DAY), endsAt: iso(PRACTICE_T0 + 700 * DAY) };
  for (const desk of [deskA, deskB]) {
    desk.trustLists = [report];
    await desk.publish(cpdRule({ body: desk.did, providerList: `${publisher.did}#${report.listId}` }, { dates }));
  }
  const person = await createHeadlessWallet({ practice: true, seed: "doors", now, transport: net.transport, pinnedPublishers: [publisher.did] });
  await person.wallet.trust.add(list);
  await person.wallet.proof.set(provider.origin, "on", provider.name);
  let n = 0;
  const receive = async (hours: number, structured: boolean, daysAgo: number) => {
    const r = await person.wallet.receive.accept(await person.wallet.receive.open(provider.offer(["cpd-record"], { recordId: `cpd-${++n}`, hours, structured, completedOn: dateOf(PRACTICE_T0 - daysAgo * DAY) })));
    if (r.status !== "stored") throw new Error(`receive: ${r.status}`);
  };
  return { clock, net, publisher, provider, deskA, deskB, person, wallet: person.wallet, receive };
}

describe("the wallet's door — a rule checked on the person's side first", () => {
  test("the CPD door end to end: checklist, packet on yes, an automatic yes, the decision held as a receipt", async () => {
    const w = await doorWorld();
    await w.receive(50, true, 100);
    await w.receive(40, true, 300);
    await w.receive(45, false, 500);

    const view = await w.wallet.doors.open(w.deskA.request());
    const state = Object.fromEntries(view.checklist.rows.map((r) => [r.criterion, r.state]));
    expect(state).toEqual({ "cycle-hours": "answered", "structured-hours": "answered", declaration: "own-word" });
    expect(view.decider).toBe("CPD officer");
    expect(view.declineCosts).toContain("Saying no costs only this");

    const sent = await w.wallet.doors.send(view, { ownWord: { declaration: { declared: true } } });
    const answer = sent.answer as { route: string; decision_offer?: string };
    expect(answer.route).toBe("automatic-yes");
    expect(w.deskA.received[0]!.check.problems).toEqual([]);

    // The decision comes back as a receipt the person keeps — in copies, for the next door.
    await w.wallet.proof.set(w.deskA.origin, "on", w.deskA.name);
    const got = await w.wallet.receive.accept(await w.wallet.receive.open(answer.decision_offer!));
    expect(got.status).toBe("stored");
    const decisions = (await w.wallet.records.list()).filter((e) => e.manifest.type.tag === DECISION_VCT);
    expect(decisions.length).toBeGreaterThan(1);
    expect(decisions.every((d) => d.manifest.issuer === w.deskA.did)).toBe(true);
  });

  test("an anchor's door: another body adopts the rule at 150 hours — the checklist reads its value, and the decision is the anchor's (d85(b) rule 8, (d))", async () => {
    const w = await doorWorld();
    await w.receive(50, true, 100);
    await w.receive(40, true, 300);
    await w.receive(45, false, 500);
    const rule = (await w.wallet.doors.open(w.deskA.request())).rule;
    const adoption = await w.deskB.adopt(rule, "cpd-cycle", { minHours: 150 });

    // 135 hours: enough under the rule's own 120, not under the anchor's 150.
    const short = await w.wallet.doors.open(w.deskB.request());
    expect(short.door).toBe(w.deskB.did);
    expect(short.adoption?.hash).toBe(adoption.hash);
    expect(short.adoption?.body.parameters).toEqual({ minHours: 150 });
    expect(short.checklist.rows.find((r) => r.criterion === "cycle-hours")!.state).toBe("missing");

    await w.receive(20, true, 50);
    const view = await w.wallet.doors.open(w.deskB.request());
    expect(view.checklist.rows.find((r) => r.criterion === "cycle-hours")!.state).toBe("answered");
    const sent = await w.wallet.doors.send(view, { ownWord: { declaration: { declared: true } } });
    const answer = sent.answer as { route: string; decision_offer?: string };
    expect(answer.route).toBe("automatic-yes");
    expect(w.deskB.received[0]!.route.adoption).toEqual({ id: adoption.body.id, anchor: w.deskB.did, hash: adoption.hash });
    expect(w.deskB.received[0]!.holderKeys.length).toBeGreaterThan(0);

    await w.wallet.proof.set(w.deskB.origin, "on", w.deskB.name);
    const got = await w.wallet.receive.accept(await w.wallet.receive.open(answer.decision_offer!));
    expect(got.status).toBe("stored");
    const decisions = (await w.wallet.records.list()).filter((e) => e.manifest.type.tag === DECISION_VCT);
    expect(decisions.length).toBeGreaterThan(0);
    expect(decisions.every((d) => d.manifest.issuer === w.deskB.did)).toBe(true);
  });

  test("an adoption carried by anyone but its anchor is refused unopened", async () => {
    const w = await doorWorld();
    const rule = (await w.wallet.doors.open(w.deskA.request())).rule;
    await w.deskB.adopt(rule, "cpd-cycle", { minHours: 150 });
    const req = { ...w.deskB.request(), client_id: w.deskA.did };
    const err = await w.wallet.doors.open(req).catch((e) => e);
    expect(isWalletError(err, "DOOR_REFUSED")).toBe(true);
  });

  test("two doors never receive the same holder key, and a copy shown to one is never shown to the other (d62(d)3)", async () => {
    const w = await doorWorld();
    await w.receive(80, true, 100);
    await w.receive(60, true, 200);
    for (const desk of [w.deskA, w.deskB]) {
      const view = await w.wallet.doors.open(desk.request());
      await w.wallet.doors.send(view, { ownWord: { declaration: { declared: true } } });
    }
    const a = new Set(w.deskA.received[0]!.holderKeys);
    const b = w.deskB.received[0]!.holderKeys;
    expect(a.size).toBeGreaterThan(0);
    expect(b.some((k) => a.has(k))).toBe(false);
    const assigned = (await w.wallet.records.list()).filter((e) => e.local.assignedVerifier !== null).map((e) => e.local.assignedVerifier);
    expect(new Set(assigned)).toEqual(new Set([w.deskA.did, w.deskB.did]));
    // The same door, asked again, is shown the copies it already saw — never fresh ones that would look like more records.
    const again = await w.wallet.doors.open(w.deskA.request());
    await w.wallet.doors.send(again, { ownWord: { declaration: { declared: true } } });
    const firstA = w.deskA.received[0]!.check.byCriterion["cycle-hours"]!.receipts.map((m) => m.view.id).sort();
    const secondA = w.deskA.received[1]!.check.byCriterion["cycle-hours"]!.receipts.map((m) => m.view.id).sort();
    expect(secondA).toEqual(firstA);
  });

  test("after an export and an import, a copy one door saw is still never offered to another", async () => {
    const w = await doorWorld();
    await w.receive(80, true, 100);
    await w.receive(60, true, 200);
    await w.wallet.doors.send(await w.wallet.doors.open(w.deskA.request()), { ownWord: { declaration: { declared: true } } });
    const { text } = await w.wallet.exportAll({ passphrase: "a practice passphrase" });
    // The app ships its pinned publisher; the export carries the lists, the records, the keys and the log.
    const moved = await createHeadlessWallet({ practice: true, seed: "doors-moved", now: () => w.clock.t, transport: w.net.transport, pinnedPublishers: [w.publisher.did] });
    await moved.wallet.importAll(text, { passphrase: "a practice passphrase" });
    await moved.wallet.doors.send(await moved.wallet.doors.open(w.deskB.request()), { ownWord: { declaration: { declared: true } } });
    const a = new Set(w.deskA.received[0]!.holderKeys);
    expect(w.deskB.received[0]!.holderKeys.some((k) => a.has(k))).toBe(false);
    expect((await moved.wallet.log.list()).filter((e) => e.kind === "presentation").length).toBeGreaterThan(0);
  });

  test("no does nothing: no byte stored, no request sent (d49)", async () => {
    const w = await doorWorld();
    await w.receive(80, true, 100);
    const before = w.person.inspect.snapshot();
    const sentBefore = w.person.inspect.traffic().length;
    const view = await w.wallet.doors.open(w.deskA.request());
    w.wallet.doors.no(view);
    expect(w.person.inspect.snapshot()).toBe(before);
    expect(w.person.inspect.traffic().length).toBe(sentBefore);
    expect(w.deskA.received.length).toBe(0);
  });

  test("short of the cycle's hours, the checklist says so, and nothing can be sent", async () => {
    const w = await doorWorld();
    await w.receive(20, true, 100);
    const view = await w.wallet.doors.open(w.deskA.request());
    expect(view.checklist.rows.find((r) => r.criterion === "cycle-hours")!.state).toBe("missing");
    expect(view.checklist.ready).toBe(false);
    const err = await w.wallet.doors.send(view, { ownWord: { declaration: { declared: true } } }).catch((e) => e);
    expect(isWalletError(err, "NOT_ANSWERABLE")).toBe(true);
    expect(w.deskA.received.length).toBe(0);
  });

  test("a request whose query asks for more than its rule is refused unopened", async () => {
    const w = await doorWorld();
    const req = w.deskA.request();
    const err = await w.wallet.doors.open({ ...req, dcql_query: { credentials: [], credential_sets: [] } }).catch((e) => e);
    expect(isWalletError(err, "DOOR_REFUSED")).toBe(true);
  });
});

/* ── KS-Q11: the guest presents the booking receipt they countersigned ── */

/** A host's book, signing as itself: `booking.delivered/1` (OA-V1's shape, written here) and the acceptance request. */
async function hostBooking(t: number) {
  const kp = await generateKeyPair();
  const did = deriveDid(kp.publicKey);
  const host = { ...kp, did, keyid: did };
  const payload = {
    spec: "oreoasis.work-record/1",
    receiptId: "01JCPRACT1CE0B00K1NGWA11ET",
    org: "practice-host",
    actor: { class: "organisation", id: host.did },
    shape: "accepted",
    action: { type: "booking.delivered", summary: "Delivered a booking under the agreement this record names." },
    inputs: [],
    outputs: [],
    status: "completed",
    timestamp: iso(t - 4 * DAY),
    meta: { profile: "booking.delivered/1", reference: `kash-trade:0x${"cd".repeat(32)}`, door: "sabaat", listing: `${host.did}/listing/practice-room`, window: { start: iso(t - 5 * DAY), end: iso(t - 2 * DAY) } },
  };
  const subject = await signEnvelope(payload, WORK_RECORD_TYPE, host, { canonical: true });
  const body = {
    requestId: "csr_ks_q11_practice_0000000000001",
    requesterDid: host.did,
    subjectPayloadType: subject.payloadType,
    subjectDigestSha256: await sha256Hex(base64ToBytes(subject.payload)),
    statement: "Accept this receipt.",
    disclosures: [],
    nonceB64: bytesToBase64(crypto.getRandomValues(new Uint8Array(32))),
    issuedAtUnix: t - 4 * DAY,
    expiresAtUnix: t + 3 * DAY,
    relationshipContext: "practice",
    withdrawalFeed: null,
  };
  const header = { typ: "countersign-request", v: 1 };
  const request = { header, body, signature: await signEvent(header, body, host.privateKey, { dst: DST_COUNTERSIGN_REQUEST }) };
  return { host, subject, request };
}

/** The members of the wallet's core the ceremony touches — as Indusland's `internalsOf` reads them. */
interface CoreLike {
  readonly relationships: { ensure(c: string): Promise<unknown>; ensureKey(r: unknown): Promise<{ keyId: string }> };
  readonly keys: {
    withSigner<T>(k: string, use: (s: never) => Promise<T>): Promise<T>;
    withEventSigner<T>(k: string, use: (s: never) => Promise<T>): Promise<T>;
  };
  readonly records: {
    build(a: HeldArtifact, o: { relationship: string | null; declaredRetention: number | null; keepUnlisted: boolean }): Promise<{ status: string; record?: HeldRecord; reasons?: string[] }>;
    hold(r: HeldRecord, l: { counterparty: string | null; boundKey: string | null; copyGroup: string | null; assignedVerifier: string | null }): Promise<string>;
  };
}
const coreOf = (w: unknown): CoreLike => (w as { core: CoreLike }).core;

async function hold(wallet: unknown, bundle: CountersignBundle, hostDid: string, keyId: string | null): Promise<void> {
  const core = coreOf(wallet);
  const built = await core.records.build({ kind: "countersign-bundle", value: bundle }, { relationship: keyId, declaredRetention: null, keepUnlisted: true });
  if (built.status === "refused" || built.record === undefined) throw new Error(`hold: ${built.reasons?.join(", ")}`);
  await core.records.hold(built.record, { counterparty: hostDid, boundKey: keyId, copyGroup: null, assignedVerifier: null });
}

/** The guest accepts with the wallet's own key for this host (as Indusland's IL-V4 does), and keeps the bundle. */
async function acceptAndHold(wallet: unknown, b: Awaited<ReturnType<typeof hostBooking>>, signedAt: number): Promise<{ bundle: CountersignBundle; keyId: string }> {
  const core = coreOf(wallet);
  const { keyId } = await core.relationships.ensureKey(await core.relationships.ensure(b.host.did));
  const accBody = {
    act: "countersign" as const,
    requestId: b.request.body.requestId,
    requestDigestSha256: await countersignRequestDigest(b.request),
    subjectPayloadType: b.subject.payloadType,
    subjectDigestSha256: b.request.body.subjectDigestSha256,
    countersignerDid: keyId,
    keyCustody: "subject-generated" as const,
    signedAtUnix: signedAt,
  };
  const header = { typ: "countersign", v: 1 };
  const signature = await core.keys.withEventSigner(keyId, (s: never) => signEventWith(header, accBody, s, { dst: DST_COUNTERSIGN_ACCEPTANCE }));
  const sig = await core.keys.withSigner(keyId, (s: never) => signBytes(s, pae(b.subject.payloadType, base64ToBytes(b.subject.payload)), "der"));
  const bundle = {
    formatVersion: COUNTERSIGN_BUNDLE_FORMAT,
    subject: { ...b.subject, signatures: [...b.subject.signatures, { keyid: keyId, sig: bytesToBase64(sig as Uint8Array) }] },
    request: b.request,
    acceptances: [{ header, body: accBody, signature }],
  } as unknown as CountersignBundle;
  await hold(wallet, bundle, b.host.did, keyId);
  return { bundle, keyId };
}

async function reviewWorld() {
  const clock = { t: PRACTICE_T0 };
  const now = () => clock.t;
  const net = new PracticeNetwork();
  const desk = await PracticeDesk.create({ origin: "https://reviews.practice.invalid", name: "A practice reviews desk", now });
  net.mount(desk.origin, desk.handler);
  const dates = { published: iso(PRACTICE_T0 - 10 * DAY), renewBy: iso(PRACTICE_T0 + 300 * DAY), endsAt: iso(PRACTICE_T0 + 700 * DAY) };
  await desk.publish(bookingReviewRule({ author: desk.did }, { dates }));
  const booking = await hostBooking(PRACTICE_T0);
  const guest = await createHeadlessWallet({ practice: true, seed: "guest", now, transport: net.transport });
  await guest.wallet.proof.set(booking.host.did, "on", "A practice host");
  return { desk, booking, guest, now, net };
}

describe("KS-Q11 — a guest presents the booking receipt they countersigned", () => {
  test("a headless wallet holding an accepted booking.delivered/1 answers a door whose query names the countersigner", async () => {
    const w = await reviewWorld();
    const { keyId } = await acceptAndHold(w.guest.wallet, w.booking, PRACTICE_T0 - 4 * DAY + 600);
    const view = await w.guest.wallet.doors.open(w.desk.request());
    expect(view.checklist.rows.find((r) => r.criterion === "delivered")!.state).toBe("answered");
    expect(view.links).toContain("delivered");
    const sent = await w.guest.wallet.doors.send(view);
    expect(sent.status).toBe("sent");
    const got = w.desk.received[0]!;
    expect(got.check.problems).toEqual([]);
    expect(got.route.route).toBe("automatic-yes");
    // The desk checked the binding against the guest's key for this host — never the host's.
    expect(got.holderKeys).toEqual([keyId]);
    expect(got.holderKeys).not.toContain(w.booking.host.did);
    expect((sent.answer as { decision_offer?: unknown }).decision_offer).toBeDefined();
  });

  test("a wallet that holds the bundle but not the countersigning key cannot show it as its own", async () => {
    const w = await reviewWorld();
    const { bundle } = await acceptAndHold(w.guest.wallet, w.booking, PRACTICE_T0 - 4 * DAY + 600);
    const other = await createHeadlessWallet({ practice: true, seed: "someone-else", now: w.now, transport: w.net.transport });
    await hold(other.wallet, bundle, w.booking.host.did, null);
    const view = await other.wallet.doors.open(w.desk.request());
    const err = await other.wallet.doors.send(view).catch((e) => e);
    expect(isWalletError(err, "NOT_ANSWERABLE")).toBe(true);
    expect(w.desk.received.length).toBe(0);
  });
});
