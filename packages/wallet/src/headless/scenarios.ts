/**
 * The wallet's scenarios in the simulation's set (PLATFORM-SESSIONS PL-5):
 * receive, present, decline, export and recover — a lost phone, recovered by
 * helpers the person chose (PL-2). Each runs in a fresh practice world: a
 * trust list publisher, a listed issuer, an unlisted one, a café that runs
 * sessions and gives thank-yous, and two verifiers — all on `.practice.invalid`.
 *
 * After every scenario the constitution is checked, not trusted:
 *   · everything held verifies with networking disabled
 *   · a decline changes nothing — no stored byte, no request, no log line
 *   · no identifier crosses between relationships; the root never leaves
 *   · no key lies in the store in the clear
 *   · nothing scores, counts or sums a person
 *   · the switch never leaves the device
 *   · no default word names the ecosystem, a member, or a word a person must learn
 *
 * Everything here is practice (d11): the report says so on its first line.
 */

import { decodeJws, linkabilityBetween, parseSdJwt } from "@kashscript/attest/sd-jwt";
import { fill } from "../copy";
import type { HelperEnrolment } from "../recovery";
import { FORBIDDEN_VOUCHER_FIELDS, PREDICATE_VCT, THANK_YOU_VCT, validatePresentationLog, verifySessionReceipt } from "@kashscript/attest/exchange";
import { HOLDER_EXPORT_FORMAT, makeKeyResolver, verifyHolderExport, verifyStatusList } from "@kashscript/attest/holder";
import { DEFAULT_COPY } from "../copy";
import { bytesToBase64Url, bytesToHex, utf8Decode } from "../crypto/bytes";
import { ERROR_MESSAGES, isWalletError } from "../errors";
import { readings } from "../transport";
import { createHeadlessWallet, type HeadlessWallet } from "./wallet";
import { PracticeEstablishment } from "./practice/establishment";
import { PracticeIssuer, PRACTICE_RECORD_DST } from "./practice/issuer";
import { PracticeNetwork } from "./practice/network";
import { PracticePublisher } from "./practice/publisher";
import { PracticeVerifier } from "./practice/verifier";

export type ScenarioName = "receive" | "present" | "decline" | "export" | "recover";
export const WALLET_SCENARIOS: readonly ScenarioName[] = ["receive", "present", "decline", "export", "recover"];

export interface AssertionResult {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export interface ScenarioResult {
  readonly name: ScenarioName;
  readonly status: "green" | "red" | "pending";
  readonly reason: string | null;
  readonly checks: readonly AssertionResult[];
  readonly constitution: readonly AssertionResult[];
}

/** 2026-09-25T12:00:00Z — a fixed "now", moved only by the run itself. */
export const PRACTICE_T0 = 1_790_337_600;
const DAY = 86_400;

/** Words the wallet's own strings may never use (d44; d51's wallet list). */
export const BANNED_WORDS =
  /\b(indorania|proof economy|standing|kashscript|kash script|indusland|duedale|oreoasis|tehzeeb|kumak|industown|presence|flow|process|predicate|credentials?)\b/i;

class Checks {
  readonly list: AssertionResult[] = [];
  ok(name: string, condition: unknown, detail = ""): void {
    this.list.push({ name, ok: condition === true, detail });
  }
}

interface World {
  readonly clock: { t: number };
  readonly net: PracticeNetwork;
  readonly publisher: PracticePublisher;
  readonly issuer: PracticeIssuer;
  readonly stranger: PracticeIssuer;
  readonly cafe: PracticeEstablishment;
  readonly verifierA: PracticeVerifier;
  readonly verifierB: PracticeVerifier;
  /** The person's wallet. After a lost phone (recover), the new phone's. */
  person: HeadlessWallet;
  /** Every sentence the wallet produced for a person during the run. */
  readonly words: string[];
}

async function world(seed: string): Promise<World> {
  const clock = { t: PRACTICE_T0 };
  const now = () => clock.t;
  const net = new PracticeNetwork();
  const publisher = await PracticePublisher.create(now);
  const issuer = await PracticeIssuer.create({ origin: "https://records.practice.invalid", name: "A practice records desk", now, batchSize: 5 });
  const stranger = await PracticeIssuer.create({ origin: "https://stranger.practice.invalid", name: "A practice sender no list names", now });
  const cafe = await PracticeEstablishment.create({ origin: "https://cafe.practice.invalid", name: "A practice café", now });
  const verifierA = await PracticeVerifier.create({ origin: "https://verifier-a.practice.invalid", name: "A practice insurer", now });
  const verifierB = await PracticeVerifier.create({ origin: "https://verifier-b.practice.invalid", name: "A practice buyer", now });
  for (const x of [issuer, stranger, cafe.issuer]) net.mount(x.origin, x.handler);
  for (const v of [verifierA, verifierB]) net.mount(v.origin, v.handler);
  const person = await createHeadlessWallet({ practice: true, seed, now, transport: net.transport, pinnedPublishers: [publisher.did] });
  await person.wallet.trust.add(
    await publisher.list([
      { did: issuer.did, label: issuer.name, dsts: [PRACTICE_RECORD_DST, PREDICATE_VCT] },
      { did: cafe.issuer.did, label: cafe.name, dsts: [THANK_YOU_VCT] },
    ]),
  );
  return { clock, net, publisher, issuer, stranger, cafe, verifierA, verifierB, person, words: [] };
}

/** Run with every `fetch` refused, so anything that still passes provably needed no network. */
async function offline<T>(run: () => Promise<T>): Promise<T> {
  const saved = globalThis.fetch;
  globalThis.fetch = (() => {
    throw new Error("offline: fetch is disabled in this check");
  }) as unknown as typeof fetch;
  try {
    return await run();
  } finally {
    globalThis.fetch = saved;
  }
}

/* ── shared steps ──────────────────────────────────────────────────────── */

async function receiveYes(w: World): Promise<readonly string[]> {
  const { wallet } = w.person;
  await wallet.proof.set(w.issuer.origin, "on", w.issuer.name);
  const r = await wallet.receive.accept(await wallet.receive.open(w.issuer.offer(["practice-visit", "practice-yes"])));
  if (r.status !== "stored") throw new Error(`receive ended ${r.status}`);
  await wallet.status.carry(await w.issuer.statusList());
  const list = await verifyStatusList(await w.issuer.statusList(), { resolveKey: makeKeyResolver(new Map(), new Map()), nowSec: w.clock.t, source: "fetched" });
  w.verifierA.statusLists = [list];
  w.verifierB.statusLists = [list];
  return r.slots;
}

async function answer(w: World, verifier: PracticeVerifier, key: string) {
  const { wallet } = w.person;
  const ask = verifier.ask(key);
  await wallet.asks.remember(ask);
  const view = await wallet.present.open(await verifier.request(ask));
  w.words.push(view.why, view.goodFor, view.declineCosts, view.libraryText);
  return view;
}

async function completeSession(w: World): Promise<void> {
  const { wallet } = w.person;
  await wallet.proof.set(w.cafe.origin, "on", w.cafe.name);
  const joined = await wallet.sessions.join(w.cafe.origin);
  if (joined.status !== "joined") throw new Error("could not join");
  const lines = [
    await w.cafe.open(joined.personDid),
    await w.cafe.line(joined.personDid, "presence", {}),
    await w.cafe.flow(joined.personDid, { label: "a pot of tea", amount: "300.00" }),
    await w.cafe.close(joined.personDid, { amount: "300.00", currency: "PKR" }, 1),
  ];
  for (const line of lines) {
    const signed = await wallet.sessions.cosign(w.cafe.origin, line);
    if (signed.status !== "signed") throw new Error(`cosign ended ${signed.status}`);
    w.cafe.accept(joined.personDid, signed.line);
  }
  await wallet.sessions.keep(w.cafe.origin, w.cafe.receipt(joined.personDid));
}

/* ── the scenarios ─────────────────────────────────────────────────────── */

async function receive(w: World, c: Checks): Promise<void> {
  const { wallet, inspect } = w.person;
  const offer = w.issuer.offer(["practice-visit", "practice-yes"]);

  const firstView = await wallet.receive.open(offer);
  const sentBefore = inspect.traffic().length;
  const unasked = await wallet.receive.accept(firstView);
  c.ok("the switch is asked first, never pre-ticked, and nothing is sent before it", unasked.status === "needs-choice" && firstView.proof === "unset" && inspect.traffic().length === sentBefore);

  await wallet.proof.set(w.issuer.origin, "on", w.issuer.name);
  const view = await wallet.receive.open(offer);
  const stored = await wallet.receive.accept(view);
  c.ok("a listed record and a batch of copies of a yes are kept", stored.status === "stored" && stored.slots.length === 6, JSON.stringify(stored.status));
  const held = await wallet.records.list();
  c.ok("records from a listed issuer show as listed", held.length === 6 && held.every((e) => e.manifest.listing === "listed"));
  c.ok("each copy is bound to its own key", new Set(held.filter((e) => e.manifest.type.tag === PREDICATE_VCT).map((e) => e.local.boundKey)).size === 5);

  const snap = inspect.snapshot();
  let replay = "";
  try {
    await wallet.receive.accept(view);
  } catch (e) {
    replay = isWalletError(e) ? e.code : String(e);
  }
  c.ok("a used offer is refused, and nothing is stored", replay === "ISSUER_REFUSED" && inspect.snapshot() === snap, replay);

  await wallet.proof.set(w.stranger.origin, "on", w.stranger.name);
  const unlisted = await wallet.receive.accept(await wallet.receive.open(w.stranger.offer(["practice-visit"])));
  c.ok("a record from a sender no list names waits for the holder's choice", unlisted.status === "needs-keep-choice");
  if (unlisted.status === "needs-keep-choice") {
    const kept = await wallet.receive.keep(unlisted.pending);
    const e = kept.status === "stored" ? await wallet.records.get(kept.slots[0]!) : null;
    c.ok("kept by choice, and marked unlisted", e !== null && e.manifest.listing === "unlisted" && e.manifest.keptUnlistedAtUnix !== null);
  }
  const snap2 = inspect.snapshot();
  const second = await wallet.receive.accept(await wallet.receive.open(w.stranger.offer(["practice-visit"])));
  if (second.status === "needs-keep-choice") await wallet.receive.discard(second.pending);
  c.ok("discarding leaves nothing behind", second.status === "needs-keep-choice" && inspect.snapshot() === snap2);

  await wallet.proof.set(w.cafe.origin, "off", w.cafe.name);
  const sentOff = inspect.traffic().length;
  const off = await wallet.receive.accept(await wallet.receive.open(w.cafe.issuer.offer(["practice-thank-you"])));
  c.ok("switched off: nothing is sent, and the offer just expires", off.status === "off" && inspect.traffic().length === sentOff);

  await wallet.proof.set(w.cafe.origin, "on", w.cafe.name);
  const ty = await wallet.receive.accept(await wallet.receive.open(w.cafe.issuer.offer(["practice-thank-you"])));
  const notes = await wallet.thankYous.list();
  for (const n of notes) w.words.push(n.words);
  c.ok("a thank-you is claimed and shown as a single note in words", ty.status === "stored" && notes.length === 1 && /tea/.test(notes[0]!.value));

  const sentPrefetch = inspect.traffic().length;
  const lists = await wallet.status.prefetch();
  const prefetchTraffic = inspect.traffic().slice(sentPrefetch);
  c.ok(
    "fetching status lists is an explicit call that carries no identifier",
    lists.length === 2 && lists.every((l) => l.ok) && prefetchTraffic.every((r) => r.method === "GET" && r.body === null),
    `${lists.length} lists`,
  );

  const seen = [w.issuer.seenKeys, w.stranger.seenKeys, w.cafe.issuer.seenKeys];
  const overlap = seen.some((a, i) => seen.some((b, j) => i !== j && a.some((k) => b.includes(k))));
  c.ok("no two places ever saw the same key", !overlap && seen.every((s) => s.length > 0));
}

async function present(w: World, c: Checks): Promise<void> {
  const { wallet } = w.person;
  await receiveYes(w);
  const viewA = await answer(w, w.verifierA, "ask:practice-check-a");
  c.ok("the request is checked and matches the public list", viewA.answerable && viewA.library === "in-library");
  await wallet.present.yes(viewA);
  c.ok("one yes reaches the first verifier and verifies there, offline", w.verifierA.received.length === 1 && w.verifierA.received[0]!.report.ok, w.verifierA.received[0]?.report.reason ?? "");

  const viewB = await answer(w, w.verifierB, "ask:practice-check-b");
  await wallet.present.yes(viewB);
  c.ok("a second verifier gets its own copy, and it verifies", w.verifierB.received.length === 1 && w.verifierB.received[0]!.report.ok);
  const links = await linkabilityBetween(w.verifierA.received[0]!.presentation, w.verifierB.received[0]!.presentation);
  c.ok("the two verifiers share nothing that links them", links.length === 0, links.map((l) => l.kind).join(", "));
  c.ok("no record hash was disclosed", w.verifierA.received[0]!.report.disclosedRecordHashes.length === 0);

  const again = await answer(w, w.verifierA, "ask:practice-check-a2");
  await wallet.present.yes(again);
  c.ok("the same verifier sees the same copy again, not a new one", w.verifierA.received[1]?.report.holder === w.verifierA.received[0]!.report.holder);

  const log = await wallet.log.list();
  c.ok("the holder's log records each yes, and passes its own rules", log.length === 3 && validatePresentationLog(log).ok);
}

async function decline(w: World, c: Checks): Promise<void> {
  const { wallet, inspect } = w.person;
  await receiveYes(w);
  const view = await answer(w, w.verifierA, "ask:practice-check-no");
  const snap = inspect.snapshot();
  const sent = inspect.traffic().length;
  const logBefore = JSON.stringify(await wallet.log.list());
  wallet.present.no(view);
  c.ok("no: not a byte stored, not a request sent, not a log line", inspect.snapshot() === snap && inspect.traffic().length === sent && JSON.stringify(await wallet.log.list()) === logBefore);
  c.ok("no: the verifier receives nothing at all, not even a refusal", w.verifierA.received.length === 0);

  // A session the person joined, then switched off before the first line was signed.
  await wallet.proof.set(w.cafe.origin, "on", w.cafe.name);
  const joined = await wallet.sessions.join(w.cafe.origin);
  if (joined.status !== "joined") throw new Error("could not join");
  const openLine = await w.cafe.open(joined.personDid);
  await wallet.proof.set(w.cafe.origin, "off", w.cafe.name);
  const snap2 = inspect.snapshot();
  const sent2 = inspect.traffic().length;
  const res = await wallet.sessions.cosign(w.cafe.origin, openLine);
  c.ok("switched off in a session: nothing signed, stored or sent", res.status === "off" && inspect.snapshot() === snap2 && inspect.traffic().length === sent2);
  const report = await verifySessionReceipt(w.cafe.receipt(joined.personDid), { nowSec: w.clock.t });
  c.ok("the café's line stays single-signed: pending, never proof", report.state === "pending" && report.proof === false);
}

async function exportScenario(w: World, c: Checks): Promise<void> {
  const { wallet } = w.person;
  await receiveYes(w);
  await wallet.present.yes(await answer(w, w.verifierA, "ask:practice-check-a"));
  await wallet.proof.set(w.cafe.origin, "on", w.cafe.name);
  await wallet.receive.accept(await wallet.receive.open(w.cafe.issuer.offer(["practice-thank-you"])));
  await completeSession(w);
  const held = await wallet.records.list();
  c.ok("a session the person signed is kept as signed by both", held.some((e) => e.artifact.kind === "session-receipt" && e.manifest.type.attestation === "countersigned"));

  const plain = await offline(() => wallet.exportAll());
  const again = await offline(() => wallet.exportAll());
  const report = await offline(() => verifyHolderExport(JSON.parse(plain.text), { pinnedPublishers: [w.publisher.did], nowSec: w.clock.t, rawText: plain.text }));
  c.ok("the export verifies with networking disabled", report.ok && report.network === "none", report.reasons.join(", "));
  c.ok("the export is byte-stable", report.canonical === true && plain.text === again.text && !plain.text.endsWith("\n"));
  c.ok("without a passphrase, the file carries no key at all", plain.keysIncluded === false && JSON.parse(plain.text).encryptedKeyBackup === null);
  const parsed = JSON.parse(plain.text) as Record<string, unknown>;
  const topKeys = ["formatVersion", "exportedAtUnix", "records", "keySuccession", "trustLists", "statusLists", "revocations", "heldKeys", "encryptedKeyBackup", "presentationLog"];
  c.ok("the file is the documented format and nothing else", parsed.formatVersion === HOLDER_EXPORT_FORMAT && Object.keys(parsed).every((k) => topKeys.includes(k)));

  const withKeys = await wallet.exportAll({ passphrase: "practice passphrase" });
  const fresh = await createHeadlessWallet({ practice: true, seed: "a second practice phone", now: () => w.clock.t, transport: w.net.transport, pinnedPublishers: [w.publisher.did] });
  const imported = await fresh.wallet.importAll(withKeys.text, { passphrase: "practice passphrase" });
  const ids = (list: readonly { manifest: { recordId: string } }[]) => list.map((e) => e.manifest.recordId).sort().join();
  c.ok("imported on a second phone: every record, and the keys, back", ids(await fresh.wallet.records.list()) === ids(await wallet.records.list()) && imported.keysRestored > 0);
  c.ok("the switch did not travel: every place is asked again", (await fresh.wallet.proof.get(w.issuer.origin)) === "unset" && (await fresh.wallet.relationships.list()).length === 0);

  const viewB = await fresh.wallet.present.open(await w.verifierB.request(w.verifierB.ask("ask:practice-after-move")));
  await fresh.wallet.present.yes(viewB);
  const holderA = w.verifierA.received[0]!.report.holder;
  c.ok("after the move, a copy shown to one verifier is never shown to another", w.verifierB.received.length === 1 && w.verifierB.received[0]!.report.ok && w.verifierB.received[0]!.report.holder !== holderA);

  const visit = held.find((e) => e.manifest.type.tag === PRACTICE_RECORD_DST)!;
  w.clock.t = (visit.manifest.expiresAtUnix ?? w.clock.t) + 1;
  const gone = await wallet.records.sweep();
  const after = await wallet.exportAll();
  c.ok("at expiry the record is deleted, and a later export never brings it back", gone >= 1 && !(await wallet.records.list()).some((e) => e.slot === visit.slot) && !after.text.includes(visit.manifest.recordId));
  w.clock.t = PRACTICE_T0;
}

/**
 * A lost phone, recovered by helpers the person chose (d47(g)(4)) — the steps
 * of Indorania's lost-phone-recovered scenario, through this wallet. The old
 * phone keeps Ed25519 keys sealed in software; the new one keeps P-256 keys in
 * its (practice) secure chip, so the succession crosses algorithms.
 */
async function recover(w: World, c: Checks): Promise<void> {
  const old = w.person;
  const { wallet } = old;
  const now = () => w.clock.t;
  const seed = "practice/recover";

  // The platform is never a helper by default: a wallet starts with none at all.
  const fresh = await wallet.recovery.status();
  w.words.push(fresh.text);
  c.ok("a new wallet has no helpers at all — no platform or other key is preloaded", fresh.available === false && fresh.helpers === 0);

  // Records from two places: the records desk (a visit and copies of a yes) and the café (a session both signed).
  await receiveYes(w);
  await completeSession(w);
  const oldDesk = (await wallet.relationships.list()).find((r) => r.counterparty === w.issuer.origin)!;
  const oldCafe = (await wallet.relationships.list()).find((r) => r.counterparty === w.cafe.origin)!;

  // Three people the person trusts enrol from their own phones, in person.
  const people = ["a neighbour", "a cousin", "a colleague"];
  const helpers: { label: string; h: HeadlessWallet }[] = [];
  for (let i = 0; i < people.length; i++) {
    helpers.push({ label: people[i]!, h: await createHeadlessWallet({ practice: true, seed: `${seed}/helper-${i}`, now, transport: null }) });
  }
  const invite = await wallet.recovery.invite();
  const enrolments: { label: string; enrolment: HelperEnrolment }[] = [];
  for (const { label, h } of helpers) enrolments.push({ label, enrolment: await h.wallet.recovery.becomeHelper(invite, "the person I help") });
  const refusal = async (run: () => Promise<unknown>): Promise<string> => {
    try {
      await run();
      return "accepted";
    } catch (e) {
      return isWalletError(e) ? e.code : String(e);
    }
  };
  c.ok("one helper phone cannot enrol twice for the same person", (await refusal(() => helpers[0]!.h.wallet.recovery.becomeHelper(invite, "again"))) === "RECOVERY_ALREADY_HELPING");
  c.ok("the person cannot be their own helper", (await refusal(() => wallet.recovery.becomeHelper(invite, "me"))) === "RECOVERY_HELPERS_INVALID");
  c.ok("a quorum of one is refused — one key alone is a copy, not a quorum", (await refusal(() => wallet.recovery.chooseHelpers(enrolments, 1))) === "RECOVERY_HELPERS_INVALID");
  c.ok("one helper alone is refused", (await refusal(() => wallet.recovery.chooseHelpers(enrolments.slice(0, 1), 1))) === "RECOVERY_HELPERS_INVALID");
  const chosen = await wallet.recovery.chooseHelpers(enrolments, 2);
  w.words.push(chosen.text, wallet.copy().recoveryChooseHelpers, wallet.copy().recoveryNeedsCopy, wallet.copy().recoveryNotPeople);
  c.ok("two of three chosen, and both places' keys named their helpers in advance", chosen.available && chosen.need === 2 && chosen.covered === 2 && chosen.uncovered === 0, JSON.stringify(chosen));

  // The copy the person kept, somewhere other than the phone.
  const saved = await offline(() => wallet.exportAll());
  const savedValue = JSON.parse(saved.text) as {
    recoveryHelpers: { counterparty: string; helperSet: { body: { helpers: string[] } } }[];
    records: { manifest: { recordId: string }; artifact: unknown }[];
  };
  const [setA, setB] = savedValue.recoveryHelpers.map((e) => e.helperSet.body.helpers);
  c.ok("the saved copy verifies offline and carries no key", saved.report.ok && saved.keysIncluded === false && savedValue.recoveryHelpers.length === 2);
  c.ok("no helper key is shared between two places — helpers cannot link them", setA!.every((k) => !setB!.includes(k)));

  // The phone is lost, and nobody needs to be told. A new phone, with keys in its (practice) chip.
  const newPhone = await createHeadlessWallet({ practice: true, seed: `${seed}/new-phone`, now, transport: w.net.transport, pinnedPublishers: [w.publisher.did], hardwareSigning: true });
  const sentBefore = newPhone.inspect.traffic().length;
  const { request, code } = await newPhone.wallet.recovery.startOnNewPhone(saved.text);
  const ids = (list: readonly { manifest: { recordId: string } }[]) => list.map((e) => e.manifest.recordId).sort().join();
  c.ok("records came back from the saved copy — not from any server, and nothing was sent", ids(await newPhone.wallet.records.list()) === ids(await wallet.records.list()) && newPhone.inspect.traffic().length === sentBefore);
  const requestText = JSON.stringify(request);
  c.ok(
    "the request carries keys only — no record, no record id, no place",
    !savedValue.records.some((r) => requestText.includes(r.manifest.recordId)) && !requestText.includes("practice.invalid") && !requestText.includes("tea"),
  );

  // A helper reads the request: the same code as the new phone, and how many places — never which.
  const v0 = await helpers[0]!.h.wallet.recovery.answer(request);
  w.words.push(fill(wallet.copy().recoveryHelperQuestion, { name: v0.label, code: v0.code }));
  c.ok("the helper's phone shows the same six digits as the new phone", v0.code === code && /^[0-9]{6}$/.test(code) && v0.places === 2);
  const stranger = await createHeadlessWallet({ practice: true, seed: `${seed}/stranger`, now, transport: null });
  c.ok("a phone that helps nobody here cannot answer it", (await refusal(() => stranger.wallet.recovery.answer(request))) === "RECOVERY_NOT_YOURS");
  const a0 = await helpers[0]!.h.wallet.recovery.approve(v0);

  // One helper of the two needed: nothing changes.
  const waiting = await newPhone.wallet.recovery.finish([{ label: helpers[0]!.label, approval: a0 }]);
  w.words.push(fill(wallet.copy().recoveryWaiting, { n: "1" }));
  c.ok("one helper alone changes nothing — a succession is not a takeover", waiting.status === "waiting" && (await newPhone.wallet.relationships.list()).length === 0);

  // A second helper: the quorum.
  const a2 = await helpers[2]!.h.wallet.recovery.approve(await helpers[2]!.h.wallet.recovery.answer(request));
  const done = await newPhone.wallet.recovery.finish([
    { label: helpers[0]!.label, approval: a0 },
    { label: helpers[2]!.label, approval: a2 },
  ]);
  w.words.push(wallet.copy().recoveryDone);
  c.ok("two of three helpers bring both places back, and are chosen again for the new keys", done.status === "recovered" && done.recovered === 2 && done.helpersAgain === 2, JSON.stringify(done));
  c.ok("the helpers' phones sent nothing", helpers.every((x) => x.h.inspect.traffic().length === 0));

  // The new phone's export: offline, the succession named prior → successor, across algorithms.
  const after = await offline(() => newPhone.wallet.exportAll());
  const claims = after.report.keySuccession;
  c.ok(
    "the new phone's export verifies with networking disabled, carrying both successions",
    after.report.ok && after.report.network === "none" && claims.length === 2 && claims.every((k) => k.ok && k.path === "helpers"),
    after.report.reasons.join(", "),
  );
  c.ok(
    "the lost Ed25519 keys are succeeded by P-256 keys in the new phone's chip",
    claims.every((k) => k.priorKeyType === "Ed25519" && k.successorKeyType === "P-256") && claims.map((k) => k.priorDid).sort().join() === [oldDesk.keyId, oldCafe.keyId].sort().join(),
  );
  const oldArtifacts = new Map(savedValue.records.map((r) => [r.manifest.recordId, JSON.stringify(r.artifact)]));
  const newRecords = (JSON.parse(after.text) as typeof savedValue).records;
  c.ok(
    "old records are byte for byte what they were — valid under the old keys, nothing re-signed",
    newRecords.length === oldArtifacts.size && newRecords.every((r) => oldArtifacts.get(r.manifest.recordId) === JSON.stringify(r.artifact)) && after.report.records.every((r) => r.signatureOk),
  );
  const covered = await newPhone.wallet.recovery.status();
  c.ok("the new keys are covered again at once, by the helpers who came", covered.available && covered.covered === 2 && (JSON.parse(after.text) as { recoveryHelpers?: unknown[] }).recoveryHelpers?.length === 2);

  // The café, shown the succession — the person's choice — checks it offline and knows them again.
  await newPhone.wallet.proof.set(w.cafe.origin, "on", w.cafe.name);
  w.words.push(fill(wallet.copy().recoveryShowPlace, { name: w.cafe.name }));
  const cafeNow = (await newPhone.wallet.relationships.list()).find((r) => r.counterparty === w.cafe.origin)!;
  const shown = await newPhone.wallet.recovery.successionFor(w.cafe.origin);
  const recognised = await offline(() => w.cafe.recognise(shown, cafeNow.keyId!));
  c.ok("the café verifies the succession offline and carries its book on under the new key", recognised.ok && recognised.priorDid === oldCafe.keyId && w.cafe.knows(cafeNow.keyId!), recognised.reason ?? "");
  c.ok("the café is shown its own place's claim and nothing about the other place", shown.length === 1 && !JSON.stringify(shown).includes(oldDesk.keyId!));

  // A fresh yes from the desk, bound to a key in the new phone's chip, presented and checked offline.
  w.person = newPhone;
  await receiveYes(w);
  const view = await answer(w, w.verifierA, "ask:practice-after-recovery");
  await newPhone.wallet.present.yes(view);
  const got = w.verifierA.received.at(-1);
  const kb = got === undefined ? null : decodeJws(parseSdJwt(got.presentation)?.kbJwt ?? "");
  c.ok("a yes presented from the new phone is ES256, signed in its chip, and verifies offline", got !== undefined && got.report.ok && kb?.header.alg === "ES256", got?.report.reason ?? "nothing received");

  // Keys in the chip never leave it: a backup with a passphrase brings back none of them.
  const withPassphrase = await newPhone.wallet.exportAll({ passphrase: "practice passphrase" });
  const restoreOn = await createHeadlessWallet({ practice: true, seed: `${seed}/restore-check`, now, transport: null, pinnedPublishers: [w.publisher.did] });
  const restored = await restoreOn.wallet.importAll(withPassphrase.text, { passphrase: "practice passphrase" });
  c.ok(
    "keys in the chip never leave it — even a backup the person asked for carries none of them",
    newPhone.inspect.chipKeys() > 0 && withPassphrase.keysIncluded && restored.keysRestored === 0,
    `${newPhone.inspect.chipKeys()} keys in the chip; ${restored.keysRestored} restored from the backup`,
  );
}

/* ── the constitution, checked after every scenario ───────────────────── */

async function constitution(w: World): Promise<AssertionResult[]> {
  const c = new Checks();
  const { wallet, inspect } = w.person;

  const exported = await offline(() => wallet.exportAll());
  c.ok("everything held verifies with networking disabled", exported.report.ok && exported.report.network === "none", exported.report.reasons.join(", "));

  const traffic = inspect.traffic().map(readings);
  const root = inspect.rootPublicKey();
  const rootForms = [bytesToBase64Url(root), bytesToHex(root), bytesToBase64Url(root.slice(1, 33))];
  const rels = await wallet.relationships.list();
  const localForms = rels.flatMap((r) => [r.mailbox, r.id]);
  c.ok("the root's public key never leaves the device", !traffic.some((t) => rootForms.some((f) => t.includes(f))));
  c.ok("no relationship's mailbox or local name is ever sent", !traffic.some((t) => localForms.some((f) => t.includes(f))));
  c.ok("the switch is in no request and no export", !traffic.some((t) => /"proof"\s*:/.test(t)) && !localForms.some((f) => exported.text.includes(f)));

  const leaky: string[] = [];
  for (const [name, bytes] of inspect.blobs()) {
    if (name === "w.meta") {
      const meta = JSON.parse(utf8Decode(bytes) ?? "{}") as Record<string, unknown>;
      if (Object.keys(meta).sort().join() !== "format,sealed") leaky.push(name);
    } else if (utf8Decode(bytes) !== null && /[{"]/.test(utf8Decode(bytes) ?? "")) {
      leaky.push(name);
    }
  }
  c.ok("nothing is stored in the clear — every blob but the sealed header is ciphertext", leaky.length === 0, leaky.join(", "));

  const notes = await wallet.thankYous.list();
  const forbidden = notes.flatMap((n) => Object.keys(n)).filter((k) => FORBIDDEN_VOUCHER_FIELDS.includes(k.toLowerCase()));
  c.ok("nothing counts, sums or scores: thank-yous are single notes", forbidden.length === 0, forbidden.join(", "));

  const strings = [...Object.values(DEFAULT_COPY), ...Object.values(ERROR_MESSAGES), wallet.root().info.text, ...w.words];
  const banned = strings.filter((s) => BANNED_WORDS.test(s));
  c.ok("no default word names the ecosystem, a member, or a word a person must learn", banned.length === 0, banned.join(" | "));
  return c.list;
}

/* ── the runner ────────────────────────────────────────────────────────── */

const RUNS: Readonly<Record<ScenarioName, (w: World, c: Checks) => Promise<void>>> = {
  receive,
  present,
  decline,
  export: exportScenario,
  recover,
};

export async function runWalletScenarios(opts: { readonly seed?: string; readonly only?: readonly ScenarioName[] } = {}): Promise<readonly ScenarioResult[]> {
  const seed = opts.seed ?? "practice";
  const out: ScenarioResult[] = [];
  for (const name of WALLET_SCENARIOS) {
    if (opts.only !== undefined && !opts.only.includes(name)) continue;
    const w = await world(`${seed}/${name}`);
    const c = new Checks();
    let reason: string | null = null;
    try {
      await RUNS[name](w, c);
    } catch (e) {
      reason = e instanceof Error ? `${e.message}${isWalletError(e) && e.detail ? ` (${e.detail})` : ""}` : String(e);
    }
    const constitutionChecks = await constitution(w).catch((e: unknown) => [{ name: "the constitution could be checked", ok: false, detail: String(e) }]);
    const failed = reason !== null || c.list.some((x) => !x.ok) || constitutionChecks.some((x) => !x.ok);
    out.push({
      name,
      status: failed ? "red" : "green",
      reason: reason ?? (failed ? "a check failed" : null),
      checks: c.list,
      constitution: constitutionChecks,
    });
  }
  return out;
}

export { DAY as PRACTICE_DAY };
