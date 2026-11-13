/**
 * Doors — a rule checked on the person's side first (ECOSYSTEM d84(a)). A door
 * publishes a rule; the wallet checks it against the records it holds, as a
 * checklist and never a score; the person sends a packet by choice, one copy
 * per viewer; the desk checks it free; the decision comes back as a receipt.
 *
 * - **open** — the rule verifies offline from its author's DID, passes the
 *   floor's validation, is in force, and the request's DCQL query is exactly
 *   the rule's own. At an anchor's door the anchor's adoption verifies too, and
 *   its local values are what the checklist reads (d85(b) rule 8). Then the
 *   checklist, over this wallet's records. Nothing is written and nothing is
 *   sent.
 * - **send** — on the person's yes only: copies this viewer has seen or no one
 *   has, never another viewer's (d62(d)3); the person's own word under a fresh
 *   key made for this viewer alone; a countersigned record only where this
 *   wallet holds the key the record names — and the view says such a record
 *   links (it cannot be re-keyed). Posted to the door; the copies then become
 *   this viewer's.
 * - **no** — nothing at all. No message, no record, no request (d49).
 */

import { credentialCopySha256, THANK_YOU_VCT, type PresentationLogEntry } from "@kashscript/attest/exchange";
import { decodeDisclosure, decodeJws, parseSdJwt } from "@kashscript/attest/sd-jwt";
import { signBytes, type RawSigner } from "@kashscript/attest/signing";
import { canonicalize } from "@kashscript/identity-core";
import {
  artifactHolderOf,
  buildPacket,
  checklist,
  criterionQueries,
  matchCriterion,
  openRuleRequest,
  readReceipts,
  AdoptionError,
  RuleError,
  PacketError,
  KASH_ARTIFACT_FORMAT,
  type Checklist,
  type DcqlCredentialQuery,
  type HeldReceipt,
  type ReceiptView,
  type PacketEntry,
  type ReadAdoption,
  type ReadRule,
  type RuleRequest,
} from "@kashscript/predicate";
import { base64UrlToBytes } from "./crypto/bytes";
import type { WalletCore } from "./core";
import { WalletError } from "./errors";
import type { HeldEntry } from "./records";

export interface DoorView {
  readonly request: RuleRequest;
  readonly rule: ReadRule;
  /** The anchor's adoption, at a door that runs another author's rule with its own values. Null at the author's own door. */
  readonly adoption: ReadAdoption | null;
  /** The door — the rule's author, or the anchor that adopted it — and the audience every copy is bound to. */
  readonly door: string;
  readonly title: string;
  readonly purpose: string;
  /** Who decides: a role. */
  readonly decider: string;
  /** What a yes grants. */
  readonly grants: string;
  /** P4's first rule: the other way to show the same thing. */
  readonly anotherWay: string;
  readonly contest: string;
  readonly checklist: Checklist;
  /** What the rule takes on the person's own word, to ask before sending. */
  readonly ownWord: readonly { readonly criterion: string; readonly statement: string; readonly fields: Readonly<Record<string, string>> }[];
  /** Rows that would show a record two viewers could recognise — said before the person sends. */
  readonly links: readonly string[];
  /** Saying no costs only what a yes grants. */
  readonly declineCosts: string;
}

export type DoorSendResult = { readonly status: "sent"; readonly door: string; readonly answer: unknown };

/** A signer that opens the wallet's key only for the one signature it makes, so keys never leave the wallet. */
async function deferredSigner(core: WalletCore, keyId: string): Promise<RawSigner & { readonly keyid: string }> {
  const k = await core.keys.find(keyId);
  if (k === null) throw new WalletError("NOT_FOUND", `no key ${keyId}`);
  const publicKey = base64UrlToBytes(k.publicKey);
  if (k.alg === "ES256") {
    return { alg: "ES256", keyid: k.keyId, publicKey, sign: (m: Uint8Array) => core.keys.withSigner(keyId, async (s) => ({ signature: await signBytes(s, m, "raw"), format: "raw" as const })) };
  }
  return { alg: "Ed25519", keyid: k.keyId, publicKey, sign: (m: Uint8Array) => core.keys.withSigner(keyId, (s) => signBytes(s, m, "raw")) };
}

const ARTIFACT_KINDS = new Set(["countersign-bundle", "dsse", "kash-event"]);

/**
 * Which copies are one record: the group a handoff gave them, or — after an
 * import, which keeps no groups — the same issuer, type, times and claims,
 * leaving out what differs per copy (its key, its status entry, its salts).
 */
async function copyGroupOf(e: HeldEntry): Promise<string> {
  if (e.local.copyGroup !== null) return e.local.copyGroup;
  const p = parseSdJwt(e.artifact.value as string);
  const payload = p === null ? null : decodeJws(p.issuerJwt)?.payload ?? null;
  if (p === null || payload === null) return `slot:${e.slot}`;
  const { cnf: _cnf, credentialStatus: _status, _sd: _digests, _sd_alg: _alg, ...visible } = payload as Record<string, unknown>;
  const disclosed: unknown[] = [];
  for (const d of p.disclosures) {
    const dd = await decodeDisclosure(d);
    if (dd !== null) disclosed.push([dd.name, dd.value]);
  }
  disclosed.sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
  return `content:${await sha256HexOf(canonicalize({ visible: stripDigests(visible), disclosed }))}`;
}

/** Array claims hold per-copy digests (`{"...": d}`); they are not content. */
function stripDigests(v: unknown): unknown {
  if (Array.isArray(v)) return v.filter((x) => !(typeof x === "object" && x !== null && "..." in x)).map(stripDigests);
  if (typeof v === "object" && v !== null) return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, stripDigests(x)]));
  return v;
}

async function sha256HexOf(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s) as unknown as BufferSource);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export class Doors {
  constructor(private readonly core: WalletCore) {}

  /** The records a door may read: one copy per group — this viewer's own, else a fresh one — and countersigned records. */
  private async held(door: string): Promise<{ held: HeldReceipt[]; bySlot: Map<string, HeldEntry> }> {
    const all = await this.core.records.list();
    const mineFirst = [...all].sort((a, b) => Number(b.local.assignedVerifier === door) - Number(a.local.assignedVerifier === door));
    const groups = new Set<string>();
    const held: HeldReceipt[] = [];
    const bySlot = new Map<string, HeldEntry>();
    for (const e of mineFirst) {
      if (e.artifact.kind === "sd-jwt") {
        // A thank-you is a promise to one relationship, never shown elsewhere (d49).
        if (e.manifest.type.tag === THANK_YOU_VCT) continue;
        // A copy shown to another viewer would link this door to that one (d62(d)3).
        if (e.local.assignedVerifier !== null && e.local.assignedVerifier !== door) continue;
        if (e.local.boundKey === null || (await this.core.keys.find(e.local.boundKey)) === null) continue;
        const group = await copyGroupOf(e);
        if (groups.has(group)) continue;
        groups.add(group);
      } else if (!ARTIFACT_KINDS.has(e.artifact.kind)) {
        continue;
      }
      held.push({ ref: e.slot, value: e.artifact.value });
      bySlot.set(e.slot, e);
    }
    return { held, bySlot };
  }

  private async list(rule: ReadRule, held: readonly HeldReceipt[], ownWord: Readonly<Record<string, Readonly<Record<string, unknown>>>> | undefined, adoption: ReadAdoption | null): Promise<Checklist> {
    const ctx = await this.core.trust.context();
    return checklist(rule, held, {
      asOf: this.core.now(),
      trustLists: ctx.trustLists,
      statusLists: ctx.statusLists,
      resolveKey: ctx.resolveKey,
      ...(ownWord !== undefined ? { ownWord } : {}),
      ...(adoption !== null ? { adoption } : {}),
    });
  }

  /** Check a door's request and its rule against what this wallet holds. Sends nothing; writes nothing. */
  async open(input: string | object, opts: { readonly ownWord?: Readonly<Record<string, Readonly<Record<string, unknown>>>> } = {}): Promise<DoorView> {
    let opened: { request: RuleRequest; rule: ReadRule; adoption?: ReadAdoption };
    try {
      opened = await openRuleRequest(input, this.core.now());
    } catch (e) {
      if (e instanceof RuleError || e instanceof AdoptionError || e instanceof SyntaxError) throw new WalletError("DOOR_REFUSED", e.message);
      throw e;
    }
    const { request, rule } = opened;
    const adoption = opened.adoption ?? null;
    const { held } = await this.held(request.client_id);
    const list = await this.list(rule, held, opts.ownWord, adoption);
    const body = rule.body;
    const links = list.rows.filter((r) => r.receipts.some((ref) => held.find((h) => h.ref === ref && typeof h.value !== "string"))).map((r) => r.criterion);
    return {
      request,
      rule,
      adoption,
      door: request.client_id,
      title: body.title,
      purpose: body.purpose,
      decider: body.decider.role,
      grants: body.outcome.grants,
      anotherWay: body.anotherWay,
      contest: body.contest.how,
      checklist: list,
      ownWord: body.criteria.flatMap((c) => (c.answer.by === "own-word" ? [{ criterion: c.id, statement: c.answer.statement, fields: { ...c.answer.fields } }] : [])),
      links,
      declineCosts: `Saying no costs only this: ${body.outcome.grants}`,
    };
  }

  /** Yes: send the packet. Only what the checklist chose, and the person's own word as they state it. */
  async send(view: DoorView, opts: { readonly ownWord?: Readonly<Record<string, Readonly<Record<string, unknown>>>> } = {}): Promise<DoorSendResult> {
    const { request, rule } = view;
    const now = this.core.now();
    const { held, bySlot } = await this.held(view.door);
    const list = await this.list(rule, held, opts.ownWord, view.adoption);
    if (!list.ready) throw new WalletError("NOT_ANSWERABLE", list.rows.filter((r) => !(r.state === "answered" || r.state === "sealed" || (r.state === "own-word" && r.holds === true))).map((r) => r.criterion).join(", "));

    const ctx = await this.core.trust.context();
    const views = await readReceipts(held, { ...ctx, nowSec: now });
    const entries: PacketEntry[] = [];
    const keyIds: string[] = [];
    const sent = new Set<string>();
    /** What the holder's own log says each sent record was shown under: its key and the claims the door read. */
    const shown = new Map<string, { key: string; read: string[] }>();
    for (const row of list.rows) {
      const c = rule.body.criteria.find((x) => x.id === row.criterion)!;
      if (c.answer.by === "own-word") {
        // A fresh key for this viewer alone: the statement links to nothing else the person holds.
        const k = await this.core.keys.create("copy");
        keyIds.push(k.keyId);
        const signer = await deferredSigner(this.core, k.keyId);
        entries.push({ kind: "own-word", queryId: `${c.id}_word`, fields: opts.ownWord?.[c.id] ?? {}, signer, keyType: k.alg === "ES256" ? "P-256" : "Ed25519" });
        continue;
      }
      const matched = matchCriterion(rule.body, rule.hash, c, views, { trustLists: ctx.trustLists, nowSec: now });
      for (const ref of row.receipts) {
        if (sent.has(ref)) continue; // one receipt answers every criterion that reads it — sent once
        sent.add(ref);
        const m = [...matched.receipts, ...matched.predicates].find((x) => x.view.ref === ref);
        const entry = bySlot.get(ref);
        if (m === undefined || entry === undefined) throw new WalletError("NOT_ANSWERABLE", `${c.id}: a chosen record no longer fits`);
        const query = criterionQueries(rule.body, rule.hash, c).queries.find((q) => q.id === m.queryId);
        const read = [...new Set((query?.claims ?? []).map((cl) => cl.path[0]).filter((p): p is string => typeof p === "string"))];
        if (m.view.format === KASH_ARTIFACT_FORMAT) {
          const named = query === undefined ? null : await this.artifactKey(query, m.view, entry);
          if (named === null) throw new WalletError("NOT_ANSWERABLE", `${c.id}: this wallet holds no key the record names, so it cannot be shown as yours`);
          keyIds.push(named);
          shown.set(ref, { key: named, read });
          entries.push({ kind: "artifact", queryId: m.queryId, artifact: entry.artifact.value as Record<string, unknown>, signer: await deferredSigner(this.core, named) });
        } else {
          const bound = entry.local.boundKey!;
          keyIds.push(bound);
          shown.set(ref, { key: bound, read });
          entries.push({ kind: "sd-jwt", queryId: m.queryId, held: entry.artifact.value as string, signer: await deferredSigner(this.core, bound) });
        }
      }
    }

    let packet;
    try {
      packet = await buildPacket({ rule, request, entries, iatUnix: now });
    } catch (e) {
      if (e instanceof PacketError) throw new WalletError("NOT_ANSWERABLE", e.message);
      throw e;
    }
    const res = await this.core.postForm(
      request.response_uri,
      { vp_token: JSON.stringify(packet.vp_token), ...(request.state !== undefined ? { state: request.state } : {}) },
      await this.core.allowed(keyIds),
    );
    if (res.status < 200 || res.status >= 300) throw new WalletError("SEND_FAILED", `the door answered ${res.status}`);
    // Only after it arrived: these copies are now this viewer's, and the holder's own log says so —
    // which is also what rebuilds the assignment after an export and an import.
    const askRef = { key: rule.body.id, version: rule.body.version, sha256: rule.hash };
    const log: PresentationLogEntry[] = [];
    for (const ref of sent) {
      const e = bySlot.get(ref);
      const s = shown.get(ref);
      if (e === undefined || s === undefined) continue;
      if (e.artifact.kind === "sd-jwt") {
        await this.core.records.updateLocal(e.slot, { ...e.local, assignedVerifier: view.door });
        log.push({ kind: "presentation", atUnix: now, verifier: view.door, relationship: s.key, ask: askRef, credentials: [{ vct: e.manifest.type.tag, copySha256: await credentialCopySha256(e.artifact.value as string) }], disclosed: s.read, attachedRecordIds: [], linkedByHolder: false });
      } else {
        // A countersigned record cannot be re-keyed: showing it links, by the holder's choice.
        log.push({ kind: "presentation", atUnix: now, verifier: view.door, relationship: s.key, ask: askRef, credentials: [], disclosed: s.read, attachedRecordIds: [e.manifest.recordId], linkedByHolder: true });
      }
    }
    if (log.length > 0) await this.core.log.append(...log);
    return { status: "sent", door: view.door, answer: res.json };
  }

  /**
   * No. This does nothing — deliberately, and provably (`test/doors.test.ts`
   * compares every stored byte and every request before and after).
   */
  no(_view: DoorView): void {
    return;
  }

  /**
   * The key the query names as the record's holder — read by predicate's own
   * `artifactHolderOf`, as the desk reads it: the countersigner the bundle's
   * verified acceptance names (`holder: "countersigner"`, KS-Q11), the key at
   * `holder_path`, else the requester — and only when this wallet holds it. A
   * guest's key for a host is named by its own `did:kash`, which is the
   * acceptance's `countersignerDid`.
   */
  private async artifactKey(query: DcqlCredentialQuery, view: ReceiptView, entry: HeldEntry): Promise<string | null> {
    const named = artifactHolderOf(query, view, entry.artifact.value as Record<string, unknown>);
    return named !== null && (await this.core.keys.find(named)) !== null ? named : null;
  }
}
