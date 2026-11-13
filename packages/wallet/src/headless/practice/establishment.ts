/**
 * A practice establishment — a café — that runs sessions with the person and
 * gives thank-yous. It writes each line, signs it with a key it keeps for this
 * person alone, and asks the person's wallet to sign the same bytes. The
 * platform is not a party: no third key signs anything (d47(d)).
 */

import { generateKeyPair, deriveDid, type KashKeyPair } from "@kashscript/identity-core";
import type { DsseEnvelope } from "@kashscript/attest/dsse";
import { verifySuccessionSet, type KeyClaim } from "@kashscript/attest/succession";
import {
  lineItemCommitment,
  newLineItemSalt,
  SESSION_EVENT_SPEC,
  SESSION_RECEIPT_FORMAT,
  sessionEventSha256,
  sessionGenesisSha256,
  signSessionEvent,
  type SessionEventPayload,
  type SessionReceipt,
} from "@kashscript/attest/exchange";
import { bytesToHex } from "../../crypto/bytes";
import type { Clock } from "../../platform";
import { PracticeIssuer } from "./issuer";

const DAY = 86_400;

interface Open {
  readonly sessionId: string;
  readonly key: KashKeyPair;
  readonly did: string;
  readonly person: string;
  readonly events: DsseEnvelope[];
  prev: string;
}

export class PracticeEstablishment {
  private readonly sessions = new Map<string, Open>();

  private constructor(
    readonly origin: string,
    readonly name: string,
    /** The café hands over its thank-yous through the same handoff as any issuer. */
    readonly issuer: PracticeIssuer,
    private readonly now: Clock,
  ) {}

  static async create(opts: { origin: string; name: string; now: Clock }): Promise<PracticeEstablishment> {
    return new PracticeEstablishment(opts.origin, opts.name, await PracticeIssuer.create(opts), opts.now);
  }

  /** The opening line: what will be recorded, shown before anything is (d42 §4). */
  async open(personDid: string): Promise<DsseEnvelope> {
    const key = await generateKeyPair();
    const s: Open = { sessionId: `practice-session-${bytesToHex(crypto.getRandomValues(new Uint8Array(8)))}`, key, did: deriveDid(key.publicKey), person: personDid, events: [], prev: "" };
    s.prev = await sessionGenesisSha256(s.sessionId);
    this.sessions.set(personDid, s);
    return this.line(personDid, "open", {
      profile: "presence+flow",
      parties: { establishment: s.did, person: personDid },
      consent: { records: ["presence", "flow"], asks: [] },
      place: `${this.name} (practice)`,
    });
  }

  async line(personDid: string, kind: SessionEventPayload["kind"], body: Record<string, unknown>): Promise<DsseEnvelope> {
    const s = this.sessions.get(personDid);
    if (s === undefined) throw new Error("no open session with that person");
    const payload: SessionEventPayload = { spec: SESSION_EVENT_SPEC, sessionId: s.sessionId, seq: s.events.length, prevSha256: s.prev, kind, atUnix: this.now(), by: "establishment", body };
    const env = await signSessionEvent(payload, { keyid: s.did, privateKey: s.key.privateKey, publicKey: s.key.publicKey });
    s.events.push(env);
    s.prev = await sessionEventSha256(env);
    return env;
  }

  /**
   * A returning person shows that a new key is still them (PL-2). The café
   * checks the claims offline — nothing fetched, nobody asked — and only if the
   * chain starts at someone in its own book and ends at the key in front of it.
   * Then its book carries on under the new key. It learns nothing about any
   * other place: the person showed it this place's claims alone.
   */
  async recognise(claims: readonly KeyClaim[], newPersonDid: string): Promise<{ readonly ok: boolean; readonly priorDid: string | null; readonly reason: string | null }> {
    if (claims.length === 0) return { ok: false, priorDid: null, reason: "no claim shown" };
    const report = await verifySuccessionSet(claims);
    if (!report.ok) return { ok: false, priorDid: null, reason: report.claims.find((c) => !c.ok)?.reason ?? "conflict" };
    for (let i = 1; i < claims.length; i++) {
      if (claims[i]!.body.priorDid !== claims[i - 1]!.body.successorDid) return { ok: false, priorDid: null, reason: "the claims do not chain" };
    }
    const first = claims[0]!.body.priorDid;
    if (claims.at(-1)!.body.successorDid !== newPersonDid) return { ok: false, priorDid: first, reason: "the chain does not end at this key" };
    const book = this.sessions.get(first);
    if (book === undefined) return { ok: false, priorDid: first, reason: "not someone in this book" };
    this.sessions.set(newPersonDid, { ...book, person: newPersonDid });
    return { ok: true, priorDid: first, reason: null };
  }

  /** Whether the café's book knows this key — as a person it ran a session with. */
  knows(personDid: string): boolean {
    return this.sessions.has(personDid);
  }

  /** The person's countersigned copy replaces the café's single-signed one. */
  accept(personDid: string, cosigned: DsseEnvelope): void {
    const s = this.sessions.get(personDid);
    if (s === undefined) throw new Error("no open session with that person");
    const i = s.events.findIndex((e) => e.payload === cosigned.payload);
    if (i === -1) throw new Error("not a line of this session");
    s.events[i] = cosigned;
  }

  /** A flow line: the item stays with the person as a salted commitment — the café shares the total only. */
  async flow(personDid: string, item: { label: string; amount: string }): Promise<DsseEnvelope> {
    return this.line(personDid, "flow", { lineItems: [await lineItemCommitment(newLineItemSalt(), item)] });
  }

  async close(personDid: string, total: { amount: string; currency: string }, lineItemCount: number): Promise<DsseEnvelope> {
    return this.line(personDid, "close", { total, lineItemCount, expiresAtUnix: this.now() + 365 * DAY });
  }

  receipt(personDid: string): SessionReceipt {
    const s = this.sessions.get(personDid);
    if (s === undefined) throw new Error("no session with that person");
    return { formatVersion: SESSION_RECEIPT_FORMAT, sessionId: s.sessionId, profile: "presence+flow", parties: { establishment: s.did, person: s.person }, events: [...s.events], anchor: null };
  }
}
