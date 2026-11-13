/**
 * Sessions — the person's side of one encounter (d42 §4; session receipt).
 * Every line needs both signatures, and the person's comes from here: the
 * same bytes, signed with the person's key for that place and no other.
 *
 * The switch decides first (d49(a)). Off, or not yet answered, and the wallet
 * signs nothing and sends nothing: the line stays single-signed — pending,
 * never proof — and the encounter goes ahead unchanged. A decline leaves no
 * trace because there is nothing to leave.
 */

import { verifyEnvelope, type DsseEnvelope } from "@kashscript/attest/dsse";
import { cosignSessionEvent, SESSION_EVENT_DST, SESSION_EVENT_SPEC, verifySessionReceipt, type SessionReceipt } from "@kashscript/attest/exchange";
import { decodeEnvelopePayload, selfCertifyingTypedKey } from "@kashscript/attest/holder";
import type { WalletCore } from "./core";
import { WalletError } from "./errors";

export type JoinResult =
  | { readonly status: "joined"; readonly personDid: string }
  | { readonly status: "needs-choice"; readonly counterparty: string }
  | { readonly status: "off" };

export type CosignResult =
  | { readonly status: "signed"; readonly line: DsseEnvelope }
  | { readonly status: "needs-choice"; readonly counterparty: string }
  | { readonly status: "off" };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export class Sessions {
  constructor(private readonly core: WalletCore) {}

  /** The name this place knows the person by in a session — given only with records switched on. */
  async join(counterparty: string): Promise<JoinResult> {
    const proof = await this.core.relationships.proof(counterparty);
    if (proof === "unset") return { status: "needs-choice", counterparty };
    if (proof === "off") return { status: "off" };
    const r = await this.core.relationships.ensureKey(await this.core.relationships.ensure(counterparty));
    return { status: "joined", personDid: r.keyId };
  }

  /** Countersign one line the place wrote. Checks the line before signing it. */
  async cosign(counterparty: string, line: DsseEnvelope): Promise<CosignResult> {
    const proof = await this.core.relationships.proof(counterparty);
    if (proof === "unset") return { status: "needs-choice", counterparty };
    if (proof === "off") return { status: "off" };
    const r = await this.core.relationships.ensureKey(await this.core.relationships.ensure(counterparty));

    const payload = decodeEnvelopePayload(line);
    if (line?.payloadType !== SESSION_EVENT_DST || !isPlainObject(payload) || payload.spec !== SESSION_EVENT_SPEC || payload.by !== "establishment") {
      throw new WalletError("LINE_REFUSED", "not a session line written by the place");
    }
    // The place's session name: from the opening line the first time, then held to it.
    let theirDid = r.theirDid;
    if (payload.kind === "open") {
      const body = isPlainObject(payload.body) ? payload.body : {};
      const parties = isPlainObject(body.parties) ? body.parties : {};
      if (parties.person !== r.keyId) throw new WalletError("LINE_REFUSED", "the session does not name the person's key for this place");
      if (typeof parties.establishment !== "string") throw new WalletError("LINE_REFUSED", "the session names no establishment");
      theirDid = parties.establishment;
    }
    if (theirDid === null || selfCertifyingTypedKey(theirDid) === null) throw new WalletError("LINE_REFUSED", "the place's session name is unknown");
    const author = line.signatures[0]?.keyid;
    if (author !== theirDid || line.signatures.length !== 1) throw new WalletError("LINE_REFUSED", "the line is not signed by the place alone");
    // The place's key may be Ed25519 or P-256; its own did:kash says which.
    const checked = await verifyEnvelope(line, (kid) => (kid === theirDid ? selfCertifyingTypedKey(kid) : null));
    if (!checked.verifiedKeyids.includes(theirDid)) throw new WalletError("LINE_REFUSED", "the place's signature does not verify");

    if (payload.kind === "open") await this.core.relationships.learnTheirDid(r, theirDid);
    return { status: "signed", line: await this.core.keys.withSigner(r.keyId, (s) => cosignSessionEvent(line, s)) };
  }

  /** Keep a session receipt the person signed. A pending one is kept as pending — never as proof. */
  async keep(counterparty: string, receipt: SessionReceipt): Promise<string> {
    const r = await this.core.relationships.find(counterparty);
    if (r === null || r.keyId === null || r.proof !== "on") throw new WalletError("NOT_FOUND", "no session with this place");
    const report = await verifySessionReceipt(receipt, { nowSec: this.core.now() });
    if (!report.ok || report.parties?.person !== r.keyId) throw new WalletError("RECORD_REFUSED", report.faults.map((f) => f.fault).join(", ") || "not this person's session");
    // The person signed it, so keeping it is their choice — even though no list names a session.
    const built = await this.core.records.build({ kind: "session-receipt", value: receipt }, { relationship: r.keyId, declaredRetention: null, keepUnlisted: true });
    if (built.status !== "ready") throw new WalletError("RECORD_REFUSED", built.status === "refused" ? built.reasons.join(", ") : "not ready");
    return this.core.records.hold(built.record, { counterparty: r.counterparty, boundKey: r.keyId, copyGroup: null, assignedVerifier: null });
  }
}
