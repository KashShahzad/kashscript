/**
 * The canonical Domain-Separation-Tag (DST) registry.
 *
 * Every signed artifact in the ecosystem binds a DST (Kash-Event / Indus token
 * families) or a DSSE `payloadType` (DSSE family) so a signature over one
 * context cannot be replayed in another. This registry is the single source of
 * truth: **new DSTs are added here first, by rule** (ROADMAP M1.2).
 *
 * The live tags below were harvested from the three seeds (Oreoasis / Duedale /
 * Indusland) plus identity-core, and reserved slots for the protocol layer.
 */

import { AttestError } from "./errors";

export type DstFamily =
  /** `Ed25519( DST\n ‖ JCS({header,body}) )` via identity-core. Tag ends with `\n`. */
  | "kash-event"
  /** DSSE `payloadType` — separation is the media type itself (no prefix). */
  | "dsse-type"
  /** `Ed25519( DST ‖ 0x00 ‖ headerB64u ‖ "." ‖ bodyB64u )`. Tag has no `\n`. */
  | "indus"
  /** SD-JWT VC (`typ: dc+sd-jwt`) — separation is the `vct` claim inside the
   *  issuer-signed JWT. The tag IS the `vct` string. */
  | "sd-jwt-vct"
  /** An RFC 6962 leaf: `SHA-256( 0x00 ‖ tag ‖ data )`, `data` fixed-length per
   *  tag. Nothing signs a leaf — a witness signs the tree's root; the tag keeps
   *  a leaf of one kind from being read as another. Tag ends with `\n`. */
  | "merkle-leaf";

export interface DstEntry {
  /** The exact tag string (Kash-Event tags include the trailing `\n`). */
  readonly tag: string;
  /** Owning package / venture (and its Manifestation destination). */
  readonly owner: string;
  readonly family: DstFamily;
  /** Human description of what this DST scopes. */
  readonly kind: string;
  /** True for reserved-but-not-yet-live tags. */
  readonly reserved?: boolean;
}

const ENTRIES: DstEntry[] = [
  // identity-core
  { tag: "kash-record-v1\n", owner: "@kashscript/identity-core", family: "kash-event", kind: "default Kash-Event record" },
  // Duedale (→ @kashscript/whiffin)
  { tag: "kash-grant-v1\n", owner: "duedale → @kashscript/whiffin", family: "kash-event", kind: "purpose-bound grant (grant→deliver→redeem)" },
  { tag: "kash-report-v1\n", owner: "duedale → @kashscript/whiffin", family: "kash-event", kind: "every-rupee reconciliation report" },
  // Oreoasis (→ @kashscript/hudhud)
  { tag: "oreoasis-ledger-v1\n", owner: "oreoasis → @kashscript/hudhud", family: "kash-event", kind: "signed action-ledger row" },
  { tag: "oreoasis-attestation-v1\n", owner: "oreoasis → @kashscript/hudhud", family: "kash-event", kind: "compile-SOP attestation" },
  { tag: "application/vnd.oreoasis.audit-bundle+json", owner: "oreoasis → @kashscript/hudhud", family: "dsse-type", kind: "DSSE audit-bundle payloadType" },
  { tag: "application/vnd.oreoasis.agent-receipt+json", owner: "oreoasis → @oreoasis/sdk", family: "dsse-type", kind: "DSSE Agent Receipt payloadType — one signed AI-agent action" },
  // The work-record tag exists BESIDE the agent-receipt tag, not in place of it:
  // that one is permanently described as an AI-agent action, and Oreoasis is now
  // the process-proof platform for work done by people AND agents (ECOSYSTEM
  // decision 43). A carpenter's signed record must not carry a tag that says
  // AI-agent action. Neither tag is ever retired; a signer picks the one that is
  // true of its actor. Profiles ride on this tag instead of adding tags (d59(e)):
  // `kashscript-cohort/1`, station zero's record of a finished cohort
  // (./profiles/cohort, specs/cohort-profile.md).
  { tag: "application/vnd.oreoasis.work-record+json", owner: "oreoasis → @oreoasis/sdk", family: "dsse-type", kind: "DSSE Work Record payloadType — one signed unit of work, by a person, an agent or a system" },
  // A predicate is the boundary-crossing artifact (ECOSYSTEM d27.2 — prove
  // predicates, not data): an answer plus the hash of its justification, signed
  // by the establishment's Org key. It carries no underlying record, no count
  // and no actor, so a verifier learns the answer without learning the work.
  { tag: "application/vnd.oreoasis.predicate+json", owner: "oreoasis → core-host", family: "dsse-type", kind: "DSSE predicate payloadType — a signed yes/no over the work ledger, naming its window and the rule version it was judged against" },
  // The improvement statement (d43 §5 — "improved the way this work is done").
  // Two tags because two parties sign: the HOLDER signs the request with their
  // per-relationship key (only the holder can ask), and the establishment's Org
  // key signs the statement. It is a feed for the one standing issuer (d44),
  // not a standing item in its own right.
  { tag: "application/vnd.oreoasis.improvement-statement-request+json", owner: "oreoasis → core-host", family: "dsse-type", kind: "DSSE holder request for an improvement statement — signed by the author's per-relationship key" },
  { tag: "application/vnd.oreoasis.improvement-statement+json", owner: "oreoasis → core-host", family: "dsse-type", kind: "DSSE improvement statement — the establishment attests n adopted revisions by this holder, in a period, to these rules; issued only on the holder's request" },
  // The doer's own export (d43 §4.8): only a request signed by the doer's own
  // per-relationship did:kash opens it — the key is read from that DID, so no one
  // can ask for someone else's history.
  { tag: "application/vnd.oreoasis.holder-export-request+json", owner: "oreoasis → core-host", family: "dsse-type", kind: "DSSE holder request for their own work history — signed by the doer's per-relationship did:kash" },
  // Indusland
  { tag: "indus.poe.v1.qr", owner: "indusland", family: "indus", kind: "IPOE1 proof-of-experience QR" },
  { tag: "indus.vfc.v1.cert", owner: "indusland", family: "indus", kind: "IVFC1 verified-footfall certificate" },
  { tag: "indus.bps.v1.bpass", owner: "indusland", family: "indus", kind: "IBPS1 booking pass" },
  { tag: "indus.poe.v1.geo", owner: "indusland", family: "indus", kind: "IGEO1 device geo check-in" },
  // Signed through identity-core's signEvent, so these are kash-event tags even
  // though Indusland owns them. indus.label.v1 signed every org label before
  // this registry knew about it; recorded 2026-09-24.
  { tag: "indus.label.v1\n", owner: "indusland", family: "kash-event", kind: "platform-signed org trust label" },
  { tag: "indus.mark.v1\n", owner: "indusland", family: "kash-event", kind: "Tehzeeb mark — one service, one standard version, held until expiry unless revoked" },
  { tag: "indus.mark.revoke.v1\n", owner: "indusland", family: "kash-event", kind: "Tehzeeb mark revocation — carries the reason's SHA-256, never its text" },
  { tag: "application/vnd.indusland.tehzeeb-enrolment+json", owner: "indusland", family: "dsse-type", kind: "DSSE payloadType — a business's countersigned acceptance of one Tehzeeb standard version" },
  // Indorania (the Indorania repository, apps/site-indorania — moved out of KashScript 2026-09-13; SIMULATION.md there)
  { tag: "application/vnd.indorania.visa+json", owner: "indorania", family: "dsse-type", kind: "DSSE visitor-visa payloadType — a model-session receipt: attests a session in the model, never a real-world fact" },
  { tag: "application/vnd.indorania.day+json", owner: "indorania", family: "dsse-type", kind: "DSSE working-day payloadType — a model-session receipt: attests a session in the model, never a real-world fact; rows carry the day's event chain" },
  // countersign — the generic second-signature mechanic (ADR-0018). Four tags,
  // one per signed shape in the ceremony. The thing being countersigned keeps
  // its OWN payloadType: adding a second signature to an existing DSSE envelope
  // needs no new DST, which is why nothing below names an artifact kind.
  { tag: "kash-countersign-request-v1\n", owner: "@kashscript/identity-server", family: "kash-event", kind: "countersign request — a holder addresses a counterparty" },
  { tag: "kash-countersign-v1\n", owner: "@kashscript/identity-server", family: "kash-event", kind: "countersign acceptance — binds request, subject digest, key custody and signing time" },
  { tag: "kash-countersign-withdrawal-v1\n", owner: "@kashscript/identity-server", family: "kash-event", kind: "countersign withdrawal — a holder withdraws a request (presented, never looked up)" },
  { tag: "kash-key-claim-v1\n", owner: "@kashscript/identity-server", family: "kash-event", kind: "key succession — a prior key and its successor sign one body; or, after a loss, the successor and a quorum of the helpers the prior key named (specs/recovery.md)" },
  // Recovery by succession, never by copying (d47(g)(4); specs/recovery.md,
  // PL-2). Signed IN ADVANCE by the key it protects: the helper keys that may,
  // a strict majority of them together, countersign a key claim for that key
  // once it is lost. Each relationship key names its own helper keys, so no
  // helper key is shared between two places (d41).
  { tag: "kash-recovery-helpers-v1\n", owner: "@kashscript/attest", family: "kash-event", kind: "recovery helpers — the helper keys a key names in advance, and how many of them must agree to move its authority to a successor" },
  // hudhud — exception classification + Work Certificate. The first and third
  // were live since M5 but never registered here; recorded 2026-09-23 (OA-P6).
  // v1 stays live forever: records signed under it must verify unchanged.
  { tag: "kash-exception-classification-v1\n", owner: "@kashscript/hudhud", family: "kash-event", kind: "exception classification v1 — model-failure class, operator-signed (deprecated for new records)" },
  { tag: "kash-exception-classification-v2\n", owner: "@kashscript/hudhud", family: "kash-event", kind: "exception classification v2 — deviation class (d43) + optional model-failure class, operator-signed" },
  { tag: "kash-exception-doer-account-v1\n", owner: "@kashscript/hudhud", family: "kash-event", kind: "doer's own account + countersignature over a v2 classification, per-classification key (unlinkable)" },
  { tag: "application/vnd.kash.work-certificate+json", owner: "@kashscript/hudhud", family: "dsse-type", kind: "DSSE Work Certificate payloadType (formats kash-work-certificate/1 and /2)" },
  // The holder contract (specs/holder-contract.md, PL-1). Neither signs a
  // record: the trust list says which issuers a wallet admits (a policy, never
  // a gate on the format — d47(e)), and the status list is the issuer's own
  // revocation bitstring, the one check that may touch the network.
  { tag: "application/vnd.kash.trust-list+json", owner: "@kashscript/attest", family: "dsse-type", kind: "DSSE trust list — a publisher's signed, versioned list of issuers, the exact DSTs each may issue, and their validity windows" },
  { tag: "application/vnd.kash.status-list+json", owner: "@kashscript/attest", family: "dsse-type", kind: "DSSE status list — an issuer's signed revocation bitstring (W3C Bitstring Status List encoding, ≥131,072 entries so no index stands out)" },
  // Presentation and the session (PL-3: specs/presentation.md,
  // specs/session-receipt.md, specs/thank-you.md). An ask is answered with a
  // yes, never with the data (d27.2, d42 §5): the predicate credential carries
  // the yes to a holder, who presents it bound to a relationship key. The
  // session event is signed by the two parties only — Indorania anchors a
  // session and never signs one (d47(d)). The thank-you is a promise, never a
  // balance, and cannot move (d49).
  { tag: "https://kashscript.com/vct/predicate/1", owner: "@kashscript/attest", family: "sd-jwt-vct", kind: "SD-JWT VC predicate credential — a yes over records, naming its rule version (d43) and window; record hashes selectively disclosable" },
  { tag: "application/vnd.indorania.session-event+json", owner: "indorania", family: "dsse-type", kind: "DSSE session event — one line of a session, signed by the establishment's and the person's relationship keys over the same bytes, never by Indorania" },
  { tag: "https://kashscript.com/vct/thank-you/1", owner: "indorania", family: "sd-jwt-vct", kind: "SD-JWT VC thank-you — an issuer's non-transferable promise for the answering, never the answer; value as text, no balance" },
  // identity-sdk's lifecycle events. All three have been signing in identity-sdk's
  // source under the constants KASH_RECOVERY_DST, KASH_ROTATION_DST and
  // KASH_REVOCATION_DST without a row here; PL-2 found the first two (ADR-0020)
  // and the third had not been checked. Recorded 2026-10-03 (GP-1), each tag
  // checked byte-for-byte against the constant that signs it. Registered because
  // they sign today, not because attest verifies them: ADR-0020 did not adopt
  // identity-sdk's recovery format (Ed25519 only), and these are not the
  // succession tags above.
  { tag: "kash-recovery-v1\n", owner: "@kashscript/identity-sdk", family: "kash-event", kind: "recovery quorum — the user's signed enrolment naming advisors and a strict-majority threshold, and each advisor's attestation over a recovery claim" },
  { tag: "kash-rotation-v1\n", owner: "@kashscript/identity-sdk", family: "kash-event", kind: "key rotation — the retiring key signs a numbered link naming its successor" },
  { tag: "kash-revocation-v1\n", owner: "@kashscript/identity-sdk", family: "kash-event", kind: "credential revocation — the issuer signs that a credential it issued is no longer valid" },
  // The session anchor's leaf (GP-6; specs/session-receipt.md §3, v1.1). Not a
  // signature: SHA-256(0x00 ‖ tag ‖ size ‖ head) — size the batch's leaf count
  // as 8 bytes big-endian (an RFC 6962 path alone does not fix it), head the
  // 32-byte SHA-256 of the line the anchor covers. A witness signs the batch's
  // root; each receipt carries its own audit path and nothing of any other session.
  { tag: "kash-session-head-v1\n", owner: "@kashscript/attest", family: "merkle-leaf", kind: "session anchor leaf — a session receipt's head as one leaf of an RFC 6962 batch; the receipt carries only its own audit path" },
  // The door (KS-Q1; specs/rule.md, specs/decision.md; ECOSYSTEM d84(a)): a rule,
  // a receipt, a decision. The rule is a public record its author signs as itself
  // (d62(d)2), DSSE like the trust lists any host may mirror (d62(d)5). The
  // decision comes back to the person as an SD-JWT VC they keep and may show at
  // the next door, in copies, the way a predicate travels (d62(d)3); it carries
  // the hashes of the receipts it relied on, never their content. The person's own
  // word is issued by the person to themselves, under a fresh key for one viewer,
  // so a statement travels in the same vp_token as the receipts and links nothing.
  { tag: "application/vnd.kash.rule+json", owner: "@kashscript/predicate", family: "dsse-type", kind: "DSSE door rule — what a door decides, its criteria (OpenID4VP DCQL queries plus FEEL conditions), reasons, contest window, renewal and end dates; signed by the authoring organisation" },
  { tag: "https://kashscript.com/vct/decision/1", owner: "@kashscript/predicate", family: "sd-jwt-vct", kind: "SD-JWT VC decision receipt — an outcome under one rule version, its reasons and fired rows, and hashes of the receipts relied on; signed by the deciding organisation to the person" },
  { tag: "https://kashscript.com/vct/own-word/1", owner: "@kashscript/predicate", family: "sd-jwt-vct", kind: "SD-JWT VC the person's own word — a statement a rule accepts on the person's word, self-issued under a fresh key for one viewer; never an issuer's claim" },
  // Rulebooks written once, executed locally (KS-Q1b; d85(b) rule 8, (d)): an
  // anchor adopts one version of a rule with its own values for the parameters
  // the rule bounds. A public record the anchor signs as itself (d62(d)2).
  { tag: "application/vnd.kash.adoption+json", owner: "@kashscript/predicate", family: "dsse-type", kind: "DSSE rule adoption — an anchor adopts one version of a rule with local values for its bounded parameters; signed by the adopting organisation" },
  // reserved — protocol-layer slots (ROADMAP)
  { tag: "hudhud-action-ledger-v1\n", owner: "@kashscript/hudhud", family: "kash-event", kind: "reserved: hudhud action ledger", reserved: true },
  { tag: "kash-identity-event-v1\n", owner: "@kashscript/identity-server", family: "kash-event", kind: "reserved: identity server event", reserved: true },
];

const BY_TAG = new Map<string, DstEntry>(ENTRIES.map((e) => [e.tag, e]));

/** Immutable view of the registry. */
export const DST_REGISTRY: readonly DstEntry[] = ENTRIES;

export function lookupDst(tag: string): DstEntry | null {
  return BY_TAG.get(tag) ?? null;
}

export function isRegisteredDst(tag: string): boolean {
  return BY_TAG.has(tag);
}

/** Return the entry for `tag`, or throw if it is not registered. */
export function assertRegistered(tag: string): DstEntry {
  const e = BY_TAG.get(tag);
  if (!e) {
    throw new AttestError(
      "UNKNOWN_DST",
      `DST not in registry: ${JSON.stringify(tag)}. New DSTs must be registered in @kashscript/attest/dst first.`,
    );
  }
  return e;
}

/** Register a new DST at runtime (e.g. a downstream package adding its own). */
export function registerDst(entry: DstEntry): void {
  if (BY_TAG.has(entry.tag)) {
    throw new AttestError("INVALID_INPUT", `DST already registered: ${JSON.stringify(entry.tag)}`);
  }
  ENTRIES.push(entry);
  BY_TAG.set(entry.tag, entry);
}
