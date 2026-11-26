/**
 * The rules the two shapes cannot write (RW-14; `specs/attestation/README.md` §2.2). Pure: no clock, no
 * key, no network. Each fault names the decision it enforces. Run them after the shape validates —
 * `checkAttestation` and `checkMandate` do both.
 *
 * **What a format cannot see, said once:** a mandate's delegate `kind` is the principal's own word, so the
 * format cannot tell a machine's key from a person's; a counterparty's key made on the issuer's own domain
 * proves no independence (d91(d): the defence is a third signal); a statement's words are checked for a
 * contact, a link and an identifier, never for a name or a judgement. Those are conduct, attested by the
 * operator and sanctioned through the trust list (d91(f)).
 */

import { findPersonIdentity } from "@kashscript/lexicons/extensions/public";
import { validate } from "@kashscript/lexicons/schema";
import { alphaProblem, boundVerdict, limitVerdict } from "../batch/chance";
import { OVER_PLAN_REASON } from "../batch/seal";
import {
  KASH_ATTESTATION_1_1_BODY_SCHEMA,
  KASH_MANDATE_BODY_SCHEMA,
  KEY_DID_PATTERN,
  isPublicReference,
  type AttestationBody,
  type AttestationKind,
  type AttestationOutcome,
  type MandateBody,
  type ReferenceKind,
  type ScopedKind,
} from "./lexicon";

export type AttestationFaultCode =
  | "SHAPE"
  | "OUTCOME_FOR_KIND"
  | "REFERENCE_FOR_KIND"
  | "PUBLIC_REFERENCE"
  | "PRIVATE_REFERENCE_ID"
  | "REASONS"
  | "CONTESTS"
  | "COUNTERPARTY_FOR_KIND"
  | "COUNTERPARTY_IS_ISSUER"
  | "COUNTERPARTY_WEB"
  | "COUNTERPARTY_MANDATE"
  | "GRADE_REQUIRED"
  | "GRADE_WITHOUT_COUNTERPARTY"
  | "GRADE_ZERO_PRACTICE"
  | "DATES"
  | "MANDATE_PRINCIPAL"
  | "PERSON_IDENTITY"
  // 1.1.0 — a batch accepted on a sample (PY-5; specs/attestation/batch.md §5)
  | "BATCH_KIND"
  | "BATCH_REFERENCE"
  | "BATCH_BY_A_PERSON"
  | "BATCH_LIMITS"
  | "BATCH_CENSUS"
  | "BATCH_FOUND"
  | "BATCH_OVER_PLAN"
  | "BATCH_PLAN"
  | "BATCH_BOUND";

export type MandateFaultCode =
  | "SHAPE"
  | "ID_PRINCIPAL"
  | "DELEGATE_IS_PRINCIPAL"
  | "SCOPE_EMPTY"
  | "MACHINE_REFUSAL"
  | "AGENT_SCOPE"
  | "DESK_DECIDES_ONLY"
  | "DATES"
  | "PERSON_IDENTITY";

export interface Fault<C extends string> {
  readonly code: C;
  readonly message: string;
}

/** Which outcomes each kind may carry, and why (d91(a), d49, d84 P3). */
export const OUTCOMES_BY_KIND: Readonly<Record<AttestationKind, readonly AttestationOutcome[]>> = {
  // The other side's acceptance, or its *not yet* with what is missing. Never *refused*: a decline by
  // either party means no record, and leaves no trace (d49).
  receipt: ["accepted", "not-yet"],
  // A deviation against a standard, countersigned by the doer (d43).
  finding: ["finding"],
  // An assessor's attestation over a packet or an issuer's practice.
  assurance: ["accepted", "not-yet", "finding"],
  // The subject's own attestation against a decision, under the rule's recourse clause: the one place a
  // party writes *refused*, and it is the subject's word about a decision, never anyone's about the subject.
  contest: ["refused"],
};

/** Which references each kind is made against. A contest is made against the rule whose recourse clause it invokes (d91(a)), and names the decision in `contests`. */
export const REFERENCES_BY_KIND: Readonly<Record<AttestationKind, readonly ReferenceKind[]>> = {
  receipt: ["agreement", "purpose", "artefact", "attestation"],
  finding: ["standard", "rule"],
  assurance: ["artefact", "attestation", "standard", "rule"],
  contest: ["rule"],
};

/**
 * Whether the other side signs the same bytes. A receipt is the other side's acceptance and a finding is
 * countersigned by the doer, so both need it (d41: two signatures or it is not proof; d43). A contest is the
 * subject's word alone. An assurance carries the assessor's own liability, with or without one.
 */
export const COUNTERPARTY_BY_KIND: Readonly<Record<AttestationKind, "required" | "optional" | "never">> = {
  receipt: "required",
  finding: "required",
  assurance: "optional",
  contest: "never",
};

/** What an agent's mandate may cover: receipts only — agents prepare and carry, never decide, judge or contest (d88; d84 F; d43). */
export const AGENT_KINDS: readonly ScopedKind[] = ["receipt"];

const MAX_MANDATE_DAYS = 366;
const DAY_MS = 86_400_000;

/** The DID a mandate id (`<did>/mandate/<slug>`) is under, or null when it is not a mandate id. */
export function principalOfMandateId(id: string): string | null {
  const at = id.indexOf("/mandate/");
  return at > 0 ? id.slice(0, at) : null;
}

/** A statement is words: no link, no identifier, no contact. What it holds otherwise, in two words, or null. */
export function statementProblem(text: string): string | null {
  if (/https?:\/\/|www\./i.test(text)) return "a link";
  if (/\bdid:[a-z0-9]+:/i.test(text)) return "an identifier";
  const hit = findPersonIdentity(text);
  return hit === null ? null : hit.what;
}

/** The cross-field rules of `kash.attestation@1.0.0` and, for a batch, 1.1.0's — on a body whose shape already validates. */
export function attestationFaults(body: AttestationBody): readonly Fault<AttestationFaultCode>[] {
  const out: Fault<AttestationFaultCode>[] = [];
  const add = (code: AttestationFaultCode, message: string): void => {
    out.push({ code, message });
  };

  if (!OUTCOMES_BY_KIND[body.kind].includes(body.outcome)) {
    add(
      "OUTCOME_FOR_KIND",
      body.kind === "receipt" && body.outcome === "refused"
        ? "a receipt is accepted or not yet, never refused — a decline leaves no trace (d49); a refusal is a person's decision under a rule (kash.decision, d84 P3)"
        : `a ${body.kind} carries ${OUTCOMES_BY_KIND[body.kind].join(" or ")}, not ${body.outcome} (d91(a))`,
    );
  }
  if (!REFERENCES_BY_KIND[body.kind].includes(body.reference.kind)) {
    add("REFERENCE_FOR_KIND", `a ${body.kind} is made against ${REFERENCES_BY_KIND[body.kind].join(", ")} — not a ${body.reference.kind} (d91(a))`);
  }
  if (isPublicReference(body.reference.kind)) {
    if (body.reference.id === undefined || body.reference.version === undefined) add("PUBLIC_REFERENCE", "a rule or a standard is cited by its library id, its version and its hash (d91(a))");
  } else if (body.reference.id !== undefined) {
    add("PRIVATE_REFERENCE_ID", "a private reference is cited by its hash, and its version when it has one — a book's own id would be a second string to join on and a key to look up by (d41)");
  }
  if ((body.outcome === "not-yet" || body.kind === "contest") && (body.reasons === undefined || body.reasons.length === 0)) {
    add("REASONS", body.kind === "contest" ? "a contest gives its grounds" : "a not yet says what is missing (d85(e))");
  }
  if (body.kind === "contest" && body.contests === undefined) add("CONTESTS", "a contest names the decision it contests, by the content id of the copy its subject holds");
  if (body.kind !== "contest" && body.contests !== undefined) add("CONTESTS", "only a contest names a decision it contests");

  const cp = COUNTERPARTY_BY_KIND[body.kind];
  if (cp === "required" && body.counterparty === undefined) {
    add("COUNTERPARTY_FOR_KIND", body.kind === "receipt" ? "a receipt is the other side's acceptance: it names the counterparty whose signature completes it (d91(a); d41: two signatures or it is not proof)" : "a finding is countersigned by the doer: it names them (d43)");
  }
  if (cp === "never" && body.counterparty !== undefined) add("COUNTERPARTY_FOR_KIND", "a contest is the subject's own word, signed by the subject alone (d91(a))");
  if (body.counterparty !== undefined && body.counterparty === body.issuer) add("COUNTERPARTY_IS_ISSUER", "the counterparty is the other side — one party signing twice is one signature (d26)");
  if (body.counterparty !== undefined && !KEY_DID_PATTERN.test(body.counterparty) && body.grade !== 3) {
    add("COUNTERPARTY_WEB", "a did:web counterparty is an organisation signing as itself, at grade 3; a person signs with a key made for this one relationship (d41; d62(d)2–3)");
  }
  if (body.counterpartyMandate !== undefined) {
    if (body.counterparty === undefined) add("COUNTERPARTY_MANDATE", "a counterparty's mandate needs the counterparty it was granted by");
    else if (principalOfMandateId(body.counterpartyMandate.id) !== body.counterparty) add("COUNTERPARTY_MANDATE", "the counterparty's mandate is one the counterparty granted — its id is under the counterparty's DID (d91(a))");
  }
  if ((body.kind === "receipt" || body.kind === "finding") && body.practice !== true && body.grade === undefined) {
    add("GRADE_REQUIRED", "outside practice, a receipt or a finding states its counterparty's grade — grade 1 is the minimum for a customer (d91(d))");
  }
  if (body.grade !== undefined && body.counterparty === undefined) add("GRADE_WITHOUT_COUNTERPARTY", "the grade is the counterparty's signing ceremony's (d91(d)) — with no counterparty there is nothing to grade");
  if (body.grade === 0 && body.practice !== true) add("GRADE_ZERO_PRACTICE", "grade 0 — a one-time browser key — is practice only, never a customer's record (d91(d))");
  if (!(Date.parse(body.expiresAt) > Date.parse(body.claimedAt))) add("DATES", "an attestation expires after it is made (d27.5)");
  if (body.mandate !== undefined && principalOfMandateId(body.mandate.id) !== body.issuer) {
    add("MANDATE_PRINCIPAL", "a cited mandate is one the issuer granted — its id is under the issuer's DID (d91(a))");
  }
  const said = statementProblem(body.statement);
  if (said !== null) add("PERSON_IDENTITY", `the statement holds ${said} — it is plain words about the work, never a person's contact, link or identifier`);
  if (body.reference.id !== undefined) {
    const hit = findPersonIdentity(body.reference.id);
    if (hit !== null) add("PERSON_IDENTITY", `the reference's id holds ${hit.what} — a library id names a rule or a standard, never a person`);
  }
  if (body.batch !== undefined) batchFaults(body, add);
  return out;
}

/**
 * The rules of a batch accepted on a sample (1.1.0; specs/attestation/batch.md §5) that need no hashing: who may
 * answer, the plan's limits, census or draw, the positions found, and the exact plan and bound. The seal's
 * digest, the stamp, the blocks and whether each found position was drawn are `verifyAttestationRecord`'s.
 */
function batchFaults(body: AttestationBody, add: (code: AttestationFaultCode, message: string) => void): void {
  const b = body.batch!;
  const seal = b.seal;
  const plan = seal.plan;
  if (body.kind !== "receipt") add("BATCH_KIND", "a batch rides only on a receipt: the other side's acceptance of the items (d91(a))");
  if (body.reference.kind !== "artefact") add("BATCH_REFERENCE", "a batch's receipt is made against the batch itself: an artefact reference naming the seal's digest");
  if (body.counterparty !== undefined && !KEY_DID_PATTERN.test(body.counterparty)) {
    add("BATCH_BY_A_PERSON", "a person answers for a batch, with a key made for this relationship — never an organisation's own key, which a machine can hold (d84 P3; d88)");
  }
  if (body.grade === 3) add("BATCH_BY_A_PERSON", "grade 3 is the organisation signing as itself, which a machine can do — a person answers for a batch (d84 P3; d88)");

  let sane = true;
  const limit = (message: string): void => {
    sane = false;
    add("BATCH_LIMITS", message);
  };
  if (plan.sample > seal.size) limit("a draw takes at most every item in the batch");
  if (plan.accept >= plan.sample) limit("a plan accepts fewer short items than it draws — one that accepts as many passes anything, and bounds nothing");
  const a = alphaProblem(plan.alpha);
  if (a !== null) limit(a);

  const census = plan.sample === seal.size;
  if (census && (seal.draw !== undefined || b.stamp !== undefined || b.blocks !== undefined || b.coinbase !== undefined)) {
    add("BATCH_CENSUS", "a census checks every item: it carries no draw, stamp, blocks or coinbase");
  }
  // The coinbase is the draw block's own word for its height (BIP34; PY-5r): without it, the headers could end at any block.
  if (!census && (seal.draw === undefined || b.stamp === undefined || b.blocks === undefined || b.coinbase === undefined)) {
    add("BATCH_CENSUS", "a sampled batch names its draw block in the seal and carries the stamp, the blocks, and the draw block's coinbase that names its height");
  }

  let foundSane = true;
  for (let k = 0; k < b.found.length; k++) {
    const pos = b.found[k]!;
    if (pos >= seal.size || (k > 0 && pos <= b.found[k - 1]!)) {
      foundSane = false;
      add("BATCH_FOUND", "the positions found short are listed once each, ascending, each inside the batch");
      break;
    }
  }
  if (b.found.length > plan.sample) {
    foundSane = false;
    add("BATCH_FOUND", "more positions are found short than the plan draws");
  }

  if (b.found.length > plan.accept) {
    if (body.outcome === "accepted") {
      add("BATCH_OVER_PLAN", `${b.found.length} were found short and the plan accepts at most ${plan.accept}: the batch can only be answered not yet — never accepted, and never an automatic no (d84 P3)`);
    } else if (!(body.reasons ?? []).includes(OVER_PLAN_REASON)) {
      add("BATCH_OVER_PLAN", `a not yet over the plan says so: its reasons include ${OVER_PLAN_REASON}`);
    }
  } else if ((body.reasons ?? []).includes(OVER_PLAN_REASON)) {
    // PY-5r: the converse — the record would say of itself what is not so.
    add("BATCH_OVER_PLAN", `${b.found.length} found short is within the plan, which accepts up to ${plan.accept}: the reason ${OVER_PLAN_REASON} would say otherwise — a not yet within the plan gives its own reasons`);
  }

  if (!sane) return;
  // Two evaluations each, never a search (batch.md §4): a fault says which way a figure is off; the maker's
  // limitOf and boundOf find the exact one. A search here let a record shaped to be wrong hold a checker for
  // minutes (PY-5r).
  const chance = `a chance of ${plan.alpha.num} in ${plan.alpha.den}`;
  const lv = limitVerdict({ size: seal.size, sample: plan.sample, accept: plan.accept, alpha: plan.alpha, limit: plan.limit });
  if (lv !== "exact") {
    add("BATCH_PLAN", `the plan's limit, ${plan.limit}, is ${lv}: with ${plan.sample} drawn, ${plan.accept} accepted and ${chance}, the exact limit is ${lv === "too high" ? "lower" : "higher"} — limitOf finds it; a checker never searches`);
  }
  if (!foundSane) return;
  const bv = boundVerdict({ size: seal.size, sample: plan.sample, found: b.found.length, alpha: plan.alpha, bound: b.bound });
  if (bv !== "exact") {
    add("BATCH_BOUND", `the bound, ${b.bound}, is ${bv}: with ${b.found.length} found short among ${plan.sample} drawn and ${chance}, the exact bound is ${bv === "too high" ? "lower" : "higher"} — boundOf finds it; a checker never searches`);
  }
}

/** The cross-field rules of `kash.mandate@1.0.0`, on a body whose shape already validates. */
export function mandateFaults(body: MandateBody): readonly Fault<MandateFaultCode>[] {
  const out: Fault<MandateFaultCode>[] = [];
  const add = (code: MandateFaultCode, message: string): void => {
    out.push({ code, message });
  };
  const s = body.scope;
  const kind = body.delegate.kind;

  if (principalOfMandateId(body.id) !== body.principal) add("ID_PRINCIPAL", "a mandate's id is under its principal's DID");
  if (body.delegate.key === body.principal) add("DELEGATE_IS_PRINCIPAL", "a principal signing as itself needs no mandate (d91(a))");
  if ([s.kinds, s.outcomes, s.dsts, s.profiles, s.references].every((x) => x === undefined || x.length === 0)) {
    add("SCOPE_EMPTY", "a mandate is bounded: it names the kinds, outcomes, tags, profiles or references it covers (d91(a): with scope and expiry)");
  }
  // A refusal carries a person-role signature: only a seat or a representative may carry one (d91(f)).
  if ((kind === "agent" || kind === "desk" || kind === "organisation") && (s.outcomes === undefined || s.outcomes.includes("refused"))) {
    add("MACHINE_REFUSAL", `a${kind === "agent" ? "n agent" : kind === "desk" ? " desk" : "nother organisation"}'s mandate names its outcomes, and refused is never one — a refusal carries a person-role signature and never a machine mandate (d91(f); d84 P3)`);
  }
  if (kind === "agent" && (s.kinds === undefined || s.kinds.some((k) => !AGENT_KINDS.includes(k)))) {
    add("AGENT_SCOPE", "an agent's mandate names its kinds, and they are receipts only — agents prepare and carry; they never decide, judge a deviation, assure or contest (d88; d84 F; d43)");
  }
  if (kind === "desk" && (s.kinds === undefined || s.kinds.some((k) => k !== "decision"))) {
    add("DESK_DECIDES_ONLY", "a desk's mandate is to apply a rule author's standing yes: decisions only (d91(a); d84 P3)");
  }
  const from = Date.parse(body.dates.from);
  const until = Date.parse(body.dates.until);
  if (!(until > from) || until - from > MAX_MANDATE_DAYS * DAY_MS) add("DATES", `a mandate ends after it starts, and within ${MAX_MANDATE_DAYS} days (d43: everything renews)`);
  if (body.delegate.role !== undefined) {
    const said = statementProblem(body.delegate.role);
    if (said !== null) add("PERSON_IDENTITY", `the role holds ${said} — a mandate names a role and a key, never a person (d97: a seat is a sign-in with a mandate, never a file on a person)`);
  }
  return out;
}

export interface Checked<B, C extends string> {
  readonly ok: boolean;
  readonly body: B | null;
  readonly faults: readonly Fault<C>[];
}

/** The shape — the newest, 1.1.0, of which every 1.0.0 body is one — then the cross-field rules. */
export function checkAttestation(value: unknown): Checked<AttestationBody, AttestationFaultCode> {
  const v = validate<AttestationBody>(KASH_ATTESTATION_1_1_BODY_SCHEMA, value);
  if (!v.ok) return { ok: false, body: null, faults: v.errors.map((e) => ({ code: "SHAPE" as const, message: `$.${e.path.join(".")}: ${e.message}` })) };
  const faults = attestationFaults(v.value);
  return { ok: faults.length === 0, body: v.value, faults };
}

/** The shape, then the cross-field rules. */
export function checkMandate(value: unknown): Checked<MandateBody, MandateFaultCode> {
  const v = validate<MandateBody>(KASH_MANDATE_BODY_SCHEMA, value);
  if (!v.ok) return { ok: false, body: null, faults: v.errors.map((e) => ({ code: "SHAPE" as const, message: `$.${e.path.join(".")}: ${e.message}` })) };
  const faults = mandateFaults(v.value);
  return { ok: faults.length === 0, body: v.value, faults };
}
