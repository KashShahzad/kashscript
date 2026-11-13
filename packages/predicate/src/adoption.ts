/**
 * Adoption — an anchor adopts a rulebook's rule with its own local values
 * (ECOSYSTEM d85(b) rule 8, (c), (d)): written once, openly; executed locally,
 * within the bounds the rule states. `kash.adoption@1.0.0`, signed by the
 * anchor as itself (d62(d)2), DSSE `application/vnd.kash.adoption+json`.
 *
 * An anchor's adoption is its pact (d85(d)): the door it runs decides under the
 * rule with these values, and an automatic outcome is signed as the anchor's
 * standing decision. **An adoption names an organisation and numbers — never a
 * person**: its shape is closed, every value is typed and bounded, and string
 * values are read for contact details.
 */

import { canonicalize, canonicalizeBytes } from "@kashscript/identity-core";
import { sha256Hex } from "@kashscript/attest/chain";
import { signEnvelope, verifyEnvelope, type DsseEnvelope, type DsseSigner } from "@kashscript/attest/dsse";
import { base64ToBytes } from "@kashscript/attest/ed25519";
import { resolveVerificationKey } from "@kashscript/attest/signing";
import { validate } from "@kashscript/lexicons/schema";
import { KASH_ADOPTION_BODY_SCHEMA, type AdoptionBody, type Criterion1_1, type RuleBody1_1 } from "@kashscript/lexicons/extensions/door";
import { inBounds } from "./bounds";
import { parametersRead } from "./criteria";
import { fromJson, type FeelValue, type InputType } from "./feel";
import { CONTACT_PATTERNS } from "./vocabulary";
import { DAY, MAX_RENEW_DAYS } from "./constants";
import type { ReadRule } from "./rule";

export type { AdoptionBody } from "@kashscript/lexicons/extensions/door";

export const ADOPTION_PAYLOAD_TYPE = "application/vnd.kash.adoption+json" as const;

export type AdoptionRefusalCode = "SHAPE" | "RULE_MISMATCH" | "DRAFT" | "PRIVATE" | "ID_MISMATCH" | "NOT_ADOPTABLE" | "OUT_OF_BOUNDS" | "DATES" | "PERSON_IDENTITY";

export interface AdoptionValidation {
  readonly ok: boolean;
  readonly refusals: readonly { readonly code: AdoptionRefusalCode; readonly path: string; readonly message: string }[];
}

/** The parameters an anchor may set: a public rule's parameters that state bounds. The rest are fixed by the rulebook. */
export function adoptableParameters(rule: RuleBody1_1): string[] {
  if (rule.visibility !== "public") return [];
  return Object.entries(rule.parameters ?? {}).filter(([, p]) => p.bounds !== undefined && p.sealed === undefined).map(([n]) => n);
}

const sec = (s: string): number => Date.parse(s) / 1000;

/** Validate an adoption against the rule it names. Pure. */
export function validateAdoption(body: unknown, rule: ReadRule): AdoptionValidation {
  const refusals: { code: AdoptionRefusalCode; path: string; message: string }[] = [];
  const refuse = (code: AdoptionRefusalCode, path: string, message: string): void => {
    refusals.push({ code, path, message });
  };
  const shape = validate<AdoptionBody>(KASH_ADOPTION_BODY_SCHEMA, body);
  if (!shape.ok) {
    for (const e of shape.errors) refuse("SHAPE", `$.${e.path.join(".")}`, e.message);
    return { ok: false, refusals };
  }
  const a = shape.value;
  const r = rule.body;
  if (!a.id.startsWith(`${a.anchor}/adoption/`)) refuse("ID_MISMATCH", "$.id", "an adoption's id is its anchor's DID, then /adoption/, then its slug");
  if (a.rule.id !== r.id || a.rule.version !== r.version || a.rule.hash !== rule.hash) refuse("RULE_MISMATCH", "$.rule", "an adoption names the exact rule, version and hash it adopts");
  if (r.draft === true) refuse("DRAFT", "$.rule", "a draft is published for comment — it cannot be adopted");
  if (r.visibility !== "public") refuse("PRIVATE", "$.rule", "a private rule's thresholds are sealed by its author — it cannot be adopted with local values");

  const adoptable = new Set(adoptableParameters(r));
  for (const [name, raw] of Object.entries(a.parameters)) {
    const at = `$.parameters.${name}`;
    const p = r.parameters?.[name];
    if (p === undefined) {
      refuse("NOT_ADOPTABLE", at, `the rule has no parameter ${name}`);
      continue;
    }
    if (!adoptable.has(name)) {
      refuse("NOT_ADOPTABLE", at, `${name} states no bounds, so the rulebook fixes it — an anchor sets only what the rule bounds`);
      continue;
    }
    const value = fromJson(raw, p.type as InputType);
    if (value === null) refuse("OUT_OF_BOUNDS", at, `the value does not read as a ${p.type}`);
    else if (!inBounds(p, value)) refuse("OUT_OF_BOUNDS", at, `${String(raw)} is outside the bounds the rule states for ${name}`);
    if (typeof raw === "string") {
      for (const { what, find } of CONTACT_PATTERNS) if (find(raw) !== null) refuse("PERSON_IDENTITY", at, `carries ${what} — an adoption names an anchor and its values, never a person`);
    }
  }

  // d43: it renews and ends, within the rule's own life.
  const adopted = sec(a.dates.adopted);
  const renew = sec(a.dates.renewBy);
  const end = sec(a.dates.endsAt);
  if (!(adopted < renew && renew <= end)) refuse("DATES", "$.dates", "adopted, then renewed, then ended — in that order");
  if (renew - adopted > MAX_RENEW_DAYS * DAY) refuse("DATES", "$.dates.renewBy", `an adoption is reviewed within ${MAX_RENEW_DAYS} days`);
  if (adopted < sec(r.dates.published) || end > sec(r.dates.endsAt)) refuse("DATES", "$.dates", "an adoption lives within the rule it adopts");
  return { ok: refusals.length === 0, refusals };
}

export class AdoptionError extends Error {
  constructor(
    message: string,
    readonly refusals: AdoptionValidation["refusals"] = [],
  ) {
    super(message);
    this.name = "AdoptionError";
  }
}

export interface ReadAdoption {
  readonly body: AdoptionBody;
  readonly hash: string;
  readonly envelope: DsseEnvelope;
}

/** Sign a valid adoption as its anchor. */
export async function signAdoption(body: AdoptionBody, rule: ReadRule, signer: DsseSigner): Promise<DsseEnvelope> {
  const v = validateAdoption(body, rule);
  if (!v.ok) throw new AdoptionError(`the adoption does not validate: ${v.refusals.map((r) => r.code).join(", ")}`, v.refusals);
  if (signer.keyid.split("#")[0] !== body.anchor) throw new AdoptionError("an adoption is signed by its anchor's own key");
  return signEnvelope(body, ADOPTION_PAYLOAD_TYPE, signer, { canonical: true });
}

/** Read a signed adoption offline, from its anchor's DID, against the rule it adopts. Throws `AdoptionError`. */
export async function readAdoption(envelope: DsseEnvelope, rule: ReadRule): Promise<ReadAdoption> {
  if (envelope?.payloadType !== ADOPTION_PAYLOAD_TYPE) throw new AdoptionError("not an adoption");
  let result;
  try {
    result = await verifyEnvelope(envelope, (keyid) => resolveVerificationKey(keyid));
  } catch {
    throw new AdoptionError("the envelope does not read");
  }
  if (result.payloadJson === undefined) throw new AdoptionError("the envelope does not read");
  const body = result.payloadJson as AdoptionBody;
  const anchor = typeof body?.anchor === "string" ? body.anchor : null;
  if (!result.ok || anchor === null || !result.verifiedKeyids.some((k) => k.split("#")[0] === anchor)) throw new AdoptionError("the adoption is not signed by its anchor");
  const bytes = base64ToBytes(envelope.payload);
  if (canonicalize(body) !== new TextDecoder().decode(bytes)) throw new AdoptionError("the signed bytes are not the adoption's canonical form");
  const v = validateAdoption(body, rule);
  if (!v.ok) throw new AdoptionError(`the adoption does not validate: ${v.refusals.map((r) => r.code).join(", ")}`, v.refusals);
  return { body, hash: await sha256Hex(bytes), envelope };
}

/** SHA-256 hex over JCS of the body — the exact bytes the anchor signs. */
export function adoptionHash(body: AdoptionBody): Promise<string> {
  return sha256Hex(canonicalizeBytes(body));
}

/**
 * The adopted parameters a criterion's condition reads. An issuer's predicate
 * says a criterion is met under the rule's own values, so it does not answer a
 * criterion whose threshold the anchor set: there the receipts are read.
 */
export function adoptedRead(rule: RuleBody1_1, c: Criterion1_1, adoption: { readonly body: AdoptionBody } | undefined): string[] {
  if (adoption === undefined) return [];
  const set = new Set(Object.keys(adoption.body.parameters));
  return parametersRead(rule, c).filter((n) => set.has(n));
}

/** Is the adoption in force at `nowSec` — adopted, and not yet ended? */
export function adoptionInForce(adoption: { readonly body: AdoptionBody }, nowSec: number): boolean {
  return sec(adoption.body.dates.adopted) <= nowSec && nowSec < sec(adoption.body.dates.endsAt);
}

/** The adoption's local values, read as the rule types them — what the evaluator puts over the rule's own. */
export function adoptedValues(rule: RuleBody1_1, adoption: { readonly body: AdoptionBody } | undefined): Record<string, FeelValue> {
  const out: Record<string, FeelValue> = {};
  if (adoption === undefined) return out;
  for (const [name, raw] of Object.entries(adoption.body.parameters)) {
    const p = rule.parameters?.[name];
    if (p !== undefined) out[name] = fromJson(raw, p.type as InputType);
  }
  return out;
}
