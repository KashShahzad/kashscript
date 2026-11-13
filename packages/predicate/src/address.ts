/**
 * The rule's address (ECOSYSTEM d85(c)): sector, anchor family, authority,
 * journey and the seven givens — area, spaces, capitals, culture, economy, time
 * and relations, VISION's seven pillars read as the context every service has
 * in space and time. **A rule is complete when all seven are answered** (d85(b)
 * rule 7); an incomplete one publishes only as a draft.
 *
 * Each given is written twice: `text` for people, and fields a machine can
 * compare. A place is always a reference — `did:kash:<publisher>/place/<slug>`
 * — and never a coordinate (d60).
 */

import { GIVENS, type Given, type RuleAddress, type RuleBody1_1 } from "@kashscript/lexicons/extensions/door";
import { parseDuration } from "./feel";
import { isicSection } from "./isic";

export interface AddressProblem {
  readonly path: string;
  readonly message: string;
}

export interface Completeness {
  /** The rule carries an address — a 1.1.0 rule. Without one it is a 1.0.0 rule. */
  readonly addressed: boolean;
  /** All seven givens answered. */
  readonly complete: boolean;
  readonly missing: readonly Given[];
}

export function completeness(rule: RuleBody1_1): Completeness {
  if (rule.address === undefined) return { addressed: false, complete: false, missing: [...GIVENS] };
  const missing = GIVENS.filter((g) => {
    const given = rule.address!.givens[g] as { text?: string } | undefined;
    return given === undefined || typeof given.text !== "string" || given.text.trim().length === 0;
  });
  return { addressed: true, complete: missing.length === 0, missing };
}

/** What the schema cannot say: a real ISIC section or division, durations that read, an area that agrees with itself. */
export function checkAddress(address: RuleAddress): AddressProblem[] {
  const out: AddressProblem[] = [];
  if (isicSection(address.sector.code) === null) {
    out.push({ path: "$.address.sector.code", message: `${address.sector.code} is not an ISIC Revision 5 section (A–V) or division` });
  }
  const g = address.givens;
  if (g.area?.anywhere === true && (g.area.countries !== undefined || g.area.places !== undefined)) {
    out.push({ path: "$.address.givens.area", message: "an area is anywhere, or it names countries or places — not both" });
  }
  for (const k of ["lasts", "renews"] as const) {
    const d = g.time?.[k];
    if (d !== undefined && parseDuration(d) === null) out.push({ path: `$.address.givens.time.${k}`, message: `${d} is not an ISO 8601 duration of one kind` });
  }
  return out;
}

/** Plain-language parts of the address a person's identity must never appear in. */
export function addressTexts(address: RuleAddress): { text: string; path: string }[] {
  const out: { text: string; path: string }[] = [];
  for (const g of GIVENS) {
    const given = address.givens[g] as { text?: string } | undefined;
    if (given?.text !== undefined) out.push({ text: given.text, path: `$.address.givens.${g}.text` });
  }
  if (address.authority.name !== undefined) out.push({ text: address.authority.name, path: "$.address.authority.name" });
  for (const n of address.givens.capitals?.needs ?? []) out.push({ text: n.what, path: "$.address.givens.capitals.needs" });
  return out;
}
