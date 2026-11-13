/**
 * The floor's vocabulary: the words validation refuses (d85(b) rules 1 and 3;
 * P4's second rule; node rule 10) and the known proxies it warns about, which
 * an author answers in writing (ECOSYSTEM d84 (f) P4; d27; d36; d43; GDPR art. 9).
 *
 * **It knows its subject** (KS-Q1b). d85(b) rule 1 — judged by what you can
 * show, never by who you are — binds **when the subject is a person, or an
 * organisation's people**. So a product's country of origin is allowed and a
 * person's is not; a place's district is allowed and a person's is warned; an
 * organisation's nationality (where it is registered) is allowed, and its
 * owners' gender is not. The table is in `SUBJECT_POLICY` and `specs/rule.md`.
 *
 * Matching is by whole tokens after splitting camelCase, snake_case and
 * kebab-case, so `placeOfBirth`, `place_of_birth` and `place-of-birth` all
 * read as "place of birth" — and `original`, `insect` and `orientation week`
 * do not match `origin`, `sect` or `sexual orientation`.
 *
 * **What this does not do:** a vocabulary catches what is named and obvious.
 * A rule that hides an ascribed identity behind a neutral word, or behind a
 * value no list names, passes this check; P5's one-page look before a new kind
 * of door, and the trust lists' consequence for breaking the floor (P4.7), are
 * the rest of the defence.
 */

import type { Subject } from "@kashscript/lexicons/extensions/door";

export type RefusalCategory = "SENSITIVE_CATEGORY" | "ASCRIBED_IDENTITY" | "ASKS_FOR_A_REFUSAL" | "READS_A_SCORE";
export type WarningCategory = "RESIDENCE_PROXY" | "NAME_PROXY" | "LANGUAGE_ORIGIN_PROXY" | "AGE_PROXY" | "FAMILY_STATUS_PROXY" | "APPEARANCE_PROXY" | "GRADE";

/** GDPR art. 9, the kinds that are only ever someone's identity — refused for a person, an organisation and a place. */
const SENSITIVE_IDENTITY: readonly string[] = [
  "race", "racial", "racial origin",
  "religion", "religions", "religious", "religious belief", "philosophical belief", "philosophical beliefs",
  "muslim", "christian", "hindu", "sikh", "parsi", "jewish", "buddhist", "atheist",
  "political opinion", "political opinions", "political party", "political affiliation", "political view", "political views", "party membership",
  "trade union", "trade unions", "union membership",
  "sexual", "sexuality", "sex life", "sexual orientation",
];

/** GDPR art. 9, the kinds a product or a place may legitimately be about (a medical device, a health facility). */
const SENSITIVE_DATA: readonly string[] = [
  "genetic", "genetics", "genome", "dna",
  "biometric", "biometrics", "fingerprint", "fingerprints", "iris scan", "face template", "faceprint",
  "health", "medical", "diagnosis", "disability", "disabilities", "disabled", "illness", "disease", "pregnancy", "pregnant", "hiv",
];

/** Where an organisation is registered, or a product or place comes from — not who anyone is. */
const JURISDICTION: readonly string[] = ["nationality", "nationalities", "citizenship", "origin", "origins", "country of origin", "place of origin"];

/** Ascribed identity: what someone is born into, never what they did (d85(b) rule 1; d27; d36). */
const ASCRIBED: readonly string[] = [
  "caste", "castes", "zaat", "zat", "biradari", "baradari", "qaum",
  "sect", "sects", "sectarian", "shia", "sunni", "ahmadi", "ismaili", "deobandi", "barelvi",
  "ethnic", "ethnicity", "ethnicities", "ethnic origin", "tribe", "tribes", "tribal", "clan", "clans",
  "lineage", "ancestry", "ancestries", "ancestor", "ancestors", "ancestral", "descent",
  "father name", "fathers name", "father s name", "mother name", "mothers name", "maiden name",
  "place of birth", "birth place", "birthplace", "country of birth", "birth country", "city of birth",
  "gender", "genders", "sex", "women", "woman", "female", "male", "men",
  ...JURISDICTION,
];

/** Node rule 10 and d85(b) rule 6: no rule may ask for a refusal. */
const REFUSAL: readonly string[] = [
  "refused", "refusal", "refusals", "rejected", "rejection", "rejections", "declined", "denied", "denial", "denials",
  "blacklist", "blacklisted", "blocklist", "blocklisted", "banned", "debarred",
];

/** d85(b) rule 3 and d43: nothing scores, rates or ranks a person. Providers and institutions may be compared. */
const SCORE: readonly string[] = [
  "score", "scores", "scoring", "credit score", "rank", "ranks", "ranking", "rankings", "ranked",
  "percentile", "percentiles", "percentage", "percent", "rating", "ratings",
];

/** Words that make a claim about an organisation a claim about its people (d85(b) rule 1: "or an organisation's people"). */
const PEOPLE: readonly string[] = [
  "staff", "employee", "employees", "worker", "workers", "member", "members", "owner", "owners", "owned", "founder", "founders",
  "director", "directors", "board", "workforce", "personnel", "people", "team", "shareholder", "shareholders", "partner", "partners",
  // …and a place's: what describes those who live there describes people.
  "resident", "residents", "inhabitant", "inhabitants", "population", "household", "households", "locals",
];

const WARN: Readonly<Record<WarningCategory, readonly string[]>> = {
  RESIDENCE_PROXY: ["address", "addresses", "postcode", "postal code", "zip", "zipcode", "zip code", "neighbourhood", "neighborhood", "district", "locality", "street", "hometown", "home town", "residence", "domicile"],
  NAME_PROXY: ["surname", "family name", "familyname", "last name", "lastname", "given name", "first name", "full name", "birth name"],
  LANGUAGE_ORIGIN_PROXY: ["mother tongue", "native language", "first language", "home language"],
  AGE_PROXY: ["birthdate", "birth date", "date of birth", "dob", "birth year", "year of birth"],
  FAMILY_STATUS_PROXY: ["marital", "marital status", "married", "spouse", "husband", "wife", "children", "dependants", "dependents"],
  APPEARANCE_PROXY: ["photo", "photos", "photograph", "portrait", "picture", "selfie", "face", "height", "weight"],
  GRADE: ["grade", "grades", "gpa", "cgpa"],
};

const REFUSE: Readonly<Record<RefusalCategory, readonly string[]>> = {
  SENSITIVE_CATEGORY: [...SENSITIVE_IDENTITY, ...SENSITIVE_DATA],
  ASCRIBED_IDENTITY: ASCRIBED,
  ASKS_FOR_A_REFUSAL: REFUSAL,
  READS_A_SCORE: SCORE,
};

/** `placeOfBirth` → "place of birth"; `zip_code` → "zip code". */
export function tokens(text: string): string[] {
  return text
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0);
}

function hits(text: string, terms: readonly string[]): string[] {
  const joined = ` ${tokens(text).join(" ")} `;
  return terms.filter((t) => joined.includes(` ${t} `));
}

export interface VocabularyHit<C extends string> {
  readonly category: C;
  readonly term: string;
}

/**
 * Which refusals bind for each subject. `people` means: only when the text
 * also names the organisation's people (its staff, owners, members…).
 */
export const SUBJECT_POLICY: Readonly<Record<Subject, { readonly ascribed: "all" | "except-jurisdiction" | "none"; readonly sensitiveIdentity: boolean; readonly sensitiveData: "all" | "people" | "none"; readonly score: boolean; readonly proxies: "all" | "people" | "none" }>> = {
  person: { ascribed: "all", sensitiveIdentity: true, sensitiveData: "all", score: true, proxies: "all" },
  organisation: { ascribed: "except-jurisdiction", sensitiveIdentity: true, sensitiveData: "people", score: false, proxies: "people" },
  product: { ascribed: "none", sensitiveIdentity: false, sensitiveData: "none", score: false, proxies: "none" },
  place: { ascribed: "except-jurisdiction", sensitiveIdentity: true, sensitiveData: "none", score: false, proxies: "none" },
};

/** Every refused word in `text`, by category, for a criterion about `subject` (a person unless said otherwise). */
export function refusedTerms(text: string, subject: Subject = "person"): VocabularyHit<RefusalCategory>[] {
  const p = SUBJECT_POLICY[subject];
  const aboutPeople = hits(text, PEOPLE).length > 0;
  const out: VocabularyHit<RefusalCategory>[] = [];
  for (const term of hits(text, REFUSAL)) out.push({ category: "ASKS_FOR_A_REFUSAL", term });
  for (const term of hits(text, ASCRIBED)) {
    // A jurisdiction word about an organisation's people (its owners' nationality) is about people again.
    const jurisdiction = JURISDICTION.includes(term);
    if (p.ascribed === "all" || (p.ascribed === "except-jurisdiction" && (!jurisdiction || aboutPeople))) out.push({ category: "ASCRIBED_IDENTITY", term });
  }
  if (p.sensitiveIdentity) for (const term of hits(text, SENSITIVE_IDENTITY)) out.push({ category: "SENSITIVE_CATEGORY", term });
  if (p.sensitiveData === "all" || (p.sensitiveData === "people" && aboutPeople)) for (const term of hits(text, SENSITIVE_DATA)) out.push({ category: "SENSITIVE_CATEGORY", term });
  if (p.score) for (const term of hits(text, SCORE)) out.push({ category: "READS_A_SCORE", term });
  return out;
}

/** Every known proxy in `text`, by category — for a person, or for an organisation's people. */
export function proxyTerms(text: string, subject: Subject = "person"): VocabularyHit<WarningCategory>[] {
  const p = SUBJECT_POLICY[subject];
  if (p.proxies === "none" || (p.proxies === "people" && hits(text, PEOPLE).length === 0)) return [];
  const out: VocabularyHit<WarningCategory>[] = [];
  for (const [category, terms] of Object.entries(WARN) as [WarningCategory, readonly string[]][]) {
    for (const term of hits(text, terms)) out.push({ category, term });
  }
  return out;
}

/** The lists, for the spec and for a test that keeps asks and rules agreeing. */
export const VOCABULARY = { refuse: REFUSE, warn: WARN, jurisdiction: JURISDICTION, people: PEOPLE } as const;

/** A run of at least ten digits, written as a phone number is — never a date, a time or an amount. */
function phoneIn(text: string): string | null {
  const scrubbed = text.replace(/\d{4}-\d{2}-\d{2}(?:T[\d:.]+(?:Z|[+-]\d{2}:\d{2})?)?/g, " ");
  for (const m of scrubbed.matchAll(/\+?\d[\d\s().-]{8,}\d/g)) {
    const digits = m[0].replace(/\D/g, "");
    if (digits.length >= 10 && !/^\d+\.\d+$/.test(m[0].trim())) return m[0];
  }
  return null;
}

/** An email, a phone number or a DID in free text — a person's identity has no place in a rule. */
export const CONTACT_PATTERNS: readonly { readonly what: string; readonly find: (text: string) => string | null }[] = [
  { what: "an email address", find: (t) => /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.exec(t)?.[0] ?? null },
  { what: "a phone number", find: phoneIn },
  { what: "a DID", find: (t) => /did:[a-z0-9]+:[A-Za-z0-9._%-]+/.exec(t)?.[0] ?? null },
];
