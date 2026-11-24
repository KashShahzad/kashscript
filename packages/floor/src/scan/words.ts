/**
 * Words, matched as whole tokens: `trustScore` is trust + score, `COMMISSION_RATE_BPS` is commission + rate + bps,
 * `yPercent` is y + percent. A token is never a substring: `Commissioner` is not `commission`, `startDate` is not `star`.
 */

export function tokens(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((t) => t.length > 0)
    .map((t) => t.toLowerCase());
}

const set = (...w: string[]): ReadonlySet<string> => new Set(w);

/** Nouns that name a person (a model, a table, a lexicon, a field's subject). */
export const PERSON_NOUNS = set(
  "user", "users", "person", "persons", "people", "member", "members", "guest", "guests", "holder", "holders",
  "profile", "profiles", "account", "accounts", "traveller", "travellers", "traveler", "travelers", "reviewer",
  "reviewers", "applicant", "applicants", "student", "students", "worker", "workers", "employee", "employees",
  "customer", "customers", "contact", "contacts", "participant", "participants", "attendee", "attendees", "visitor",
  "visitors", "seat", "seats", "enrolment", "enrolments", "enrollment", "enrollments", "doer", "doers", "author",
  "authors", "follower", "followers", "invitee", "invitees", "recipient", "recipients", "beneficiary",
  "beneficiaries", "learner", "learners", "intern", "interns", "supervisor", "supervisors", "trainee", "trainees",
  "donor", "donors", "voter", "voters", "resident", "residents", "staff", "signer", "signers", "patient", "patients",
  "citizen", "citizens", "reporter", "reporters", "operator", "operators", "assignee", "assignees", "driver",
  "drivers", "candidate", "candidates", "freelancer", "freelancers", "talent", "talents", "identity", "identities",
);

/** Path segments that name persons. Seats are mandates (d97), so not here; nor `me`, which is the caller's own. */
export const PATH_PERSON_NOUNS = set(
  "user", "users", "person", "persons", "people", "member", "members", "guest", "guests", "holder", "holders",
  "profile", "profiles", "account", "accounts", "traveller", "travellers", "traveler", "travelers", "reviewer",
  "reviewers", "applicant", "applicants", "student", "students", "worker", "workers", "employee", "employees",
  "customer", "customers", "contact", "contacts", "participant", "participants", "attendee", "attendees", "visitor",
  "visitors", "follower", "followers", "invitee", "invitees", "recipient", "recipients", "beneficiary",
  "beneficiaries", "learner", "learners", "intern", "interns", "trainee", "trainees", "donor", "donors", "voter",
  "voters", "resident", "residents", "staff", "signer", "signers", "patient", "patients", "citizen", "citizens",
  "candidate", "candidates", "client", "clients", "driver", "drivers", "operator", "operators", "assignee", "assignees",
  "provider", "providers", "freelancer", "freelancers", "talent", "identity", "identities", "directory", "directories",
);

/** Suffixes that make a field a reference to its noun: userId, holderDid, guestEmail, traveller_rel. */
const REF_SUFFIX = set("id", "ids", "did", "dids", "ref", "rel", "key", "uuid", "email", "phone", "name", "handle");

/** Tokens that make a column an actor's, not the row's subject: created_by, reporter_id, owner_account_id, decided_by. */
const ACTOR = set(
  "created", "updated", "deleted", "modified", "by", "reporter", "reported", "submitted", "submitter", "owner",
  "author", "decided", "decider", "approved", "approver", "reviewed", "inviter", "issued", "issuer", "assigned",
  "actor", "creator", "editor", "requester", "sender",
);

export function namesPerson(name: string): boolean {
  return tokens(name).some((t) => PERSON_NOUNS.has(t));
}

/** A field that refers to a person: a person noun, alone or with a reference suffix (userId, holderDid). */
export function isPersonRef(field: string): boolean {
  const t = tokens(field);
  if (t.length === 0) return false;
  const last = t[t.length - 1]!;
  const nouns = REF_SUFFIX.has(last) ? t.slice(0, -1) : t;
  return nouns.length > 0 && nouns.some((n) => PERSON_NOUNS.has(n));
}

/** A person reference that names the row's subject, not an actor who wrote it (SQL and Prisma; lexicons stay strict). */
export function isSubjectRef(field: string): boolean {
  return isPersonRef(field) && !tokens(field).some((t) => ACTOR.has(t));
}

export function isActorColumn(field: string): boolean {
  return tokens(field).some((t) => ACTOR.has(t));
}

/** Score-shaped tokens (d27, d41, d42, d43, d85(b)3, the standard §7). `grade` is handled by the caller. */
export const SCORE = set(
  "score", "scores", "scoring", "rank", "ranks", "ranking", "rankings", "ranked", "rating", "ratings", "rated",
  "star", "stars", "average", "averages", "avg", "mean", "median", "percentile", "percentiles", "karma", "reputation",
  "kudos", "xp", "points", "streak", "streaks", "badge", "badges", "risk", "trust", "reliability", "standing",
  "leaderboard", "leaderboards", "conformance", "percent", "percentage", "pct", "ratio",
);

/** Count-shaped tokens: on a person, a count is watching (d43, the standard §7). */
export const COUNT = set("count", "counts", "tally", "tallies", "total", "totals", "num");

/** Money tokens: a `total_pkr` is a price, not a count. */
export const MONEY = set(
  "price", "prices", "pricing", "fee", "fees", "cost", "costs", "charge", "charges", "tariff", "tariffs", "amount",
  "usd", "pkr", "eur", "gbp", "aed", "sar", "paid", "bill", "billing", "credit", "credits", "commission",
  "commissions", "discount",
);

/** Objects that bear a signature and its grade (d91: a grade is a property of the signature, never of a person). */
export const SIGNING = set(
  "acceptance", "acceptances", "receipt", "receipts", "signature", "signatures", "signer", "ceremony", "key", "keys",
  "countersign", "countersignature", "countersignatures", "attestation", "attestations", "bundle", "bundles",
  "envelope", "envelopes",
);

/** Is this field score-shaped, given the object it sits on? */
export function scoreShaped(field: string, objectName: string): boolean {
  const t = tokens(field);
  if (t.some((x) => SCORE.has(x))) return true;
  if (t.includes("grade") || t.includes("grades")) return !tokens(objectName).some((x) => SIGNING.has(x));
  if (t.some((x) => COUNT.has(x))) return !t.some((x) => MONEY.has(x));
  // A rate, a level or a tier on a person ranks them (an on-time rate, a loyalty tier); a money rate does not.
  if (t.some((x) => ["rate", "rates", "level", "levels", "tier", "tiers"].includes(x))) return !t.some((x) => MONEY.has(x));
  return false;
}

/** Objects a person answers: a decline of one leaves no trace (d49(a), the standard §2.7). */
export const ANSWER_OBJECTS = set(
  "ask", "asks", "approval", "approvals", "request", "requests", "invite", "invites", "invitation", "invitations",
  "consent", "consents", "confirmation", "confirmations", "acceptance", "acceptances", "answer", "answers", "rsvp",
  "rsvps", "response", "responses", "reply", "replies", "offer", "offers",
);

export function isAnswerObject(name: string): boolean {
  return tokens(name).some((t) => ANSWER_OBJECTS.has(t));
}

/** Objects that are decisions by their name. */
const DECISION_NAMES = set("decision", "decisions", "verdict", "verdicts", "ruling", "rulings", "determination", "determinations");
/** Fields that make an object a decision: its last token. */
const DECISION_FIELDS = set("verdict", "classification", "ruling", "determination");

export function namesDecision(name: string): boolean {
  const t = tokens(name);
  return t.some((x) => DECISION_NAMES.has(x)) && !t.some((x) => x === "rule" || x === "rules" || x === "template" || x === "policy");
}

export function isDecisionField(field: string): boolean {
  const t = tokens(field);
  return t.length > 0 && DECISION_FIELDS.has(t[t.length - 1]!);
}

export type DeclineKind = "decline" | "refusal" | "no-show";

/** What a state value says: a decline (d49), a refusal outcome (P3), a no-show, or nothing of these. */
export function declineKind(value: string): DeclineKind | undefined {
  const t = tokens(value);
  const s = ` ${t.join(" ")} `;
  if (/ (declined|decline|declines|rejected|reject|rejection|optout|optedout) /.test(s)) return "decline";
  if (/ (opted|opt) out | turned down | said no /.test(s)) return "decline";
  if (/ (noshow|noshowed) | no show(ed)? | not come | did not (come|go) | didnt (come|go) /.test(s)) return "no-show";
  if (/ (refused|refusal|refuse) /.test(s)) return "refusal";
  if (s === " no " || s === " partial ") return "refusal";
  return undefined;
}

/** A query parameter that filters on an outcome: a refusal query (d91(h)). */
export function isOutcomeFilter(param: string): boolean {
  const t = tokens(param);
  return t.some((x) => ["outcome", "outcomes", "verdict", "verdicts", "result", "results", "decision", "decisions", "refused", "declined", "refusal", "refusals"].includes(x));
}

/**
 * A parameter that identifies a person: an email or phone anywhere; a person-qualified id, did or name (holderDid,
 * userId); a bare `did` or `name` only where the route is about a person or a record.
 */
export function isPersonIdentifier(param: string, subject: string): boolean {
  const t = tokens(param);
  if (t.some((x) => ["email", "emails", "phone", "mobile", "msisdn", "cnic", "nic", "passport", "ssn", "dob", "birthdate", "birthday"].includes(x))) return true;
  if (t.length >= 2 && isPersonRef(param)) return true;
  if (t.length === 1 && PERSON_NOUNS.has(t[0]!)) return true;
  if ((subject === "person" || subject === "record") && t.length === 1 && (t[0] === "did" || t[0] === "name")) return true;
  return false;
}

/* ── prices ─────────────────────────────────────────────────────────────── */

const PER_FORBIDDEN = set(
  "record", "records", "receipt", "receipts", "check", "checks", "checking", "verification", "verifications", "verify",
  "issue", "issues", "issuance", "presentation", "presentations", "present", "hold", "holding", "request", "requests",
  "ask", "asks", "answer", "answers", "decline", "declines", "view", "views", "lookup", "lookups", "confirmation",
  "confirmations", "session", "sessions", "signature", "signatures", "voucher", "vouchers", "thousand", "mille",
  "credential", "credentials", "attestation", "attestations", "proof", "proofs", "document", "documents", "call",
  "calls", "query", "queries", "scan", "scans",
);
const FEE_TOKENS = set("fee", "fees", "price", "prices", "cost", "costs", "charge", "charges", "tariff", "tariffs");
const PERCENT = set(
  "percent", "percentage", "pct", "bps", "permille", "commission", "commissions", "markup", "margin", "cut", "share",
  "royalty", "royalties", "split",
);

/**
 * A price name the floor refuses (the status note of 2026-11-12: no price for issuing, holding, presenting or checking
 * a record; no percentage of anything). `inPriceContext` is true inside a price file, or when the name's container is
 * itself named for money.
 */
export function forbiddenPrice(name: string, inPriceContext: boolean): string | undefined {
  const t = tokens(name);
  const s = ` ${t.join(" ")} `;
  const per = t.indexOf("per");
  const money = inPriceContext || t.some((x) => MONEY.has(x));
  if (per >= 0 && per + 1 < t.length && PER_FORBIDDEN.has(t[per + 1]!) && money) return `a price per ${t[per + 1]}`;
  if (t.some((x) => FEE_TOKENS.has(x))) {
    const obj = t.find((x) => PER_FORBIDDEN.has(x) && x !== "thousand" && x !== "mille");
    if (obj !== undefined) return `a price on ${obj}`;
  }
  const pct = t.find((x) => PERCENT.has(x));
  if (pct !== undefined && (money || ["commission", "commissions", "markup", "permille", "royalty", "royalties"].includes(pct))) return `a percentage (${pct})`;
  if (/ basis points? /.test(s) || / take rate /.test(s) || / fee rate /.test(s) || / (revenue|profit|platform) share /.test(s)) return "a percentage";
  return undefined;
}

/** Names that make a literal export a price (outside the price files). */
export function priceNamed(name: string): boolean {
  const t = tokens(name);
  if (t.some((x) => ["price", "prices", "pricing", "fee", "fees", "tariff", "tariffs", "commission", "commissions"].includes(x))) return true;
  return t.some((x) => ["percent", "percentage", "pct", "bps"].includes(x)) && t.some((x) => MONEY.has(x));
}

/** Currencies and bands: siblings named for them are one price in several bands (d55(e)). */
export const BAND_NAMES = set(
  "usd", "pkr", "eur", "gbp", "aed", "sar", "inr", "cny", "jpy", "cad", "aud", "chf", "sek", "nok", "dkk", "qar",
  "kwd", "omr", "bhd", "try", "bdt", "lkr", "npr", "myr", "sgd", "idr", "thb", "zar", "ngn", "kes", "egp", "global",
  "local",
);

export const DEFAULT_ENTRANCES: readonly string[] = ["link", "api", "door", "batch"];
