/**
 * Set-up packs (`kashscript-pack/1`) — PY-8 (ECOSYSTEM d94(b), d86, d96, d99; ADR-0029, ADR-0033).
 *
 * One pack format, a folder:
 *   - `pack.json`           the pack's metadata and empty labelled node-descriptor slot (ADR-0029)
 *   - `rule.json` + `rule.md`  the open rule (`kash.rule`), validated by `@kashscript/predicate`
 *   - `acceptance.json`     the acceptance words, who approves, and what approving does not prove
 *   - `screens.json`        the screens' configuration over Duedale's API, with a self-host path
 *   - `checklist.md`        the set-up checklist
 *   - `scope.json`          the fixed scope (what is covered, out of scope, and never done)
 *   - `buyer-supplies.json` what the buyer supplies before set-up starts
 *   - `floor.manifest.json` the pack's floor manifest, checked by `@kashscript/floor` (RW-17)
 *
 * Hard refusals at build time:
 *   - RW-17 (`@kashscript/floor`) missing;
 *   - any missing or malformed pack file, or a missing/unlabelled node-descriptor slot;
 *   - any price key, currency figure or percentage anywhere in the pack;
 *   - any of the three internal words (`studio`, `foundry`, `workshop`) or never-words in copy;
 *   - any open-rule refusal, unanswered warning or incomplete address;
 *   - `rule.md` drifting from `ruleHash(rule.json)` or omitting its open-data licence line;
 *   - any screen or API route in `screens.json` undeclared in `floor.manifest.json`, any waiver,
 *     or any finding from `@kashscript/floor/check` over the pack's compiled TypeScript mirror.
 */

import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import { canonicalize, signEventWith } from "@kashscript/identity-core";
import {
  DST_COUNTERSIGN_ACCEPTANCE,
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  countersignRequestDigest,
  pae,
  sha256HexOf,
  signBytes,
  signerDid,
  ulid,
  verifyCountersignBundle,
  type CountersignBundle,
  type DsseEnvelope,
  type SignedCountersignAcceptance,
  type SignedCountersignRequest,
} from "@kashscript/attest";
import { decodeCompactCountersignRequest } from "@kashscript/identity-server";
import { ruleHash, ruleToDcql, validateRule, type RuleBody } from "@kashscript/predicate";

import { KashCliError } from "./errors";

export const PACK_FORMAT = "kashscript-pack/1" as const;

export const PACK_FLOWS = ["client-sign-off", "internships-that-count", "host-receipts"] as const;
export type PackFlow = (typeof PACK_FLOWS)[number];

export const SCREEN_AUDIENCES = ["organisation", "approver", "holder", "viewer"] as const;
export type ScreenAudience = (typeof SCREEN_AUDIENCES)[number];

export interface PackFilesMap {
  readonly rule: string;
  readonly ruleDoc: string;
  readonly acceptance: string;
  readonly screens: string;
  readonly checklist: string;
  readonly scope: string;
  readonly buyerSupplies: string;
  readonly floor: string;
}

export interface PackManifest {
  readonly format: typeof PACK_FORMAT;
  readonly slug: string;
  readonly title: string;
  readonly forWhom: string;
  readonly summary: string;
  readonly cycle: string;
  /** Empty (`null`) and labelled until the one-engine merge specifies a kernel node descriptor (ADR-0029). */
  readonly descriptor: {
    readonly node: null;
    readonly label: string;
  };
  readonly files: PackFilesMap;
}

export interface PackAcceptance {
  readonly statement: string;
  readonly finalStatement?: string;
  readonly whoApproves: string;
  readonly whatApprovingSays: string;
  readonly doesNotProve: readonly string[];
  readonly whenNotReady: string;
}

export interface PackScreen {
  readonly id: string;
  readonly title: string;
  readonly audience: ScreenAudience;
  readonly route: string;
  readonly shows: readonly string[];
  readonly neverShows: readonly string[];
}

export interface PracticeEngagementConfig {
  readonly clientLabel: string;
  readonly scopeText: string;
  readonly scopeDays: number;
  readonly milestoneTitle: string;
  readonly doneMeans: string;
  readonly stack: readonly string[];
}

export interface PracticeInternshipConfig {
  readonly ruleTitle: string;
  readonly weeks: number;
  readonly hours: "asked" | "not-asked";
  readonly minimumHoursStated: number | null;
  readonly holdsDays: number;
  readonly recordsLastDays: number;
  readonly ruleText: string;
  readonly firstWeekSummary: string;
  readonly firstWeekHours?: number;
}

export interface PracticeBookingConfig {
  readonly appLabel: string;
  readonly door: "sabaat" | "suroor" | "safeer" | "maktub" | "rahmat" | "caravan" | "kumak";
  readonly listingSlug: string;
}

export interface PackScreensConfig {
  readonly engine: "duedale";
  readonly apiVersion: "v1";
  readonly selfHostPath: string;
  readonly flow: PackFlow;
  readonly recordProfile: string;
  readonly screens: readonly PackScreen[];
  readonly apiRoutes: readonly string[];
  readonly practice: {
    readonly engagement?: PracticeEngagementConfig;
    readonly internship?: PracticeInternshipConfig;
    readonly booking?: PracticeBookingConfig;
  };
}

export interface PackScope {
  readonly inScope: readonly string[];
  readonly outOfScope: readonly string[];
  readonly neverDoes: readonly string[];
  readonly fittingTerms: string;
}

export interface BuyerSupplyItem {
  readonly id: string;
  readonly label: string;
  readonly why: string;
  readonly format: string;
}

export interface PackBuyerSupplies {
  readonly items: readonly BuyerSupplyItem[];
}

export interface BuiltPack {
  readonly format: typeof PACK_FORMAT;
  readonly slug: string;
  readonly title: string;
  readonly forWhom: string;
  readonly summary: string;
  readonly cycle: string;
  readonly flow: PackFlow;
  readonly engine: "duedale";
  readonly descriptor: { readonly node: null; readonly label: string };
  readonly rule: {
    readonly id: string;
    readonly version: number;
    readonly sha256: string;
    readonly criteriaCount: number;
  };
  readonly files: Readonly<Record<string, string>>;
  readonly floor: {
    readonly ok: true;
    readonly routesChecked: number;
  };
}

export interface LoadedPack {
  readonly dir: string;
  readonly manifest: PackManifest;
  readonly rule: RuleBody;
  readonly ruleDoc: string;
  readonly acceptance: PackAcceptance;
  readonly screens: PackScreensConfig;
  readonly checklist: string;
  readonly scope: PackScope;
  readonly buyerSupplies: PackBuyerSupplies;
  readonly floorManifestRaw: Record<string, unknown>;
  readonly built: BuiltPack;
}

const SLUG_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
/** Duedale's own rule for an organisation's address name (`POST /api/v1/orgs`): 3–30 characters. */
const ENGINE_ORG_SLUG_RE = /^[a-z0-9][a-z0-9-]{2,29}$/;
const ENGINE_ORG_SLUG_MAX = 30;
const isObj = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const sha256File = (bytes: Uint8Array): string => createHash("sha256").update(bytes).digest("hex");

/** Tokens that smuggle a price, fee, currency or percentage into a pack (d50, d96, PY-8). */
const FORBIDDEN_PRICE_KEYS = new Set([
  "price", "prices", "pricing", "priced", "amount", "amounts", "fee", "fees", "cost", "costs",
  "charge", "charges", "tariff", "tariffs", "usd", "pkr", "eur", "gbp", "aed", "sar", "rupee",
  "rupees", "dollar", "dollars", "currency", "currencies", "commission", "commissions", "percent",
  "percentage", "pct", "bps", "permille", "discount", "markup", "margin", "royalty", "royalties",
]);

/** Currency figures or percentages in prose (`USD 100`, `$49`, `PKR 5,000`, `Rs. 500`, `10%`, `50 bps`). */
const CURRENCY_FIGURE_RE = /(?<![\w$])(?:USD|PKR|EUR|GBP|AED|SAR|Rs\.?)\s?\d[\d,.]*|(?<![\w$])[€£$]\s?\d[\d,.]*(?![\w[])/;
const PERCENT_FIGURE_RE = /\b\d+(?:\.\d+)?\s*(?:%|percent\b|bps\b|basis\s+points?\b)/i;

/** KashScript's three internal words — never shown to a customer (d94(a), (b), PY-8). */
const INTERNAL_WORDS: ReadonlyArray<readonly [string, RegExp]> = [
  ["studio", /\bstudio\b/i],
  ["foundry", /\bfoundry\b/i],
  ["workshop", /\bworkshops?\b/i],
];

/** Customer-copy never-words (d94(b), d7/d59(b), d88, CONTENT-AND-FLOW-STANDARD §1). */
const NEVER_COPY_WORDS: ReadonlyArray<readonly [string, RegExp, boolean]> = [
  ["template", /\btemplates?\b/i, false],
  ["GCC", /\bgcc\b/i, false],
  ["global capability centre", /global\s+capability\s+cent/i, false],
  ["virtual captive", /virtual\s+captive/i, false],
  ["sovereign", /\bsovereign\b/i, false],
  ["Passport", /\bpassport\b/i, false],
  ["DID", /\bDIDs?\b/g, false],
  ["guardrails", /\bguardrails?\b/i, false],
  ["trusted", /\btrusted\b/i, false],
  ["secure", /\bsecure(ly)?\b/i, false],
  ["reminder", /\breminders?\b/i, false],
  ["urgent", /\burgent(ly)?\b/i, false],
  ["last chance", /\blast\s+chance\b/i, false],
  ["act now", /\bact\s+now\b/i, false],
  ["works on a phone", /\bworks?\s+on\s+(a|any|your|every)\s+phone\b/i, true],
  ["conformant", /\bconformant\b/i, true],
  ["submit", /\bsubmit\b/i, false],
  ["click here", /\bclick\s+here\b/i, false],
];

const NEGATION_PREFIX = /\b(not|no|never|nothing|until|isn't|aren't)\b[^.;!?]*$/i;

function splitKeyTokens(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z0-9]+/)
    .filter((t) => t.length > 0)
    .map((t) => t.toLowerCase());
}

/** Load `@kashscript/floor/check` dynamically so a missing RW-17 installation stops with a plain report. */
async function loadFloorChecker(): Promise<{
  checkFloor: typeof import("@kashscript/floor/check").checkFloor;
  citesOf: typeof import("@kashscript/floor/check").citesOf;
}> {
  try {
    const mod = await import("@kashscript/floor/check");
    if (typeof mod.checkFloor !== "function" || typeof mod.citesOf !== "function") {
      throw new Error("@kashscript/floor/check did not export checkFloor");
    }
    return { checkFloor: mod.checkFloor, citesOf: mod.citesOf };
  } catch (err) {
    throw new KashCliError(
      "RW-17 (@kashscript/floor) has not run or is not installed here. Stop and report before building packs.",
      "FLOOR_UNAVAILABLE",
      err,
    );
  }
}

function readJson(absPath: string, label: string): unknown {
  if (!existsSync(absPath)) {
    throw new KashCliError(`Pack is missing ${label} (${absPath}).`, "PACK_INVALID");
  }
  try {
    return JSON.parse(readFileSync(absPath, "utf8"));
  } catch (err) {
    throw new KashCliError(`${label} is not valid JSON: ${(err as Error).message}`, "PACK_INVALID", err);
  }
}

function readText(absPath: string, label: string): string {
  if (!existsSync(absPath)) {
    throw new KashCliError(`Pack is missing ${label} (${absPath}).`, "PACK_INVALID");
  }
  const text = readFileSync(absPath, "utf8");
  if (text.trim().length === 0) {
    throw new KashCliError(`${label} must not be empty.`, "PACK_INVALID");
  }
  return text;
}

function requireClosedKeys(obj: Record<string, unknown>, where: string, allowed: readonly string[], optional: readonly string[] = []): void {
  const all = new Set([...allowed, ...optional]);
  for (const k of Object.keys(obj)) {
    if (!all.has(k)) {
      throw new KashCliError(`${where}.${k}: unexpected key (closed shape allows ${[...all].join(", ")}).`, "PACK_INVALID");
    }
  }
  for (const req of allowed) {
    if (!(req in obj) || obj[req] === undefined) {
      throw new KashCliError(`${where}.${req}: required field is missing.`, "PACK_INVALID");
    }
  }
}

function requireNonEmptyString(v: unknown, where: string): string {
  if (typeof v !== "string" || v.trim().length === 0) {
    throw new KashCliError(`${where}: must be a non-empty string.`, "PACK_INVALID");
  }
  return v;
}

function requireStringList(v: unknown, where: string, min = 1): readonly string[] {
  if (!Array.isArray(v) || v.length < min || !v.every((x) => typeof x === "string" && x.trim().length > 0)) {
    throw new KashCliError(`${where}: must be a list of at least ${min} non-empty string(s).`, "PACK_INVALID");
  }
  return v as readonly string[];
}

function scanNoPricesInJson(value: unknown, where: string): void {
  if (Array.isArray(value)) {
    value.forEach((item, idx) => scanNoPricesInJson(item, `${where}[${idx}]`));
    return;
  }
  if (isObj(value)) {
    for (const [k, v] of Object.entries(value)) {
      const hit = splitKeyTokens(k).find((t) => FORBIDDEN_PRICE_KEYS.has(t));
      if (hit !== undefined) {
        throw new KashCliError(
          `${where}.${k}: pack must not contain a price, fee, currency or percentage field ("${hit}").`,
          "PRICE_IN_PACK",
        );
      }
      scanNoPricesInJson(v, `${where}.${k}`);
    }
    return;
  }
  if (typeof value === "string") {
    scanNoPricesInText(value, where);
  }
}

function scanNoPricesInText(text: string, where: string): void {
  const cur = CURRENCY_FIGURE_RE.exec(text);
  if (cur !== null) {
    throw new KashCliError(
      `${where}: pack must not contain a price figure ("${cur[0].trim()}").`,
      "PRICE_IN_PACK",
    );
  }
  const pct = PERCENT_FIGURE_RE.exec(text);
  if (pct !== null) {
    throw new KashCliError(
      `${where}: pack must not contain a percentage figure ("${pct[0].trim()}").`,
      "PRICE_IN_PACK",
    );
  }
}

function scanCustomerCopy(text: string, where: string, opts: { allowDidUri?: boolean; allowMarkdownRuleHeading?: boolean } = {}): void {
  // Strip inline `did:kash:...` URI tokens before checking for bare uppercase "DID" in prose when allowed.
  const scrubbed = opts.allowDidUri ? text.replace(/did:[a-z0-9]+:[A-Za-z0-9._/%-]+/g, "") : text;
  for (const [word, re] of INTERNAL_WORDS) {
    if (re.test(scrubbed)) {
      throw new KashCliError(
        `${where}: pack must not show the internal word "${word}" to a customer (d94(a), (b)).`,
        "INTERNAL_WORD_IN_PACK",
      );
    }
  }
  for (const [word, re, negatable] of NEVER_COPY_WORDS) {
    const flags = re.flags.includes("g") ? re.flags : `${re.flags}g`;
    const globalRe = new RegExp(re.source, flags);
    for (const m of scrubbed.matchAll(globalRe)) {
      if (negatable) {
        const before = scrubbed.slice(Math.max(0, (m.index ?? 0) - 48), m.index ?? 0);
        if (NEGATION_PREFIX.test(before)) continue;
      }
      throw new KashCliError(
        `${where}: pack copy must not use "${word}" (d94(b), content standard).`,
        "COPY_VIOLATION",
      );
    }
  }
}

function scanCopyInJson(value: unknown, where: string, opts: { skipKeys?: ReadonlySet<string>; allowDidUri?: boolean } = {}): void {
  if (Array.isArray(value)) {
    value.forEach((v, i) => scanCopyInJson(v, `${where}[${i}]`, opts));
    return;
  }
  if (isObj(value)) {
    for (const [k, v] of Object.entries(value)) {
      if (opts.skipKeys?.has(k)) continue;
      scanCopyInJson(v, `${where}.${k}`, opts);
    }
    return;
  }
  if (typeof value === "string") {
    scanCustomerCopy(value, where, { ...(opts.allowDidUri === true ? { allowDidUri: true } : {}) });
  }
}

function parseManifest(raw: unknown): PackManifest {
  if (!isObj(raw)) throw new KashCliError("pack.json must be a JSON object.", "PACK_INVALID");
  requireClosedKeys(raw, "pack.json", ["format", "slug", "title", "forWhom", "summary", "cycle", "descriptor", "files"]);
  if (raw.format !== PACK_FORMAT) {
    throw new KashCliError(`pack.json.format must be "${PACK_FORMAT}".`, "PACK_INVALID");
  }
  const slug = requireNonEmptyString(raw.slug, "pack.json.slug");
  if (!SLUG_RE.test(slug)) {
    throw new KashCliError(`pack.json.slug ("${slug}") must be lowercase kebab-case.`, "PACK_INVALID");
  }
  if (INTERNAL_WORDS.some(([, re]) => re.test(slug))) {
    throw new KashCliError(`pack.json.slug ("${slug}") must not carry an internal word.`, "INTERNAL_WORD_IN_PACK");
  }
  const title = requireNonEmptyString(raw.title, "pack.json.title");
  const forWhom = requireNonEmptyString(raw.forWhom, "pack.json.forWhom");
  const summary = requireNonEmptyString(raw.summary, "pack.json.summary");
  const cycle = requireNonEmptyString(raw.cycle, "pack.json.cycle");

  if (!isObj(raw.descriptor)) throw new KashCliError("pack.json.descriptor must be an object.", "PACK_INVALID");
  requireClosedKeys(raw.descriptor, "pack.json.descriptor", ["node", "label"]);
  if (raw.descriptor.node !== null) {
    throw new KashCliError(
      "pack.json.descriptor.node must be null until the one-engine merge specifies a kernel node descriptor (ADR-0029).",
      "PACK_INVALID",
    );
  }
  const label = requireNonEmptyString(raw.descriptor.label, "pack.json.descriptor.label");

  if (!isObj(raw.files)) throw new KashCliError("pack.json.files must be an object.", "PACK_INVALID");
  requireClosedKeys(raw.files, "pack.json.files", ["rule", "ruleDoc", "acceptance", "screens", "checklist", "scope", "buyerSupplies", "floor"]);
  const files: PackFilesMap = {
    rule: requireNonEmptyString(raw.files.rule, "pack.json.files.rule"),
    ruleDoc: requireNonEmptyString(raw.files.ruleDoc, "pack.json.files.ruleDoc"),
    acceptance: requireNonEmptyString(raw.files.acceptance, "pack.json.files.acceptance"),
    screens: requireNonEmptyString(raw.files.screens, "pack.json.files.screens"),
    checklist: requireNonEmptyString(raw.files.checklist, "pack.json.files.checklist"),
    scope: requireNonEmptyString(raw.files.scope, "pack.json.files.scope"),
    buyerSupplies: requireNonEmptyString(raw.files.buyerSupplies, "pack.json.files.buyerSupplies"),
    floor: requireNonEmptyString(raw.files.floor, "pack.json.files.floor"),
  };
  for (const [k, rel] of Object.entries(files)) {
    if (rel.includes("..") || rel.startsWith("/") || rel.startsWith("\\")) {
      throw new KashCliError(`pack.json.files.${k} ("${rel}") must stay inside the pack folder.`, "PACK_INVALID");
    }
  }
  return { format: PACK_FORMAT, slug, title, forWhom, summary, cycle, descriptor: { node: null, label }, files };
}

function parseAcceptance(raw: unknown): PackAcceptance {
  if (!isObj(raw)) throw new KashCliError("acceptance.json must be a JSON object.", "PACK_INVALID");
  requireClosedKeys(
    raw,
    "acceptance.json",
    ["statement", "whoApproves", "whatApprovingSays", "doesNotProve", "whenNotReady"],
    ["finalStatement"],
  );
  return {
    statement: requireNonEmptyString(raw.statement, "acceptance.json.statement"),
    ...(raw.finalStatement !== undefined ? { finalStatement: requireNonEmptyString(raw.finalStatement, "acceptance.json.finalStatement") } : {}),
    whoApproves: requireNonEmptyString(raw.whoApproves, "acceptance.json.whoApproves"),
    whatApprovingSays: requireNonEmptyString(raw.whatApprovingSays, "acceptance.json.whatApprovingSays"),
    doesNotProve: requireStringList(raw.doesNotProve, "acceptance.json.doesNotProve", 2),
    whenNotReady: requireNonEmptyString(raw.whenNotReady, "acceptance.json.whenNotReady"),
  };
}

function parseScreens(raw: unknown): PackScreensConfig {
  if (!isObj(raw)) throw new KashCliError("screens.json must be a JSON object.", "PACK_INVALID");
  requireClosedKeys(raw, "screens.json", ["engine", "apiVersion", "selfHostPath", "flow", "recordProfile", "screens", "apiRoutes", "practice"]);
  if (raw.engine !== "duedale") throw new KashCliError('screens.json.engine must be "duedale" (d99).', "PACK_INVALID");
  if (raw.apiVersion !== "v1") throw new KashCliError('screens.json.apiVersion must be "v1".', "PACK_INVALID");
  const selfHostPath = requireNonEmptyString(raw.selfHostPath, "screens.json.selfHostPath");
  const flow = raw.flow;
  if (typeof flow !== "string" || !(PACK_FLOWS as readonly string[]).includes(flow)) {
    throw new KashCliError(`screens.json.flow must be one of ${PACK_FLOWS.join(", ")}.`, "PACK_INVALID");
  }
  const recordProfile = requireNonEmptyString(raw.recordProfile, "screens.json.recordProfile");
  if (!Array.isArray(raw.screens) || raw.screens.length === 0) {
    throw new KashCliError("screens.json.screens must be a non-empty list.", "PACK_INVALID");
  }
  const seenIds = new Set<string>();
  const screens: PackScreen[] = raw.screens.map((s, idx) => {
    const at = `screens.json.screens[${idx}]`;
    if (!isObj(s)) throw new KashCliError(`${at} must be an object.`, "PACK_INVALID");
    requireClosedKeys(s, at, ["id", "title", "audience", "route", "shows", "neverShows"]);
    const id = requireNonEmptyString(s.id, `${at}.id`);
    if (seenIds.has(id)) throw new KashCliError(`${at}.id ("${id}") is duplicated.`, "PACK_INVALID");
    seenIds.add(id);
    const audience = s.audience;
    if (typeof audience !== "string" || !(SCREEN_AUDIENCES as readonly string[]).includes(audience)) {
      throw new KashCliError(`${at}.audience must be one of ${SCREEN_AUDIENCES.join(", ")}.`, "PACK_INVALID");
    }
    const route = requireNonEmptyString(s.route, `${at}.route`);
    if (!route.startsWith("PAGE /")) {
      throw new KashCliError(`${at}.route ("${route}") must start with "PAGE /".`, "PACK_INVALID");
    }
    return {
      id,
      title: requireNonEmptyString(s.title, `${at}.title`),
      audience: audience as ScreenAudience,
      route,
      shows: requireStringList(s.shows, `${at}.shows`),
      neverShows: requireStringList(s.neverShows, `${at}.neverShows`),
    };
  });
  const apiRoutes = requireStringList(raw.apiRoutes, "screens.json.apiRoutes");
  if (!isObj(raw.practice)) throw new KashCliError("screens.json.practice must be an object.", "PACK_INVALID");
  requireClosedKeys(raw.practice, "screens.json.practice", [], ["engagement", "internship", "booking"]);

  let engagement: PracticeEngagementConfig | undefined;
  let internship: PracticeInternshipConfig | undefined;
  let booking: PracticeBookingConfig | undefined;

  if (flow === "client-sign-off") {
    const e = raw.practice.engagement;
    if (!isObj(e)) throw new KashCliError("screens.json.practice.engagement is required for client-sign-off.", "PACK_INVALID");
    requireClosedKeys(e, "screens.json.practice.engagement", ["clientLabel", "scopeText", "scopeDays", "milestoneTitle", "doneMeans", "stack"]);
    const scopeDays = e.scopeDays;
    if (typeof scopeDays !== "number" || !Number.isInteger(scopeDays) || scopeDays < 7 || scopeDays > 365) {
      throw new KashCliError("screens.json.practice.engagement.scopeDays must be an integer 7–365.", "PACK_INVALID");
    }
    engagement = {
      clientLabel: requireNonEmptyString(e.clientLabel, "screens.json.practice.engagement.clientLabel"),
      scopeText: requireNonEmptyString(e.scopeText, "screens.json.practice.engagement.scopeText"),
      scopeDays,
      milestoneTitle: requireNonEmptyString(e.milestoneTitle, "screens.json.practice.engagement.milestoneTitle"),
      doneMeans: requireNonEmptyString(e.doneMeans, "screens.json.practice.engagement.doneMeans"),
      stack: requireStringList(e.stack, "screens.json.practice.engagement.stack"),
    };
    if (!/practice/i.test(engagement.clientLabel)) {
      throw new KashCliError("screens.json.practice.engagement.clientLabel must say Practice (d11, d62(b)).", "PACK_INVALID");
    }
  } else if (flow === "internships-that-count") {
    const ic = raw.practice.internship;
    if (!isObj(ic)) throw new KashCliError("screens.json.practice.internship is required for internships-that-count.", "PACK_INVALID");
    requireClosedKeys(
      ic,
      "screens.json.practice.internship",
      ["ruleTitle", "weeks", "hours", "minimumHoursStated", "holdsDays", "recordsLastDays", "ruleText", "firstWeekSummary"],
      ["firstWeekHours"],
    );
    if (typeof ic.weeks !== "number" || !Number.isInteger(ic.weeks) || ic.weeks < 1 || ic.weeks > 52) {
      throw new KashCliError("screens.json.practice.internship.weeks must be 1–52.", "PACK_INVALID");
    }
    if (ic.hours !== "asked" && ic.hours !== "not-asked") {
      throw new KashCliError('screens.json.practice.internship.hours must be "asked" or "not-asked".', "PACK_INVALID");
    }
    if (ic.minimumHoursStated !== null && (typeof ic.minimumHoursStated !== "number" || ic.minimumHoursStated < 1)) {
      throw new KashCliError("screens.json.practice.internship.minimumHoursStated must be null or a positive integer.", "PACK_INVALID");
    }
    if (typeof ic.holdsDays !== "number" || typeof ic.recordsLastDays !== "number" || ic.recordsLastDays <= ic.holdsDays) {
      throw new KashCliError("screens.json.practice.internship.recordsLastDays must exceed holdsDays.", "PACK_INVALID");
    }
    const ruleTitle = requireNonEmptyString(ic.ruleTitle, "screens.json.practice.internship.ruleTitle");
    if (!/sample|practice/i.test(ruleTitle)) {
      throw new KashCliError("screens.json.practice.internship.ruleTitle must be labelled SAMPLE or Practice (d11).", "PACK_INVALID");
    }
    internship = {
      ruleTitle,
      weeks: ic.weeks,
      hours: ic.hours,
      minimumHoursStated: ic.minimumHoursStated as number | null,
      holdsDays: ic.holdsDays,
      recordsLastDays: ic.recordsLastDays,
      ruleText: requireNonEmptyString(ic.ruleText, "screens.json.practice.internship.ruleText"),
      firstWeekSummary: requireNonEmptyString(ic.firstWeekSummary, "screens.json.practice.internship.firstWeekSummary"),
      ...(typeof ic.firstWeekHours === "number" ? { firstWeekHours: ic.firstWeekHours } : {}),
    };
  } else {
    const b = raw.practice.booking;
    if (!isObj(b)) throw new KashCliError("screens.json.practice.booking is required for host-receipts.", "PACK_INVALID");
    requireClosedKeys(b, "screens.json.practice.booking", ["appLabel", "door", "listingSlug"]);
    const doors = ["sabaat", "suroor", "safeer", "maktub", "rahmat", "caravan", "kumak"] as const;
    if (typeof b.door !== "string" || !(doors as readonly string[]).includes(b.door)) {
      throw new KashCliError(`screens.json.practice.booking.door must be one of ${doors.join(", ")}.`, "PACK_INVALID");
    }
    const listingSlug = requireNonEmptyString(b.listingSlug, "screens.json.practice.booking.listingSlug");
    if (!SLUG_RE.test(listingSlug)) {
      throw new KashCliError("screens.json.practice.booking.listingSlug must be kebab-case.", "PACK_INVALID");
    }
    const appLabel = requireNonEmptyString(b.appLabel, "screens.json.practice.booking.appLabel");
    if (!/practice/i.test(appLabel)) {
      throw new KashCliError("screens.json.practice.booking.appLabel must say Practice (d11).", "PACK_INVALID");
    }
    booking = { appLabel, door: b.door as PracticeBookingConfig["door"], listingSlug };
  }

  return {
    engine: "duedale",
    apiVersion: "v1",
    selfHostPath,
    flow: flow as PackFlow,
    recordProfile,
    screens,
    apiRoutes,
    practice: {
      ...(engagement !== undefined ? { engagement } : {}),
      ...(internship !== undefined ? { internship } : {}),
      ...(booking !== undefined ? { booking } : {}),
    },
  };
}

function parseScope(raw: unknown): PackScope {
  if (!isObj(raw)) throw new KashCliError("scope.json must be a JSON object.", "PACK_INVALID");
  requireClosedKeys(raw, "scope.json", ["inScope", "outOfScope", "neverDoes", "fittingTerms"]);
  return {
    inScope: requireStringList(raw.inScope, "scope.json.inScope", 2),
    outOfScope: requireStringList(raw.outOfScope, "scope.json.outOfScope", 2),
    neverDoes: requireStringList(raw.neverDoes, "scope.json.neverDoes", 3),
    fittingTerms: requireNonEmptyString(raw.fittingTerms, "scope.json.fittingTerms"),
  };
}

function parseBuyerSupplies(raw: unknown): PackBuyerSupplies {
  if (!isObj(raw)) throw new KashCliError("buyer-supplies.json must be a JSON object.", "PACK_INVALID");
  requireClosedKeys(raw, "buyer-supplies.json", ["items"]);
  if (!Array.isArray(raw.items) || raw.items.length === 0) {
    throw new KashCliError("buyer-supplies.json.items must be a non-empty list.", "PACK_INVALID");
  }
  const seen = new Set<string>();
  const items: BuyerSupplyItem[] = raw.items.map((it, idx) => {
    const at = `buyer-supplies.json.items[${idx}]`;
    if (!isObj(it)) throw new KashCliError(`${at} must be an object.`, "PACK_INVALID");
    requireClosedKeys(it, at, ["id", "label", "why", "format"]);
    const id = requireNonEmptyString(it.id, `${at}.id`);
    if (seen.has(id)) throw new KashCliError(`${at}.id ("${id}") is duplicated.`, "PACK_INVALID");
    seen.add(id);
    return {
      id,
      label: requireNonEmptyString(it.label, `${at}.label`),
      why: requireNonEmptyString(it.why, `${at}.why`),
      format: requireNonEmptyString(it.format, `${at}.format`),
    };
  });
  return { items };
}

/**
 * Load, validate and check a pack folder against `@kashscript/predicate` and `@kashscript/floor`.
 * Offline: opens no socket and leaves no file inside the pack folder.
 */
export async function loadAndCheckPack(packDirArg: string): Promise<LoadedPack> {
  const { checkFloor, citesOf } = await loadFloorChecker();
  const dir = resolve(packDirArg);
  if (!existsSync(dir) || !statSync(dir).isDirectory()) {
    throw new KashCliError(`Pack folder does not exist: ${dir}`, "PACK_INVALID");
  }

  const packPath = join(dir, "pack.json");
  const rawPack = readJson(packPath, "pack.json");
  scanNoPricesInJson(rawPack, "pack.json");
  const manifest = parseManifest(rawPack);
  // Customer copy check on pack.json (descriptor.label cites ADR-0029, still must hold no internal words).
  scanCopyInJson(
    { title: manifest.title, forWhom: manifest.forWhom, summary: manifest.summary, cycle: manifest.cycle, descriptor: manifest.descriptor },
    "pack.json",
  );

  const abs = (rel: string): string => join(dir, rel);
  const rawRule = readJson(abs(manifest.files.rule), manifest.files.rule);
  const ruleDoc = readText(abs(manifest.files.ruleDoc), manifest.files.ruleDoc);
  const rawAcceptance = readJson(abs(manifest.files.acceptance), manifest.files.acceptance);
  const rawScreens = readJson(abs(manifest.files.screens), manifest.files.screens);
  const checklist = readText(abs(manifest.files.checklist), manifest.files.checklist);
  const rawScope = readJson(abs(manifest.files.scope), manifest.files.scope);
  const rawSupplies = readJson(abs(manifest.files.buyerSupplies), manifest.files.buyerSupplies);
  const rawFloor = readJson(abs(manifest.files.floor), manifest.files.floor);

  // Zero-price checks across every file in the pack.
  scanNoPricesInJson(rawRule, manifest.files.rule);
  scanNoPricesInText(ruleDoc, manifest.files.ruleDoc);
  scanNoPricesInJson(rawAcceptance, manifest.files.acceptance);
  scanNoPricesInJson(rawScreens, manifest.files.screens);
  scanNoPricesInText(checklist, manifest.files.checklist);
  scanNoPricesInJson(rawScope, manifest.files.scope);
  scanNoPricesInJson(rawSupplies, manifest.files.buyerSupplies);

  const acceptance = parseAcceptance(rawAcceptance);
  const screens = parseScreens(rawScreens);
  const scope = parseScope(rawScope);
  const buyerSupplies = parseBuyerSupplies(rawSupplies);

  if (!/^\s*1\.\s+/m.test(checklist)) {
    throw new KashCliError(`${manifest.files.checklist}: must contain numbered set-up steps ("1. …").`, "PACK_INVALID");
  }

  // Customer-copy checks across all JSON & Markdown files (never showing internal words or never-words).
  scanCopyInJson(rawRule, manifest.files.rule, { allowDidUri: true });
  scanCustomerCopy(ruleDoc, manifest.files.ruleDoc, { allowDidUri: true });
  scanCopyInJson(rawAcceptance, manifest.files.acceptance);
  scanCopyInJson(rawScreens, manifest.files.screens, { allowDidUri: true });
  scanCustomerCopy(checklist, manifest.files.checklist, { allowDidUri: true });
  scanCopyInJson(rawScope, manifest.files.scope);
  scanCopyInJson(rawSupplies, manifest.files.buyerSupplies);

  // Validate open rule with @kashscript/predicate.
  const ruleVerdict = validateRule(rawRule);
  const unanswered = ruleVerdict.warnings.filter((w) => w.answer === null);
  if (!ruleVerdict.ok || ruleVerdict.refusals.length > 0 || unanswered.length > 0 || !ruleVerdict.completeness.complete) {
    const reasons = [
      ...ruleVerdict.refusals.map((r) => `${r.path} [${r.code}]: ${r.message}`),
      ...unanswered.map((w) => `${w.path} [${w.code}]: ${w.message}`),
      ...(!ruleVerdict.completeness.complete ? [`$.address.givens: missing ${ruleVerdict.completeness.missing.join(", ")}`] : []),
    ];
    throw new KashCliError(`Open rule failed floor validation:\n  - ${reasons.join("\n  - ")}`, "RULE_INVALID");
  }
  const rule = rawRule as RuleBody;
  if (!rule.id.endsWith(`/rule/${manifest.slug}`)) {
    throw new KashCliError(`rule.json id ("${rule.id}") must end with "/rule/${manifest.slug}".`, "RULE_INVALID");
  }
  const rHash = await ruleHash(rule);
  const dcql = ruleToDcql(rule, rHash);
  if (dcql.credential_sets.length !== rule.criteria.length) {
    throw new KashCliError("Open rule criteria did not compile cleanly to DCQL credential sets.", "RULE_INVALID");
  }
  if (!ruleDoc.includes(rHash)) {
    throw new KashCliError(`${manifest.files.ruleDoc} must quote the open rule's SHA-256 (${rHash}) so the two cannot drift.`, "RULE_INVALID");
  }
  if (!/CC BY 4\.0/i.test(ruleDoc)) {
    throw new KashCliError(`${manifest.files.ruleDoc} must carry an open CC BY 4.0 licence line (d87).`, "RULE_INVALID");
  }

  // Cross-check screens.json routes against floor.manifest.json, then run @kashscript/floor/check.
  if (!isObj(rawFloor)) {
    throw new KashCliError(`${manifest.files.floor} must be a JSON object.`, "FLOOR_FAILED");
  }
  const declaredRoutes = isObj(rawFloor.routes) ? rawFloor.routes : {};
  const requiredRoutes = [...screens.screens.map((s) => s.route), ...screens.apiRoutes];
  for (const routeKey of requiredRoutes) {
    if (!(routeKey in declaredRoutes)) {
      throw new KashCliError(
        `${manifest.files.floor} does not declare "${routeKey}" from ${manifest.files.screens} (undeclared-route, d91(h)).`,
        "FLOOR_FAILED",
      );
    }
  }
  if (Array.isArray(rawFloor.waivers) && rawFloor.waivers.length > 0) {
    throw new KashCliError(`${manifest.files.floor}: a set-up pack may carry no floor waivers.`, "FLOOR_FAILED");
  }

  // Synthesize a floor workspace with a TypeScript mirror of every pack artifact so @kashscript/floor's
  // TypeScript AST rules (price-per-record, unsuppressed-count, person-lookup, declined-state, selftest)
  // inspect every field and copy line of the pack.
  const scratch = mkdtempSync(join(tmpdir(), `kash-pack-floor-${manifest.slug}-`));
  let routesChecked = 0;
  try {
    const mirrorSource = [
      `export const PACK = ${JSON.stringify(rawPack, null, 2)} as const;`,
      `export const ACCEPTANCE = ${JSON.stringify(rawAcceptance, null, 2)} as const;`,
      `export const SCREENS = ${JSON.stringify(rawScreens, null, 2)} as const;`,
      `export const SCOPE = ${JSON.stringify(rawScope, null, 2)} as const;`,
      `export const BUYER_SUPPLIES = ${JSON.stringify(rawSupplies, null, 2)} as const;`,
      `export const CHECKLIST_MD = ${JSON.stringify(checklist)};`,
      `export const RULE_MD = ${JSON.stringify(ruleDoc)};`,
      "",
    ].join("\n");
    const floorForCheck = {
      ...rawFloor,
      serves: "none",
      sources: ["pack-check.ts"],
    };
    writeFileSync(join(scratch, "pack-check.ts"), mirrorSource, "utf8");
    writeFileSync(join(scratch, "floor.manifest.json"), JSON.stringify(floorForCheck, null, 2), "utf8");

    const report = checkFloor({ root: scratch });
    if (!report.ok || report.findings.length > 0 || report.waived.length > 0 || report.selftest.length > 0) {
      const lines = [
        ...report.selftest.map((s) => `selftest: ${s}`),
        ...report.findings.map((f) => {
          const cites = citesOf(f);
          return `[${f.rule}] ${f.at}: ${f.what}${cites.length > 0 ? ` (${cites.join("; ")})` : ""}`;
        }),
      ];
      throw new KashCliError(`Pack failed @kashscript/floor check:\n  - ${lines.join("\n  - ")}`, "FLOOR_FAILED");
    }
    routesChecked = Object.keys(declaredRoutes).length;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  const hashedFiles: Record<string, string> = {
    "pack.json": sha256File(readFileSync(packPath)),
  };
  for (const rel of Object.values(manifest.files)) {
    hashedFiles[rel] = sha256File(readFileSync(abs(rel)));
  }

  const built: BuiltPack = {
    format: PACK_FORMAT,
    slug: manifest.slug,
    title: manifest.title,
    forWhom: manifest.forWhom,
    summary: manifest.summary,
    cycle: manifest.cycle,
    flow: screens.flow,
    engine: screens.engine,
    descriptor: manifest.descriptor,
    rule: {
      id: rule.id,
      version: rule.version,
      sha256: rHash,
      criteriaCount: rule.criteria.length,
    },
    files: hashedFiles,
    floor: {
      ok: true,
      routesChecked,
    },
  };

  return {
    dir,
    manifest,
    rule,
    ruleDoc,
    acceptance,
    screens,
    checklist,
    scope,
    buyerSupplies,
    floorManifestRaw: rawFloor,
    built,
  };
}

export async function buildPack(packDirArg: string): Promise<BuiltPack> {
  return (await loadAndCheckPack(packDirArg)).built;
}

/** Discover and validate every pack folder under `packsRoot` that passes `buildPack`. */
export async function listValidPacks(packsRootArg: string): Promise<readonly BuiltPack[]> {
  const root = resolve(packsRootArg);
  if (!existsSync(root) || !statSync(root).isDirectory()) {
    throw new KashCliError(`Packs directory does not exist: ${root}`, "INVALID_INPUT");
  }
  const entries = readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory() && existsSync(join(root, e.name, "pack.json")))
    .sort((a, b) => a.name.localeCompare(b.name));
  const built: BuiltPack[] = [];
  for (const entry of entries) {
    built.push(await buildPack(join(root, entry.name)));
  }
  return built;
}

/* ── One-command practice install + first approval ──────────────────────── */

export interface InstallPackOptions {
  readonly host: string;
  readonly orgName?: string;
  readonly orgSlug?: string;
  readonly email?: string;
  readonly out?: string;
  readonly fetchImpl?: typeof fetch;
}

export interface InstallPackResult {
  readonly packSlug: string;
  readonly title: string;
  readonly flow: PackFlow;
  readonly host: string;
  readonly org: { readonly name: string; readonly slug: string; readonly did: string };
  readonly approval: {
    readonly artifactKind: "countersign-bundle" | "holder-export";
    readonly receiptRef: string;
    readonly countersignerDid: string;
    readonly verifiedOffline: true;
  };
  /** Serialized artifact (CountersignBundle or HolderExport) that `kash verify` checks offline with exit 0. */
  readonly artifactJson: string;
}

interface EphemeralP256 {
  readonly did: string;
  readonly publicKey: Uint8Array;
  readonly signRaw: (message: Uint8Array) => Promise<{ readonly signature: Uint8Array; readonly format: "raw" }>;
  readonly signer: {
    readonly alg: "ES256";
    readonly publicKey: Uint8Array;
    sign(message: Uint8Array): Promise<{ readonly signature: Uint8Array; readonly format: "raw" }>;
  };
}

const ownBuf = (b: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(b);

async function makeBrowserKey(): Promise<EphemeralP256> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const signRaw = async (message: Uint8Array) => ({
    signature: new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, ownBuf(message))),
    format: "raw" as const,
  });
  const signer = { alg: "ES256" as const, publicKey, sign: signRaw };
  return { did: signerDid(signer), publicKey, signRaw, signer };
}

async function signDsseWithP256(key: EphemeralP256, payloadType: string, payloadObj: unknown): Promise<DsseEnvelope> {
  const bytes = new TextEncoder().encode(canonicalize(payloadObj as never));
  const sig = await signBytes(key.signer, pae(payloadType, bytes), "der");
  return { payloadType, payload: bytesToBase64(bytes), signatures: [{ keyid: key.did, sig: bytesToBase64(sig) }] };
}

async function signCountersignApproval(
  request: SignedCountersignRequest,
  envelope: DsseEnvelope,
  nowSec: number,
): Promise<{ readonly countersignerDid: string; readonly acceptance: SignedCountersignAcceptance; readonly envelope: DsseEnvelope }> {
  const key = await makeBrowserKey();
  const body = request.body;
  const acceptBody = {
    act: "countersign" as const,
    requestId: body.requestId,
    requestDigestSha256: await countersignRequestDigest(request),
    subjectPayloadType: body.subjectPayloadType,
    subjectDigestSha256: body.subjectDigestSha256,
    countersignerDid: key.did,
    keyCustody: "subject-generated" as const,
    signedAtUnix: nowSec,
  };
  const header = { typ: "countersign", v: 1 };
  const acceptance: SignedCountersignAcceptance = {
    header,
    body: acceptBody,
    signature: await signEventWith(header, acceptBody, { alg: "es256", sign: key.signRaw }, { dst: DST_COUNTERSIGN_ACCEPTANCE }),
  };
  const sig = await signBytes(key.signer, pae(envelope.payloadType, base64ToBytes(envelope.payload)), "der");
  const countersigned: DsseEnvelope = {
    ...envelope,
    signatures: [...envelope.signatures, { keyid: key.did, sig: bytesToBase64(sig) }],
  };
  return { countersignerDid: key.did, acceptance, envelope: countersigned };
}

function decodeApprovalLink(link: string): { readonly request: SignedCountersignRequest; readonly envelope: DsseEnvelope } {
  const raw = new URL(link).hash.replace(/^#/, "");
  if (!raw.startsWith("v1.")) {
    throw new KashCliError(`Unexpected approval link fragment in ${link}`, "INSTALL_FAILED");
  }
  const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(base64UrlToBytes(raw.slice(3)))) as {
    r?: unknown;
    e?: unknown;
  };
  if (typeof parsed.r !== "string" || !isObj(parsed.e)) {
    throw new KashCliError("Approval link fragment did not hold { r, e }.", "INSTALL_FAILED");
  }
  return {
    request: decodeCompactCountersignRequest(parsed.r),
    envelope: parsed.e as unknown as DsseEnvelope,
  };
}

function decodeEnrolLink(link: string): { readonly issuer: string; readonly code: string } {
  const raw = new URL(link).hash.replace(/^#/, "");
  if (!raw.startsWith("e1.")) {
    throw new KashCliError(`Unexpected enrolment link fragment in ${link}`, "INSTALL_FAILED");
  }
  const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(base64UrlToBytes(raw.slice(3)))) as {
    i?: unknown;
    c?: unknown;
  };
  if (typeof parsed.i !== "string" || typeof parsed.c !== "string") {
    throw new KashCliError("Enrolment link fragment did not hold { i, c }.", "INSTALL_FAILED");
  }
  return { issuer: parsed.i, code: parsed.c };
}

/**
 * The address name a practice organisation gets when none is passed: `practice-<pack slug>`, cut to leave room for a
 * four-character suffix within Duedale's 30, then the suffix — so a second install on the same host never collides.
 */
export function practiceOrgSlug(packSlug: string, suffix: string = randomBytes(2).toString("hex")): string {
  const stem = `practice-${packSlug}`.slice(0, ENGINE_ORG_SLUG_MAX - 1 - suffix.length).replace(/-+$/, "");
  return `${stem}-${suffix}`;
}

/**
 * Install a checked pack on a clean practice organisation at `opts.host` and complete its first approval.
 *
 * Two guards, both before any engagement, cohort, booking or record is written:
 *   1. the host must echo the sign-in token (`DUEDALE_AUTH_DEV_ECHO=1`) — a production host never does, since that
 *      would let anyone sign in as anyone; without it, nothing at all is written (`NOT_PRACTICE_HOST`);
 *   2. the new organisation must report that it signs in practice mode (`GET /api/v1/me` → `org.signing.mode`) — a
 *      host that echoes tokens but signs as production is refused there, leaving only the empty organisation.
 */
export async function installPackOnPractice(packDirArg: string, opts: InstallPackOptions): Promise<InstallPackResult> {
  const pack = await loadAndCheckPack(packDirArg);
  const base = opts.host.trim().replace(/\/+$/, "");
  if (!/^https?:\/\/\S+$/i.test(base)) {
    throw new KashCliError(`Invalid --host URL: "${opts.host}".`, "INVALID_INPUT");
  }
  const f = opts.fetchImpl ?? fetch;
  const nonce = randomBytes(4).toString("hex");
  const requestedSlug = (opts.orgSlug ?? practiceOrgSlug(pack.manifest.slug)).toLowerCase();
  if (!ENGINE_ORG_SLUG_RE.test(requestedSlug)) {
    throw new KashCliError(
      `Invalid --org-slug "${requestedSlug}": 3–30 characters, lowercase letters, digits and hyphens, starting with a letter or digit (Duedale's rule).`,
      "INVALID_INPUT",
    );
  }
  const rawName = opts.orgName ?? `Practice — ${pack.manifest.title}`;
  const orgName = /practice/i.test(rawName) ? rawName : `Practice — ${rawName}`;
  const email = opts.email ?? `practice-${pack.manifest.slug}-${nonce}@practice.test`;

  const call = async (
    method: string,
    path: string,
    body?: unknown,
    auth?: { cookie?: string; bearer?: string },
  ): Promise<{ status: number; body: any; text: string; headers: Headers }> => {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (auth?.cookie) headers["cookie"] = `oa_session=${auth.cookie}`;
    if (auth?.bearer) headers["authorization"] = `Bearer ${auth.bearer}`;
    const res = await f(`${base}${path}`, {
      method,
      headers,
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });
    const text = await res.text();
    let parsed: any = null;
    try {
      parsed = text === "" ? null : JSON.parse(text);
    } catch {
      parsed = null;
    }
    return { status: res.status, body: parsed, text, headers: res.headers };
  };

  /**
   * The record's public verify answer (`GET /api/v1/verify/:receiptNo/bundle`) is the engine's own page bundle; the
   * kernel's two-signature `CountersignBundle` is inside it, one per acceptance (`acceptances[i].bundle`). Take the one
   * this approval's key made, check it is about this very record, and verify it offline.
   */
  const acceptedBundleOf = async (receiptNo: string, countersignerDid: string, what: string): Promise<CountersignBundle> => {
    const res = await call("GET", `/api/v1/verify/${receiptNo}/bundle`);
    if (res.status !== 200 || !isObj(res.body)) {
      throw new KashCliError(`Could not fetch the ${what}'s public verify answer (${res.status}): ${res.text}`, "INSTALL_FAILED");
    }
    const page = res.body as Record<string, unknown>;
    const acceptances = Array.isArray(page.acceptances) ? (page.acceptances as unknown[]) : [];
    const mine = acceptances.find((a) => isObj(a) && a.countersignerDid === countersignerDid);
    if (!isObj(mine) || !isObj(mine.bundle)) {
      throw new KashCliError(`The ${what}'s public verify answer carries no acceptance by this approval's key.`, "VERIFY_FAILED");
    }
    const bundle = mine.bundle as unknown as CountersignBundle;
    const recordEnvelope = page.envelope;
    if (!isObj(recordEnvelope) || bundle.subject?.payloadType !== recordEnvelope.payloadType || bundle.subject?.payload !== recordEnvelope.payload) {
      throw new KashCliError(`The acceptance's bundle is not about the ${what} it was fetched for.`, "VERIFY_FAILED");
    }
    const verdict = await verifyCountersignBundle(bundle);
    if (!verdict.ok || !verdict.twoSignatureProof) {
      throw new KashCliError(`Offline verification of the approved ${what} failed: ${verdict.reason ?? verdict.notes.join("; ")}`, "VERIFY_FAILED");
    }
    return bundle;
  };

  // 1. Clean practice sign-up & organisation creation.
  const reqLink = await call("POST", "/api/v1/auth/request-link", { email });
  if (reqLink.status !== 202 || typeof reqLink.body?.devToken !== "string") {
    throw new KashCliError(
      `Refused: ${base} did not return a practice sign-in token (status ${reqLink.status}). Run Duedale's practice server with DUEDALE_AUTH_DEV_ECHO=1; pack install never writes practice records to production.`,
      "NOT_PRACTICE_HOST",
    );
  }
  const redeem = await call("POST", "/api/v1/auth/redeem", { token: reqLink.body.devToken });
  const setCookie = redeem.headers.get("set-cookie") ?? "";
  const cookie = /oa_session=([^;]+)/.exec(setCookie)?.[1] ?? (typeof redeem.body?.cookie === "string" ? redeem.body.cookie : undefined);
  if (redeem.status !== 200 || !cookie) {
    throw new KashCliError(`Could not redeem practice sign-in token (${redeem.status}): ${redeem.text}`, "INSTALL_FAILED");
  }
  const createdOrg = await call("POST", "/api/v1/orgs", { name: orgName, slug: requestedSlug }, { cookie });
  if (createdOrg.status !== 201) {
    throw new KashCliError(`Could not create clean practice organisation "${requestedSlug}" (${createdOrg.status}): ${createdOrg.text}`, "INSTALL_FAILED");
  }
  // The engine's answer is what holds: its address name and the organisation's signing key.
  const slug = typeof createdOrg.body?.slug === "string" ? (createdOrg.body.slug as string) : requestedSlug;
  const createdDid = createdOrg.body?.issuer?.did as string | undefined;

  // Guard 2: the organisation must sign in practice mode before anything is configured or approved.
  const me = await call("GET", "/api/v1/me", undefined, { cookie });
  const signingMode = me.body?.org?.signing?.mode as string | undefined;
  if (me.status !== 200 || signingMode !== "practice") {
    throw new KashCliError(
      `Refused: ${base} signs as "${signingMode ?? "unknown"}", not practice (GET /api/v1/me → org.signing.mode). Nothing was configured; only the empty organisation "${slug}" exists there.`,
      "NOT_PRACTICE_HOST",
    );
  }
  const meDid = me.body?.org?.issuer?.did as string | undefined;
  const orgDidOf = (fallback: string): string => createdDid ?? meDid ?? fallback;

  const DAY_MS = 24 * 60 * 60 * 1000;
  const nowMs = Date.now();
  const nowSec = Math.floor(nowMs / 1000);

  // 2. Flow-specific set-up and first approval end-to-end.
  if (pack.screens.flow === "client-sign-off") {
    const cfg = pack.screens.practice.engagement!;
    const eng = await call(
      "POST",
      "/api/v1/engagements",
      {
        clientName: cfg.clientLabel,
        scopeText: cfg.scopeText,
        scopeHoldsUntil: new Date(nowMs + cfg.scopeDays * DAY_MS).toISOString(),
        milestones: [{ title: cfg.milestoneTitle, doneMeans: cfg.doneMeans, stack: [...cfg.stack] }],
      },
      { cookie },
    );
    if (eng.status !== 201) {
      throw new KashCliError(`Failed to configure practice engagement (${eng.status}): ${eng.text}`, "INSTALL_FAILED");
    }
    const milestoneId = eng.body?.milestones?.[0]?.id as string | undefined;
    if (!milestoneId) throw new KashCliError("Created engagement returned no milestone id.", "INSTALL_FAILED");

    const delivered = await call("POST", `/api/v1/engagements/${eng.body.id}/milestones/${milestoneId}/deliver`, {}, { cookie });
    if (delivered.status !== 201 || typeof delivered.body?.link !== "string" || typeof delivered.body?.receiptNo !== "string") {
      throw new KashCliError(`Failed to deliver practice milestone (${delivered.status}): ${delivered.text}`, "INSTALL_FAILED");
    }

    const opened = decodeApprovalLink(delivered.body.link);
    if (opened.request.body.statement !== pack.acceptance.statement) {
      throw new KashCliError(
        `Approval statement mismatch: host signed "${opened.request.body.statement}", pack declares "${pack.acceptance.statement}".`,
        "INSTALL_FAILED",
      );
    }
    const signed = await signCountersignApproval(opened.request, opened.envelope, nowSec);
    const accepted = await call("POST", "/api/v1/acceptances", {
      request: opened.request,
      acceptance: signed.acceptance,
      envelope: signed.envelope,
    });
    if (accepted.status !== 201) {
      throw new KashCliError(`First milestone approval was not admitted (${accepted.status}): ${accepted.text}`, "INSTALL_FAILED");
    }

    const bundle = await acceptedBundleOf(delivered.body.receiptNo as string, signed.countersignerDid, "milestone");
    const orgDid = orgDidOf(opened.request.body.requesterDid);
    const artifactJson = JSON.stringify(bundle, null, 2);
    if (opts.out) writeFileSync(resolve(opts.out), `${artifactJson}\n`, "utf8");
    return {
      packSlug: pack.manifest.slug,
      title: pack.manifest.title,
      flow: pack.screens.flow,
      host: base,
      org: { name: orgName, slug, did: orgDid },
      approval: {
        artifactKind: "countersign-bundle",
        receiptRef: delivered.body.receiptNo,
        countersignerDid: signed.countersignerDid,
        verifiedOffline: true,
      },
      artifactJson,
    };
  }

  if (pack.screens.flow === "internships-that-count") {
    const cfg = pack.screens.practice.internship!;
    const created = await call(
      "POST",
      "/api/v1/internships",
      {
        title: cfg.ruleTitle,
        weeks: cfg.weeks,
        hours: cfg.hours,
        minimumHoursStated: cfg.minimumHoursStated,
        holdsUntil: new Date(nowMs + cfg.holdsDays * DAY_MS).toISOString(),
        recordsLastUntil: new Date(nowMs + cfg.recordsLastDays * DAY_MS).toISOString(),
        text: cfg.ruleText,
      },
      { cookie },
    );
    if (created.status !== 201 || typeof created.body?.cohortId !== "string") {
      throw new KashCliError(`Failed to configure practice internship cohort (${created.status}): ${created.text}`, "INSTALL_FAILED");
    }
    const cohortId: string = created.body.cohortId;
    const pinnedRule = created.body.rule as { id: string; version: string; hash: string; body: string };
    const parsedRuleBody = JSON.parse(pinnedRule.body) as { recordsLastUntil: string };

    // Enrol one student in person (empty body — no name or identity).
    const enrolled = await call("POST", `/api/v1/internships/${cohortId}/enrolments`, {}, { cookie });
    if (enrolled.status !== 201 || typeof enrolled.body?.link !== "string") {
      throw new KashCliError(`Failed to mint enrolment offer (${enrolled.status}): ${enrolled.text}`, "INSTALL_FAILED");
    }
    const offer = decodeEnrolLink(enrolled.body.link);
    const student = await makeBrowserKey();
    const issuerPath = new URL(offer.issuer).pathname;

    // Redeem pre-authorized code over OpenID4VCI and bind student's P-256 key.
    const tokenRes = await f(`${base}${issuerPath}/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": offer.code,
      }).toString(),
    });
    if (!tokenRes.ok) {
      throw new KashCliError(`Enrolment token step failed (${tokenRes.status}).`, "INSTALL_FAILED");
    }
    const { access_token: accessToken } = (await tokenRes.json()) as { access_token?: string };
    const nonceRes = await f(`${base}${issuerPath}/nonce`, { method: "POST" });
    if (!nonceRes.ok || !accessToken) {
      throw new KashCliError(`Enrolment nonce step failed (${nonceRes.status}).`, "INSTALL_FAILED");
    }
    const { c_nonce: cNonce } = (await nonceRes.json()) as { c_nonce?: string };
    if (!cNonce) throw new KashCliError("Enrolment nonce response carried no c_nonce.", "INSTALL_FAILED");

    const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
    const b64u = (s: string): string => bytesToBase64Url(utf8(s));
    const jwtInput = `${b64u(JSON.stringify({ alg: "ES256", typ: "openid4vci-proof+jwt", kid: student.did }))}.${b64u(
      JSON.stringify({ aud: offer.issuer, iat: nowSec, nonce: cNonce }),
    )}`;
    const proofSig = await signBytes(student.signer, utf8(jwtInput), "raw");
    const proofJwt = `${jwtInput}.${bytesToBase64Url(proofSig)}`;

    const credRes = await f(`${base}${issuerPath}/credential`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
      body: JSON.stringify({ credential_configuration_id: "work-record", proofs: { jwt: [proofJwt] } }),
    });
    if (!credRes.ok) {
      throw new KashCliError(`Enrolment credential binding failed (${credRes.status}).`, "INSTALL_FAILED");
    }

    // Student signs Week 1 and asks for site supervisor approval.
    const toDay = new Date(nowMs - DAY_MS).toISOString().slice(0, 10);
    const fromDay = new Date(nowMs - 7 * DAY_MS).toISOString().slice(0, 10);
    const receiptId = ulid(nowMs);
    const weekClaim = {
      spec: "oreoasis.work-record/1" as const,
      receiptId,
      org: slug,
      actor: { class: "person" as const, id: student.did },
      shape: "accepted" as const,
      rule: { id: pinnedRule.id, version: pinnedRule.version, hash: pinnedRule.hash },
      action: { type: "internship.week" as const, summary: cfg.firstWeekSummary },
      inputs: [] as const,
      outputs: [] as const,
      status: "completed" as const,
      timestamp: new Date(nowMs).toISOString(),
      meta: {
        profile: "oreoasis-internship-week/1" as const,
        cohort: cohortId,
        week: 1,
        from: fromDay,
        to: toDay,
        ...(cfg.hours === "asked" ? { hours: cfg.firstWeekHours ?? 20 } : {}),
        expiresAt: parsedRuleBody.recordsLastUntil,
      },
    };
    const weekEnvelope = await signDsseWithP256(student, "application/vnd.oreoasis.work-record+json", weekClaim);
    const asked = await call("POST", "/api/v1/internship-weeks", { envelope: weekEnvelope });
    if (asked.status !== 201 || typeof asked.body?.link !== "string") {
      throw new KashCliError(`Failed to request week approval (${asked.status}): ${asked.text}`, "INSTALL_FAILED");
    }

    const openedWeek = decodeApprovalLink(asked.body.link);
    if (openedWeek.request.body.statement !== pack.acceptance.statement) {
      throw new KashCliError(
        `Week approval statement mismatch: host signed "${openedWeek.request.body.statement}", pack declares "${pack.acceptance.statement}".`,
        "INSTALL_FAILED",
      );
    }
    const approvedWeek = await signCountersignApproval(openedWeek.request, openedWeek.envelope, nowSec);
    const admitWeek = await call("POST", "/api/v1/internship-approvals", {
      request: openedWeek.request,
      acceptance: approvedWeek.acceptance,
      envelope: approvedWeek.envelope,
    });
    if (admitWeek.status !== 201) {
      throw new KashCliError(`Site supervisor week approval was not admitted (${admitWeek.status}): ${admitWeek.text}`, "INSTALL_FAILED");
    }

    // Student fetches their own held export and verifies the two-signature bundle offline.
    const holderReq = await signDsseWithP256(student, "application/vnd.oreoasis.holder-export-request+json", {
      spec: "oreoasis.holder-export-request/1",
      requestedAt: new Date(nowMs).toISOString(),
    });
    const mine = await call("POST", "/api/v1/internship-records", { request: holderReq });
    const fileText = mine.body?.internships?.[0]?.file as string | undefined;
    const campusDid = mine.body?.internships?.[0]?.campus?.did as string | undefined;
    if (mine.status !== 200 || typeof fileText !== "string" || !campusDid) {
      throw new KashCliError(`Could not retrieve student's approved week export (${mine.status}): ${mine.text}`, "INSTALL_FAILED");
    }
    const parsedExport = JSON.parse(fileText) as { records?: Array<{ artifact?: { kind?: string; value?: unknown } }> };
    const weekBundle = parsedExport.records?.[0]?.artifact?.value as CountersignBundle | undefined;
    if (!weekBundle) {
      throw new KashCliError("Student export contained no countersigned week record.", "VERIFY_FAILED");
    }
    const verdict = await verifyCountersignBundle(weekBundle);
    if (!verdict.ok || !verdict.twoSignatureProof) {
      throw new KashCliError(`Offline verification of approved internship week failed: ${verdict.reason ?? verdict.notes.join("; ")}`, "VERIFY_FAILED");
    }
    if (opts.out) writeFileSync(resolve(opts.out), `${fileText.trimEnd()}\n`, "utf8");
    return {
      packSlug: pack.manifest.slug,
      title: pack.manifest.title,
      flow: pack.screens.flow,
      host: base,
      org: { name: orgName, slug, did: campusDid },
      approval: {
        artifactKind: "holder-export",
        receiptRef: receiptId,
        countersignerDid: approvedWeek.countersignerDid,
        verifiedOffline: true,
      },
      artifactJson: fileText,
    };
  }

  // 3. `host-receipts`: booking mandate → delivered booking signed by host's book → guest approval → offline verify.
  // The practice app gets only what one receipt needs: the issuing scope, and the shortest token (an hour). A real
  // app's year-long booking mandate (issue + proof pages, 366 days) is the owner's choice at set-up, never this command's.
  const cfg = pack.screens.practice.booking!;
  const connected = await call(
    "POST",
    "/api/v1/agents",
    {
      label: cfg.appLabel,
      scopes: ["duedale.bookings.issue"],
    },
    { cookie },
  );
  const agentId = connected.body?.agents?.[0]?.id as string | undefined;
  if (connected.status !== 201 || !agentId) {
    throw new KashCliError(`Failed to connect practice booking mandate (${connected.status}): ${connected.text}`, "INSTALL_FAILED");
  }
  const minted = await call("POST", `/api/v1/agents/${agentId}/tokens`, { lifetimeSeconds: 3600 }, { cookie });
  const bearer = minted.body?.token as string | undefined;
  if (minted.status !== 201 || typeof bearer !== "string") {
    throw new KashCliError(`Failed to mint booking mandate token (${minted.status}): ${minted.text}`, "INSTALL_FAILED");
  }
  const bookingsMe = await call("GET", "/api/v1/bookings/me", undefined, { bearer });
  const orgDid = bookingsMe.body?.org?.did as string | undefined;
  if (bookingsMe.status !== 200 || typeof orgDid !== "string" || !orgDid.startsWith("did:kash:")) {
    throw new KashCliError(`Could not read host DID from booking mandate (${bookingsMe.status}): ${bookingsMe.text}`, "INSTALL_FAILED");
  }

  const reference = `kash-trade:0x${randomBytes(32).toString("hex")}`;
  const listing = `${orgDid}/listing/${cfg.listingSlug}`;
  const issued = await call(
    "POST",
    "/api/v1/bookings",
    {
      reference,
      door: cfg.door,
      listing,
      window: {
        start: new Date(nowMs - 2 * DAY_MS).toISOString(),
        end: new Date(nowMs + DAY_MS).toISOString(),
      },
    },
    { bearer },
  );
  if (issued.status !== 201 || typeof issued.body?.receiptNo !== "string" || typeof issued.body?.acceptance?.compactB64u !== "string") {
    throw new KashCliError(`Failed to issue practice booking receipt (${issued.status}): ${issued.text}`, "INSTALL_FAILED");
  }
  const request = decodeCompactCountersignRequest(issued.body.acceptance.compactB64u as string);
  const envelope = issued.body.envelope as DsseEnvelope;
  if (!isObj(envelope) || !Array.isArray(envelope.signatures) || envelope.signatures.length === 0) {
    throw new KashCliError("Host returned no signed booking envelope.", "VERIFY_FAILED");
  }
  if (request.body.statement !== pack.acceptance.statement) {
    throw new KashCliError(
      `Booking acceptance statement mismatch: host signed "${request.body.statement}", pack declares "${pack.acceptance.statement}".`,
      "INSTALL_FAILED",
    );
  }

  const guestApproval = await signCountersignApproval(request, envelope, nowSec);
  const admitGuest = await call("POST", "/api/v1/acceptances", {
    request,
    acceptance: guestApproval.acceptance,
    envelope: guestApproval.envelope,
  });
  if (admitGuest.status !== 201) {
    throw new KashCliError(`Guest booking approval was not admitted (${admitGuest.status}): ${admitGuest.text}`, "INSTALL_FAILED");
  }

  const bundle = await acceptedBundleOf(issued.body.receiptNo as string, guestApproval.countersignerDid, "booking receipt");
  const artifactJson = JSON.stringify(bundle, null, 2);
  if (opts.out) writeFileSync(resolve(opts.out), `${artifactJson}\n`, "utf8");
  return {
    packSlug: pack.manifest.slug,
    title: pack.manifest.title,
    flow: pack.screens.flow,
    host: base,
    org: { name: orgName, slug, did: orgDid },
    approval: {
      artifactKind: "countersign-bundle",
      receiptRef: issued.body.receiptNo as string,
      countersignerDid: guestApproval.countersignerDid,
      verifiedOffline: true,
    },
    artifactJson,
  };
}
