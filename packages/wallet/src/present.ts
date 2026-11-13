/**
 * Present — an ask answered with one yes, never with the data (d27.2;
 * presentation §1–§6). OpenID for Verifiable Presentations 1.0: a by-value
 * request carrying a DCQL query, the verifier's nonce, and the ask itself.
 *
 * Before showing anything the wallet checks the ask against its eight rules,
 * its digest, the DCQL query it must equal, its expiry, and the wallet's copy
 * of the public list of requests. Then:
 *
 * - **yes** — one holder-bound presentation per need, from a copy of the yes
 *   that has been shown to this verifier or to no one (rule 6: two verifiers
 *   never see the same copy or key); no record hash disclosed; posted to the
 *   verifier; logged in the holder's own log.
 * - **no** — nothing. No message, no `access_denied`, no log entry, no write.
 *   The request simply expires (§6). A verifier who asked face to face would
 *   otherwise learn who said no.
 * - **too much** — the holder may note that an ask asked too much (rule 7),
 *   in their own log, only if they choose to.
 */

import { canonicalize } from "@kashscript/identity-core";
import {
  askSha256,
  askToDcql,
  credentialCopySha256,
  PREDICATE_VCT,
  validateAsk,
  type Ask,
  type AskRule,
  type PresentationLogEntry,
} from "@kashscript/attest/exchange";
import { checkStatus, statusEntryOf } from "@kashscript/attest/holder";
import { decodeJws, parseSdJwt, presentSdJwt } from "@kashscript/attest/sd-jwt";
import { fill } from "./copy";
import type { WalletCore } from "./core";
import { WalletError } from "./errors";
import type { HeldEntry } from "./records";
import type { LibraryState } from "./trust";

export interface PresentationRequest {
  readonly client_id: string;
  readonly response_type: "vp_token";
  readonly response_mode: "direct_post";
  readonly response_uri: string;
  readonly nonce: string;
  readonly state?: string;
  readonly dcql_query: unknown;
  readonly kash_ask: Ask;
  readonly kash_ask_sha256: string;
}

export interface NeedView {
  readonly id: string;
  readonly answerable: boolean;
  /** Why not, in plain words, when it can't be answered. */
  readonly missing: string | null;
}

export interface AskView {
  readonly request: PresentationRequest;
  readonly verifier: string;
  readonly who: string;
  readonly title: string;
  readonly why: string;
  readonly goodFor: string;
  /** "Saying no costs only this: …" — shown beside the yes, never below it. */
  readonly declineCosts: string;
  readonly library: LibraryState;
  readonly libraryText: string;
  readonly needs: readonly NeedView[];
  readonly answerable: boolean;
  /** The copy chosen for each need. Internal to the wallet. */
  readonly chosen: Readonly<Record<string, string>>;
}

export type PresentResult = { readonly status: "sent"; readonly verifier: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function parseJsonParam(v: unknown): unknown {
  if (typeof v !== "string") return v;
  try {
    return JSON.parse(v);
  } catch {
    return undefined;
  }
}

export function parseRequest(input: string | Readonly<Record<string, unknown>>): PresentationRequest {
  let fields: Record<string, unknown>;
  if (typeof input === "string") {
    const text = input.trim();
    if (text.startsWith("{")) {
      try {
        fields = JSON.parse(text) as Record<string, unknown>;
      } catch {
        throw new WalletError("REQUEST_INVALID", "not JSON");
      }
    } else {
      let url: URL;
      try {
        url = new URL(text);
      } catch {
        throw new WalletError("REQUEST_INVALID", "not a link");
      }
      if (url.searchParams.has("request_uri")) throw new WalletError("REQUEST_INVALID", "requests by reference are not supported in this version");
      fields = Object.fromEntries(url.searchParams.entries());
    }
  } else {
    fields = { ...input };
  }
  const req = {
    ...fields,
    dcql_query: parseJsonParam(fields.dcql_query),
    kash_ask: parseJsonParam(fields.kash_ask),
  } as Record<string, unknown>;
  if (
    typeof req.client_id !== "string" ||
    req.client_id.length === 0 ||
    req.response_type !== "vp_token" ||
    req.response_mode !== "direct_post" ||
    typeof req.response_uri !== "string" ||
    !req.response_uri.startsWith("https://") ||
    typeof req.nonce !== "string" ||
    req.nonce.length === 0 ||
    typeof req.kash_ask_sha256 !== "string" ||
    !isPlainObject(req.kash_ask) ||
    !isPlainObject(req.dcql_query) ||
    (req.state !== undefined && typeof req.state !== "string")
  ) {
    throw new WalletError("REQUEST_INVALID", "not an OpenID4VP direct_post request carrying an ask");
  }
  return req as unknown as PresentationRequest;
}

interface CandidateCopy {
  readonly entry: HeldEntry;
  readonly claims: Record<string, unknown>;
}

export class Present {
  constructor(private readonly core: WalletCore) {}

  /** Check a request and say what it asks, why, and what a no costs. Sends nothing. */
  async open(input: string | Readonly<Record<string, unknown>>): Promise<AskView> {
    const req = parseRequest(input);
    const ask = req.kash_ask;
    const now = this.core.now();
    const valid = validateAsk(ask);
    if (!valid.ok) throw new WalletError("ASK_REFUSED", valid.violations.map((v) => v.rule).join(", "));
    const sha = await askSha256(ask);
    if (sha !== req.kash_ask_sha256) throw new WalletError("ASK_REFUSED", "the ask's digest does not match");
    if (req.client_id !== ask.who.id) throw new WalletError("ASK_REFUSED", "the request is not from the verifier the ask names");
    if (canonicalize(req.dcql_query) !== canonicalize(askToDcql(ask))) throw new WalletError("ASK_REFUSED", "the query asks for more than the ask says");
    if (ask.state !== "published" || ask.expiresAtUnix <= now) throw new WalletError("ASK_REFUSED", "the ask is not live");
    const library = await this.core.trust.libraryState(ask, sha);
    if (library === "mismatch") throw new WalletError("ASK_REFUSED", "the ask differs from the one in the public list");

    const candidates = await this.candidates();
    const chosen: Record<string, string> = {};
    const needs: NeedView[] = [];
    for (const need of ask.needs) {
      const fitting = candidates.filter((c) => this.answers(c, need, now));
      const mine = fitting.find((c) => c.entry.local.assignedVerifier === req.client_id);
      const fresh = fitting.find((c) => c.entry.local.assignedVerifier === null && !Object.values(chosen).includes(c.entry.slot));
      const pick = mine ?? fresh;
      if (pick !== undefined) chosen[need.id] = pick.entry.slot;
      needs.push({ id: need.id, answerable: pick !== undefined, missing: pick === undefined ? this.core.copy.askMissing : null });
    }
    const c = this.core.copy;
    return {
      request: req,
      verifier: req.client_id,
      who: ask.who.name,
      title: ask.title,
      why: fill(c.askWhy, { why: ask.why }),
      goodFor: fill(c.askGoodFor, { goodFor: ask.goodFor }),
      declineCosts: fill(c.askDeclineCosts, { goodFor: ask.goodFor }),
      library,
      libraryText: library === "in-library" ? c.askInLibrary : c.askNotInLibrary,
      needs,
      answerable: needs.every((n) => n.answerable),
      chosen,
    };
  }

  /** One yes, for the whole ask. */
  async yes(view: AskView): Promise<PresentResult> {
    if (!view.answerable) throw new WalletError("NOT_ANSWERABLE");
    const req = view.request;
    const now = this.core.now();
    if (req.kash_ask.expiresAtUnix <= now) throw new WalletError("ASK_REFUSED", "the ask has expired");
    const vpToken: Record<string, string[]> = {};
    const used: HeldEntry[] = [];
    const keyIds: string[] = [];
    for (const need of req.kash_ask.needs) {
      const entry = await this.core.records.get(view.chosen[need.id] ?? "");
      if (entry === null || entry.local.boundKey === null || typeof entry.artifact.value !== "string") throw new WalletError("NOT_ANSWERABLE");
      if (entry.local.assignedVerifier !== null && entry.local.assignedVerifier !== req.client_id) throw new WalletError("NOT_ANSWERABLE", "that copy belongs to another verifier");
      const held = entry.artifact.value;
      // No disclosure: the record hashes stay hidden, so nothing links this yes to another.
      const presentation = await this.core.keys.withSigner(entry.local.boundKey, (s) =>
        presentSdJwt(held, () => false, s, { aud: req.client_id, nonce: req.nonce, iatUnix: now }),
      );
      vpToken[need.id] = [presentation];
      used.push(entry);
      keyIds.push(entry.local.boundKey);
    }

    const res = await this.core.postForm(
      req.response_uri,
      { vp_token: JSON.stringify(vpToken), ...(req.state !== undefined ? { state: req.state } : {}) },
      await this.core.allowed(keyIds),
    );
    if (res.status < 200 || res.status >= 300) throw new WalletError("SEND_FAILED", `the verifier answered ${res.status}`);

    // Only after it arrived: the copies are now this verifier's, and the holder's log says so.
    const askRef = { key: req.kash_ask.key, version: req.kash_ask.version, sha256: req.kash_ask_sha256 };
    const entries: PresentationLogEntry[] = [];
    for (const e of used) {
      await this.core.records.updateLocal(e.slot, { ...e.local, assignedVerifier: req.client_id });
      entries.push({
        kind: "presentation",
        atUnix: now,
        verifier: req.client_id,
        relationship: e.local.boundKey as string,
        ask: askRef,
        credentials: [{ vct: PREDICATE_VCT, copySha256: await credentialCopySha256(e.artifact.value as string) }],
        disclosed: [],
        attachedRecordIds: [],
        linkedByHolder: false,
      });
    }
    await this.core.log.append(...entries);
    return { status: "sent", verifier: req.client_id };
  }

  /**
   * No. This does nothing — deliberately, and provably (`test/present.test.ts`
   * compares every stored byte and every request before and after). There is
   * no format for a decline, so there is nothing to write or send.
   */
  no(_view: AskView): void {
    return;
  }

  /** The holder's own note that an ask asked too much. Only if they choose to; it is never sent. */
  async noteExcessive(view: AskView, rules: readonly AskRule[], note: string | null = null): Promise<void> {
    await this.core.log.append({
      kind: "excessive-ask",
      atUnix: this.core.now(),
      ask: { key: view.request.kash_ask.key, version: view.request.kash_ask.version, sha256: view.request.kash_ask_sha256 },
      rules,
      note,
    });
  }

  private async candidates(): Promise<CandidateCopy[]> {
    const lists = await this.core.trust.statusReports();
    const out: CandidateCopy[] = [];
    for (const entry of await this.core.records.list()) {
      if (entry.artifact.kind !== "sd-jwt" || entry.manifest.type.tag !== PREDICATE_VCT || typeof entry.artifact.value !== "string") continue;
      // A copy bound to a key this device does not hold — lost with a phone, or
      // imported without its keys — still verifies as signed, but cannot be shown
      // with holder binding. It is never offered; its issuer can give new copies.
      if (entry.local.boundKey === null || (await this.core.keys.find(entry.local.boundKey)) === null) continue;
      const parsed = parseSdJwt(entry.artifact.value);
      const claims = parsed === null ? null : decodeJws(parsed.issuerJwt)?.payload ?? null;
      if (claims === null) continue;
      const status = checkStatus(statusEntryOf(claims), lists).state;
      if (status === "revoked" || status === "suspended") continue;
      out.push({ entry, claims });
    }
    return out;
  }

  private answers(c: CandidateCopy, need: Ask["needs"][number], now: number): boolean {
    const p = c.claims.predicate;
    if (!isPlainObject(p) || p.kind !== need.predicate || p.answer !== true) return false;
    if (typeof c.claims.exp === "number" && c.claims.exp <= now) return false;
    const w = isPlainObject(p.window) ? p.window : null;
    const to = w !== null && typeof w.to === "string" ? Date.parse(w.to) / 1000 : NaN;
    if (!(to >= now - need.withinDays * 86_400)) return false;
    if (need.issuers !== undefined && (typeof c.claims.iss !== "string" || !need.issuers.includes(c.claims.iss))) return false;
    return true;
  }
}
