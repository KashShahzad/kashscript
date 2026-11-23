/**
 * Present — an ask answered with one yes, never with the data (d27.2;
 * presentation §1–§6). OpenID for Verifiable Presentations 1.0: a request
 * carrying a DCQL query, the verifier's nonce, and the ask itself — by value,
 * or by reference (`request_uri`, GET or POST) and signed (RW-16).
 *
 * Before showing anything the wallet checks the ask against its eight rules,
 * its digest, the DCQL query it must equal, its expiry, and the wallet's copy
 * of the public list of requests. Then:
 *
 * - **yes** — one holder-bound presentation per need, from a copy of the yes
 *   that has been shown to this verifier or to no one (rule 6: two verifiers
 *   never see the same copy or key); no record hash disclosed; posted to the
 *   verifier (`direct_post`, or encrypted to the verifier's key for
 *   `direct_post.jwt`); logged in the holder's own log.
 * - **no** — nothing. No message, no `access_denied`, no log entry, no write.
 *   The request simply expires (§6). A verifier who asked face to face would
 *   otherwise learn who said no.
 * - **too much** — the holder may note that an ask asked too much (rule 7),
 *   in their own log, only if they choose to.
 *
 * Reading a request (RW-16, 2026-11-23, at the founder's ruling) ends one of four ways:
 *
 * - **ask** — the view above.
 * - **untrusted** — the request cannot be tied to the verifier it names (a
 *   signature, certificate hash, DNS name, prefix or `client_id` that does not
 *   match). Nothing is sent: its `response_uri` is not to be trusted.
 * - **invalid** — tied to its verifier, but broken (no nonce, a transaction
 *   data type the wallet does not know, an answer mode it cannot use). The
 *   person may tell the verifier so — `present.report`, OpenID4VP's
 *   `invalid_request` or `invalid_transaction_data` — and only by choosing to
 *   (OpenID4VP §15.9.2). The error is about the request: it says nothing about
 *   the person or what they hold, and nothing is written.
 * - **no ask** — a valid request that carries no ask. It is refused and nothing
 *   is sent; so is a query the wallet cannot answer, since answering "I don't
 *   have that" would be a refusal (d84, d91's forbidden gateways).
 *
 * Client identifier prefixes read: `x509_hash`, `x509_san_dns` (both signed,
 * ES256, leaf in `x5c`) and `redirect_uri` (unsigned). **No X.509 chain is
 * validated against an anchor** — the wallet keeps no X.509 trust list (KS-C1
 * R4, the founder's); `x509_hash` binds the key by its own hash, and
 * `x509_san_dns` is checked against the leaf's own names. An unsigned request
 * with no prefix is read only when it carries an ask, which is checked by its
 * own rules, as before.
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
import { base64UrlToBytes, utf8, utf8Decode } from "./crypto/bytes";
import { asVerifierEncKey, encryptEcdhEs, type JweEnc, type VerifierEncKey } from "./crypto/jwe-ecdh";
import { readLeaf, verifyEs256WithSpki } from "./crypto/x509";
import { WalletError } from "./errors";
import type { HeldEntry } from "./records";
import type { LibraryState } from "./trust";

export type ResponseMode = "direct_post" | "direct_post.jwt";

export interface PresentationRequest {
  readonly client_id: string;
  readonly response_type: "vp_token";
  readonly response_mode: ResponseMode;
  readonly response_uri: string;
  readonly nonce: string;
  readonly state?: string;
  readonly dcql_query: unknown;
  readonly kash_ask: Ask;
  readonly kash_ask_sha256: string;
}

/** Where an answer goes, and how. */
export interface Reply {
  readonly responseUri: string;
  readonly mode: ResponseMode;
  readonly state?: string;
  /** For `direct_post.jwt`: the verifier's key and the content encryption. */
  readonly encryption: { readonly key: VerifierEncKey; readonly enc: JweEnc } | null;
}

export interface NeedView {
  readonly id: string;
  readonly answerable: boolean;
  /** Why not, in plain words, when it can't be answered. */
  readonly missing: string | null;
}

export interface AskView {
  readonly request: PresentationRequest;
  readonly reply: Reply;
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

export type InvalidRequestError = "invalid_request" | "invalid_transaction_data";

export type RequestReading =
  | { readonly kind: "ask"; readonly view: AskView }
  | { readonly kind: "untrusted"; readonly reason: string }
  | { readonly kind: "invalid"; readonly reason: string; readonly error: InvalidRequestError; readonly verifier: string; readonly reply: Reply }
  | { readonly kind: "no-ask"; readonly verifier: string; readonly reason: string };

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

function httpsUrl(v: unknown): URL | null {
  if (typeof v !== "string") return null;
  try {
    const u = new URL(v);
    return u.protocol === "https:" ? u : null;
  } catch {
    return null;
  }
}

const JSON_FIELDS = ["dcql_query", "kash_ask", "client_metadata", "transaction_data"] as const;

/** The outer parameters of a request: a link's query, a JSON object, or an object. */
function outerFields(input: string | Readonly<Record<string, unknown>>): Record<string, unknown> {
  if (typeof input !== "string") return { ...input };
  const text = input.trim();
  if (text.startsWith("{")) {
    try {
      return JSON.parse(text) as Record<string, unknown>;
    } catch {
      throw new WalletError("REQUEST_INVALID", "not JSON");
    }
  }
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new WalletError("REQUEST_INVALID", "not a link");
  }
  return Object.fromEntries(url.searchParams.entries());
}

interface DecodedJwt {
  readonly header: Record<string, unknown>;
  readonly payload: Record<string, unknown>;
  readonly signingInput: string;
  readonly signature: string;
}

function decodeJwt(jwt: string): DecodedJwt | null {
  const parts = jwt.trim().split(".");
  if (parts.length !== 3) return null;
  const read = (p: string): Record<string, unknown> | null => {
    try {
      const v = JSON.parse(utf8Decode(base64UrlToBytes(p)) ?? "");
      return isPlainObject(v) ? v : null;
    } catch {
      return null;
    }
  };
  const header = read(parts[0]!);
  const payload = read(parts[1]!);
  if (header === null || payload === null) return null;
  return { header, payload, signingInput: `${parts[0]}.${parts[1]}`, signature: parts[2]! };
}

/** The ask-carrying, by-value request of v1 — kept for callers that hold the fields already. */
export function parseRequest(input: string | Readonly<Record<string, unknown>>): PresentationRequest {
  const fields = outerFields(input);
  if (fields.request_uri !== undefined) throw new WalletError("REQUEST_INVALID", "a request by reference is read by present.read");
  const req = { ...fields, dcql_query: parseJsonParam(fields.dcql_query), kash_ask: parseJsonParam(fields.kash_ask) } as Record<string, unknown>;
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

const KNOWN_PREFIXES = ["x509_hash:", "x509_san_dns:", "redirect_uri:"] as const;

interface CandidateCopy {
  readonly entry: HeldEntry;
  readonly claims: Record<string, unknown>;
}

export class Present {
  constructor(private readonly core: WalletCore) {}

  /** Check a request and say what it asks, why, and what a no costs. Sends nothing. */
  async open(input: string | Readonly<Record<string, unknown>>): Promise<AskView> {
    const r = await this.read(input);
    if (r.kind === "ask") return r.view;
    if (r.kind === "no-ask") throw new WalletError("ASK_REFUSED", r.reason);
    throw new WalletError("REQUEST_INVALID", r.reason);
  }

  /**
   * Read a request, fetching it by reference from the verifier when the link
   * says so. The only request this sends is that fetch, to the address the
   * link names; it carries nothing about the wallet.
   */
  async read(input: string | Readonly<Record<string, unknown>>): Promise<RequestReading> {
    const outer = outerFields(input);
    let jwt: string | null = null;
    if (outer.request_uri !== undefined) {
      const uri = httpsUrl(outer.request_uri);
      if (uri === null) return { kind: "untrusted", reason: "request_uri is not an https address" };
      const method = outer.request_uri_method ?? "get";
      if (method !== "get" && method !== "post") return { kind: "untrusted", reason: `request_uri_method ${String(method)} is not one OpenID4VP defines` };
      const res = await this.core.sendText(
        method === "post"
          ? { url: uri.href, method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/oauth-authz-req+jwt" }, body: "" }
          : { url: uri.href, method: "GET", headers: { accept: "application/oauth-authz-req+jwt" }, body: null },
      );
      // OpenID4VP §5.10.2: on any HTTP error the wallet stops.
      if (res.status !== 200) return { kind: "untrusted", reason: `the request link answered ${res.status}` };
      jwt = res.text;
    } else if (typeof outer.request === "string") {
      jwt = outer.request;
    }

    let claims: Record<string, unknown>;
    let signed: DecodedJwt | null = null;
    if (jwt !== null) {
      const d = decodeJwt(jwt);
      if (d === null) return { kind: "untrusted", reason: "the request object is not a JWT" };
      if (d.header.alg !== "none") signed = d;
      // OpenID4VP §5.10.1: the outer client_id and the request object's are identical, prefix included.
      if (typeof outer.client_id !== "string" || outer.client_id !== d.payload.client_id) return { kind: "untrusted", reason: "the client_id outside the request object differs from the one inside" };
      claims = d.payload;
    } else {
      claims = outer;
    }
    claims = { ...claims };
    for (const f of JSON_FIELDS) if (claims[f] !== undefined) claims[f] = parseJsonParam(claims[f]);

    const clientId = claims.client_id;
    if (typeof clientId !== "string" || clientId.length === 0) return { kind: "untrusted", reason: "no client_id" };
    const responseUri = httpsUrl(claims.response_uri);
    if (responseUri === null) return { kind: "untrusted", reason: "no https response_uri: nowhere to answer" };

    // ── is the request tied to the verifier it names? ───────────────────────────────────────────
    const prefix = KNOWN_PREFIXES.find((p) => clientId.startsWith(p));
    if (prefix !== undefined) {
      const value = clientId.slice(prefix.length);
      if (prefix === "redirect_uri:") {
        if (signed !== null) return { kind: "untrusted", reason: "a redirect_uri client is never signed (OpenID4VP §5.9.3)" };
        if (value !== responseUri.href && value !== claims.response_uri) return { kind: "untrusted", reason: "the redirect_uri client identifier is not the response_uri" };
      } else {
        if (signed === null) return { kind: "untrusted", reason: `an ${prefix.slice(0, -1)} request must be signed` };
        const tied = await this.tiedToCertificate(signed, prefix, value, responseUri);
        if (tied !== null) return { kind: "untrusted", reason: tied };
      }
    } else if (signed !== null || claims.kash_ask === undefined) {
      return { kind: "untrusted", reason: `the client identifier prefix of ${clientId} is not one this wallet checks` };
    }

    // ── tied to its verifier; is it a request the wallet can read? ─────────────────────────────
    const reply = this.replyOf(claims, responseUri);
    const invalid = (reason: string, error: InvalidRequestError = "invalid_request"): RequestReading => ({ kind: "invalid", reason, error, verifier: clientId, reply: reply ?? { responseUri: responseUri.href, mode: "direct_post", encryption: null } });
    if (claims.transaction_data !== undefined) return invalid("transaction data of any type is not read by this wallet", "invalid_transaction_data");
    if (claims.response_type !== "vp_token") return invalid("response_type is not vp_token");
    if (claims.response_mode !== "direct_post" && claims.response_mode !== "direct_post.jwt") return invalid(`response_mode ${String(claims.response_mode)} is not built; direct_post and direct_post.jwt are`);
    if (claims.redirect_uri !== undefined) return invalid("a direct_post request carries no redirect_uri (OpenID4VP §8.2)");
    if (typeof claims.nonce !== "string" || claims.nonce.length === 0) return invalid("no nonce");
    if (claims.state !== undefined && typeof claims.state !== "string") return invalid("state is not a string");
    if (!isPlainObject(claims.dcql_query)) return invalid("no DCQL query");
    if (reply === null) return invalid("direct_post.jwt with no P-256 encryption key, or no content encryption this wallet has");

    if (claims.kash_ask === undefined) return { kind: "no-ask", verifier: clientId, reason: "this request carries no ask, so it is not answered (d42; presentation §1)" };
    if (!isPlainObject(claims.kash_ask) || typeof claims.kash_ask_sha256 !== "string") return invalid("the ask is not readable");
    const req = { ...claims, response_uri: responseUri.href } as unknown as PresentationRequest;
    return { kind: "ask", view: await this.askView(req, reply) };
  }

  /** Tell the verifier its request was broken — only when the person chooses to. Nothing is written. */
  async report(reading: Extract<RequestReading, { kind: "invalid" }>): Promise<PresentResult> {
    const params = { error: reading.error, error_description: reading.reason, ...(reading.reply.state !== undefined ? { state: reading.reply.state } : {}) };
    await this.post(reading.reply, params, []);
    return { status: "sent", verifier: reading.verifier };
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

    await this.post(view.reply, { vp_token: vpToken, ...(req.state !== undefined ? { state: req.state } : {}) }, await this.core.allowed(keyIds));

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

  /** Null when the request is tied to the certificate in its header; otherwise why not. */
  private async tiedToCertificate(jwt: DecodedJwt, prefix: "x509_hash:" | "x509_san_dns:", value: string, responseUri: URL): Promise<string | null> {
    if (jwt.header.alg !== "ES256") return `request objects signed ${String(jwt.header.alg)} are not verified here; ES256 is`;
    const x5c = jwt.header.x5c;
    if (!Array.isArray(x5c) || typeof x5c[0] !== "string") return "no certificate in the request's x5c header";
    let leaf;
    try {
      leaf = await readLeaf(x5c[0]);
    } catch (e) {
      return `the request's certificate cannot be read: ${(e as Error).message}`;
    }
    if (prefix === "x509_hash:" && leaf.sha256 !== value) return "the certificate's hash is not the one the client identifier names";
    if (prefix === "x509_san_dns:") {
      if (!leaf.dnsNames.includes(value)) return "the client identifier is not one of the certificate's DNS names";
      if (responseUri.hostname !== value) return "the response_uri is not on the client identifier's host";
    }
    const now = this.core.now();
    if (now < leaf.notBefore || now > leaf.notAfter) return "the request's certificate is not valid now";
    let sig: Uint8Array;
    try {
      sig = base64UrlToBytes(jwt.signature);
    } catch {
      return "the request's signature cannot be read";
    }
    if (!(await verifyEs256WithSpki(leaf.spki, utf8(jwt.signingInput), sig))) return "the request's signature does not verify under its certificate";
    return null;
  }

  /** How to answer: the mode, and for direct_post.jwt the verifier's key. Null when the mode needs a key there isn't. */
  private replyOf(claims: Record<string, unknown>, responseUri: URL): Reply | null {
    const state = typeof claims.state === "string" ? { state: claims.state } : {};
    if (claims.response_mode !== "direct_post.jwt") return { responseUri: responseUri.href, mode: "direct_post", ...state, encryption: null };
    const meta = isPlainObject(claims.client_metadata) ? claims.client_metadata : {};
    const keys = isPlainObject(meta.jwks) && Array.isArray(meta.jwks.keys) ? meta.jwks.keys : [];
    const key = keys.map(asVerifierEncKey).find((k) => k !== null) ?? null;
    const offered = meta.encrypted_response_enc_values_supported;
    const encs = Array.isArray(offered) ? offered : ["A128GCM"]; // OpenID4VP §5.1's default
    const enc = encs.find((e): e is JweEnc => e === "A128GCM" || e === "A256GCM");
    if (key === null || enc === undefined) return null;
    return { responseUri: responseUri.href, mode: "direct_post.jwt", ...state, encryption: { key, enc } };
  }

  /** Post an answer, in the reply's mode. An error under direct_post.jwt goes encrypted too when a key is there. */
  private async post(reply: Reply, params: Record<string, unknown>, allow: readonly string[]): Promise<void> {
    let fields: Record<string, string>;
    if (reply.mode === "direct_post.jwt" && reply.encryption !== null) {
      fields = { response: await encryptEcdhEs(utf8(JSON.stringify(params)), reply.encryption.key, reply.encryption.enc, this.core.random) };
    } else {
      fields = Object.fromEntries(Object.entries(params).map(([k, v]) => [k, typeof v === "string" ? v : JSON.stringify(v)]));
    }
    const res = await this.core.postForm(reply.responseUri, fields, allow);
    if (res.status < 200 || res.status >= 300) throw new WalletError("SEND_FAILED", `the verifier answered ${res.status}`);
  }

  private async askView(req: PresentationRequest, reply: Reply): Promise<AskView> {
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
      reply,
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
      // d91's terminal states, beside revoked and suspended: a superseded or withdrawn copy is never offered (KS-Q4).
      const status = checkStatus(statusEntryOf(claims), lists, { nowSec: this.core.now() }).state;
      if (status === "revoked" || status === "suspended" || status === "superseded" || status === "withdrawn" || status === "expired") continue;
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
