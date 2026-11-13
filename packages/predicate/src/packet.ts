/**
 * The packet — what the person sends a door, by choice: one OpenID4VP 1.0
 * `vp_token`, keyed by the rule's credential query ids (§8.1).
 *
 *   - an SD-JWT receipt or predicate: a copy that has been shown to this viewer
 *     or to no one (d62(d)3), disclosing only the claims the query reads, with a
 *     KB-JWT over this viewer's audience and nonce;
 *   - the person's own word: issued by the person to themselves under a fresh
 *     key for this viewer, then presented the same way;
 *   - a `kash-artifact` (a countersigned work record): `{artifact, kb}`, where
 *     `kb` binds the viewer's audience and nonce and the artifact's record id,
 *     signed by the key the record names as its holder (`artifactHolderOf`) — or,
 *     where the query says `holder: "countersigner"`, by the one key that
 *     countersigned it (KS-Q11).
 *
 * **What a `kash-artifact` entry does not protect:** a countersigned record
 * cannot be re-keyed per viewer, so two viewers who see the same one can tell
 * it is the same holder's (d62(d)3, until the tier-two circuit exists). An
 * organisation signs as itself (d62(d)2), so for an agency nothing is lost;
 * for a person it is a choice the wallet says out loud.
 *
 * A receipt is sent once, under one query, even when several criteria read it.
 *
 * `checkPacket` is the desk's free check, offline except for the status lists
 * the caller passes: signatures, key binding, audience, nonce, issuers, types,
 * expiry, status — then each verified receipt is matched against every
 * criterion's queries.
 */

import { decodeJws, issueSdJwt, jwkOf, parseSdJwt, presentSdJwt, signJws, verifyJws, type DecodedDisclosure, type JwsSigner } from "@kashscript/attest/sd-jwt";
import { recordIdOf } from "@kashscript/attest/holder";
import { resolveVerificationKey, type VerifyKey } from "@kashscript/attest/signing";
import { deriveDidForKey, isAlgorithmUnsupported } from "@kashscript/identity-core";
import type { DcqlCredentialQuery } from "@kashscript/lexicons/extensions/door";
import { criterionOfQueryId, criterionQueries, matchQuery, OWN_WORD_SUFFIX, PREDICATE_SUFFIX, ruleToDcql, selectClaim } from "./dcql";
import { asOfSeconds, type MatchedReceipt } from "./criteria";
import { artifactKindOf, readReceipt, type ReadContext, type ReceiptView } from "./receipts";
import type { ReadRule, RuleRequest } from "./rule";
import { ARTIFACT_KB_TYP, DAY, KASH_ARTIFACT_FORMAT, OWN_WORD_VCT, SD_JWT_FORMAT } from "./constants";

export interface ArtifactPresentation {
  readonly artifact: Readonly<Record<string, unknown>>;
  /** A compact JWS, `typ: kash-artifact-kb+jwt`, over `{aud, nonce, iat, artifact_sha256}`. */
  readonly kb: string;
}

export type Presentation = string | ArtifactPresentation;
export type VpToken = Readonly<Record<string, readonly Presentation[]>>;

/** A signer that can also say which public key it holds (to put in `cnf`, or to check a binding). */
export type HolderSigner = JwsSigner;

export type PacketEntry =
  | {
      readonly kind: "sd-jwt";
      readonly queryId: string;
      /** The held copy — never one shown to another viewer. */
      readonly held: string;
      readonly signer: HolderSigner;
      /** Claim ids to disclose. Default: every claim the query names. */
      readonly disclose?: readonly string[];
    }
  | { readonly kind: "artifact"; readonly queryId: string; readonly artifact: Readonly<Record<string, unknown>>; readonly signer: HolderSigner }
  | {
      readonly kind: "own-word";
      readonly queryId: string;
      readonly fields: Readonly<Record<string, unknown>>;
      /** A fresh key, made for this viewer alone. */
      readonly signer: HolderSigner & { readonly publicKey: Uint8Array };
      readonly keyType?: "Ed25519" | "P-256";
    };

export interface Packet {
  readonly vp_token: VpToken;
  /** The issuer-JWT hashes of the SD-JWT copies used, so the wallet marks them as this viewer's. */
  readonly copiesUsed: readonly string[];
}

export class PacketError extends Error {
  constructor(
    readonly code: "UNKNOWN_QUERY" | "ONE_ONLY" | "COPY_TWICE" | "WRONG_KIND" | "NOT_AN_SD_JWT",
    message: string,
  ) {
    super(message);
    this.name = "PacketError";
  }
}

const enc = new TextEncoder();

async function sha256HexOf(s: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s) as unknown as BufferSource);
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/** The top-level claim names (and array names) a set of claim paths touches. */
function topNames(query: DcqlCredentialQuery, ids: readonly string[] | undefined): Set<string> {
  const out = new Set<string>();
  for (const c of query.claims ?? []) {
    if (ids !== undefined && !ids.includes(c.id)) continue;
    const first = c.path[0];
    if (typeof first === "string") out.add(first);
  }
  return out;
}

/** Map each array element's digest to the array claim it sits in, from the issuer-signed payload. */
function arrayOfDigest(held: string): Map<string, string> {
  const out = new Map<string, string>();
  const p = parseSdJwt(held);
  const payload = p === null ? null : decodeJws(p.issuerJwt)?.payload ?? null;
  if (payload === null) return out;
  for (const [name, v] of Object.entries(payload)) {
    if (!Array.isArray(v)) continue;
    for (const el of v) if (isPlainObject(el) && typeof el["..."] === "string") out.set(el["..."], name);
  }
  return out;
}

const dayOf = (t: number): number => t - (t % DAY);

/** Build the person's packet. Throws `PacketError` before anything is signed if an entry does not fit the rule. */
export async function buildPacket(input: {
  readonly rule: ReadRule;
  readonly request: Pick<RuleRequest, "client_id" | "nonce">;
  readonly entries: readonly PacketEntry[];
  readonly iatUnix: number;
}): Promise<Packet> {
  const dcql = ruleToDcql(input.rule.body, input.rule.hash);
  const byId = new Map(dcql.credentials.map((q) => [q.id, q]));
  const counts = new Map<string, number>();
  const copies = new Set<string>();
  for (const e of input.entries) {
    const q = byId.get(e.queryId);
    if (q === undefined) throw new PacketError("UNKNOWN_QUERY", `the rule asks nothing under ${e.queryId}`);
    const n = (counts.get(e.queryId) ?? 0) + 1;
    if (n > 1 && q.multiple !== true) throw new PacketError("ONE_ONLY", `${e.queryId} takes one presentation`);
    counts.set(e.queryId, n);
    const wantKind = e.queryId.endsWith(OWN_WORD_SUFFIX) ? "own-word" : q.format === KASH_ARTIFACT_FORMAT ? "artifact" : "sd-jwt";
    if (e.kind !== wantKind) throw new PacketError("WRONG_KIND", `${e.queryId} is answered by ${wantKind}, not ${e.kind}`);
    if (e.kind === "sd-jwt") {
      const p = parseSdJwt(e.held);
      if (p === null) throw new PacketError("NOT_AN_SD_JWT", `${e.queryId}: not an SD-JWT`);
      const copy = await sha256HexOf(p.issuerJwt);
      if (copies.has(copy)) throw new PacketError("COPY_TWICE", "one copy cannot be shown twice — each answer takes its own");
      copies.add(copy);
    }
  }

  const kb = { aud: input.request.client_id, nonce: input.request.nonce, iatUnix: input.iatUnix };
  const vp: Record<string, Presentation[]> = {};
  for (const e of input.entries) {
    const q = byId.get(e.queryId)!;
    let pres: Presentation;
    if (e.kind === "sd-jwt") {
      const names = topNames(q, e.disclose);
      const arrays = arrayOfDigest(e.held);
      const choose = (d: DecodedDisclosure): boolean => (d.name !== null ? names.has(d.name) : names.has(arrays.get(d.digest) ?? ""));
      pres = await presentSdJwt(e.held, choose, e.signer, kb);
    } else if (e.kind === "own-word") {
      const c = criterionOfQueryId(input.rule.body, e.queryId)!;
      const key: VerifyKey = e.keyType === "P-256" ? { type: "P-256", publicKey: e.signer.publicKey } : e.signer.publicKey;
      const did = deriveDidForKey(key instanceof Uint8Array ? { type: "Ed25519", publicKey: key } : key);
      const fields = c.answer.by === "own-word" ? Object.fromEntries(Object.keys(c.answer.fields).filter((f) => f in e.fields).map((f) => [f, e.fields[f]])) : {};
      const held = await issueSdJwt({
        header: { kid: did },
        claims: {
          iss: did,
          iat: dayOf(input.iatUnix),
          exp: Math.floor(Date.parse(input.rule.body.dates.endsAt) / 1000),
          vct: OWN_WORD_VCT,
          cnf: { jwk: jwkOf(key) },
          word: { rule: { id: input.rule.body.id, version: input.rule.body.version, hash: input.rule.hash }, criterion: c.id, fields },
        },
        signer: e.signer,
      });
      pres = await presentSdJwt(held, () => true, e.signer, kb);
    } else {
      const sha = await recordIdOf({ kind: artifactKindOf(e.artifact) ?? "dsse", value: e.artifact });
      pres = { artifact: e.artifact, kb: await signJws({ typ: ARTIFACT_KB_TYP }, { aud: kb.aud, nonce: kb.nonce, iat: kb.iatUnix, artifact_sha256: sha }, e.signer) };
    }
    (vp[e.queryId] ??= []).push(pres);
  }
  return { vp_token: vp, copiesUsed: [...copies] };
}

/* ── the desk's check ──────────────────────────────────────────────────── */

export interface CheckedCriterion {
  readonly receipts: readonly MatchedReceipt[];
  readonly predicates: readonly MatchedReceipt[];
  /** The person's own word, when it checked: the fields they stated. */
  readonly word: Readonly<Record<string, unknown>> | null;
}

export interface PacketCheck {
  readonly rule: { readonly id: string; readonly version: number; readonly hash: string };
  readonly byCriterion: Readonly<Record<string, CheckedCriterion>>;
  /** What did not check, by query id — never counted. */
  readonly problems: readonly { readonly queryId: string; readonly why: string }[];
}

/**
 * The key a `kash-artifact` presentation is bound to — the one the desk checks the
 * binding against, the one a wallet must hold, and the one a decision receipt is
 * issued to. One function, so the three never disagree.
 *
 *   - `meta.holder: "countersigner"` (kash.rule@1.2.0, KS-Q11): the one countersigner
 *     attest verified in the bundle (`view.countersigners`, less the requester). None,
 *     or more than one, is no holder. Any other kind of artifact has none.
 *   - `meta.holder_path`: the key the signed payload names there (Client Sign-off:
 *     `actor.id`, the doer).
 *   - neither, for a countersign bundle: its signed request's `requesterDid`.
 *   - neither, otherwise: the issuer.
 */
export function artifactHolderOf(query: DcqlCredentialQuery, view: ReceiptView, artifact: Readonly<Record<string, unknown>>): string | null {
  if (query.meta?.holder === "countersigner") {
    return view.kind === "countersign-bundle" && view.countersigners.length === 1 ? view.countersigners[0]! : null;
  }
  const hp = query.meta?.holder_path;
  if (hp !== undefined) {
    const sel = selectClaim(view.claims, hp);
    return sel !== null && typeof sel.value === "string" ? sel.value : null;
  }
  if (view.kind === "countersign-bundle") {
    const req = artifact.request;
    return isPlainObject(req) && isPlainObject(req.body) && typeof req.body.requesterDid === "string" ? req.body.requesterDid : null;
  }
  return view.issuer;
}

/** A key binding further than this from `asOf`, either way, is stale unless the desk widens the window (AU-3, A7-08). */
export const DEFAULT_MAX_KB_AGE_SEC = 600;

/**
 * Check a packet against the rule and the request it answers. Offline except for
 * the status lists passed in.
 *
 * **Freshness (AU-3, A7-08).** Every binding — an SD-JWT's KB-JWT and a
 * `kash-artifact`'s KB — carries the moment it was made. One further than
 * `freshness.maxKbAgeSec` (default ten minutes) from `asOf`, either way, is
 * stale and does not count; a binding with no time does not count. This bounds
 * how long a captured packet stays valid. It is not the replay defence: that is
 * the caller's, who issues each nonce once and accepts it once.
 *
 * **One item that does not read never stops the rest (AU-3, A7-04):** it becomes
 * a problem line, and every other presentation is judged.
 */
export async function checkPacket(input: {
  readonly rule: ReadRule;
  readonly request: Pick<RuleRequest, "client_id" | "nonce">;
  readonly vp_token: unknown;
  readonly ctx: Omit<ReadContext, "nowSec">;
  readonly asOf: string | number;
  readonly freshness?: { readonly maxKbAgeSec?: number };
}): Promise<PacketCheck> {
  const nowSec = asOfSeconds(input.asOf);
  const ctx: ReadContext = { ...input.ctx, nowSec };
  const maxKbAgeSec = input.freshness?.maxKbAgeSec ?? DEFAULT_MAX_KB_AGE_SEC;
  const body = input.rule.body;
  const dcql = ruleToDcql(body, input.rule.hash);
  const byId = new Map(dcql.credentials.map((q) => [q.id, q]));
  const problems: { queryId: string; why: string }[] = [];
  const by: Record<string, { receipts: MatchedReceipt[]; predicates: MatchedReceipt[]; word: Record<string, unknown> | null }> = {};
  for (const c of body.criteria) by[c.id] = { receipts: [], predicates: [], word: null };
  const token = typeof input.vp_token === "string" ? (JSON.parse(input.vp_token) as unknown) : input.vp_token;
  if (!isPlainObject(token)) return { rule: { id: body.id, version: body.version, hash: input.rule.hash }, byCriterion: by, problems: [{ queryId: "", why: "the vp_token is not an object" }] };

  // 1. Verify each presentation once, under the query it was sent for.
  const verified: { queryId: string; view: ReceiptView }[] = [];
  const seen = new Set<string>();
  for (const [queryId, list] of Object.entries(token)) {
    const q = byId.get(queryId);
    if (q === undefined || criterionOfQueryId(body, queryId) === null) {
      problems.push({ queryId, why: "the rule asks nothing under this id" });
      continue;
    }
    const items = Array.isArray(list) ? list : [list];
    if (items.length > 1 && q.multiple !== true) {
      problems.push({ queryId, why: "one presentation is asked for here; none of these were counted" });
      continue;
    }
    for (const [i, item] of items.entries()) {
      const ref = `${queryId}#${i}`;
      let view: ReceiptView | null = null;
      try {
        if (q.format === SD_JWT_FORMAT) {
          if (typeof item !== "string") {
            problems.push({ queryId, why: "not an SD-JWT presentation" });
            continue;
          }
          view = await readReceipt({ ref, value: item }, ctx, { presentedTo: { audience: input.request.client_id, nonce: input.request.nonce }, maxKbAgeSec });
          // A credential that does not check says why below; only one that checks and still
          // carries no binding is "not bound" (a forged issuer, for one, is named as such).
          if (view !== null && view.counts && view.sdJwt !== null && !view.sdJwt.keyBinding.present) {
            problems.push({ queryId, why: "not bound to this viewer" });
            continue;
          }
        } else {
          if (!isPlainObject(item) || !isPlainObject(item.artifact) || typeof item.kb !== "string") {
            problems.push({ queryId, why: "a kash-artifact presentation is {artifact, kb}" });
            continue;
          }
          view = await readReceipt({ ref, value: item.artifact }, ctx);
          if (view !== null) {
            const why = await artifactBindingProblem(q, view, item.artifact, item.kb, input.request, nowSec, maxKbAgeSec);
            if (why !== null) {
              problems.push({ queryId, why });
              continue;
            }
          }
        }
      } catch (err) {
        // An item anyone could have mangled is a problem line; the rest are still judged (AU-3, A7-04).
        if (isAlgorithmUnsupported(err)) throw err;
        problems.push({ queryId, why: "does not read" });
        continue;
      }
      if (view === null) {
        problems.push({ queryId, why: "not a receipt this version reads" });
        continue;
      }
      if (!view.counts) {
        problems.push({ queryId, why: view.problems.join("; ") || "does not count" });
        continue;
      }
      // One record, one count — by what was signed, not by how it was wrapped (AU-3, A7-03).
      if (seen.has(view.contentId)) {
        problems.push({ queryId, why: "the same receipt twice — it was counted once" });
        continue;
      }
      seen.add(view.contentId);
      verified.push({ queryId, view });
    }
  }

  // 2. Match every verified receipt against every criterion's queries: one receipt
  //    may answer several criteria (a CPD record counts toward hours and structured
  //    hours), so the person sends it once. A predicate and an own word answer only
  //    the query they were sent under, whose claims pin rule, version and criterion.
  const matchCtx = { trustLists: ctx.trustLists ?? [], nowSec };
  for (const c of body.criteria) {
    for (const q of criterionQueries(body, input.rule.hash, c).queries) {
      const special = q.id.endsWith(OWN_WORD_SUFFIX) || q.id.endsWith(PREDICATE_SUFFIX);
      for (const v of verified) {
        if (special && v.queryId !== q.id) continue;
        if (!special && (v.queryId.endsWith(OWN_WORD_SUFFIX) || v.queryId.endsWith(PREDICATE_SUFFIX))) continue;
        const m = matchQuery(q, v.view, matchCtx);
        if (!m.ok) {
          if (v.queryId === q.id) problems.push({ queryId: q.id, why: m.why });
          continue;
        }
        const entry: MatchedReceipt = { queryId: q.id, view: v.view, values: m.values };
        const slot = by[c.id]!;
        if (q.id.endsWith(OWN_WORD_SUFFIX)) {
          if (v.view.issuer === null || v.view.holder === null || v.view.issuer.split("#")[0] !== v.view.holder) {
            problems.push({ queryId: q.id, why: "an own-word statement is issued by the person to themselves" });
            continue;
          }
          const claims = v.view.claims;
          const fields = isPlainObject(claims) && isPlainObject(claims.word) && isPlainObject(claims.word.fields) ? claims.word.fields : {};
          slot.word = { ...fields };
          slot.receipts.push(entry);
        } else if (q.id.endsWith(PREDICATE_SUFFIX)) {
          slot.predicates.push(entry);
        } else if (!slot.receipts.some((r) => r.view.contentId === v.view.contentId)) {
          slot.receipts.push(entry);
        }
      }
    }
  }
  return { rule: { id: body.id, version: body.version, hash: input.rule.hash }, byCriterion: by, problems };
}

async function artifactBindingProblem(
  q: DcqlCredentialQuery,
  view: ReceiptView,
  artifact: Readonly<Record<string, unknown>>,
  kb: string,
  request: Pick<RuleRequest, "client_id" | "nonce">,
  nowSec: number,
  maxKbAgeSec: number,
): Promise<string | null> {
  const jws = decodeJws(kb);
  if (jws === null || jws.header.typ !== ARTIFACT_KB_TYP) return "its binding does not read";
  const p = jws.payload;
  if (p.aud !== request.client_id) return "bound to another viewer";
  if (p.nonce !== request.nonce) return "bound to another request";
  if (p.artifact_sha256 !== view.id) return "its binding is for another record";
  // The binding's age is bounded (AU-3, A7-08): no time, or a time outside the window, does not count.
  if (typeof p.iat !== "number" || !Number.isFinite(p.iat)) return "its binding carries no time";
  if (Math.abs(nowSec - p.iat) > maxKbAgeSec) return "its binding is stale — made outside the window this desk accepts";
  const holder = artifactHolderOf(q, view, artifact);
  if (holder === null && q.meta?.holder === "countersigner") return "the record names no single countersigner to check its binding";
  const key = holder === null ? null : resolveVerificationKey(holder);
  if (key === null) return "the record names no holder key to check its binding";
  return (await verifyJws(jws, key)) ? null : "its binding is not signed by the record's holder";
}
