/**
 * SD-JWT (IETF Selective Disclosure for JWTs) with SD-JWT VC's `dc+sd-jwt`
 * issuer JWT and a Key Binding JWT — the presentation format of
 * specs/presentation.md. Written against the standard, not invented.
 *
 *   held credential : <issuer-JWT>~<disclosure>~…~<disclosure>~
 *   presentation    : <issuer-JWT>~<chosen disclosures>~…~<KB-JWT>
 *
 * A disclosure is `b64u(JSON([salt, name, value]))` for an object property or
 * `b64u(JSON([salt, value]))` for an array element; the issuer signs only its
 * digest, `b64u(SHA-256(ASCII(disclosure)))`. The KB-JWT binds the
 * presentation to the holder key in `cnf.jwk`, to one audience and one nonce,
 * and to these exact disclosures through `sd_hash`.
 *
 * Nothing here fetches anything: the issuer's key resolves through the holder
 * contract's order (self-certifying `iss`, pinned trust list, held key), and
 * SD-JWT VC's issuer-metadata and type-metadata lookups are never made.
 *
 * **The key is `iss`'s, never a header's** (AU-3, A7-01). A `kid` only selects
 * among the issuer's keys: it must name `iss` (a `#fragment` apart), or the
 * credential is refused as `KID_NOT_ISSUER`. Resolving a key from the header
 * and then reporting `iss` as the issuer would let any key sign in any
 * organisation's name.
 */

import { base64UrlToBytes, bytesToBase64Url } from "../ed25519";
import { decodeJws, didOfJwk, keyOfJwk, signJws, verifyJws, type DecodedJws, type JwsSigner } from "./jws";
import { keyOfResolved, stripFragment, type KeyResolver, type KeySource } from "../holder/keys";
import { isAlgorithmUnsupported } from "@kashscript/identity-core";

export const SD_JWT_TYP = "dc+sd-jwt" as const;
export const KB_JWT_TYP = "kb+jwt" as const;
export const SD_ALG = "sha-256" as const;

const enc = new TextEncoder();

async function digestOf(disclosure: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(disclosure) as unknown as BufferSource);
  return bytesToBase64Url(new Uint8Array(d));
}
function randomB64u(bytes = 16): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(bytes)));
}
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/* ── issuance ──────────────────────────────────────────────────────────── */

export interface IssueSdJwtInput {
  /** Extra header parameters (e.g. `kid`). `alg` and `typ` are set here. */
  readonly header?: Readonly<Record<string, unknown>>;
  /** Claims always visible to every verifier. */
  readonly claims: Readonly<Record<string, unknown>>;
  /** Top-level claims the holder may disclose one by one. */
  readonly sdProperties?: Readonly<Record<string, unknown>>;
  /** Top-level array claims whose ELEMENTS the holder may disclose one by one. */
  readonly sdArrays?: Readonly<Record<string, readonly unknown[]>>;
  /** Decoy digests added to `_sd` and to each selectively-disclosable array, so counts do not show. */
  readonly decoys?: number;
  readonly signer: JwsSigner;
}

/** Issue an SD-JWT; returns the held form, with every disclosure. */
export async function issueSdJwt(input: IssueSdJwtInput): Promise<string> {
  const payload: Record<string, unknown> = { ...input.claims };
  const disclosures: string[] = [];
  const sd: string[] = [];
  const decoys = input.decoys ?? 0;

  for (const [name, value] of Object.entries(input.sdProperties ?? {})) {
    if (name in payload || name === "_sd" || name === "...") throw new Error(`claim ${name} is already visible`);
    const d = bytesToBase64Url(enc.encode(JSON.stringify([randomB64u(), name, value])));
    disclosures.push(d);
    sd.push(await digestOf(d));
  }
  for (const [name, values] of Object.entries(input.sdArrays ?? {})) {
    if (name in payload) throw new Error(`claim ${name} is already visible`);
    const placeholders: { "...": string }[] = [];
    for (const v of values) {
      const d = bytesToBase64Url(enc.encode(JSON.stringify([randomB64u(), v])));
      disclosures.push(d);
      placeholders.push({ "...": await digestOf(d) });
    }
    for (let i = 0; i < decoys; i++) placeholders.push({ "...": await digestOf(randomB64u(32)) });
    // Shuffle so position says nothing about which element is real.
    for (let i = placeholders.length - 1; i > 0; i--) {
      const j = crypto.getRandomValues(new Uint32Array(1))[0]! % (i + 1);
      [placeholders[i], placeholders[j]] = [placeholders[j]!, placeholders[i]!];
    }
    payload[name] = placeholders;
  }
  for (let i = 0; i < decoys; i++) sd.push(await digestOf(randomB64u(32)));
  if (sd.length > 0) payload._sd = [...sd].sort();
  if (disclosures.length > 0 || decoys > 0) payload._sd_alg = SD_ALG;

  const jwt = await signJws({ ...(input.header ?? {}), typ: SD_JWT_TYP }, payload, input.signer);
  return `${jwt}~${disclosures.map((d) => `${d}~`).join("")}`;
}

/* ── parsing ───────────────────────────────────────────────────────────── */

export interface ParsedSdJwt {
  readonly issuerJwt: string;
  readonly disclosures: readonly string[];
  /** The KB-JWT, or null for a held credential. */
  readonly kbJwt: string | null;
}

export function parseSdJwt(input: string): ParsedSdJwt | null {
  if (typeof input !== "string") return null;
  const s = input.trim();
  if (!s.includes("~")) return null;
  const parts = s.split("~");
  const issuerJwt = parts[0]!;
  const last = parts[parts.length - 1]!;
  const disclosures = parts.slice(1, -1);
  if (decodeJws(issuerJwt) === null) return null;
  if (disclosures.some((d) => d.length === 0)) return null;
  return { issuerJwt, disclosures, kbJwt: last.length > 0 ? last : null };
}

/** Is this string shaped like an SD-JWT (held or presented)? */
export function isSdJwt(value: unknown): value is string {
  return typeof value === "string" && parseSdJwt(value) !== null;
}

export interface DecodedDisclosure {
  readonly encoded: string;
  readonly digest: string;
  readonly salt: string;
  /** Property name, or null for an array element. */
  readonly name: string | null;
  readonly value: unknown;
}

export async function decodeDisclosure(encoded: string): Promise<DecodedDisclosure | null> {
  let arr: unknown;
  try {
    arr = JSON.parse(new TextDecoder().decode(base64UrlToBytes(encoded)));
  } catch {
    return null;
  }
  if (!Array.isArray(arr) || typeof arr[0] !== "string") return null;
  if (arr.length === 3 && typeof arr[1] === "string") {
    return { encoded, digest: await digestOf(encoded), salt: arr[0], name: arr[1], value: arr[2] };
  }
  if (arr.length === 2) return { encoded, digest: await digestOf(encoded), salt: arr[0], name: null, value: arr[1] };
  return null;
}

/* ── presentation ──────────────────────────────────────────────────────── */

export interface KeyBindingInput {
  readonly aud: string;
  readonly nonce: string;
  readonly iatUnix: number;
}

/**
 * Present a held SD-JWT: keep only the disclosures `choose` returns true for,
 * and bind the result to one audience and one nonce with the holder's key.
 */
export async function presentSdJwt(
  held: string,
  choose: (d: DecodedDisclosure) => boolean,
  holder: JwsSigner,
  kb: KeyBindingInput,
): Promise<string> {
  const parsed = parseSdJwt(held);
  if (parsed === null) throw new Error("not an SD-JWT");
  const kept: string[] = [];
  for (const d of parsed.disclosures) {
    const decoded = await decodeDisclosure(d);
    if (decoded !== null && choose(decoded)) kept.push(d);
  }
  const base = `${parsed.issuerJwt}~${kept.map((d) => `${d}~`).join("")}`;
  const sdHash = await digestOf(base);
  const kbJwt = await signJws({ typ: KB_JWT_TYP }, { iat: kb.iatUnix, aud: kb.aud, nonce: kb.nonce, sd_hash: sdHash }, holder);
  return base + kbJwt;
}

/* ── verification ──────────────────────────────────────────────────────── */

export type SdJwtFailureReason =
  | "MALFORMED_SD_JWT"
  | "ALG_UNSUPPORTED"
  | "TYP_MISMATCH"
  | "ISSUER_KEY_UNRESOLVED"
  /** The header's `kid` names another identifier than `iss`: the key would not be the issuer's (AU-3, A7-01). */
  | "KID_NOT_ISSUER"
  | "ISSUER_SIGNATURE_INVALID"
  | "INVALID_DISCLOSURE"
  | "DUPLICATE_DISCLOSURE"
  | "DUPLICATE_DIGEST"
  | "UNREFERENCED_DISCLOSURE"
  | "SD_ALG_UNSUPPORTED"
  | "CREDENTIAL_EXPIRED"
  | "HOLDER_KEY_MISSING"
  | "KEY_BINDING_MISSING"
  | "KEY_BINDING_INVALID"
  | "SD_HASH_MISMATCH"
  | "AUDIENCE_MISMATCH"
  | "NONCE_MISMATCH"
  | "KEY_BINDING_STALE"
  /** This runtime cannot run the algorithm a key needs (older browsers lack Ed25519). Nothing was judged. */
  | "RUNTIME_CANNOT_CHECK";

export interface DisclosedItem {
  /** Where the value landed: a property name, or `[arrayName, index]`. */
  readonly path: readonly (string | number)[];
  readonly value: unknown;
}

export interface SdJwtReport {
  readonly ok: boolean;
  readonly reason: SdJwtFailureReason | null;
  readonly issuer: string | null;
  readonly issuerKeySource: KeySource | null;
  readonly vct: string | null;
  /** The claims a verifier sees: visible claims plus what the holder disclosed. */
  readonly claims: Record<string, unknown> | null;
  readonly disclosed: readonly DisclosedItem[];
  /** The `did:kash` of the holder key in `cnf.jwk` — the relationship identifier. */
  readonly holder: string | null;
  readonly keyBinding: {
    readonly present: boolean;
    readonly signatureOk: boolean;
    readonly sdHashOk: boolean;
    readonly audience: string | null;
    readonly nonce: string | null;
    readonly iat: number | null;
    /** null when no expected value was supplied. */
    readonly audienceOk: boolean | null;
    readonly nonceOk: boolean | null;
  };
  readonly notes: readonly string[];
}

export interface VerifySdJwtOptions {
  readonly resolveKey: KeyResolver;
  /** Presentations must carry a KB-JWT; a held credential need not. */
  readonly requireKeyBinding: boolean;
  readonly audience?: string;
  readonly nonce?: string;
  readonly nowSec?: number;
  /** When set, a KB-JWT older than this fails. Only meaningful at the moment of receipt. */
  readonly maxKbAgeSec?: number;
}

function report(partial: Partial<SdJwtReport> & { reason: SdJwtFailureReason | null }, notes: string[] = []): SdJwtReport {
  return {
    ok: partial.reason === null,
    issuer: null,
    issuerKeySource: null,
    vct: null,
    claims: null,
    disclosed: [],
    holder: null,
    keyBinding: { present: false, signatureOk: false, sdHashOk: false, audience: null, nonce: null, iat: null, audienceOk: null, nonceOk: null },
    ...partial,
    notes: [...(partial.notes ?? []), ...notes],
  };
}

/**
 * Verify an SD-JWT offline — held (no KB-JWT) or presented (with one).
 * Structurally junk input returns a report, never a throw. A runtime that
 * cannot run a key's algorithm returns `RUNTIME_CANNOT_CHECK`, never invalid.
 */
export async function verifySdJwt(input: string, opts: VerifySdJwtOptions): Promise<SdJwtReport> {
  try {
    return await verifySdJwtInner(input, opts);
  } catch (err) {
    if (isAlgorithmUnsupported(err)) {
      return report({ reason: "RUNTIME_CANNOT_CHECK" }, ["this runtime cannot run a signature algorithm this SD-JWT needs (Ed25519 arrived late in some browsers) — nothing was judged; check it in Node 22+ or a current browser"]);
    }
    throw err;
  }
}

async function verifySdJwtInner(input: string, opts: VerifySdJwtOptions): Promise<SdJwtReport> {
  const parsed = parseSdJwt(input);
  if (parsed === null) return report({ reason: "MALFORMED_SD_JWT" }, ["not an SD-JWT"]);
  const jwt = decodeJws(parsed.issuerJwt) as DecodedJws;
  // EdDSA or ES256 — and below, only the one the issuer's KEY implies.
  if (jwt.header.alg !== "EdDSA" && jwt.header.alg !== "ES256") return report({ reason: "ALG_UNSUPPORTED" }, [`alg ${String(jwt.header.alg)} — this version verifies EdDSA and ES256`]);
  if (jwt.header.typ !== SD_JWT_TYP) return report({ reason: "TYP_MISMATCH" }, [`typ must be ${SD_JWT_TYP}`]);
  const payload = jwt.payload;
  const iss = typeof payload.iss === "string" ? payload.iss : null;
  const vct = typeof payload.vct === "string" ? payload.vct : null;

  // The issuer's key is iss's — resolved offline, never fetched. A kid only selects
  // among that issuer's keys; one naming anything else is refused (AU-3, A7-01).
  if (iss === null) return report({ reason: "ISSUER_KEY_UNRESOLVED", vct }, ["no iss — the key is the issuer's, never a header's, so there is no issuer to bind it to"]);
  const kid = jwt.header.kid;
  if (kid !== undefined && (typeof kid !== "string" || stripFragment(kid) !== stripFragment(iss))) {
    return report(
      { reason: "KID_NOT_ISSUER", issuer: iss, vct },
      [`the header's kid (${typeof kid === "string" ? stripFragment(kid) : String(kid)}) is not the issuer (${stripFragment(iss)}) — the key is the issuer's, and a kid only selects among its keys`],
    );
  }
  const key = opts.resolveKey(iss) ?? opts.resolveKey(stripFragment(iss));
  if (key === null) return report({ reason: "ISSUER_KEY_UNRESOLVED", issuer: iss, vct }, ["the issuer's key is not self-certifying, listed or held"]);
  if (!(await verifyJws(jwt, keyOfResolved(key)))) {
    const mismatch = jwt.header.alg !== (key.type === "P-256" ? "ES256" : "EdDSA");
    return report(
      { reason: "ISSUER_SIGNATURE_INVALID", issuer: iss, vct, issuerKeySource: key.source },
      mismatch ? [`the header says ${String(jwt.header.alg)} but the issuer's key is ${key.type} — the key decides`] : [],
    );
  }
  const base = { issuer: iss, vct, issuerKeySource: key.source };

  if (payload._sd_alg !== undefined && payload._sd_alg !== SD_ALG) return report({ ...base, reason: "SD_ALG_UNSUPPORTED" });

  // Disclosures, each referenced exactly once.
  const byDigest = new Map<string, DecodedDisclosure>();
  for (const d of parsed.disclosures) {
    const decoded = await decodeDisclosure(d);
    if (decoded === null) return report({ ...base, reason: "INVALID_DISCLOSURE" });
    if (byDigest.has(decoded.digest)) return report({ ...base, reason: "DUPLICATE_DISCLOSURE" });
    byDigest.set(decoded.digest, decoded);
  }
  const used = new Set<string>();
  const seen = new Set<string>();
  const disclosed: DisclosedItem[] = [];
  let fault: SdJwtFailureReason | null = null;

  const expand = (value: unknown, path: readonly (string | number)[]): unknown => {
    if (Array.isArray(value)) {
      const out: unknown[] = [];
      for (const el of value) {
        if (isPlainObject(el) && Object.keys(el).length === 1 && typeof el["..."] === "string") {
          const digest = el["..."];
          if (seen.has(digest)) fault ??= "DUPLICATE_DIGEST";
          seen.add(digest);
          const d = byDigest.get(digest);
          if (d === undefined) continue; // undisclosed, or a decoy
          if (d.name !== null) {
            fault ??= "INVALID_DISCLOSURE";
            continue;
          }
          used.add(digest);
          const idx = out.length;
          const v = expand(d.value, [...path, idx]);
          out.push(v);
          disclosed.push({ path: [...path, idx], value: v });
        } else {
          out.push(expand(el, [...path, out.length]));
        }
      }
      return out;
    }
    if (isPlainObject(value)) {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value)) {
        if (k === "_sd" || k === "_sd_alg") continue;
        out[k] = expand(v, [...path, k]);
      }
      const sd = value._sd;
      if (sd !== undefined) {
        if (!Array.isArray(sd)) {
          fault ??= "INVALID_DISCLOSURE";
          return out;
        }
        for (const digest of sd) {
          if (typeof digest !== "string") continue;
          if (seen.has(digest)) fault ??= "DUPLICATE_DIGEST";
          seen.add(digest);
          const d = byDigest.get(digest);
          if (d === undefined) continue;
          if (d.name === null || d.name === "_sd" || d.name === "..." || d.name in out) {
            fault ??= "INVALID_DISCLOSURE";
            continue;
          }
          used.add(digest);
          const v = expand(d.value, [...path, d.name]);
          out[d.name] = v;
          disclosed.push({ path: [...path, d.name], value: v });
        }
      }
      return out;
    }
    return value;
  };
  const claims = expand(payload, []) as Record<string, unknown>;
  if (fault !== null) return report({ ...base, reason: fault });
  if (used.size !== byDigest.size) return report({ ...base, reason: "UNREFERENCED_DISCLOSURE" }, ["a disclosure matches no digest the issuer signed"]);

  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  if (typeof claims.exp === "number" && claims.exp < now) {
    return report({ ...base, claims, disclosed, reason: "CREDENTIAL_EXPIRED" });
  }
  const cnf = isPlainObject(claims.cnf) ? claims.cnf : null;
  const holderKey = cnf === null ? null : keyOfJwk(cnf.jwk);
  const holder = cnf === null ? null : didOfJwk(cnf.jwk);
  const withClaims = { ...base, claims, disclosed, holder };

  if (parsed.kbJwt === null) {
    if (opts.requireKeyBinding) return report({ ...withClaims, reason: "KEY_BINDING_MISSING" }, ["a presentation must be bound to the holder's key"]);
    return report({ ...withClaims, reason: null }, ["a held credential — no key binding, so it proves nothing about who shows it"]);
  }
  if (holderKey === null) return report({ ...withClaims, reason: "HOLDER_KEY_MISSING" });
  const kb = decodeJws(parsed.kbJwt);
  if (kb === null || kb.header.typ !== KB_JWT_TYP) return report({ ...withClaims, reason: "KEY_BINDING_INVALID" });
  const kbSigOk = await verifyJws(kb, holderKey);
  const baseString = input.trim().slice(0, input.trim().length - parsed.kbJwt.length);
  const sdHashOk = kb.payload.sd_hash === (await digestOf(baseString));
  const aud = typeof kb.payload.aud === "string" ? kb.payload.aud : null;
  const nonce = typeof kb.payload.nonce === "string" ? kb.payload.nonce : null;
  const iat = typeof kb.payload.iat === "number" ? kb.payload.iat : null;
  const audienceOk = opts.audience === undefined ? null : aud === opts.audience;
  const nonceOk = opts.nonce === undefined ? null : nonce === opts.nonce;
  const keyBinding = { present: true, signatureOk: kbSigOk, sdHashOk, audience: aud, nonce, iat, audienceOk, nonceOk };
  const notes: string[] = [];
  let reason: SdJwtFailureReason | null = null;
  if (!kbSigOk) reason = "KEY_BINDING_INVALID";
  else if (!sdHashOk) reason = "SD_HASH_MISMATCH";
  else if (audienceOk === false) reason = "AUDIENCE_MISMATCH";
  else if (nonceOk === false) reason = "NONCE_MISMATCH";
  else if (opts.maxKbAgeSec !== undefined && (iat === null || Math.abs(now - iat) > opts.maxKbAgeSec)) reason = "KEY_BINDING_STALE";
  if (audienceOk === null || nonceOk === null) notes.push("audience or nonce not checked — supply the ones the verifier sent");
  return report({ ...withClaims, keyBinding, reason }, notes);
}

/* ── unlinkability ─────────────────────────────────────────────────────── */

export interface Correlator {
  readonly kind:
    | "issuer-signature"
    | "holder-key"
    | "disclosure-digest"
    | "disclosure-salt"
    | "status-index"
    | "issued-at"
    | "jti"
    | "disclosed-value";
  readonly note: string;
}

/**
 * What two presentations share that could link them. Values every holder of
 * the same kind shares by construction (issuer, vct, the rule, a day-rounded
 * `iat`, a common `exp`) are not correlators. An empty result means a verifier
 * holding both learns nothing linking them — the ask library's rule 6.
 */
export async function linkabilityBetween(a: string, b: string): Promise<readonly Correlator[]> {
  const pa = parseSdJwt(a);
  const pb = parseSdJwt(b);
  if (pa === null || pb === null) return [{ kind: "issuer-signature", note: "unparseable — treat as linked" }];
  const ja = decodeJws(pa.issuerJwt) as DecodedJws;
  const jb = decodeJws(pb.issuerJwt) as DecodedJws;
  const out: Correlator[] = [];
  if (ja.signatureB64u === jb.signatureB64u) out.push({ kind: "issuer-signature", note: "the same issued copy, shown twice" });
  const xa = isPlainObject(ja.payload.cnf) && isPlainObject(ja.payload.cnf.jwk) ? ja.payload.cnf.jwk.x : null;
  const xb = isPlainObject(jb.payload.cnf) && isPlainObject(jb.payload.cnf.jwk) ? jb.payload.cnf.jwk.x : null;
  if (xa !== null && xa === xb) out.push({ kind: "holder-key", note: "one relationship key used with two verifiers" });

  const digestsIn = (p: Record<string, unknown>): Set<string> => {
    const s = new Set<string>();
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(walk);
      else if (isPlainObject(v)) {
        if (Array.isArray(v._sd)) for (const d of v._sd) if (typeof d === "string") s.add(d);
        if (typeof v["..."] === "string") s.add(v["..."]);
        Object.values(v).forEach(walk);
      }
    };
    walk(p);
    return s;
  };
  const da = digestsIn(ja.payload);
  if ([...digestsIn(jb.payload)].some((d) => da.has(d))) out.push({ kind: "disclosure-digest", note: "the same signed digests — one issued copy, or reused salts" });

  const salts = async (p: ParsedSdJwt) => new Set((await Promise.all(p.disclosures.map(decodeDisclosure))).flatMap((d) => (d === null ? [] : [d.salt])));
  const sa = await salts(pa);
  if ([...(await salts(pb))].some((s) => sa.has(s))) out.push({ kind: "disclosure-salt", note: "a disclosure salt appears in both" });

  const st = (p: Record<string, unknown>): string | null => {
    const c = p.credentialStatus;
    return isPlainObject(c) ? `${String(c.statusListCredential)}#${String(c.statusListIndex)}` : null;
  };
  if (st(ja.payload) !== null && st(ja.payload) === st(jb.payload)) out.push({ kind: "status-index", note: "the same status-list index" });
  const iatA = ja.payload.iat;
  if (typeof iatA === "number" && iatA === jb.payload.iat && iatA % 86_400 !== 0) out.push({ kind: "issued-at", note: "the same iat to the second — issuers round it to the day" });
  if (ja.payload.jti !== undefined && ja.payload.jti === jb.payload.jti) out.push({ kind: "jti", note: "the same jti" });

  const vals = async (p: ParsedSdJwt) => new Set((await Promise.all(p.disclosures.map(decodeDisclosure))).flatMap((d) => (d === null ? [] : [JSON.stringify(d.value)])));
  const va = await vals(pa);
  if ([...(await vals(pb))].some((v) => va.has(v))) {
    out.push({ kind: "disclosed-value", note: "the holder disclosed the same value to both (for example a record hash) — their choice, and it links them" });
  }
  return out;
}
