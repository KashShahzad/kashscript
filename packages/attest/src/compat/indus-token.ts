/**
 * Compat verifier — Indusland dot-delimited tokens (IPOE1 / IVFC1 / IBPS1 / IGEO1).
 *
 *   Wire:          PREFIX.<headerB64u>.<bodyB64u>.<sigB64u>
 *   Signing input: DST ‖ 0x00 ‖ utf8(headerB64u) ‖ "." ‖ utf8(bodyB64u)
 *   Alg:           Ed25519 (EdDSA)
 *
 * **Verify over the received b64url segments verbatim** — the minters encode the
 * header with `JSON.stringify` (not JCS) and some encode the body with JCS, so
 * re-encoding would break verification. Indusland ships no IVFC1 verifier; this
 * is written from the issuers (`issue-footfall-certificate` / `verify-attendance-scan`).
 */

import { AttestError } from "../errors";
import { base64UrlToBytes, bytesToBase64Url, verifyRaw } from "../ed25519";

/** prefix → DST (no trailing `\n` — the Indus family does not newline-terminate). */
export const INDUS_PREFIX_DST: Readonly<Record<string, string>> = {
  IPOE1: "indus.poe.v1.qr",
  IVFC1: "indus.vfc.v1.cert",
  IBPS1: "indus.bps.v1.bpass",
  IGEO1: "indus.poe.v1.geo",
};

export interface ParsedIndusToken {
  readonly prefix: string;
  readonly dst: string;
  readonly headerB64u: string;
  readonly bodyB64u: string;
  readonly sigB64u: string;
  readonly header: Record<string, unknown>;
  readonly body: Record<string, unknown>;
}

export function parseIndusToken(token: string): ParsedIndusToken {
  const parts = token.trim().split(".");
  if (parts.length !== 4) {
    throw new AttestError("MALFORMED_TOKEN", `indus token must have 4 dot-separated parts (got ${parts.length})`);
  }
  const prefix = parts[0]!;
  const headerB64u = parts[1]!;
  const bodyB64u = parts[2]!;
  const sigB64u = parts[3]!;
  const dst = INDUS_PREFIX_DST[prefix];
  if (dst === undefined) {
    throw new AttestError("MALFORMED_TOKEN", `unknown indus token prefix: ${JSON.stringify(prefix)}`);
  }
  let header: Record<string, unknown>;
  let body: Record<string, unknown>;
  try {
    header = JSON.parse(new TextDecoder().decode(base64UrlToBytes(headerB64u))) as Record<string, unknown>;
    body = JSON.parse(new TextDecoder().decode(base64UrlToBytes(bodyB64u))) as Record<string, unknown>;
  } catch {
    throw new AttestError("MALFORMED_TOKEN", "header/body are not valid base64url JSON");
  }
  return { prefix, dst, headerB64u, bodyB64u, sigB64u, header, body };
}

/** `DST ‖ 0x00 ‖ headerB64u ‖ "." ‖ bodyB64u` — over the received strings verbatim. */
function signingInput(dst: string, headerB64u: string, bodyB64u: string): Uint8Array {
  const enc = new TextEncoder();
  const d = enc.encode(dst);
  const h = enc.encode(headerB64u);
  const dot = enc.encode(".");
  const b = enc.encode(bodyB64u);
  const out = new Uint8Array(d.length + 1 + h.length + dot.length + b.length);
  let o = 0;
  out.set(d, o); o += d.length;
  out[o] = 0x00; o += 1;
  out.set(h, o); o += h.length;
  out.set(dot, o); o += dot.length;
  out.set(b, o);
  return out;
}

/** JWKS shape published at `/.well-known/indus-keys.json`. */
export interface Jwk {
  readonly kty: string;
  readonly crv?: string;
  readonly x?: string;
  readonly kid?: string;
}
export interface Jwks {
  readonly keys: ReadonlyArray<Jwk>;
}

/** Resolve a JWKS entry (by `kid`, or the first key) to a raw 32-byte pubkey. */
export function publicKeyFromJwks(jwks: Jwks, kid?: string): Uint8Array | null {
  const key = kid !== undefined ? jwks.keys.find((k) => k.kid === kid) : jwks.keys[0];
  if (key === undefined || typeof key.x !== "string") return null;
  return base64UrlToBytes(key.x);
}

export interface IndusVerifyOptions {
  /** Wall-clock (unix seconds) for the time-window check. Injectable for tests. */
  readonly nowSec?: number;
  /** Allowed clock skew in seconds (default 30, matching the venture verifier). */
  readonly skewSec?: number;
}

export interface IndusVerifyResult {
  readonly ok: boolean;
  readonly prefix: string;
  readonly dst: string;
  readonly kid: string | null;
  readonly signatureOk: boolean;
  readonly timeOk: boolean;
  /** IVFC1 only: the `certId` derivation matches (`b64url(SHA-256("indus.vfc.v1:"+org+":"+label))[:16]`). null for other prefixes. */
  readonly certIdOk: boolean | null;
  readonly body: Record<string, unknown>;
  readonly reason: string | null;
}

/** Verify an Indus token against a known 32-byte Ed25519 public key. */
export async function verifyIndusToken(
  token: string,
  publicKey: Uint8Array,
  opts: IndusVerifyOptions = {},
): Promise<IndusVerifyResult> {
  const p = parseIndusToken(token);
  const signatureOk = await verifyRaw(
    base64UrlToBytes(p.sigB64u),
    signingInput(p.dst, p.headerB64u, p.bodyB64u),
    publicKey,
  );

  const now = opts.nowSec ?? Math.floor(Date.now() / 1000);
  const skew = opts.skewSec ?? 30;
  let timeOk = true;
  let reason: string | null = null;
  const iat = typeof p.body.iat === "number" ? p.body.iat : null;
  const exp = typeof p.body.exp === "number" ? p.body.exp : null;
  if (exp !== null && exp < now - skew) {
    timeOk = false;
    reason = "expired";
  } else if (iat !== null && iat > now + skew) {
    timeOk = false;
    reason = "not-yet-valid";
  }

  let certIdOk: boolean | null = null;
  if (p.prefix === "IVFC1") certIdOk = await checkVfcCertId(p.body);

  if (!signatureOk && reason === null) reason = "bad-signature";
  if (certIdOk === false && reason === null) reason = "certid-mismatch";

  const kid = typeof p.header.kid === "string" ? p.header.kid : null;
  return {
    ok: signatureOk && timeOk && certIdOk !== false,
    prefix: p.prefix,
    dst: p.dst,
    kid,
    signatureOk,
    timeOk,
    certIdOk,
    body: p.body,
    reason,
  };
}

/** Verify against a JWKS, resolving the key by the token header's `kid`. */
export async function verifyIndusTokenWithJwks(
  token: string,
  jwks: Jwks,
  opts: IndusVerifyOptions = {},
): Promise<IndusVerifyResult> {
  const p = parseIndusToken(token);
  const kid = typeof p.header.kid === "string" ? p.header.kid : undefined;
  const pub = publicKeyFromJwks(jwks, kid);
  if (pub === null) {
    throw new AttestError("UNKNOWN_ACTOR", `no JWKS key for kid ${JSON.stringify(kid ?? null)}`);
  }
  return verifyIndusToken(token, pub, opts);
}

async function checkVfcCertId(body: Record<string, unknown>): Promise<boolean | null> {
  const org = body.org;
  const certId = body.certId;
  const period = body.period as Record<string, unknown> | undefined;
  const label = period?.label;
  if (typeof org !== "string" || typeof certId !== "string" || typeof label !== "string") return null;
  const pre = new TextEncoder().encode(`indus.vfc.v1:${org}:${label}`);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", pre as unknown as BufferSource));
  return bytesToBase64Url(digest.slice(0, 16)) === certId;
}
