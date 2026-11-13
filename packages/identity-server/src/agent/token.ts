// ============================================================================
// @kashscript/identity-server — the agent-identity token (MCP-conformant)
// ----------------------------------------------------------------------------
// A `did:kash` root ("owner") mints an OAuth 2.1 access token that a delegated
// agent presents to an MCP server. The shape conforms to the MCP authorization
// spec — it is NOT a parallel scheme:
//
//   • RFC 9068  — JWT access-token profile: header `typ:"at+jwt"`, `alg:"EdDSA"`.
//   • RFC 8707  — Resource Indicators: the requested `resource` becomes `aud`;
//                 the MCP server MUST validate it is the audience (confused-
//                 deputy defence). `verifyAgentToken` enforces this.
//   • RFC 8693  — Token Exchange delegation: `act.sub` names the agent acting
//                 for the owner (`sub`). THIS is the agent→owner binding.
//   • RFC 7800  — optional `cnf` proof-of-possession key binding.
//
// The token is signed with raw Ed25519 (attest.signRaw) over the JWS signing
// input. The signer key resolves three ways at verify time, in priority order:
// an explicit `publicKey`, a JWKS `kid` lookup, or — by default — the owner's
// self-certifying `did:kash` (`sub`), which needs no network + no key registry.
// ============================================================================

import { isKashDid, parseDid } from "@kashscript/identity-core";
import { base64UrlToBytes, bytesToBase64Url, signRaw, verifyRaw } from "@kashscript/attest";
import { KashscriptIdentityMalformedDidError, KashscriptIdentityMalformedPayloadError } from "../errors";
import { assertDidWellFormed, newTraceId, nowUnix, utf8Encode } from "../internal";
import { publicKeyFromJwks } from "../jwks";
import type { Jwks } from "../jwks";
import type { Did, UnixSeconds } from "../types";
import { canonicalizeResourceUri } from "./resource";

// ----------------------------------------------------------------------------
// Token shape
// ----------------------------------------------------------------------------

/** JOSE header for the agent access token (RFC 9068 §2.1). */
export interface AgentTokenHeader {
  readonly alg: "EdDSA";
  readonly typ: "at+jwt";
  readonly kid: string;
}

/** RFC 7800 confirmation (proof-of-possession key binding). */
export interface JwtConfirmation {
  /** JWK SHA-256 thumbprint (RFC 7638), when using DPoP-style binding. */
  readonly jkt?: string;
  readonly [key: string]: unknown;
}

/** The agent access-token claim set (RFC 9068 + 8707 + 8693). */
export interface AgentTokenClaims {
  /** Authorization-server issuer (an https URL, or the owner `did:kash`). */
  readonly iss: string;
  /** The resource owner — a `did:kash` root. The token's principal + signer. */
  readonly sub: Did;
  /** RFC 8707 audience — the MCP server's canonical resource URI. */
  readonly aud: string | readonly string[];
  readonly iat: UnixSeconds;
  readonly exp: UnixSeconds;
  readonly jti: string;
  /** The agent's OAuth client identifier. */
  readonly client_id: string;
  /** Space-delimited scopes. */
  readonly scope: string;
  /** RFC 8693 delegation: the agent acting for `sub`. The agent→owner binding. */
  readonly act: { readonly sub: Did };
  /** RFC 7800 proof-of-possession key binding (optional). */
  readonly cnf?: JwtConfirmation;
  readonly [claim: string]: unknown;
}

export type AgentTokenFailureReason =
  | "MALFORMED_TOKEN"
  | "MALFORMED_CLAIMS"
  | "UNSUPPORTED_ALG"
  | "UNSUPPORTED_TOKEN_TYPE"
  | "KEY_NOT_FOUND"
  | "SIGNATURE_INVALID"
  | "EXPIRED"
  | "NOT_YET_VALID"
  | "ISSUER_MISMATCH"
  | "AUDIENCE_MISMATCH"
  | "MISSING_OWNER_BINDING";

// ----------------------------------------------------------------------------
// Mint
// ----------------------------------------------------------------------------

/** The owner root that mints (and signs) the token. */
export interface AgentTokenOwner {
  /** did:kash root — becomes `sub` and the signing identity. */
  readonly did: Did;
  /** 32-byte Ed25519 private seed corresponding to `did`. */
  readonly privateKey: Uint8Array;
  /** The owner's 32-byte Ed25519 public key. REQUIRED when `did` is not a
   *  self-certifying canonical `did:kash:<base58-pubkey>` (e.g. a structured,
   *  registry-resolved DID) — the signer key can't be parsed from such a DID.
   *  When omitted, it is derived from `did` (the canonical, back-compat path). */
  readonly publicKey?: Uint8Array;
}

export interface MintAgentTokenOptions {
  readonly owner: AgentTokenOwner;
  /** The delegated agent principal (`act.sub`). A `did:kash`. */
  readonly agent: Did;
  /** RFC 8707 resource URI → canonicalized into `aud`. */
  readonly audience: string;
  /** `iss` — an AS URL for hosted discovery, or the owner `did:kash`. */
  readonly issuer: string;
  /** The agent's OAuth `client_id`. */
  readonly clientId: string;
  /** Space-delimited `scope`. */
  readonly scope: string;
  readonly expiresInSeconds: number;
  readonly nowSec?: UnixSeconds;
  readonly jti?: string;
  /** Header `kid` (defaults to the owner `did:kash`). */
  readonly kid?: string;
  /** Optional RFC 7800 `cnf` key binding. */
  readonly confirmation?: JwtConfirmation;
  /** Extra claims merged UNDER the mandatory claims (cannot override them). */
  readonly additionalClaims?: Readonly<Record<string, unknown>>;
  /** Override the DID-acceptance policy for `owner.did` + `agent` (default: the
   *  canonical `did:kash` gate, `isKashDid`). A consumer whose DIDs are
   *  structured/registry-resolved injects its own validator here. DID FORMAT is
   *  an identity-method policy; the token's integrity rests on the signature. */
  readonly isValidDid?: (did: string) => boolean;
}

export interface MintAgentTokenResult {
  readonly token: string;
  readonly claims: AgentTokenClaims;
}

function b64urlJson(value: unknown): string {
  return bytesToBase64Url(utf8Encode(JSON.stringify(value)));
}

/** A fresh `jti_<24hex>` token identifier. */
function newJti(): string {
  return `jti_${newTraceId().slice("trace_".length)}`;
}

/**
 * Mints an agent access token: the owner `did:kash` signs a compact
 * `header.payload.signature` JWT binding the agent (`act.sub`) to the owner
 * (`sub`) for a specific audience (`aud`).
 *
 * @throws KashscriptIdentityMalformedDidError on a bad owner/agent DID.
 * @throws KashscriptIdentityMalformedPayloadError on a bad audience/expiry.
 */
export async function mintAgentToken(opts: MintAgentTokenOptions): Promise<MintAgentTokenResult> {
  if (typeof opts !== "object" || opts === null) {
    throw new KashscriptIdentityMalformedPayloadError("opts");
  }
  if (opts.isValidDid !== undefined) {
    if (typeof opts.owner?.did !== "string" || !opts.isValidDid(opts.owner.did)) {
      throw new KashscriptIdentityMalformedDidError(String(opts.owner?.did));
    }
    if (typeof opts.agent !== "string" || !opts.isValidDid(opts.agent)) {
      throw new KashscriptIdentityMalformedDidError(String(opts.agent));
    }
  } else {
    assertDidWellFormed(opts.owner?.did);
    assertDidWellFormed(opts.agent);
  }
  if (!(opts.owner.privateKey instanceof Uint8Array) || opts.owner.privateKey.length !== 32) {
    throw new KashscriptIdentityMalformedPayloadError("owner.privateKey");
  }
  if (typeof opts.expiresInSeconds !== "number" || opts.expiresInSeconds <= 0) {
    throw new KashscriptIdentityMalformedPayloadError("expiresInSeconds");
  }
  if (typeof opts.issuer !== "string" || opts.issuer.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("issuer");
  }
  if (typeof opts.clientId !== "string" || opts.clientId.length === 0) {
    throw new KashscriptIdentityMalformedPayloadError("clientId");
  }
  if (typeof opts.scope !== "string") {
    throw new KashscriptIdentityMalformedPayloadError("scope");
  }

  const iat = opts.nowSec ?? nowUnix();
  const aud = canonicalizeResourceUri(opts.audience);
  const kid = opts.kid ?? opts.owner.did;

  const header: AgentTokenHeader = { alg: "EdDSA", typ: "at+jwt", kid };
  const claims: AgentTokenClaims = {
    ...(opts.additionalClaims ?? {}),
    iss: opts.issuer,
    sub: opts.owner.did,
    aud,
    iat,
    exp: iat + opts.expiresInSeconds,
    jti: opts.jti ?? newJti(),
    client_id: opts.clientId,
    scope: opts.scope,
    act: { sub: opts.agent },
    ...(opts.confirmation !== undefined ? { cnf: opts.confirmation } : {}),
  };

  const signingInput = `${b64urlJson(header)}.${b64urlJson(claims)}`;
  // Canonical owner DIDs self-certify their key; structured DIDs supply it.
  const publicKey = opts.owner.publicKey ?? parseDid(opts.owner.did);
  const signature = await signRaw(utf8Encode(signingInput), opts.owner.privateKey, publicKey);
  return { token: `${signingInput}.${bytesToBase64Url(signature)}`, claims };
}

// ----------------------------------------------------------------------------
// Verify
// ----------------------------------------------------------------------------

export interface VerifyAgentTokenOptions {
  /** RFC 8707: the resource server's own canonical identifier. REQUIRED. */
  readonly expectedAudience: string;
  /** When set, `iss` must equal this exactly. */
  readonly expectedIssuer?: string;
  readonly nowSec?: UnixSeconds;
  /** Allowed clock skew for exp/nbf, in seconds (default 0). */
  readonly clockSkewSeconds?: number;
  /** Resolve the signer key by header `kid` from this JWKS. */
  readonly jwks?: Jwks;
  /** Explicit signer public key (overrides jwks + self-certifying resolution).
   *  REQUIRED when `sub`/`act.sub` are structured (non-self-certifying) DIDs. */
  readonly publicKey?: Uint8Array;
  /** Override the DID-acceptance policy for `sub` + `act.sub` (default: the
   *  canonical `did:kash` gate). Structured-DID consumers inject their own. */
  readonly isValidDid?: (did: string) => boolean;
}

/** The extracted agent→owner delegation binding. */
export interface AgentOwnerBinding {
  /** The resource owner (`sub`). */
  readonly owner: Did;
  /** The delegated agent (`act.sub`). */
  readonly agent: Did;
}

export interface VerifyAgentTokenResult {
  readonly ok: boolean;
  readonly reason: AgentTokenFailureReason | null;
  readonly claims: AgentTokenClaims | null;
  readonly audienceOk: boolean;
  readonly ownerBinding: AgentOwnerBinding | null;
  readonly traceId: string;
}

function decodeJsonSegment(segment: string): unknown {
  return JSON.parse(new TextDecoder().decode(base64UrlToBytes(segment)));
}

// audit r1 F2: `sub` and `act.sub` are the owner→agent delegation identities the
// resource server keys authorization on — they MUST be well-formed DIDs (the
// canonical `did:kash` gate, or a consumer's `isValidDid`), not any non-empty
// string, so a downstream lookup can't be fed a bare label. Enforced by the
// per-call `acceptDid` closure inside `verifyAgentToken`.

function audienceMatches(aud: unknown, expectedCanonical: string): boolean {
  const list = Array.isArray(aud) ? aud : [aud];
  for (const entry of list) {
    if (typeof entry !== "string") continue;
    try {
      if (canonicalizeResourceUri(entry) === expectedCanonical) return true;
    } catch {
      // non-canonicalizable entry never matches
    }
  }
  return false;
}

/**
 * Verifies an agent access token: JWS signature (under an explicit key, a JWKS
 * `kid`, or the self-certifying owner `did:kash`), temporal validity, optional
 * issuer, the RFC 8707 audience binding, and the RFC 8693 owner→agent binding.
 *
 * Never throws for a well-formed-but-invalid token — returns `ok:false` with a
 * discriminating `reason` (mirrors the verifier posture across the ecosystem).
 */
export async function verifyAgentToken(
  token: string,
  opts: VerifyAgentTokenOptions,
): Promise<VerifyAgentTokenResult> {
  const traceId = newTraceId();
  const fail = (
    reason: AgentTokenFailureReason,
    extra?: { claims?: AgentTokenClaims; audienceOk?: boolean; ownerBinding?: AgentOwnerBinding },
  ): VerifyAgentTokenResult => ({
    ok: false,
    reason,
    claims: extra?.claims ?? null,
    audienceOk: extra?.audienceOk ?? false,
    ownerBinding: extra?.ownerBinding ?? null,
    traceId,
  });

  // DID-acceptance policy for `sub`/`act.sub` — canonical `did:kash` by default,
  // or a consumer-supplied validator for structured/registry-resolved DIDs.
  const acceptDid = (v: unknown): v is Did =>
    typeof v === "string" && (opts.isValidDid ? opts.isValidDid(v) : isKashDid(v));

  if (typeof token !== "string" || token.length === 0) return fail("MALFORMED_TOKEN");
  if (typeof opts !== "object" || opts === null || typeof opts.expectedAudience !== "string") {
    throw new KashscriptIdentityMalformedPayloadError("expectedAudience");
  }

  const parts = token.split(".");
  if (parts.length !== 3) return fail("MALFORMED_TOKEN");
  const [headerSeg, payloadSeg, signatureSeg] = parts as [string, string, string];

  let header: AgentTokenHeader;
  let claims: AgentTokenClaims;
  try {
    header = decodeJsonSegment(headerSeg) as AgentTokenHeader;
    claims = decodeJsonSegment(payloadSeg) as AgentTokenClaims;
  } catch {
    return fail("MALFORMED_TOKEN");
  }
  if (typeof header !== "object" || header === null || typeof claims !== "object" || claims === null) {
    return fail("MALFORMED_TOKEN");
  }

  // -------- Header discipline (RFC 9068) --------------------------------
  if (header.alg !== "EdDSA") return fail("UNSUPPORTED_ALG", { claims });
  if (header.typ !== "at+jwt") return fail("UNSUPPORTED_TOKEN_TYPE", { claims });

  // -------- Minimal claim shape -----------------------------------------
  if (
    typeof claims.iss !== "string" ||
    !acceptDid(claims.sub) ||
    typeof claims.exp !== "number" ||
    typeof claims.iat !== "number" ||
    claims.aud === undefined
  ) {
    return fail("MALFORMED_CLAIMS", { claims });
  }

  // -------- Resolve the signer key --------------------------------------
  let publicKey: Uint8Array | null;
  if (opts.publicKey !== undefined) {
    publicKey = opts.publicKey;
  } else if (opts.jwks !== undefined) {
    // audit r1 F1 (CRITICAL): resolve the signer key by the OWNER did (`claims.sub`),
    // NOT by the attacker-controlled header `kid`. Selecting by `kid` lets any key a
    // multi-tenant JWKS happens to hold sign a token claiming an arbitrary `sub`
    // (owner impersonation). Keying by `sub` binds signer→owner and stays rotation-
    // safe (a rotated owner publishes their current key under `kid = sub` in the JWKS).
    publicKey = publicKeyFromJwks(opts.jwks, claims.sub);
  } else {
    // Default: the owner `did:kash` (`sub`) is self-certifying — extract its
    // public key directly, no network + no registry.
    try {
      publicKey = parseDid(claims.sub);
    } catch {
      publicKey = null;
    }
  }
  if (publicKey === null) return fail("KEY_NOT_FOUND", { claims });

  // -------- JWS signature -----------------------------------------------
  let signatureValid = false;
  try {
    const signingInput = `${headerSeg}.${payloadSeg}`;
    signatureValid = await verifyRaw(base64UrlToBytes(signatureSeg), utf8Encode(signingInput), publicKey);
  } catch {
    return fail("SIGNATURE_INVALID", { claims });
  }
  if (!signatureValid) return fail("SIGNATURE_INVALID", { claims });

  // -------- Owner→agent binding (RFC 8693) ------------------------------
  const actSub = (claims.act as { sub?: unknown } | undefined)?.sub;
  if (!acceptDid(actSub)) return fail("MISSING_OWNER_BINDING", { claims });
  const ownerBinding: AgentOwnerBinding = { owner: claims.sub, agent: actSub };

  // -------- Temporal validity -------------------------------------------
  const now = opts.nowSec ?? nowUnix();
  // audit r1 F5: clamp caller-supplied skew to a small ceiling so a mis-set (or
  // hostile-env) value can't silently widen the window enough to accept long-
  // expired tokens. 300s matches common JWT guidance.
  const skew = Math.min(Math.max(opts.clockSkewSeconds ?? 0, 0), 300);
  if (claims.exp + skew <= now) return fail("EXPIRED", { claims, ownerBinding });
  if (typeof claims.nbf === "number" && claims.nbf - skew > now) {
    return fail("NOT_YET_VALID", { claims, ownerBinding });
  }

  // -------- Issuer (optional) -------------------------------------------
  if (opts.expectedIssuer !== undefined && claims.iss !== opts.expectedIssuer) {
    return fail("ISSUER_MISMATCH", { claims, ownerBinding });
  }

  // -------- Audience (RFC 8707 — confused-deputy defence) ---------------
  let expectedCanonical: string;
  try {
    expectedCanonical = canonicalizeResourceUri(opts.expectedAudience);
  } catch (err) {
    throw new KashscriptIdentityMalformedPayloadError("expectedAudience", err);
  }
  const audienceOk = audienceMatches(claims.aud, expectedCanonical);
  if (!audienceOk) return fail("AUDIENCE_MISMATCH", { claims, ownerBinding });

  // -------- Success ------------------------------------------------------
  return { ok: true, reason: null, claims, audienceOk: true, ownerBinding, traceId };
}
