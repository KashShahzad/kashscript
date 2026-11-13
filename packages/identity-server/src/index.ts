// ============================================================================
// @kashscript/identity-server — server-side did:kash identity + the
// agent-identity (MCP-OAuth) profile.
// ----------------------------------------------------------------------------
// Phase M2 of the protocol Manifestation (ADR-0016). Two layers:
//
//   1. The server identity surface ported from @duedale/identity-kernel —
//      server-issued guest DIDs, handshake challenge/response, self-certifying
//      DID resolution, PDS read/write — refit from NotImplemented shells into
//      real store-backed implementations (interfaces + InMemory reference;
//      Prisma/Redis/muffler adapters stay venture-side, ADR-0016 guard b).
//
//   2. The agent-identity profile (net-new) — a did:kash root minting OAuth 2.1
//      + PKCE (S256), RFC 8707 audience-bound, RFC 8693 agent→owner delegated
//      access tokens (RFC 9068 JWT), conforming to the MCP authorization spec.
//      This is the auth surface @kashscript/hudhud consumes in M5.
//
// Identity stays free: Apache-2.0.
// ============================================================================

// -------- Error + type vocabulary -------------------------------------------
export * from "./errors";
export * from "./types";

// -------- Server identity surface (kernel-ported + store-backed) ------------
export * from "./hashing";
export * from "./guest-did";
export * from "./handshake";
export * from "./did";
export * from "./pds";
export * from "./stores";

// -------- The countersign ceremony (ADR-0018) -------------------------------
// The mechanic decision 26 names: a link, one click, signed. The artifact
// format and its free offline verifier live in @kashscript/attest.
export * from "./countersign";
export * from "./countersign-page";

// -------- JWKS publishing ---------------------------------------------------
export * from "./jwks";

// -------- The agent-identity / MCP-OAuth profile ----------------------------
export * from "./agent";
export * from "./pkce";
export * from "./metadata";

/** Bumped whenever a wire-level behaviour (token shape, JWKS wire form, guest
 *  DID recipe, handshake construction) changes. */
export const IDENTITY_SERVER_VERSION = "0.2.0" as const;

/**
 * Health probe for the identity surface. Unlike the @duedale/identity-kernel
 * stub this ports from (which reported `available: false, WORKSPACE_STUB`),
 * identity-server implements its surface end-to-end against WebCrypto, so the
 * honest answer is `available: true`.
 */
export function probeAvailability() {
  return {
    available: true,
    reason: "READY",
    version: IDENTITY_SERVER_VERSION,
    cryptoBackend: "WEB_CRYPTO",
  } as const;
}
