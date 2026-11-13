/**
 * @kashscript/identity-core — main export surface.
 *
 * Pure deterministic cryptography + DID Document formatting for the
 * `did:kash` method. Zero runtime dependencies (WebCrypto API only).
 * No network code. No storage code. Bytes in, strings/objects out.
 */

export * from "./errors";
export * from "./base58";
export * from "./base64url";
export * from "./hex";
export * from "./canonical";
export * from "./keys";
export * from "./p256";
export * from "./runtime";
export * from "./did";
export * from "./document";
export * from "./signatures";
export * from "./signer";
export * from "./ed25519-strict";

/** Public version constant — bumped whenever the wire-level output of any
 *  formatter changes (DID format, DID Document shape, canonical encoding,
 *  signature payload composition). */
export const IDENTITY_CORE_VERSION = "0.4.0-alpha.2" as const;
