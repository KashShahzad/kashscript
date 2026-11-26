/**
 * @kashscript/attest — the Evidence Commons.
 *
 * Verification is free (Apache-2.0). One package that signs, canonicalizes,
 * witnesses, chains, and **verifies** the three signing families the ecosystem
 * uses — Kash-Event (`DST‖JCS`, via identity-core), DSSE/PAE (Sigstore-compatible),
 * and the Indus dot-token — plus a standalone verifier CLI and compat verifiers
 * for the shipped venture formats. See ADR-0016 (protocol Manifestation, M1).
 */

export * from "./errors";
export * from "./ed25519";
export * from "./dsse";
export * from "./dst";
export * from "./chain";
export * from "./ids";
export * from "./witness";
export * from "./ledger";
export * from "./bundle";
export * from "./countersign";
export * from "./succession";
export * from "./signing";
export * from "./compat";
export * from "./holder";
export * from "./sd-jwt";
export * from "./exchange";
export * from "./profiles";
export * from "./log";

/** Bumped whenever a wire-level verification behaviour changes. KS-Q4: a presentation needs its audience and nonce; the trust list's standing, class and scope are read; status verdicts carry a cache time; the trust log. RW-14: the attestation and mandate tags, and `./attestation`. */
export const ATTEST_VERSION = "0.3.0-alpha.4" as const;
