// ============================================================================
// @kashscript/whiffin — the mandate protocol.
// ----------------------------------------------------------------------------
// Purpose-bound mandates (W3C VC, AP2 semantics). It never moves money.
//
// A mandate says: this value is dedicated to this purpose, within these limits,
// until this date, and arrival is confirmed by the recipient — two signatures, or
// it is not proof (d41). Whiffin declares and signs that; the payer pays on their
// own rail (DECLARE → PAY → CONFIRM → RECONCILE), and Duedale proves the money
// arrived within the mandate. Nothing in this package calls a rail, holds a
// balance, or marks a payment done on its own say.
//
// Built in phase M4 of the protocol Manifestation (ADR-0016); the machinery is
// derived from the Duedale grant/report seeds, and venture-specific parts
// (SegmentPolicy content, DD_* mapping, funder/vendor UI, the demo SIMULATION
// posture) stay venture-side (guard b). Mandates are W3C Verifiable Credentials
// with AP2 mandate semantics; reports anchor on @kashscript/attest. 0.2.0
// (KS-R4, d59) removed every path that moved or marked value, and every rail
// adapter; only the rails' names remain, for a declaration to cite.
//
// Apache-2.0 (from 0.2.1) — see LICENSE.
// ============================================================================

export * from "./errors";
export * from "./money";
export * from "./mandate";
export * from "./policy";
export * from "./credential";
export * from "./rails";
export * from "./report";

/** Bumped whenever a wire-level behaviour (mandate/credential shape, report
 *  envelope, rail names, policy codes) changes. */
export const WHIFFIN_VERSION = "0.2.0" as const;
