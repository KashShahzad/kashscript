/**
 * `@kashscript/attest/attestation` — d91(a)'s one record type, its mandate, and their three forms
 * (RW-14; `specs/attestation/README.md`).
 *
 *   lexicon → `kash.attestation@1.0.0` and `kash.mandate@1.0.0`, closed shapes in the lexicons' DSL;
 *   faults  → the cross-field rules a shape cannot write, each naming its decision;
 *   forms   → the record of truth's tags, a copy's claims, and the VC 2.0 projection.
 *
 * A subpath on purpose: it is the one part of attest that reads `@kashscript/lexicons`, and the root
 * export stays as light as it was.
 */

export * from "./lexicon";
export * from "./faults";
export * from "./forms";
