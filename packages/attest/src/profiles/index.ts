/**
 * Profiles — registered types reused with their open slots pinned, instead of
 * new tags (ECOSYSTEM d59(e): attest's registry is append-only, and a profile
 * over a registered type is preferred). Each profile names itself inside the
 * payload it constrains and has its own spec.
 *
 *   • `kashscript-cohort/1` — station zero's record of a finished cohort, over
 *     the Oreoasis work record (`specs/cohort-profile.md`).
 */

export * from "./cohort";
