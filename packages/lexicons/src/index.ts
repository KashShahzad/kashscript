/**
 * @kashscript/lexicons — main export surface.
 *
 * Exposes:
 *   - Framework (types, schema DSL, semver, envelope) — the Box.
 *   - Registry + Engine (LexiconRegistry, validateEvent, getSchemaDefinition).
 *   - Standard Library (identity-tier lexicons) — the agnostic core Content.
 *
 * Extensions are NOT auto-exported here. They live under subpath imports:
 *   - the public, organisation-authored records of the open protocol (ECOSYSTEM d59):
 *     @kashscript/lexicons/extensions/door   — kash.rule, kash.adoption
 *     @kashscript/lexicons/extensions/place  — kash.place, kash.place.pointer, kash.listing, kash.guide
 *     @kashscript/lexicons/extensions/lists  — kash.trust-list, kash.status-list
 *     @kashscript/lexicons/extensions/public — all of the above as one list, their cross-field checks,
 *                                               and the person-identity scan muffler's guard runs
 *   - the apps' own vocabularies: @kashscript/lexicons/extensions/{social,zkp,education,civic,community}
 *
 * This package is zero-dependency. No network, no crypto, no storage —
 * pure data modelling and validation.
 */

export * from "./types";
export * from "./schema";
export * from "./semver";
export * from "./envelope";
export * from "./registry";
export * from "./engine";
export * from "./json-schema";

// Standard Library (identity tier) — a person's own records, for the PDS that holds them.
// The public records and the apps' vocabularies ship as separately-imported Extensions.
export * from "./lexicons";

export const LEXICONS_FRAMEWORK_VERSION = "1.0.0" as const;
