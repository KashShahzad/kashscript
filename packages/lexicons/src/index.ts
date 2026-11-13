/**
 * @kashscript/lexicons — main export surface.
 *
 * Exposes:
 *   - Framework (types, schema DSL, semver, envelope) — the Box.
 *   - Registry + Engine (LexiconRegistry, validateEvent, getSchemaDefinition).
 *   - Standard Library (identity-tier lexicons) — the agnostic core Content.
 *
 * Domain Extensions (Social, Trade, …) are NOT auto-exported here.
 * They live under subpath imports:
 *   - @kashscript/lexicons/extensions/social
 *   - @kashscript/lexicons/extensions/trade
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

// Standard Library (identity tier) — lexicons consumers will almost always want.
// Domain content (social, trade, neuron) ships as separately-imported Extensions.
export * from "./lexicons";

export const LEXICONS_FRAMEWORK_VERSION = "1.0.0" as const;
