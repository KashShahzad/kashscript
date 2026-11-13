/**
 * Validation Engine — pure-function entry points that compose a registry
 * with the schema engine.
 *
 *  validateEvent(event, registry)
 *    1. Validate the Kash-Event envelope shape (header + signature; body deferred).
 *    2. Parse the declared Lexicon ID from `header.lexicon`.
 *    3. Look up a forward-compatible registered schema via the registry.
 *    4. Deep-validate `body` against the registered schema.
 *
 *  getSchemaDefinition(lexiconId, registry)
 *    Returns a JSON-Schema Draft-2020-12 representation of the body schema for
 *    a given Lexicon ID. Used by Oreoasis (and any external AI/tooling) to
 *    "teach" itself a new data type at runtime without code changes.
 *
 * Both functions are pure and stateless. No network, no crypto, no storage.
 */

import { BASE_ENVELOPE_SCHEMA, type KashEvent } from "./envelope";
import { toJsonSchema, type JsonSchema } from "./json-schema";
import type { LexiconRegistry } from "./registry";
import {
  validate,
  type Schema,
  type ValidationError,
  type ValidationResult,
} from "./schema";
import { parseLexiconId } from "./semver";

/**
 * Full envelope-and-body validation against a registry.
 *
 * Returns the typed `KashEvent<Body>` on success, or a flat list of errors
 * keyed by JSON-pointer-style path on failure. All errors are collected
 * (not fail-fast) so the caller can render a complete diagnostic.
 */
export function validateEvent<Body = unknown>(
  event: unknown,
  registry: LexiconRegistry,
): ValidationResult<KashEvent<Body>> {
  // Stage 1 — envelope shape (header + signature; body permissive).
  const envResult = validate<KashEvent>(BASE_ENVELOPE_SCHEMA, event);
  if (!envResult.ok) return envResult as ValidationResult<KashEvent<Body>>;

  const env = envResult.value;

  // Stage 2 — parse declared Lexicon ID.
  const parsed = parseLexiconId(env.header.lexicon);
  if (parsed === null) {
    return failOne(["header", "lexicon"], "unparseable lexicon ID", env.header.lexicon);
  }

  // Stage 3 — resolve from registry (forward-compatible within major).
  const entry = registry.resolve(parsed.nsid, parsed.semver);
  if (!entry) {
    return failOne(
      ["header", "lexicon"],
      `no registered lexicon supports "${env.header.lexicon}"`,
      env.header.lexicon,
    );
  }

  // Stage 4 — deep-validate body against the registered schema.
  const bodyResult = validate(entry.bodySchema, env.body);
  if (!bodyResult.ok) {
    const rebased: ValidationError[] = bodyResult.errors.map((e) => ({
      path: ["body", ...e.path],
      message: e.message,
      received: e.received,
    }));
    return { ok: false, errors: rebased };
  }

  return { ok: true, value: env as KashEvent<Body> };
}

/**
 * Validate a raw body against a registered lexicon — bypasses the envelope.
 * Useful when constructing a record locally before signing it.
 */
export function validateBody<Body = unknown>(
  lexiconId: string,
  body: unknown,
  registry: LexiconRegistry,
): ValidationResult<Body> {
  const parsed = parseLexiconId(lexiconId);
  if (parsed === null) {
    return failOne([], `invalid lexicon ID "${lexiconId}"`, lexiconId);
  }
  const entry = registry.resolve(parsed.nsid, parsed.semver);
  if (!entry) {
    return failOne([], `no registered lexicon supports "${lexiconId}"`, lexiconId);
  }
  return validate<Body>(entry.bodySchema, body);
}

/**
 * Return a JSON-Schema-Draft-2020-12 representation of the registered lexicon.
 *
 * Used by Oreoasis (and any external AI / tooling) to load a previously
 * unknown lexicon's structure at runtime. The returned object includes
 * `$schema`, `$id`, `title`, and `description` metadata.
 *
 * Returns `null` if the Lexicon ID is malformed or no compatible entry is
 * registered.
 */
export function getSchemaDefinition(
  lexiconId: string,
  registry: LexiconRegistry,
): JsonSchema | null {
  const parsed = parseLexiconId(lexiconId);
  if (parsed === null) return null;
  const entry = registry.resolve(parsed.nsid, parsed.semver);
  if (!entry) return null;

  const body = toJsonSchema(entry.bodySchema);
  const out: Record<string, unknown> = {
    $schema:     "https://json-schema.org/draft/2020-12/schema",
    $id:         `https://kashscript.com/lexicons/${entry.id}`,
    title:       entry.title ?? entry.id,
    description: entry.description ?? `Body schema for ${entry.id}`,
    ...body,
  };
  return out;
}

/** Return the raw internal Schema (not JSON-Schema) for advanced consumers. */
export function getRawSchema(lexiconId: string, registry: LexiconRegistry): Schema | null {
  const parsed = parseLexiconId(lexiconId);
  if (parsed === null) return null;
  const entry = registry.resolve(parsed.nsid, parsed.semver);
  return entry?.bodySchema ?? null;
}

function failOne(
  path: readonly (string | number)[],
  message: string,
  received: unknown,
): { ok: false; errors: readonly ValidationError[] } {
  return { ok: false, errors: [{ path, message, received }] };
}
