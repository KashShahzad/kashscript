/**
 * Zero-dependency schema DSL + validation engine.
 *
 * Schemas are plain data — no class methods, no closures — so they are
 * trivially serialisable and comparable. The `S` namespace provides a
 * Zod-style fluent builder for ergonomic authoring.
 *
 * Validation is depth-first and accumulates ALL errors (not fail-fast)
 * so callers can render a complete diagnostic on first attempt.
 */

/* ── schema variants ────────────────────────────────────────────── */

export type Schema =
  | AnySchema
  | StringSchema
  | NumberSchema
  | BooleanSchema
  | LiteralSchema
  | EnumSchema
  | ArraySchema
  | ObjectSchema
  | UnionSchema
  | OptionalSchema
  | RecordSchema;

export interface AnySchema {
  readonly kind: "any";
}

export type SchemaStringFormat =
  | "did-ks"
  | "cid"
  | "iso8601"
  | "url"
  | "multibase"
  | "bcp47"
  | "iso4217"
  | "lexicon-id"
  | "nsid";

export interface StringSchema {
  readonly kind: "string";
  readonly minLength?: number;
  readonly maxLength?: number;
  readonly pattern?: RegExp;
  readonly format?: SchemaStringFormat;
}

export interface NumberSchema {
  readonly kind: "number";
  readonly min?: number;
  readonly max?: number;
  readonly integer?: boolean;
}

export interface BooleanSchema {
  readonly kind: "boolean";
}

export interface LiteralSchema {
  readonly kind: "literal";
  readonly value: string | number | boolean | null;
}

export interface EnumSchema {
  readonly kind: "enum";
  readonly values: readonly (string | number)[];
}

export interface ArraySchema {
  readonly kind: "array";
  readonly items: Schema;
  readonly minItems?: number;
  readonly maxItems?: number;
}

export interface ObjectSchema {
  readonly kind: "object";
  readonly properties: Readonly<Record<string, Schema>>;
  readonly required: readonly string[];
  /** When false, unknown keys cause validation failure. Default: false. */
  readonly additionalProperties: boolean;
}

export interface UnionSchema {
  readonly kind: "union";
  readonly variants: readonly Schema[];
}

export interface OptionalSchema {
  readonly kind: "optional";
  readonly inner: Schema;
}

export interface RecordSchema {
  readonly kind: "record";
  readonly keys: StringSchema;
  readonly values: Schema;
}

/* ── fluent builders ────────────────────────────────────────────── */

export const S = {
  any(): AnySchema {
    return { kind: "any" };
  },
  string(opts?: Omit<StringSchema, "kind">): StringSchema {
    return { kind: "string", ...opts };
  },
  number(opts?: Omit<NumberSchema, "kind">): NumberSchema {
    return { kind: "number", ...opts };
  },
  boolean(): BooleanSchema {
    return { kind: "boolean" };
  },
  literal(value: string | number | boolean | null): LiteralSchema {
    return { kind: "literal", value };
  },
  enum(...values: readonly (string | number)[]): EnumSchema {
    return { kind: "enum", values };
  },
  array(items: Schema, opts?: { readonly minItems?: number; readonly maxItems?: number }): ArraySchema {
    return { kind: "array", items, ...opts };
  },
  object(
    properties: Readonly<Record<string, Schema>>,
    required: readonly string[] = [],
    additionalProperties: boolean = false,
  ): ObjectSchema {
    return { kind: "object", properties, required, additionalProperties };
  },
  union(...variants: readonly Schema[]): UnionSchema {
    return { kind: "union", variants };
  },
  optional(inner: Schema): OptionalSchema {
    return { kind: "optional", inner };
  },
  record(values: Schema, keys: StringSchema = { kind: "string" }): RecordSchema {
    return { kind: "record", keys, values };
  },
};

/* ── validation results ─────────────────────────────────────────── */

export interface ValidationError {
  readonly path: readonly (string | number)[];
  readonly message: string;
  readonly received?: unknown;
}

export type ValidationResult<T = unknown> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly errors: readonly ValidationError[] };

/* ── string format patterns ─────────────────────────────────────── */

/** Canonical source-of-truth for the built-in string formats.
 *  Exported so the JSON-Schema exporter can read `.source` without
 *  re-typing the regex literals. */
export const FORMAT_PATTERNS: Record<SchemaStringFormat, RegExp> = {
  // identity-core's DID method is `did:kash:` with a base58btc-encoded pubkey
  // body. Ed25519 pubkeys (32 bytes) round-trip to 43-44 chars in base58btc.
  // The format-id stays `did-ks` (schema-internal name) for backward
  // compatibility; the regex now matches what `@kashscript/identity-core`
  // emits via `deriveDid()`.
  "did-ks":     /^did:kash:[1-9A-HJ-NP-Za-km-z]{32,48}$/,
  "cid":        /^bafy[a-z2-7]{52,}$/,
  "iso8601":    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/,
  "url":        /^https?:\/\/[^\s]+$/,
  "multibase":  /^z[1-9A-HJ-NP-Za-km-z]+$/,
  "bcp47":      /^[a-z]{2,3}(-[A-Z]{2})?$/,
  "iso4217":    /^[A-Z]{3}$/,
  "lexicon-id": /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+@\d+\.\d+\.\d+$/,
  "nsid":       /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$/,
};

/* ── public entry point ─────────────────────────────────────────── */

export function validate<T = unknown>(schema: Schema, value: unknown): ValidationResult<T> {
  const errors: ValidationError[] = [];
  validateRec(schema, value, [], errors);
  return errors.length === 0
    ? { ok: true, value: value as T }
    : { ok: false, errors };
}

/** Convenience type-guard. Returns true iff `value` matches `schema`. */
export function matches(schema: Schema, value: unknown): boolean {
  const errors: ValidationError[] = [];
  validateRec(schema, value, [], errors);
  return errors.length === 0;
}

/* ── recursive validator ────────────────────────────────────────── */

function validateRec(
  schema: Schema,
  value: unknown,
  path: readonly (string | number)[],
  errors: ValidationError[],
): void {
  switch (schema.kind) {
    case "any":
      return;
    case "string":
      validateString(schema, value, path, errors);
      return;
    case "number":
      validateNumber(schema, value, path, errors);
      return;
    case "boolean":
      if (typeof value !== "boolean") errors.push(err(path, "expected boolean", value));
      return;
    case "literal":
      if (value !== schema.value) {
        errors.push(err(path, `expected literal ${JSON.stringify(schema.value)}`, value));
      }
      return;
    case "enum":
      if (typeof value !== "string" && typeof value !== "number") {
        errors.push(err(path, "expected string|number for enum", value));
        return;
      }
      if (!schema.values.includes(value as string | number)) {
        errors.push(err(path, `expected one of ${JSON.stringify(schema.values)}`, value));
      }
      return;
    case "array":
      validateArray(schema, value, path, errors);
      return;
    case "object":
      validateObject(schema, value, path, errors);
      return;
    case "union":
      validateUnion(schema, value, path, errors);
      return;
    case "optional":
      if (value === undefined) return;
      validateRec(schema.inner, value, path, errors);
      return;
    case "record":
      validateRecord(schema, value, path, errors);
      return;
  }
}

function err(path: readonly (string | number)[], message: string, received: unknown): ValidationError {
  return { path, message, received };
}

function validateString(s: StringSchema, value: unknown, path: readonly (string | number)[], errors: ValidationError[]): void {
  if (typeof value !== "string") {
    errors.push(err(path, "expected string", value));
    return;
  }
  if (s.minLength !== undefined && value.length < s.minLength) {
    errors.push(err(path, `string too short (min ${s.minLength}, got ${value.length})`, value));
  }
  if (s.maxLength !== undefined && value.length > s.maxLength) {
    errors.push(err(path, `string too long (max ${s.maxLength}, got ${value.length})`, value));
  }
  if (s.pattern && !s.pattern.test(value)) {
    errors.push(err(path, `does not match pattern ${s.pattern.toString()}`, value));
  }
  if (s.format && !FORMAT_PATTERNS[s.format].test(value)) {
    errors.push(err(path, `does not match format "${s.format}"`, value));
  }
}

function validateNumber(s: NumberSchema, value: unknown, path: readonly (string | number)[], errors: ValidationError[]): void {
  if (typeof value !== "number" || Number.isNaN(value)) {
    errors.push(err(path, "expected number", value));
    return;
  }
  if (s.integer && !Number.isInteger(value)) {
    errors.push(err(path, "expected integer", value));
  }
  if (s.min !== undefined && value < s.min) {
    errors.push(err(path, `below minimum ${s.min}`, value));
  }
  if (s.max !== undefined && value > s.max) {
    errors.push(err(path, `above maximum ${s.max}`, value));
  }
}

function validateArray(s: ArraySchema, value: unknown, path: readonly (string | number)[], errors: ValidationError[]): void {
  if (!Array.isArray(value)) {
    errors.push(err(path, "expected array", value));
    return;
  }
  if (s.minItems !== undefined && value.length < s.minItems) {
    errors.push(err(path, `array too short (min ${s.minItems}, got ${value.length})`, value));
  }
  if (s.maxItems !== undefined && value.length > s.maxItems) {
    errors.push(err(path, `array too long (max ${s.maxItems}, got ${value.length})`, value));
  }
  for (let i = 0; i < value.length; i++) {
    validateRec(s.items, value[i], [...path, i], errors);
  }
}

function validateObject(s: ObjectSchema, value: unknown, path: readonly (string | number)[], errors: ValidationError[]): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    errors.push(err(path, "expected object", value));
    return;
  }
  const obj = value as Record<string, unknown>;
  for (const k of s.required) {
    if (!(k in obj)) {
      errors.push(err([...path, k], "missing required field", undefined));
    }
  }
  for (const k of Object.keys(s.properties)) {
    if (k in obj) {
      const subSchema = s.properties[k]!;
      validateRec(subSchema, obj[k], [...path, k], errors);
    }
  }
  if (!s.additionalProperties) {
    for (const k of Object.keys(obj)) {
      // audit r1 (muffler F5): use own-key membership, not `k in s.properties`.
      // `"__proto__" in s.properties` is `true` via Object.prototype, so the `in`
      // form silently ACCEPTS a `__proto__`/`constructor` key under a strict
      // (additionalProperties:false) schema — a prototype-pollution passthrough.
      if (!Object.prototype.hasOwnProperty.call(s.properties, k)) {
        errors.push(err([...path, k], "unknown field", obj[k]));
      }
    }
  }
}

function validateUnion(s: UnionSchema, value: unknown, path: readonly (string | number)[], errors: ValidationError[]): void {
  for (const variant of s.variants) {
    const subErrors: ValidationError[] = [];
    validateRec(variant, value, path, subErrors);
    if (subErrors.length === 0) return;
  }
  errors.push(err(path, `value matched none of ${s.variants.length} union variants`, value));
}

function validateRecord(s: RecordSchema, value: unknown, path: readonly (string | number)[], errors: ValidationError[]): void {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    errors.push(err(path, "expected object (record)", value));
    return;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    validateRec(s.keys, k, [...path, k], errors);
    validateRec(s.values, v, [...path, k], errors);
  }
}
