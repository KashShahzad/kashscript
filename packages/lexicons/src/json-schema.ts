/**
 * Convert a `Schema` (the internal DSL) to a JSON-Schema Draft 2020-12 object.
 *
 * Output is intended for consumption by external AI tools and documentation
 * generators (Oreoasis ingestion, OpenAPI exporters, schema crawlers). The
 * conversion is lossless for our DSL: every constraint we model maps to a
 * documented JSON-Schema keyword.
 *
 * Kash-specific string formats (did-ks, cid, lexicon-id, …) are exposed via
 * the `format` keyword AND as `pattern` regex so consumers without a custom
 * format registry can still validate.
 */

import {
  FORMAT_PATTERNS,
  type ArraySchema,
  type EnumSchema,
  type LiteralSchema,
  type NumberSchema,
  type ObjectSchema,
  type RecordSchema,
  type Schema,
  type SchemaStringFormat,
  type StringSchema,
  type UnionSchema,
} from "./schema";

/** Minimal JSON-Schema object. Booleans (`true`/`false` schemas) are NOT emitted. */
export type JsonSchema = Readonly<Record<string, unknown>>;

/** Map Kash string-format identifiers to JSON-Schema `format` values.
 *  Standard formats (date-time, uri) use the JSON-Schema names; Kash-specific
 *  ones use a prefix. The regex source is reused from `FORMAT_PATTERNS` so we
 *  never duplicate the canonical regex. */
const FORMAT_NAMES: Record<SchemaStringFormat, string> = {
  "did-ks":     "did-ks",
  "cid":        "cid",
  "iso8601":    "date-time",
  "url":        "uri",
  "multibase":  "multibase",
  "bcp47":      "bcp47-language-tag",
  "iso4217":    "iso-4217-currency",
  "lexicon-id": "kash-lexicon-id",
  "nsid":       "kash-nsid",
};

/** Convert any internal Schema to a JSON-Schema-Draft-2020-12 object. */
export function toJsonSchema(schema: Schema): JsonSchema {
  switch (schema.kind) {
    case "any":
      return {};
    case "boolean":
      return { type: "boolean" };
    case "literal":
      return convertLiteral(schema);
    case "enum":
      return convertEnum(schema);
    case "string":
      return convertString(schema);
    case "number":
      return convertNumber(schema);
    case "array":
      return convertArray(schema);
    case "object":
      return convertObject(schema);
    case "union":
      return convertUnion(schema);
    case "optional":
      // Optionality is encoded by the parent object's `required` array.
      return toJsonSchema(schema.inner);
    case "record":
      return convertRecord(schema);
  }
}

function convertLiteral(s: LiteralSchema): JsonSchema {
  return { const: s.value };
}

function convertEnum(s: EnumSchema): JsonSchema {
  return { enum: [...s.values] };
}

function convertString(s: StringSchema): JsonSchema {
  const out: Record<string, unknown> = { type: "string" };
  if (s.minLength !== undefined) out.minLength = s.minLength;
  if (s.maxLength !== undefined) out.maxLength = s.maxLength;
  if (s.pattern) out.pattern = s.pattern.source;
  if (s.format) {
    out.format = FORMAT_NAMES[s.format];
    if (out.pattern === undefined) out.pattern = FORMAT_PATTERNS[s.format].source;
  }
  return out;
}

function convertNumber(s: NumberSchema): JsonSchema {
  const out: Record<string, unknown> = { type: s.integer ? "integer" : "number" };
  if (s.min !== undefined) out.minimum = s.min;
  if (s.max !== undefined) out.maximum = s.max;
  return out;
}

function convertArray(s: ArraySchema): JsonSchema {
  const out: Record<string, unknown> = {
    type: "array",
    items: toJsonSchema(s.items),
  };
  if (s.minItems !== undefined) out.minItems = s.minItems;
  if (s.maxItems !== undefined) out.maxItems = s.maxItems;
  return out;
}

function convertObject(s: ObjectSchema): JsonSchema {
  const properties: Record<string, JsonSchema> = {};
  for (const k of Object.keys(s.properties)) {
    const sub = s.properties[k]!;
    properties[k] = toJsonSchema(sub);
  }
  const out: Record<string, unknown> = {
    type: "object",
    properties,
    additionalProperties: s.additionalProperties,
  };
  if (s.required.length > 0) out.required = [...s.required];
  return out;
}

function convertUnion(s: UnionSchema): JsonSchema {
  return { anyOf: s.variants.map(toJsonSchema) };
}

function convertRecord(s: RecordSchema): JsonSchema {
  const out: Record<string, unknown> = {
    type: "object",
    additionalProperties: toJsonSchema(s.values),
  };
  if (s.keys.pattern) {
    out.propertyNames = { pattern: s.keys.pattern.source };
  }
  return out;
}
