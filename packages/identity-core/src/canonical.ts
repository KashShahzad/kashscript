/**
 * ╔════════════════════════════════════════════════════════════════════╗
 * ║                       SECURITY ADVISORY                            ║
 * ║                                                                    ║
 * ║ This file is the load-bearing core of the Kash signature scheme.   ║
 * ║                                                                    ║
 * ║ Every Kash-Event signature is computed over the canonical bytes    ║
 * ║ produced here. If two implementations disagree on those bytes by   ║
 * ║ even ONE character — a re-ordered key, a different number          ║
 * ║ representation, an extra whitespace — every signature they sign    ║
 * ║ will fail to verify against each other. Equally, an attacker who   ║
 * ║ can manipulate the canonicalisation can either:                    ║
 * ║                                                                    ║
 * ║   1. Reuse a captured signature against a semantically-different   ║
 * ║      payload that happens to canonicalise the same way             ║
 * ║      (signature laundering).                                       ║
 * ║   2. Produce two payloads with identical canonical bytes but       ║
 * ║      different on-the-wire JSON, then swap them after signing      ║
 * ║      (malleability).                                               ║
 * ║                                                                    ║
 * ║ This implementation follows RFC 8785 (JSON Canonicalization        ║
 * ║ Scheme, JCS) on the subset of JSON values the Kash protocol uses:  ║
 * ║ objects, arrays, strings, finite numbers, booleans, null.          ║
 * ║                                                                    ║
 * ║ Key invariants (do NOT change without coordinating with all        ║
 * ║ other implementations):                                            ║
 * ║                                                                    ║
 * ║   • Object keys sorted in UTF-16 code-unit order.                  ║
 * ║   • Numbers serialised via ECMAScript Number.toString() per        ║
 * ║     RFC 8785 §3.2.2.3.                                             ║
 * ║   • Strings serialised via RFC 8259 §7 minimal-escape form         ║
 * ║     (delegated to native JSON.stringify).                          ║
 * ║   • No whitespace between any token.                               ║
 * ║   • Negative zero serialises as "0".                               ║
 * ║                                                                    ║
 * ║ Hard-rejected at canonicalisation time:                            ║
 * ║   • NaN, +Infinity, -Infinity         (RFC 8785 §3.2.2.3)          ║
 * ║   • BigInt                            (not JSON-representable)     ║
 * ║   • undefined inside arrays           (would corrupt position)     ║
 * ║   • symbols, functions                (not JSON-representable)     ║
 * ║   • circular references               (infinite output)            ║
 * ║                                                                    ║
 * ║ Silent (matches JSON.stringify):                                   ║
 * ║   • undefined object fields are omitted from output.               ║
 * ╚════════════════════════════════════════════════════════════════════╝
 */

import { KashCryptoError } from "./errors";

const TEXT_ENCODER = new TextEncoder();

/**
 * Canonicalise a JSON-compatible value to its RFC 8785 string form.
 *
 * Pure deterministic function: same input always yields byte-identical output.
 * No I/O, no logging, no global mutation.
 */
export function canonicalize(value: unknown): string {
  return serializeValue(value, new WeakSet<object>());
}

/** UTF-8 bytes of {@link canonicalize}. */
export function canonicalizeBytes(value: unknown): Uint8Array {
  return TEXT_ENCODER.encode(canonicalize(value));
}

/* ── internal serialiser ─────────────────────────────────────────── */

function serializeValue(value: unknown, seen: WeakSet<object>): string {
  if (value === null) return "null";

  switch (typeof value) {
    case "boolean":
      return value ? "true" : "false";

    case "number": {
      const n = value;
      if (!Number.isFinite(n)) {
        throw new KashCryptoError(
          `Non-finite numbers cannot be canonicalised: ${n}`,
          "INVALID_INPUT",
        );
      }
      // RFC 8785 §3.2.2.3: ES Number.toString algorithm. JS String(n) implements it.
      // Negative zero serialises as "0" — explicit because Object.is(-0, 0) === false.
      return Object.is(n, -0) ? "0" : String(n);
    }

    case "string":
      // RFC 8259 §7 minimal-escape form is exactly what JSON.stringify(string) emits.
      return JSON.stringify(value);

    case "bigint":
      throw new KashCryptoError(
        "BigInt cannot be canonicalised (not JSON-representable).",
        "INVALID_INPUT",
      );

    case "undefined":
    case "function":
    case "symbol":
      throw new KashCryptoError(
        `${typeof value} cannot be canonicalised.`,
        "INVALID_INPUT",
      );

    case "object": {
      const obj = value as object;
      if (seen.has(obj)) {
        throw new KashCryptoError(
          "Circular reference encountered during canonicalisation.",
          "INVALID_INPUT",
        );
      }
      seen.add(obj);
      const out = Array.isArray(obj)
        ? serializeArray(obj as readonly unknown[], seen)
        : serializeObject(obj as Record<string, unknown>, seen);
      seen.delete(obj);
      return out;
    }
  }

  // The `typeof` cases above are exhaustive; this is unreachable. The throw
  // keeps the return-type narrowed to `string` and satisfies strict TS.
  throw new KashCryptoError(`Unsupported value type: ${typeof value}.`, "INVALID_INPUT");
}

function serializeArray(arr: readonly unknown[], seen: WeakSet<object>): string {
  const parts: string[] = [];
  for (let i = 0; i < arr.length; i++) {
    const item = arr[i];
    if (item === undefined) {
      throw new KashCryptoError(
        `Array element at index ${i} is undefined; cannot canonicalise.`,
        "INVALID_INPUT",
      );
    }
    parts.push(serializeValue(item, seen));
  }
  return "[" + parts.join(",") + "]";
}

function serializeObject(obj: Record<string, unknown>, seen: WeakSet<object>): string {
  // Default Array.sort uses UTF-16 code-unit comparison, matching RFC 8785 §3.2.3.
  const keys = Object.keys(obj).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const v = obj[k];
    if (v === undefined) continue; // silent skip — matches JSON.stringify semantics.
    parts.push(JSON.stringify(k) + ":" + serializeValue(v, seen));
  }
  return "{" + parts.join(",") + "}";
}
