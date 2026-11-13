/**
 * Known-answer tests for RFC 8785 JSON Canonicalization (JCS).
 *
 * Every Kash-Event signature is computed over these bytes. A divergence
 * of one character breaks cross-implementation verification, so these
 * pin the load-bearing behaviours: key ordering, number form, negative
 * zero, and the hard-rejects.
 */

import { describe, expect, test } from "bun:test";
import { canonicalize } from "./canonical";

describe("canonical · RFC 8785 KAT", () => {
  test("object keys sort in UTF-16 code-unit order", () => {
    expect(canonicalize({ b: 1, a: 2 })).toBe('{"a":2,"b":1}');
    expect(canonicalize({ z: 1, A: 2, a: 3 })).toBe('{"A":2,"a":3,"z":1}'); // 'A'(65) < 'a'(97) < 'z'(122)
  });

  test("array element order is preserved (not sorted)", () => {
    expect(canonicalize({ z: [3, 1, 2], a: 1 })).toBe('{"a":1,"z":[3,1,2]}');
  });

  test("nested objects canonicalise recursively", () => {
    expect(canonicalize({ outer: { b: 1, a: 2 } })).toBe('{"outer":{"a":2,"b":1}}');
  });

  test("numbers use ECMAScript Number.toString", () => {
    expect(canonicalize({ n: 1.5 })).toBe('{"n":1.5}');
    expect(canonicalize({ n: 100 })).toBe('{"n":100}');
    expect(canonicalize({ n: 0 })).toBe('{"n":0}');
  });

  test("negative zero serialises as 0", () => {
    expect(canonicalize({ n: -0 })).toBe('{"n":0}');
  });

  test("booleans + null", () => {
    expect(canonicalize({ t: true, f: false, n: null })).toBe('{"f":false,"n":null,"t":true}');
  });

  test("no whitespace anywhere", () => {
    const out = canonicalize({ a: [1, { b: 2 }], c: "x" });
    expect(out).not.toMatch(/\s/);
    expect(out).toBe('{"a":[1,{"b":2}],"c":"x"}');
  });

  test("undefined object fields are omitted (matches JSON.stringify)", () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });
});

describe("canonical · hard rejects (RFC 8785 §3.2.2.3 + JSON limits)", () => {
  test("rejects NaN / ±Infinity", () => {
    expect(() => canonicalize({ n: NaN })).toThrow();
    expect(() => canonicalize({ n: Infinity })).toThrow();
    expect(() => canonicalize({ n: -Infinity })).toThrow();
  });
  test("rejects BigInt", () => {
    expect(() => canonicalize({ n: 1n })).toThrow();
  });
  test("rejects undefined inside an array (would corrupt position)", () => {
    expect(() => canonicalize({ a: [1, undefined, 3] })).toThrow();
  });
  test("rejects circular references", () => {
    const o: Record<string, unknown> = { a: 1 };
    o["self"] = o;
    expect(() => canonicalize(o)).toThrow();
  });
});
