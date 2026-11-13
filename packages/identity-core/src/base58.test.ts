/**
 * Known-answer + round-trip tests for base58btc.
 *
 * The #1 base58 interop bug is leading-zero handling — each leading
 * 0x00 byte must map to exactly one "1". These KATs pin that, plus
 * round-trip stability across byte patterns.
 */

import { describe, expect, test } from "bun:test";
import { encodeBase58, decodeBase58 } from "./base58";

describe("base58 · leading-zero KAT (the classic interop bug)", () => {
  test("a single 0x00 byte encodes to exactly one '1'", () => {
    expect(encodeBase58(Uint8Array.of(0x00))).toBe("1");
  });
  test("N leading zero bytes encode to N leading '1's", () => {
    expect(encodeBase58(Uint8Array.of(0x00, 0x00))).toBe("11");
    expect(encodeBase58(Uint8Array.of(0x00, 0x00, 0x00))).toBe("111");
  });
  test("leading zeros survive a decode round-trip", () => {
    const bytes = Uint8Array.of(0x00, 0x00, 0x01, 0x02, 0x03);
    expect(Array.from(decodeBase58(encodeBase58(bytes)))).toEqual([0, 0, 1, 2, 3]);
  });
});

describe("base58 · empty + round-trip", () => {
  test("empty input round-trips to empty", () => {
    expect(encodeBase58(new Uint8Array(0))).toBe("");
    expect(decodeBase58("").length).toBe(0);
  });

  test("round-trips arbitrary byte patterns byte-for-byte", () => {
    const cases: number[][] = [
      [1],
      [255],
      [0, 255, 0, 255],
      [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
      Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff), // pubkey-sized
    ];
    for (const c of cases) {
      const bytes = Uint8Array.from(c);
      const round = decodeBase58(encodeBase58(bytes));
      expect(Array.from(round)).toEqual(c);
    }
  });

  test("output charset is base58btc (no 0, O, I, l)", () => {
    const s = encodeBase58(Uint8Array.from(Array.from({ length: 64 }, (_, i) => i & 0xff)));
    expect(s).not.toMatch(/[0OIl]/);
  });
});
