/**
 * `@kashscript/attest/ids` — the canonical ULID + SHA-256 helpers that replace
 * the venture-local copies (ECOSYSTEM-AUDIT §2.1 / §2.2, decision 13).
 *
 * These assert the properties the ventures actually depend on, so a future edit
 * that changes the wire shape of an id or a digest fails here rather than in a
 * signature check months later.
 */

import { describe, it, expect } from "bun:test";
import {
  ulid,
  isUlid,
  ulidTimeMs,
  sha256Hex,
  sha256HexOf,
  ULID_ALPHABET,
  ULID_PATTERN,
} from "../src/ids";
import { sha256Hex as chainSha256Hex } from "../src/chain";
import { AttestError } from "../src/errors";
import { DST_REGISTRY, lookupDst, isRegisteredDst } from "../src/dst";

describe("ids — ulid", () => {
  it("mints 26 Crockford-base32 characters", () => {
    for (let i = 0; i < 200; i++) {
      const id = ulid();
      expect(id).toHaveLength(26);
      expect(ULID_PATTERN.test(id)).toBe(true);
      for (const ch of id) expect(ULID_ALPHABET.includes(ch)).toBe(true);
    }
  });

  it("never emits the Crockford-excluded letters I, L, O or U", () => {
    const joined = Array.from({ length: 300 }, () => ulid()).join("");
    for (const bad of ["I", "L", "O", "U"]) expect(joined.includes(bad)).toBe(false);
  });

  it("encodes the injected timestamp, recoverable via ulidTimeMs", () => {
    for (const ms of [0, 1, 1_000, 1_785_000_000_000, Date.now()]) {
      expect(ulidTimeMs(ulid(ms))).toBe(ms);
    }
  });

  it("sorts lexicographically by mint time", () => {
    const early = ulid(1_700_000_000_000);
    const mid = ulid(1_785_000_000_000);
    const late = ulid(1_900_000_000_000);
    expect([late, early, mid].sort()).toEqual([early, mid, late]);
  });

  it("is byte-identical in shape to the venture copies it replaces", () => {
    // Oreoasis sdk/receipt.ts + core-host/ulid.ts: 10 time chars + 16 random.
    const id = ulid(1_785_000_000_000);
    const timeHalf = id.slice(0, 10);
    expect(id.slice(0, 10)).toBe(timeHalf);
    expect(ulid(1_785_000_000_000).slice(0, 10)).toBe(timeHalf); // time half is deterministic
    expect(id.slice(10)).toHaveLength(16);
  });

  it("is unique across a burst within one millisecond", () => {
    const fixed = 1_785_000_000_000;
    const seen = new Set(Array.from({ length: 2_000 }, () => ulid(fixed)));
    expect(seen.size).toBe(2_000); // 80 bits of randomness — no collisions
  });

  it("rejects a nonsense timestamp rather than minting a malformed id", () => {
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, -1]) {
      expect(() => ulid(bad)).toThrow(AttestError);
    }
  });

  it("isUlid accepts real ids and rejects near-misses", () => {
    expect(isUlid(ulid())).toBe(true);
    expect(isUlid("")).toBe(false);
    expect(isUlid("0".repeat(25))).toBe(false);
    expect(isUlid("0".repeat(27))).toBe(false);
    expect(isUlid("I".repeat(26))).toBe(false); // excluded letter
    expect(isUlid("0".repeat(25) + "u")).toBe(false); // lowercase + excluded
  });

  it("ulidTimeMs refuses a non-ULID", () => {
    expect(() => ulidTimeMs("not-a-ulid")).toThrow(AttestError);
  });
});

describe("ids — sha256", () => {
  it("re-exports chain's digest — one implementation, not two", async () => {
    expect(sha256Hex).toBe(chainSha256Hex);
  });

  it("matches the published SHA-256 test vector for the empty input", async () => {
    expect(await sha256Hex(new Uint8Array())).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });

  it("matches the published SHA-256 test vector for \"abc\"", async () => {
    expect(await sha256HexOf("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  it("sha256HexOf agrees with sha256Hex over the same UTF-8 bytes", async () => {
    for (const s of ["", "abc", "Islamabad", "receipt × 2", "اردو"]) {
      expect(await sha256HexOf(s)).toBe(await sha256Hex(new TextEncoder().encode(s)));
    }
  });

  it("emits lowercase hex of exactly 64 chars", async () => {
    const d = await sha256HexOf("anything");
    expect(d).toMatch(/^[0-9a-f]{64}$/);
  });

  it("sha256Hex rejects a string with a typed AttestError naming sha256HexOf", async () => {
    // The naming trap (simulation-stack 2026-07-28 §5): this used to surface as
    // a raw Node ERR_INVALID_ARG_TYPE from WebCrypto. The contract stays
    // bytes-only; the failure just becomes legible.
    const err = await sha256Hex("not bytes" as unknown as Uint8Array).then(
      () => null,
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(AttestError);
    expect((err as AttestError).code).toBe("INVALID_INPUT");
    expect((err as AttestError).message).toContain("sha256HexOf");
    expect((err as AttestError).message).toContain("@kashscript/attest/ids");
  });

  it("sha256Hex rejects null / undefined / number / ArrayBuffer the same way", async () => {
    for (const bad of [null, undefined, 42, new ArrayBuffer(4), { length: 3 }]) {
      await expect(sha256Hex(bad as unknown as Uint8Array)).rejects.toBeInstanceOf(AttestError);
    }
  });

  it("sha256Hex still accepts real bytes after the guard", async () => {
    expect(await sha256Hex(new TextEncoder().encode("abc"))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });
});

describe("dst — the Agent Receipt payloadType is registered in source", () => {
  const TAG = "application/vnd.oreoasis.agent-receipt+json";

  it("is present in DST_REGISTRY without any runtime registration", () => {
    // Regression guard for ECOSYSTEM-AUDIT §4.9: runtime self-registration must
    // never be the ONLY place a shipped DST exists, or a stale attest verifies
    // artifacts it has no record of.
    expect(isRegisteredDst(TAG)).toBe(true);
    expect(DST_REGISTRY.some((e) => e.tag === TAG)).toBe(true);
  });

  it("is a live dsse-type entry, not a reserved slot", () => {
    const entry = lookupDst(TAG);
    expect(entry).not.toBeNull();
    expect(entry!.family).toBe("dsse-type");
    expect(entry!.reserved).toBeUndefined();
  });
});
