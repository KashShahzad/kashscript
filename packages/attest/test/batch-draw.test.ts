/**
 * PY-5 — the draw (`specs/attestation/batch.md` §3): a seed from the seal and the draw block, a SHA-256 word
 * stream, rejection sampling, a partial Fisher–Yates shuffle. Deterministic, distinct, in range, unbiased — and
 * fixed for strangers by the conformance file `batch-draw@1`.
 */

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { bytesToHex, hexToBytes } from "../src/chain";
import { DRAW_DOMAIN, DrawStream, checkDrawCoinbase, drawPositions, drawSeed, fetchDrawCoinbase, heightPush, uniformBelow, type FetchText, type WordSource } from "../src/batch";
import { blockOf, coinbaseOf, mineHeader, testHeightPush } from "./helpers/batch";

const SEAL = "11".repeat(32);
const BLOCK = "00000000000000000000c3caf5193ab69e0955153c74135f8afc615ff2400b3".padStart(64, "0");

describe("the seed and the stream", () => {
  test("the seed is SHA-256 of the domain, the seal digest and the block hash, as written", async () => {
    const tag = new TextEncoder().encode(DRAW_DOMAIN);
    const msg = new Uint8Array([...tag, ...hexToBytes(SEAL), ...hexToBytes(BLOCK)]);
    const want = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", msg)));
    expect(await drawSeed(SEAL, BLOCK)).toBe(want);
  });

  test("a different seal or a different block gives a different seed", async () => {
    const s = await drawSeed(SEAL, BLOCK);
    expect(await drawSeed("12".repeat(32), BLOCK)).not.toBe(s);
    expect(await drawSeed(SEAL, "01".padStart(64, "0"))).not.toBe(s);
  });

  test("the stream's first word is the first eight bytes of SHA-256(seed ‖ 0), big-endian; the fifth word starts the next block", async () => {
    const seed = hexToBytes(await drawSeed(SEAL, BLOCK));
    const block = async (n: number): Promise<Uint8Array> => {
      const m = new Uint8Array(36);
      m.set(seed, 0);
      new DataView(m.buffer).setUint32(32, n, false);
      return new Uint8Array(await crypto.subtle.digest("SHA-256", m));
    };
    const s = new DrawStream(seed);
    const words: bigint[] = [];
    for (let i = 0; i < 5; i++) words.push(await s.next());
    const b0 = await block(0);
    const b1 = await block(1);
    expect(words[0]).toBe(BigInt("0x" + bytesToHex(b0.slice(0, 8))));
    expect(words[3]).toBe(BigInt("0x" + bytesToHex(b0.slice(24, 32))));
    expect(words[4]).toBe(BigInt("0x" + bytesToHex(b1.slice(0, 8))));
  });
});

/** Words a test chooses. */
const words = (...ws: bigint[]): WordSource => {
  let i = 0;
  return { next: async () => ws[i++]! };
};
const TWO_64 = 1n << 64n;

describe("a number below m", () => {
  test("a word at or above the largest multiple of m under 2^64 is passed over; the next is used", async () => {
    // 2^64 mod 3 = 1, so the largest multiple of 3 below 2^64 is 2^64 − 1: that word alone is passed over.
    expect(await uniformBelow(words(TWO_64 - 1n, 5n), 3)).toBe(2);
    expect(await uniformBelow(words(TWO_64 - 2n), 3)).toBe(Number((TWO_64 - 2n) % 3n));
    // m = 2^52: 2^64 is a multiple, so nothing is passed over.
    expect(await uniformBelow(words(TWO_64 - 1n), 2 ** 52)).toBe(Number((TWO_64 - 1n) % 2n ** 52n));
    // m beyond the safe integers is refused, never computed.
    await expect(uniformBelow(words(0n), 2 ** 53)).rejects.toThrow();
  });

  test("for small ranges, every accepted word maps to each number the same number of times", () => {
    for (let m = 1; m <= 50; m++) {
      const M = BigInt(m);
      const limit = TWO_64 - (TWO_64 % M);
      expect(limit % M).toBe(0n); // each residue is hit exactly limit / m times
      expect(TWO_64 - limit).toBeLessThan(M);
    }
  });
});

describe("the positions", () => {
  test("a draw is deterministic, distinct, in range, ascending, and exactly sample long", async () => {
    const seed = await drawSeed(SEAL, BLOCK);
    const a = await drawPositions(seed, 2000, 140);
    expect(await drawPositions(seed, 2000, 140)).toEqual(a);
    expect(a).toHaveLength(140);
    expect(new Set(a).size).toBe(140);
    for (let i = 0; i < a.length; i++) {
      expect(a[i]).toBeGreaterThanOrEqual(0);
      expect(a[i]).toBeLessThan(2000);
      if (i > 0) expect(a[i]).toBeGreaterThan(a[i - 1]!);
    }
  });

  test("drawing every item gives every position", async () => {
    expect(await drawPositions(await drawSeed(SEAL, BLOCK), 50, 50)).toEqual(Array.from({ length: 50 }, (_, i) => i));
  });

  test("over 4,000 seeds, each of ten positions is drawn about three times in ten, within a chi-square bound", async () => {
    const counts = new Array<number>(10).fill(0);
    const seeds = 4000;
    for (let i = 0; i < seeds; i++) {
      const seed = await drawSeed(bytesToHex(new Uint8Array(32).fill(i & 0xff)).slice(0, 56) + i.toString(16).padStart(8, "0"), BLOCK);
      for (const p of await drawPositions(seed, 10, 3)) counts[p]!++;
    }
    const expected = (seeds * 3) / 10;
    const chi = counts.reduce((s, c) => s + (c - expected) ** 2 / expected, 0);
    // 9 degrees of freedom: P(χ² > 27.88) = 0.001. The seeds are fixed, so this never flakes.
    expect(chi).toBeLessThan(27.88);
  }, 60_000);

  test("malformed inputs are refused", async () => {
    await expect(drawPositions("zz", 10, 3)).rejects.toThrow();
    await expect(drawPositions(SEAL, 10, 11)).rejects.toThrow();
    await expect(drawPositions(SEAL, 0, 0)).rejects.toThrow();
    await expect(drawSeed(SEAL, "short")).rejects.toThrow();
  });
});

describe("the draw block's height — its first transaction (BIP34; PY-5r)", () => {
  // The genesis block: its one transaction and its header, as Bitcoin has carried them since 2009.
  const GENESIS_TX =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
  const GENESIS_HEADER =
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";
  const sha256 = async (b: Uint8Array): Promise<Uint8Array> => new Uint8Array(await crypto.subtle.digest("SHA-256", b as unknown as BufferSource));
  const sha256d = async (b: Uint8Array): Promise<Uint8Array> => sha256(await sha256(b));
  const join = (a: Uint8Array, b: Uint8Array): Uint8Array => Uint8Array.from([...a, ...b]);

  test("BIP34's push is Bitcoin Core's CScript() << height", () => {
    const hex = (h: number): string => bytesToHex(heightPush(h));
    expect(hex(0)).toBe("00");
    expect(hex(1)).toBe("51");
    expect(hex(16)).toBe("60");
    expect(hex(17)).toBe("0111");
    expect(hex(128)).toBe("028000");
    expect(hex(256)).toBe("020001");
    expect(hex(227_931)).toBe("035b7a03"); // the block from which BIP34 binds
    expect(hex(977_713)).toBe("0331eb0e"); // the worked example's draw block
    expect(hex(8_388_608)).toBe("0400008000");
    for (const h of [32_768, 900_003, 977_713, 8_388_607]) expect(hex(h)).toBe(bytesToHex(Uint8Array.from(testHeightPush(h))));
  });

  test("a real transaction: the genesis coinbase's id is the genesis header's Merkle root — and, before BIP34, it names no height of its own", async () => {
    // The path reaches the root, so only the height is refused: the script begins with a push of the difficulty.
    expect(await checkDrawCoinbase({ tx: GENESIS_TX, path: [] }, GENESIS_HEADER, 0)).toBe("the draw block's first transaction names height 486604799, not 0: these headers do not end at the block the seal named");
    expect(await checkDrawCoinbase({ tx: GENESIS_TX, path: ["00".repeat(32)] }, GENESIS_HEADER, 0)).toContain("does not reach the draw block's Merkle root");
  });

  test("a block's first transaction, in witness form or not, two levels deep, stands for its own height and no other, and only by its own path", async () => {
    const cb = await coinbaseOf(977_713);
    const block = await blockOf(cb);
    const header = await mineHeader(new Uint8Array(32), block.root, 1_790_000_000);
    expect(await checkDrawCoinbase(block.coinbase, header, 977_713)).toBeNull();
    expect(await checkDrawCoinbase(block.coinbase, header, 977_714)).toContain("names height 977713, not 977714");
    expect(await checkDrawCoinbase({ ...block.coinbase, path: [...block.coinbase.path].reverse() }, header, 977_713)).toContain("does not reach");
    expect(await checkDrawCoinbase({ ...block.coinbase, path: block.coinbase.path.slice(1) }, header, 977_713)).toContain("does not reach");
    const legacy = await coinbaseOf(977_713, { witness: false });
    expect(bytesToHex(legacy.txid)).toBe(bytesToHex(cb.txid));
    expect(await checkDrawCoinbase({ tx: legacy.hex, path: block.coinbase.path }, header, 977_713)).toBeNull();
  });

  test("what is not a block's first transaction is refused in words, never thrown", async () => {
    const cb = await coinbaseOf(977_713, { witness: false });
    const block = await blockOf(cb);
    const header = await mineHeader(new Uint8Array(32), block.root, 1_790_000_000);
    const raw = hexToBytes(cb.hex);
    const edit = (f: (b: number[]) => void): string => {
      const b = [...raw];
      f(b);
      return bytesToHex(Uint8Array.from(b));
    };
    const words = async (tx: string): Promise<string | null> => checkDrawCoinbase({ tx, path: block.coinbase.path }, header, 977_713);
    expect(await words(edit((b) => (b[5] = 1)))).toContain("spends an earlier output");
    expect(await words(edit((b) => (b[4] = 2)))).toContain("has one input");
    expect(await words(cb.hex.slice(0, -8))).toContain("ends early");
    expect(await words(`${cb.hex}00`)).toContain("bytes follow");
    expect(await words(edit((b) => (b[41] = 1)))).toContain("2 to 100 bytes");
    expect(await words("zz")).toContain("not a transaction in hex");
    expect(await checkDrawCoinbase({ tx: cb.hex, path: ["ab"] }, header, 977_713)).toContain("not a transaction in hex");
    expect(await checkDrawCoinbase(undefined, header, 977_713)).toContain("the draw block's height is not shown");
    expect(await checkDrawCoinbase(null as unknown as undefined, header, 977_713)).toContain("the draw block's height is not shown");
    expect(await checkDrawCoinbase(block.coinbase, "00", 977_713)).toContain("not 80 bytes");
    expect(await checkDrawCoinbase(block.coinbase, header, 2 ** 40)).toContain("cannot be checked");
    // 64 bytes without its witness: a transaction that size can pass for a node of the tree, so none is read.
    const tx64 = Uint8Array.from([2, 0, 0, 0, 1, ...new Array<number>(32).fill(0), 0xff, 0xff, 0xff, 0xff, 4, ...testHeightPush(977_713), 0xff, 0xff, 0xff, 0xff, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    expect(tx64.length).toBe(64);
    expect(await checkDrawCoinbase({ tx: bytesToHex(tx64), path: [] }, header, 977_713)).toContain("64-byte transaction");
  });

  test("the maker's fetch reads a block's ids and first transaction and works out a path the check accepts — for blocks of 1 to 9 transactions", async () => {
    for (let n = 1; n <= 9; n++) {
      const cb = await coinbaseOf(977_713);
      const ids = [cb.txid, ...(await Promise.all(Array.from({ length: n - 1 }, (_, k) => sha256(Uint8Array.of(n, k)))))];
      let level = ids;
      while (level.length > 1) {
        const next: Uint8Array[] = [];
        for (let k = 0; k < level.length; k += 2) next.push(await sha256d(join(level[k]!, level[k + 1] ?? level[k]!)));
        level = next;
      }
      const header = await mineHeader(new Uint8Array(32), level[0]!, 1_790_000_000);
      const hash = bytesToHex((await sha256d(hexToBytes(header))).reverse());
      const shown = ids.map((t) => bytesToHex(t.slice().reverse()));
      const fetch: FetchText = async (url) => {
        const body = url === `https://blocks.example/api/block/${hash}/txids` ? JSON.stringify(shown) : url === `https://blocks.example/api/tx/${shown[0]}/hex` ? cb.hex : null;
        return { ok: body !== null, status: body === null ? 404 : 200, text: async () => body ?? "" };
      };
      const got = await fetchDrawCoinbase(hash, { fetch, source: "https://blocks.example/api/" });
      expect(got.tx).toBe(cb.hex);
      expect(await checkDrawCoinbase(got, header, 977_713)).toBeNull();
    }
  });
});

describe("batch-draw@1 — the conformance file", () => {
  interface Case {
    readonly name: string;
    readonly sealDigest: string;
    readonly blockHash: string;
    readonly seed: string;
    readonly size: number;
    readonly sample: number;
    readonly positions: readonly number[];
  }
  const file = JSON.parse(readFileSync(join(import.meta.dir, "..", "..", "..", "specs", "attestation", "tck", "batch-draw@1", "cases.json"), "utf8")) as { cases: Case[] };

  test("every case reaches its stated seed and positions", async () => {
    expect(file.cases.length).toBeGreaterThanOrEqual(5);
    for (const c of file.cases) {
      const seed = await drawSeed(c.sealDigest, c.blockHash);
      expect(seed).toBe(c.seed);
      expect(await drawPositions(seed, c.size, c.sample)).toEqual([...c.positions]);
    }
  });
});
