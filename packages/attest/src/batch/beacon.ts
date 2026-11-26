/**
 * Where a batch's draw comes from — Bitcoin, through OpenTimestamps (PY-5; the founder's ruling of
 * 2026-11-26; `specs/attestation/batch.md` §3).
 *
 * The seal names a block height ahead of the chain's tip. The asker stamps the seal's digest with
 * OpenTimestamps; the stamp's Bitcoin attestation lands in some block below that height, which shows the seal
 * existed before the named block was mined. The named block's hash then seeds the draw (`./draw`). Naming the
 * height inside the seal is what stops the asker choosing between two calendars' blocks — **once the draw block
 * shows its height** (below).
 *
 * **What a checker requires, offline:** between 2 and {@link MAX_DRAW_GAP} + 1 headers, each naming the one before
 * by its hash and claiming at least {@link SEED_MIN_WORK_BITS} bits of work; **the draw block's first transaction
 * and its Merkle path** (`coinbase`), reaching the last header's Merkle root and naming, as BIP34 makes every block
 * since 227,931 do, the height the seal named; and a Bitcoin attestation in the stamp at height
 * `draw height − (blocks − 1)`, reaching the first header's Merkle root.
 *
 * **Why the coinbase (PY-5r).** A block header does not carry its height, and the stamp's Bitcoin attestation names
 * one in a number nothing signs. Without the draw block's own word, an asker who edited that number and handed in
 * more headers could pass any of the next {@link MAX_DRAW_GAP} real blocks as the one the seal named, and choose
 * among their draws, at no cost. With it, passing another block as the named one takes a block mined at the floor's
 * work with a false height.
 *
 * **What it cannot see:** that these headers are Bitcoin's own chain, rather than a costly private one — compare
 * the draw block's hash with any copy of the chain. A miner could throw away a block it found, at the cost of the
 * block's reward, to change one draw.
 *
 * The fetchers at the bottom are the maker's, with `fetch` injected; no check calls them.
 */

import { bytesToHex, hexToBytes } from "../chain";
import { base64ToBytes } from "../ed25519";
import { AttestError } from "../errors";
import { checkBitcoinHeader, otsLeaves, parseOts } from "../witness/ots";

/**
 * The least work a draw's header may claim. Blocks of November 2026 claim 79.1 bits (blocks 974281 to 974322,
 * measured `[v 11-26]`); 76 leaves room for an eight-fold fall in difficulty, while a forged header still costs
 * about a sixth of a block's reward. A number with a date: the founder changes it by a dated note.
 */
export const SEED_MIN_WORK_BITS = 76;
/** The most blocks between the stamp and the draw: one day. */
export const MAX_DRAW_GAP = 144;

const HEADER = /^[0-9a-f]{160}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX_BYTES = /^(?:[0-9a-f]{2})+$/;

/* ── the draw block's height: its first transaction (BIP34) ── */

/** The most bytes a draw block's first transaction may hold here. A pool that pays many outputs runs to kilobytes. */
export const MAX_COINBASE_BYTES = 100_000;
/** The longest Merkle path read: 24 levels is 2^24 transactions, far past any block's weight. */
export const MAX_COINBASE_PATH = 24;

/** The draw block's first transaction and its Merkle path: the block's height, in its miner's own words (BIP34). */
export interface DrawCoinbase {
  /** The transaction, as hex, as the block carries it — its witness included, when it has one. */
  readonly tx: string;
  /**
   * Its path to the block's Merkle root, nearest sibling first: 32 bytes each, as hex, in the byte order the hashing
   * reads them — the order a header stores its root in (block explorers show transaction ids reversed).
   */
  readonly path: readonly string[];
}

/** BIP34: what a block's first input script begins with at this height — Bitcoin Core's `CScript() << height`. */
export function heightPush(height: number): Uint8Array {
  if (!Number.isSafeInteger(height) || height < 0 || height > 0x7fffffff) throw new AttestError("INVALID_INPUT", "a block height is a whole number below 2^31");
  if (height === 0) return Uint8Array.of(0x00);
  if (height <= 16) return Uint8Array.of(0x50 + height);
  const le: number[] = [];
  for (let v = height; v > 0; v = Math.floor(v / 256)) le.push(v % 256);
  if ((le[le.length - 1]! & 0x80) !== 0) le.push(0);
  return Uint8Array.of(le.length, ...le);
}

/** The height an input script's first push names, when it is one; null otherwise. For the words of a refusal only. */
function heightNamed(script: Uint8Array): number | null {
  const op = script[0];
  if (op === undefined) return null;
  if (op === 0x00) return 0;
  if (op >= 0x51 && op <= 0x60) return op - 0x50;
  if (op < 1 || op > 6 || script.length < 1 + op || (script[op]! & 0x80) !== 0) return null;
  let v = 0;
  for (let k = op; k >= 1; k--) v = v * 256 + script[k]!;
  return v;
}

async function sha256d(bytes: Uint8Array): Promise<Uint8Array> {
  const once = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", once));
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Bitcoin's transaction bytes, read once; every length is bounded by what is left. */
class TxReader {
  private pos = 0;
  constructor(private readonly b: Uint8Array) {}
  get at(): number {
    return this.pos;
  }
  done(): boolean {
    return this.pos === this.b.length;
  }
  peek(): number | undefined {
    return this.b[this.pos];
  }
  take(n: number): Uint8Array {
    if (!Number.isSafeInteger(n) || n < 0 || this.pos + n > this.b.length) throw new AttestError("MALFORMED_PAYLOAD", "the transaction ends early");
    const out = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  u32(): number {
    const x = this.take(4);
    return (x[0]! | (x[1]! << 8) | (x[2]! << 16) | (x[3]! << 24)) >>> 0;
  }
  /** A CompactSize, written in the fewest bytes, as Bitcoin requires. */
  compact(): number {
    const first = this.take(1)[0]!;
    if (first < 0xfd) return first;
    const n = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
    const x = this.take(n);
    let v = 0;
    for (let k = n - 1; k >= 0; k--) v = v * 256 + x[k]!;
    const least = first === 0xfd ? 0xfd : first === 0xfe ? 0x1_0000 : 2 ** 32;
    if (!Number.isSafeInteger(v) || v < least) throw new AttestError("MALFORMED_PAYLOAD", "a length is written in more bytes than it needs");
    return v;
  }
}

/** A block's first transaction, read: its id (in the hashing's byte order) and its input script. Throws for anything else. */
async function readCoinbase(raw: Uint8Array): Promise<{ readonly txid: Uint8Array; readonly script: Uint8Array }> {
  const r = new TxReader(raw);
  r.take(4); // version
  let witness = false;
  if (r.peek() === 0x00) {
    r.take(1);
    if (r.take(1)[0] !== 0x01) throw new AttestError("MALFORMED_PAYLOAD", "the transaction's witness flag is not 1");
    witness = true;
  }
  const from = r.at;
  if (r.compact() !== 1) throw new AttestError("MALFORMED_PAYLOAD", "a block's first transaction has one input");
  const prev = r.take(32);
  if (prev.some((x) => x !== 0) || r.u32() !== 0xffffffff) throw new AttestError("MALFORMED_PAYLOAD", "it spends an earlier output — a block's first transaction spends nothing");
  const length = r.compact();
  if (length < 2 || length > 100) throw new AttestError("MALFORMED_PAYLOAD", "a block's first input script is 2 to 100 bytes");
  const script = r.take(length).slice();
  r.take(4); // sequence
  const outputs = r.compact();
  if (outputs < 1) throw new AttestError("MALFORMED_PAYLOAD", "a transaction has at least one output");
  for (let k = 0; k < outputs; k++) {
    r.take(8);
    r.take(r.compact());
  }
  const to = r.at;
  if (witness) for (let items = r.compact(); items > 0; items--) r.take(r.compact());
  r.take(4); // lock time
  if (!r.done()) throw new AttestError("MALFORMED_PAYLOAD", "bytes follow the transaction");
  // The id is over the transaction without its witness: version ‖ inputs and outputs ‖ lock time.
  const stripped = new Uint8Array(8 + (to - from));
  stripped.set(raw.subarray(0, 4), 0);
  stripped.set(raw.subarray(from, to), 4);
  stripped.set(raw.subarray(raw.length - 4), 4 + (to - from));
  if (stripped.length === 64) throw new AttestError("MALFORMED_PAYLOAD", "a 64-byte transaction can pass for a node of the Merkle tree");
  return { txid: await sha256d(stripped), script };
}

/**
 * Whether this is the first transaction of the block with this header, and names `height` (BIP34): its path reaches
 * the header's Merkle root, and its input script begins with the height. A problem in words, or null. Never throws.
 */
export async function checkDrawCoinbase(coinbase: DrawCoinbase | undefined, headerHex: string, height: number): Promise<string | null> {
  try {
    if (coinbase === undefined || coinbase === null) return "the draw block's height is not shown: the record carries no coinbase — that block's first transaction and its Merkle path, which name its height (BIP34)";
    const { tx, path } = coinbase;
    if (typeof tx !== "string" || tx.length > 2 * MAX_COINBASE_BYTES || !HEX_BYTES.test(tx) || !Array.isArray(path) || path.length > MAX_COINBASE_PATH || !path.every((p) => typeof p === "string" && HEX64.test(p))) {
      return "the coinbase is not a transaction in hex and a path of 32-byte hashes";
    }
    if (!HEADER.test(headerHex)) return "the draw block's header is not 80 bytes";
    let read: { readonly txid: Uint8Array; readonly script: Uint8Array };
    try {
      read = await readCoinbase(hexToBytes(tx));
    } catch (e) {
      return `the draw block's first transaction cannot be read: ${plain(e)}`;
    }
    let node = read.txid;
    for (const p of path) node = await sha256d(concat(node, hexToBytes(p)));
    if (bytesToHex(node) !== headerHex.slice(72, 136)) return "the coinbase's path does not reach the draw block's Merkle root — it is not that block's first transaction";
    const want = heightPush(height);
    if (read.script.length < want.length || want.some((x, k) => read.script[k] !== x)) {
      const named = heightNamed(read.script);
      return `the draw block's first transaction names ${named === null ? "no height" : `height ${named}`}, not ${height}: these headers do not end at the block the seal named`;
    }
    return null;
  } catch (e) {
    return `the coinbase cannot be checked: ${plain(e)}`;
  }
}

export interface DrawBlocksInput {
  /** The OpenTimestamps proof over the seal's digest, as base64. */
  readonly stamp: string;
  readonly sealDigest: string;
  /** The headers, from the block the stamp reached up to the draw block, as hex. */
  readonly blocks: readonly string[];
  /** The draw block's first transaction and its Merkle path, which name its height (BIP34). Absent, the draw does not stand. */
  readonly coinbase?: DrawCoinbase;
  /** The height the seal named. */
  readonly drawHeight: number;
  /** Tests only: a lower floor for headers they mine themselves. Reported when used. */
  readonly minWorkBits?: number;
}

export interface DrawBlocksCheck {
  readonly ok: boolean;
  readonly problems: readonly string[];
  /** The draw block's hash, as Bitcoin displays it — the seed's second half — when the headers stand. */
  readonly drawBlockHash: string | null;
  /** The height the stamp reached. */
  readonly stampHeight: number | null;
  readonly minWorkBits: number;
}

/** The checks a stranger runs on a sampled batch's draw blocks. Never throws. */
export async function checkDrawBlocks(i: DrawBlocksInput): Promise<DrawBlocksCheck> {
  const minWorkBits = i.minWorkBits ?? SEED_MIN_WORK_BITS;
  const problems: string[] = [];
  const done = (drawBlockHash: string | null, stampHeight: number | null): DrawBlocksCheck => ({ ok: problems.length === 0, problems, drawBlockHash, stampHeight, minWorkBits });
  const blocks = i.blocks;
  if (!Array.isArray(blocks) || blocks.length < 2 || blocks.length > MAX_DRAW_GAP + 1 || !blocks.every((b) => typeof b === "string" && HEADER.test(b))) {
    problems.push(`the draw needs from 2 to ${MAX_DRAW_GAP + 1} block headers, each 160 hex characters, from the stamp's block to the draw block`);
    return done(null, null);
  }
  if (!Number.isSafeInteger(i.drawHeight) || i.drawHeight < blocks.length) {
    problems.push("the draw height is not one these headers can reach");
    return done(null, null);
  }
  const stampHeight = i.drawHeight - (blocks.length - 1);

  // Each header stands on its own work, and names the one before by its hash.
  const checked: { hashHex: string; merkleRoot: Uint8Array }[] = [];
  for (let k = 0; k < blocks.length; k++) {
    try {
      const h = await checkBitcoinHeader(blocks[k]!, minWorkBits);
      checked.push({ hashHex: h.hashHex, merkleRoot: h.merkleRoot });
    } catch (e) {
      problems.push(`block ${stampHeight + k}: ${plain(e)}`);
      return done(null, stampHeight);
    }
    if (k > 0) {
      const prev = hexToBytes(blocks[k]!).slice(4, 36);
      if (bytesToHex(prev) !== bytesToHex(hexToBytes(checked[k - 1]!.hashHex).reverse())) {
        problems.push(`block ${stampHeight + k} does not name block ${stampHeight + k - 1} as the one before it`);
        return done(null, stampHeight);
      }
    }
  }

  // The draw block names its own height, in its first transaction (BIP34): a header carries none, and the stamp's
  // attestation names one in a number nothing signs (PY-5r). Only this ties the last header to the seal's height.
  const named = await checkDrawCoinbase(i.coinbase, blocks[blocks.length - 1]!, i.drawHeight);
  if (named !== null) problems.push(named);

  // The stamp: over the seal's digest, with a Bitcoin attestation at the first header's height reaching its Merkle root.
  let reached = false;
  try {
    const file = await parseOts(base64ToBytes(i.stamp));
    if (file.hashOp !== "sha256" || bytesToHex(file.digest) !== i.sealDigest) problems.push("the stamp is not over this seal's digest");
    else {
      const root = bytesToHex(checked[0]!.merkleRoot);
      reached = otsLeaves(file.timestamp).some((l) => l.unsupportedOp === null && l.attestation.kind === "bitcoin" && l.attestation.height === stampHeight && bytesToHex(l.msg) === root);
      if (!reached) problems.push(`the stamp has no Bitcoin attestation at block ${stampHeight} reaching that header's Merkle root — the seal is not shown to exist before block ${i.drawHeight}`);
    }
  } catch (e) {
    problems.push(`the stamp cannot be read: ${plain(e)}`);
  }
  return done(checked[checked.length - 1]!.hashHex, stampHeight);
}

/** An error's words, without attest's code prefix. */
const plain = (e: unknown): string => (e instanceof Error ? e.message : String(e)).replace(/^\[[A-Z_]+\]\s*/, "");

/* ── for the maker: a public block source (Esplora's API), `fetch` injected ── */

export type FetchText = (url: string) => Promise<{ ok: boolean; status: number; text(): Promise<string> }>;

/** Two independent Esplora hosts; a maker may pass its own. */
export const DEFAULT_BLOCK_SOURCES: readonly string[] = ["https://mempool.space/api", "https://blockstream.info/api"];

async function getText(fetch: FetchText, url: string): Promise<string> {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
  return (await res.text()).trim();
}

/** The chain's tip height, from a public block source. */
export async function fetchBitcoinTip(opts: { readonly fetch: FetchText; readonly source?: string }): Promise<number> {
  const base = (opts.source ?? DEFAULT_BLOCK_SOURCES[0]!).replace(/\/+$/, "");
  const height = Number(await getText(opts.fetch, `${base}/blocks/tip/height`));
  if (!Number.isSafeInteger(height) || height < 1) throw new Error(`${base}: not a block height`);
  return height;
}

/** The headers from `from` to `to`, inclusive, as hex, from a public block source. Checked by `checkDrawBlocks`, never trusted. */
export async function fetchBitcoinHeaders(from: number, to: number, opts: { readonly fetch: FetchText; readonly source?: string }): Promise<string[]> {
  if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || from < 0 || to < from || to - from > MAX_DRAW_GAP) throw new Error(`from 1 to ${MAX_DRAW_GAP + 1} headers, in order`);
  const base = (opts.source ?? DEFAULT_BLOCK_SOURCES[0]!).replace(/\/+$/, "");
  const out: string[] = [];
  for (let h = from; h <= to; h++) {
    const hash = await getText(opts.fetch, `${base}/block-height/${h}`);
    if (!/^[0-9a-f]{64}$/.test(hash)) throw new Error(`${base}: block ${h} has no hash yet`);
    const header = await getText(opts.fetch, `${base}/block/${hash}/header`);
    if (!HEADER.test(header)) throw new Error(`${base}: block ${h}'s header is not 80 bytes`);
    out.push(header);
  }
  return out;
}

/**
 * The first transaction of the block with this hash (as Bitcoin displays it) and its Merkle path, from a public block
 * source: the block's transaction ids, then the first one's bytes. The path is worked out here from the ids, in the
 * hashing's byte order. Checked by `checkDrawBlocks`, never trusted.
 */
export async function fetchDrawCoinbase(blockHash: string, opts: { readonly fetch: FetchText; readonly source?: string }): Promise<DrawCoinbase> {
  if (!HEX64.test(blockHash)) throw new Error("a block hash is 64 lowercase hex characters");
  const base = (opts.source ?? DEFAULT_BLOCK_SOURCES[0]!).replace(/\/+$/, "");
  const ids = JSON.parse(await getText(opts.fetch, `${base}/block/${blockHash}/txids`)) as unknown;
  if (!Array.isArray(ids) || ids.length === 0 || !ids.every((t): t is string => typeof t === "string" && HEX64.test(t))) throw new Error(`${base}: block ${blockHash} lists no transaction ids`);
  const tx = (await getText(opts.fetch, `${base}/tx/${ids[0]}/hex`)).toLowerCase();
  if (tx.length > 2 * MAX_COINBASE_BYTES || !HEX_BYTES.test(tx)) throw new Error(`${base}: block ${blockHash}'s first transaction is not hex, or is longer than ${MAX_COINBASE_BYTES} bytes`);
  // Position 0's path: at each level its sibling is the second node; a level of odd length pairs its last node with itself.
  let level = (ids as string[]).map((t) => hexToBytes(t).reverse());
  const path: string[] = [];
  while (level.length > 1) {
    path.push(bytesToHex(level[1]!));
    const next: Uint8Array[] = [];
    for (let k = 0; k < level.length; k += 2) next.push(await sha256d(concat(level[k]!, level[k + 1] ?? level[k]!)));
    level = next;
  }
  return { tx, path };
}
