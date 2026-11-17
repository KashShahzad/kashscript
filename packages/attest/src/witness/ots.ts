/**
 * OpenTimestamps, read and written offline (KS-Q4; ECOSYSTEM d5, d89(a);
 * `anchors/anchor.py` in A-List does the same in Python for the decision log).
 *
 * A detached `.ots` proof is a tree of operations from a digest to one or more
 * attestations: `pending` (a calendar's URI, before the calendar committed it to
 * Bitcoin) or `bitcoin` (a block height; the operations lead from the digest to
 * that block's Merkle root). This file is the standard format, byte for byte —
 * the same `ots` tooling reads what it writes — and it never contacts a
 * calendar unless given a `fetch`.
 *
 * What verifying offline can and cannot do: the operations are recomputed from
 * the digest; a Bitcoin attestation is **final** only against a block header
 * the checker supplies (80 bytes; its proof-of-work checked, its Merkle root
 * compared); without one it is **unchecked**, with the height named. A pending
 * attestation is **pending**. An operation this file does not implement
 * (keccak256) leaves its branch **unchecked**, never invalid.
 */

import { bytesToHex, hexToBytes } from "../chain";
import { AttestError } from "../errors";
import { ripemd160 } from "./ripemd160";
import type { WitnessVerdict } from "./verdict";

/* ── the format ────────────────────────────────────────────────────────── */

const enc = new TextEncoder();
const dec = new TextDecoder();

export const OTS_MAGIC: Uint8Array = Uint8Array.from([0x00, ...enc.encode("OpenTimestamps"), 0x00, 0x00, ...enc.encode("Proof"), 0x00, 0xbf, 0x89, 0xe2, 0xe8, 0x84, 0xe8, 0x92, 0x94]);
export const OTS_MAJOR_VERSION = 1;

const TAG_SHA1 = 0x02;
const TAG_RIPEMD160 = 0x03;
const TAG_SHA256 = 0x08;
const TAG_KECCAK256 = 0x67;
const TAG_APPEND = 0xf0;
const TAG_PREPEND = 0xf1;
const TAG_REVERSE = 0xf2;
const TAG_HEXLIFY = 0xf3;

const ATTESTATION_TAG_PENDING = "83dfe30d2ef90c8e";
const ATTESTATION_TAG_BITCOIN = "0588960d73d71901";
const ATTESTATION_TAG_LITECOIN = "06869a0d73d71b45";
const ATTESTATION_TAG_ETHEREUM = "30fe8087b5c7ead7";

const MAX_MSG_LENGTH = 4096;
const MAX_ATTESTATION_PAYLOAD = 8192;
const MAX_URI_LENGTH = 1000;
const MAX_DEPTH = 256;

export type OtsOp =
  | { readonly op: "sha1" }
  | { readonly op: "ripemd160" }
  | { readonly op: "sha256" }
  | { readonly op: "keccak256" }
  | { readonly op: "reverse" }
  | { readonly op: "hexlify" }
  | { readonly op: "append"; readonly arg: Uint8Array }
  | { readonly op: "prepend"; readonly arg: Uint8Array };

export type OtsAttestation =
  | { readonly kind: "pending"; readonly uri: string }
  | { readonly kind: "bitcoin"; readonly height: number }
  | { readonly kind: "litecoin"; readonly height: number }
  | { readonly kind: "ethereum"; readonly payload: Uint8Array }
  | { readonly kind: "unknown"; readonly tagHex: string; readonly payload: Uint8Array };

/** A node of the proof: the attestations over this node's message, and the operations leading on from it. */
export interface OtsTimestamp {
  readonly msg: Uint8Array;
  readonly attestations: OtsAttestation[];
  readonly ops: { readonly op: OtsOp; readonly next: OtsTimestamp }[];
}

export interface OtsFile {
  /** The file digest's algorithm — SHA-256 for everything this ecosystem stamps. */
  readonly hashOp: "sha256" | "sha1" | "ripemd160" | "keccak256";
  readonly digest: Uint8Array;
  readonly timestamp: OtsTimestamp;
}

/* ── bytes in, bytes out ───────────────────────────────────────────────── */

class Writer {
  private parts: number[] = [];
  byte(b: number): void {
    this.parts.push(b & 0xff);
  }
  bytes(b: Uint8Array): void {
    for (let i = 0; i < b.length; i++) this.parts.push(b[i]!);
  }
  varuint(value: number): void {
    if (!Number.isSafeInteger(value) || value < 0) throw new AttestError("INVALID_INPUT", "a varuint is a non-negative integer");
    if (value === 0) {
      this.byte(0);
      return;
    }
    let v = value;
    while (v !== 0) {
      let b = v % 128;
      if (v > 127) b |= 0x80;
      this.byte(b);
      if (v <= 127) break;
      v = Math.floor(v / 128);
    }
  }
  varbytes(b: Uint8Array): void {
    this.varuint(b.length);
    this.bytes(b);
  }
  out(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

class Reader {
  private pos = 0;
  constructor(private readonly buf: Uint8Array) {}
  get offset(): number {
    return this.pos;
  }
  eof(): boolean {
    return this.pos >= this.buf.length;
  }
  byte(): number {
    if (this.pos >= this.buf.length) throw new AttestError("MALFORMED_PAYLOAD", "the proof ends early");
    return this.buf[this.pos++]!;
  }
  bytes(n: number): Uint8Array {
    if (this.pos + n > this.buf.length) throw new AttestError("MALFORMED_PAYLOAD", "the proof ends early");
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  varuint(): number {
    let value = 0;
    let shift = 1;
    for (;;) {
      const b = this.byte();
      value += (b & 0x7f) * shift;
      if ((b & 0x80) === 0) break;
      shift *= 128;
      if (shift > 2 ** 56) throw new AttestError("MALFORMED_PAYLOAD", "a varuint is too long");
    }
    if (!Number.isSafeInteger(value)) throw new AttestError("MALFORMED_PAYLOAD", "a varuint is too large");
    return value;
  }
  varbytes(max: number): Uint8Array {
    const n = this.varuint();
    if (n > max) throw new AttestError("MALFORMED_PAYLOAD", `a length of ${n} exceeds ${max}`);
    return this.bytes(n);
  }
}

function opTag(op: OtsOp): number {
  switch (op.op) {
    case "sha1": return TAG_SHA1;
    case "ripemd160": return TAG_RIPEMD160;
    case "sha256": return TAG_SHA256;
    case "keccak256": return TAG_KECCAK256;
    case "reverse": return TAG_REVERSE;
    case "hexlify": return TAG_HEXLIFY;
    case "append": return TAG_APPEND;
    case "prepend": return TAG_PREPEND;
  }
}

function opFromTag(tag: number, r: Reader): OtsOp {
  switch (tag) {
    case TAG_SHA1: return { op: "sha1" };
    case TAG_RIPEMD160: return { op: "ripemd160" };
    case TAG_SHA256: return { op: "sha256" };
    case TAG_KECCAK256: return { op: "keccak256" };
    case TAG_REVERSE: return { op: "reverse" };
    case TAG_HEXLIFY: return { op: "hexlify" };
    case TAG_APPEND: return { op: "append", arg: r.varbytes(MAX_MSG_LENGTH) };
    case TAG_PREPEND: return { op: "prepend", arg: r.varbytes(MAX_MSG_LENGTH) };
    default: throw new AttestError("MALFORMED_PAYLOAD", `unknown operation tag 0x${tag.toString(16)}`);
  }
}

const opArg = (op: OtsOp): Uint8Array => (op.op === "append" || op.op === "prepend" ? op.arg : new Uint8Array(0));

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
  return a.length - b.length;
}
/** The reference client's order: by tag, then by argument. */
const compareOps = (a: OtsOp, b: OtsOp): number => opTag(a) - opTag(b) || compareBytes(opArg(a), opArg(b));

function attestationTag(a: OtsAttestation): string {
  switch (a.kind) {
    case "pending": return ATTESTATION_TAG_PENDING;
    case "bitcoin": return ATTESTATION_TAG_BITCOIN;
    case "litecoin": return ATTESTATION_TAG_LITECOIN;
    case "ethereum": return ATTESTATION_TAG_ETHEREUM;
    case "unknown": return a.tagHex;
  }
}
function attestationPayload(a: OtsAttestation): Uint8Array {
  const w = new Writer();
  switch (a.kind) {
    case "pending": w.varbytes(enc.encode(a.uri)); break;
    case "bitcoin":
    case "litecoin": w.varuint(a.height); break;
    case "ethereum":
    case "unknown": w.bytes(a.payload); break;
  }
  return w.out();
}
/** The reference client's order: by tag bytes, then by the attestation's own order (uri, height, payload). */
function compareAttestations(a: OtsAttestation, b: OtsAttestation): number {
  const byTag = compareBytes(hexToBytes(attestationTag(a)), hexToBytes(attestationTag(b)));
  if (byTag !== 0) return byTag;
  if (a.kind === "pending" && b.kind === "pending") return compareBytes(enc.encode(a.uri), enc.encode(b.uri));
  if ((a.kind === "bitcoin" || a.kind === "litecoin") && (b.kind === "bitcoin" || b.kind === "litecoin")) return a.height - b.height;
  return compareBytes(attestationPayload(a), attestationPayload(b));
}

function writeAttestation(w: Writer, a: OtsAttestation): void {
  w.bytes(hexToBytes(attestationTag(a)));
  w.varbytes(attestationPayload(a));
}

function readAttestation(r: Reader): OtsAttestation {
  const tagHex = bytesToHex(r.bytes(8));
  const payload = r.varbytes(MAX_ATTESTATION_PAYLOAD);
  const p = new Reader(payload);
  if (tagHex === ATTESTATION_TAG_PENDING) {
    const uri = dec.decode(p.varbytes(MAX_URI_LENGTH));
    if (!p.eof()) throw new AttestError("MALFORMED_PAYLOAD", "a pending attestation carries only its URI");
    if (!/^[A-Za-z0-9._/:-]+$/.test(uri)) throw new AttestError("MALFORMED_PAYLOAD", "a calendar URI holds only letters, digits and ._/:-");
    return { kind: "pending", uri };
  }
  if (tagHex === ATTESTATION_TAG_BITCOIN || tagHex === ATTESTATION_TAG_LITECOIN) {
    const height = p.varuint();
    if (!p.eof()) throw new AttestError("MALFORMED_PAYLOAD", "a block attestation carries only its height");
    return { kind: tagHex === ATTESTATION_TAG_BITCOIN ? "bitcoin" : "litecoin", height };
  }
  if (tagHex === ATTESTATION_TAG_ETHEREUM) return { kind: "ethereum", payload };
  return { kind: "unknown", tagHex, payload };
}

function writeTimestamp(w: Writer, t: OtsTimestamp): void {
  if (t.attestations.length === 0 && t.ops.length === 0) throw new AttestError("INVALID_INPUT", "an empty timestamp cannot be written");
  const atts = [...t.attestations].sort(compareAttestations);
  for (const a of atts.slice(0, -1)) {
    w.byte(0xff);
    w.byte(0x00);
    writeAttestation(w, a);
  }
  if (t.ops.length === 0) {
    w.byte(0x00);
    writeAttestation(w, atts[atts.length - 1]!);
    return;
  }
  if (atts.length > 0) {
    w.byte(0xff);
    w.byte(0x00);
    writeAttestation(w, atts[atts.length - 1]!);
  }
  const ops = [...t.ops].sort((a, b) => compareOps(a.op, b.op));
  for (const { op, next } of ops.slice(0, -1)) {
    w.byte(0xff);
    writeOp(w, op);
    writeTimestamp(w, next);
  }
  const last = ops[ops.length - 1]!;
  writeOp(w, last.op);
  writeTimestamp(w, last.next);
}

function writeOp(w: Writer, op: OtsOp): void {
  w.byte(opTag(op));
  if (op.op === "append" || op.op === "prepend") w.varbytes(op.arg);
}

/** Apply one operation. Null for an operation this file does not implement. */
export async function applyOtsOp(op: OtsOp, msg: Uint8Array): Promise<Uint8Array | null> {
  switch (op.op) {
    case "sha256": return new Uint8Array(await crypto.subtle.digest("SHA-256", msg as unknown as BufferSource));
    case "sha1": return new Uint8Array(await crypto.subtle.digest("SHA-1", msg as unknown as BufferSource));
    case "ripemd160": return ripemd160(msg);
    case "keccak256": return null;
    case "reverse": return msg.slice().reverse();
    case "hexlify": return enc.encode(bytesToHex(msg));
    case "append": return concat(msg, op.arg);
    case "prepend": return concat(op.arg, msg);
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  if (out.length > MAX_MSG_LENGTH) throw new AttestError("MALFORMED_PAYLOAD", "a message grew past the format's limit");
  return out;
}

async function readTimestamp(r: Reader, msg: Uint8Array, depth: number): Promise<OtsTimestamp> {
  if (depth > MAX_DEPTH) throw new AttestError("MALFORMED_PAYLOAD", "the proof is nested too deep");
  const t: OtsTimestamp = { msg, attestations: [], ops: [] };
  const tagOrAttestation = async (tag: number): Promise<void> => {
    if (tag === 0x00) {
      t.attestations.push(readAttestation(r));
      return;
    }
    const op = opFromTag(tag, r);
    // An unimplemented operation still has to be read past: its branch is kept with a sentinel message.
    const result = (await applyOtsOp(op, msg)) ?? new Uint8Array(0);
    t.ops.push({ op, next: await readTimestamp(r, result, depth + 1) });
  };
  let tag = r.byte();
  while (tag === 0xff) {
    await tagOrAttestation(r.byte());
    tag = r.byte();
  }
  await tagOrAttestation(tag);
  return t;
}

/** Write a detached proof in the standard format. */
export function serializeOts(file: OtsFile): Uint8Array {
  const w = new Writer();
  w.bytes(OTS_MAGIC);
  w.varuint(OTS_MAJOR_VERSION);
  w.byte(opTag({ op: file.hashOp }));
  w.bytes(file.digest);
  writeTimestamp(w, file.timestamp);
  return w.out();
}

/** Read a detached proof. Throws `AttestError` for anything that is not one. */
export async function parseOts(bytes: Uint8Array): Promise<OtsFile> {
  const r = new Reader(bytes);
  if (compareBytes(r.bytes(OTS_MAGIC.length), OTS_MAGIC) !== 0) throw new AttestError("MALFORMED_PAYLOAD", "not an OpenTimestamps proof (bad magic)");
  const version = r.varuint();
  if (version !== OTS_MAJOR_VERSION) throw new AttestError("MALFORMED_PAYLOAD", `OpenTimestamps major version ${version} is not read here`);
  const tag = r.byte();
  const hashOp = tag === TAG_SHA256 ? "sha256" : tag === TAG_SHA1 ? "sha1" : tag === TAG_RIPEMD160 ? "ripemd160" : tag === TAG_KECCAK256 ? "keccak256" : null;
  if (hashOp === null) throw new AttestError("MALFORMED_PAYLOAD", "the file hash operation is not a hash");
  const digest = r.bytes(hashOp === "sha256" || hashOp === "keccak256" ? 32 : 20);
  const timestamp = await readTimestamp(r, digest, 0);
  if (!r.eof()) throw new AttestError("MALFORMED_PAYLOAD", "trailing bytes after the proof");
  return { hashOp, digest, timestamp };
}

/** Read a bare timestamp (what a calendar answers), starting from `msg`. */
export async function parseOtsTimestamp(bytes: Uint8Array, msg: Uint8Array): Promise<OtsTimestamp> {
  const r = new Reader(bytes);
  const t = await readTimestamp(r, msg, 0);
  if (!r.eof()) throw new AttestError("MALFORMED_PAYLOAD", "trailing bytes after the timestamp");
  return t;
}

/** Merge `other` into `into` (the same message): attestations united, operations shared. */
export function mergeOtsTimestamps(into: OtsTimestamp, other: OtsTimestamp): void {
  if (compareBytes(into.msg, other.msg) !== 0) throw new AttestError("INVALID_INPUT", "timestamps over different messages cannot be merged");
  for (const a of other.attestations) {
    if (!into.attestations.some((b) => compareAttestations(a, b) === 0)) into.attestations.push(a);
  }
  for (const { op, next } of other.ops) {
    const mine = into.ops.find((o) => compareOps(o.op, op) === 0);
    if (mine === undefined) into.ops.push({ op, next });
    else mergeOtsTimestamps(mine.next, next);
  }
}

/* ── walking a proof ───────────────────────────────────────────────────── */

export interface OtsLeaf {
  readonly attestation: OtsAttestation;
  /** The message the attestation is over — for Bitcoin, the block's Merkle root the operations reach. */
  readonly msg: Uint8Array;
  /** An operation on the way this file could not compute; the message is then not known. */
  readonly unsupportedOp: OtsOp["op"] | null;
}

/** Every attestation in the proof, with the message it is over. */
export function otsLeaves(t: OtsTimestamp, unsupported: OtsOp["op"] | null = null): OtsLeaf[] {
  const out: OtsLeaf[] = [];
  for (const a of t.attestations) out.push({ attestation: a, msg: t.msg, unsupportedOp: unsupported });
  for (const { op, next } of t.ops) out.push(...otsLeaves(next, unsupported ?? (op.op === "keccak256" ? "keccak256" : null)));
  return out;
}

/* ── Bitcoin headers ───────────────────────────────────────────────────── */

export interface BitcoinHeader {
  readonly height: number;
  /** The 80 header bytes, hex. */
  readonly headerHex: string;
}

/** Headers claiming less work than this could be mined cheaply by a forger (the decision log's anchors use the same floor). */
export const MIN_BLOCK_WORK_BITS = 64;

export interface CheckedBitcoinHeader {
  readonly hashHex: string;
  readonly merkleRoot: Uint8Array;
  readonly timeUnix: number;
}

async function sha256d(bytes: Uint8Array): Promise<Uint8Array> {
  const once = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", once));
}

/** Proof-of-work and field extraction for an 80-byte block header. Throws when the header does not stand on its own. */
export async function checkBitcoinHeader(headerHex: string, minWorkBits: number = MIN_BLOCK_WORK_BITS): Promise<CheckedBitcoinHeader> {
  if (typeof headerHex !== "string" || !/^[0-9a-f]{160}$/.test(headerHex)) throw new AttestError("INVALID_INPUT", "a block header is 80 bytes, as 160 lowercase hex characters");
  const raw = hexToBytes(headerHex);
  const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
  const bits = view.getUint32(72, true);
  const exp = bits >>> 24;
  const mant = bits & 0x7fffff;
  if ((bits & 0x800000) !== 0 || mant === 0) throw new AttestError("INVALID_INPUT", "invalid difficulty field");
  const target = exp >= 3 ? BigInt(mant) << BigInt(8 * (exp - 3)) : BigInt(mant) >> BigInt(8 * (3 - exp));
  // Judge the work the header CLAIMS (its target), not its hash, which can be lucky.
  if (target >= 1n << BigInt(256 - minWorkBits)) throw new AttestError("INVALID_INPUT", `the header claims less than ${minWorkBits} bits of work — a forger could mine it cheaply`);
  const hash = await sha256d(raw);
  const asNumber = BigInt("0x" + bytesToHex(hash.slice().reverse()));
  if (asNumber > target) throw new AttestError("INVALID_INPUT", "the header does not meet its own proof-of-work target");
  return { hashHex: bytesToHex(hash.slice().reverse()), merkleRoot: raw.slice(36, 68), timeUnix: view.getUint32(68, true) };
}

/* ── the verdict ───────────────────────────────────────────────────────── */

/**
 * Verify a proof over `digestHex` offline. `final` needs a supplied, valid block
 * header whose Merkle root the operations reach; `pending` means the calendars
 * only; `unchecked` names the block whose header was not supplied, or the
 * operation this file cannot compute. Never throws.
 */
export async function verifyOpenTimestamps(bytes: Uint8Array, digestHex: string, opts: { readonly headers?: readonly BitcoinHeader[] } = {}): Promise<WitnessVerdict> {
  const verdict = (state: WitnessVerdict["state"], digestOk: boolean, by: string, detail: string, timeUnix: number | null = null): WitnessVerdict => ({
    kind: "opentimestamps",
    state,
    timeUnix,
    digestOk,
    by,
    detail,
  });
  let file: OtsFile;
  try {
    file = await parseOts(bytes);
  } catch (e) {
    return verdict("invalid", false, "nobody", `cannot read the proof: ${e instanceof Error ? e.message : String(e)}`);
  }
  if (file.hashOp !== "sha256") return verdict("invalid", false, "nobody", "the proof is not over a SHA-256 digest");
  if (bytesToHex(file.digest) !== digestHex) return verdict("invalid", false, "nobody", `the proof is over ${bytesToHex(file.digest).slice(0, 16)}…, not ${digestHex.slice(0, 16)}…`);

  const leaves = otsLeaves(file.timestamp);
  const pending: string[] = [];
  const waiting: number[] = [];
  const good: { timeUnix: number; height: number }[] = [];
  const problems: string[] = [];
  let unsupported: string | null = null;
  for (const leaf of leaves) {
    const a = leaf.attestation;
    if (leaf.unsupportedOp !== null) {
      unsupported = leaf.unsupportedOp;
      continue;
    }
    if (a.kind === "pending") {
      pending.push(a.uri.replace(/^https?:\/\//, ""));
      continue;
    }
    if (a.kind !== "bitcoin") continue; // other chains are not witnesses here (d89: Bitcoin through OpenTimestamps)
    const header = (opts.headers ?? []).find((h) => h.height === a.height);
    if (header === undefined) {
      waiting.push(a.height);
      continue;
    }
    try {
      const checked = await checkBitcoinHeader(header.headerHex);
      if (leaf.msg.length !== 32 || compareBytes(leaf.msg, checked.merkleRoot) !== 0) {
        problems.push(`block ${a.height}: the operations do not reach the header's Merkle root`);
        continue;
      }
      good.push({ timeUnix: checked.timeUnix, height: a.height });
    } catch (e) {
      problems.push(`block ${a.height}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  if (good.length > 0) {
    const best = good.reduce((x, y) => (y.timeUnix < x.timeUnix ? y : x));
    const note = problems.length > 0 ? ` (also failed: ${problems.join("; ")})` : "";
    return verdict("final", true, `Bitcoin block ${best.height}`, `the operations reach block ${best.height}'s Merkle root; the block's time is ${new Date(best.timeUnix * 1000).toISOString()} — a block's time can be off by up to about two hours${note}`, best.timeUnix);
  }
  if (problems.length > 0) return verdict("invalid", true, "nobody", problems.join("; "));
  if (waiting.length > 0) return verdict("unchecked", true, `Bitcoin block ${Math.min(...waiting)}`, `attested in Bitcoin block ${Math.min(...waiting)}, whose header was not supplied — give the checker the 80-byte header to finish`);
  if (unsupported !== null) return verdict("unchecked", true, "nobody", `the proof uses an operation this checker does not compute (${unsupported})`);
  if (pending.length > 0) return verdict("pending", true, `calendars ${[...new Set(pending)].sort().join(", ")}`, "waiting for a Bitcoin confirmation; upgrade the proof once a block has it");
  return verdict("invalid", true, "nobody", "the proof carries no attestation");
}

/* ── the calendars (the only networked functions here; `fetch` is injected) ── */

/** The reference client's defaults: aggregators run by independent operators. */
export const DEFAULT_OTS_CALENDARS: readonly string[] = [
  "https://a.pool.opentimestamps.org",
  "https://b.pool.opentimestamps.org",
  "https://a.pool.eternitywall.com",
  "https://ots.btc.catallaxy.com",
];
/** The calendars a proof may be upgraded from. */
export const KNOWN_OTS_CALENDARS: readonly string[] = [
  "https://alice.btc.calendar.opentimestamps.org",
  "https://bob.btc.calendar.opentimestamps.org",
  "https://finney.calendar.eternitywall.com",
  "https://btc.calendar.catallaxy.com",
];
export const DEFAULT_MIN_OTS_CALENDARS = 2;

export type FetchBytes = (url: string, init: { method: "GET" | "POST"; body?: Uint8Array; headers: Record<string, string> }) => Promise<{ ok: boolean; status: number; bytes(): Promise<Uint8Array> }>;

export interface StampOpenTimestampsOptions {
  readonly fetch: FetchBytes;
  readonly calendars?: readonly string[];
  readonly minCalendars?: number;
  /** 16 bytes; random when omitted. Tests pass one so the file is reproducible. */
  readonly nonce?: Uint8Array;
}

export interface StampedOpenTimestamps {
  readonly ots: Uint8Array;
  readonly file: OtsFile;
  readonly accepted: readonly string[];
  readonly problems: readonly string[];
}

/**
 * Commit a SHA-256 digest to the calendars, as `ots stamp` does: a random nonce
 * appended so the calendars learn nothing about neighbouring digests, SHA-256 of
 * that, and the result submitted to each calendar. At least `minCalendars`
 * must accept. The calendars receive 32 bytes and nothing else (d27).
 */
export async function stampOpenTimestamps(digestHex: string, opts: StampOpenTimestampsOptions): Promise<StampedOpenTimestamps> {
  if (!/^[0-9a-f]{64}$/.test(digestHex)) throw new AttestError("INVALID_INPUT", "a digest is 64 lowercase hex characters");
  const digest = hexToBytes(digestHex);
  const nonce = opts.nonce ?? crypto.getRandomValues(new Uint8Array(16));
  if (nonce.length !== 16) throw new AttestError("INVALID_INPUT", "the nonce is 16 bytes");
  const appended: OtsTimestamp = { msg: concat(digest, nonce), attestations: [], ops: [] };
  const commitmentMsg = (await applyOtsOp({ op: "sha256" }, appended.msg))!;
  const commitment: OtsTimestamp = { msg: commitmentMsg, attestations: [], ops: [] };
  appended.ops.push({ op: { op: "sha256" }, next: commitment });
  const root: OtsTimestamp = { msg: digest, attestations: [], ops: [{ op: { op: "append", arg: nonce }, next: appended }] };

  const calendars = opts.calendars ?? DEFAULT_OTS_CALENDARS;
  const accepted: string[] = [];
  const problems: string[] = [];
  const results = await Promise.all(
    calendars.map(async (cal) => {
      const base = cal.replace(/\/+$/, "");
      try {
        const res = await opts.fetch(`${base}/digest`, { method: "POST", body: commitmentMsg, headers: { Accept: "application/vnd.opentimestamps.v1", "Content-Type": "application/x-www-form-urlencoded" } });
        if (!res.ok) return { base, error: `HTTP ${res.status}` };
        return { base, stamp: await parseOtsTimestamp(await res.bytes(), commitmentMsg) };
      } catch (e) {
        return { base, error: e instanceof Error ? e.message : String(e) };
      }
    }),
  );
  for (const r of results) {
    if ("stamp" in r && r.stamp !== undefined) {
      mergeOtsTimestamps(commitment, r.stamp);
      accepted.push(r.base);
    } else {
      problems.push(`${r.base}: ${"error" in r ? r.error : "no answer"}`);
    }
  }
  const min = opts.minCalendars ?? DEFAULT_MIN_OTS_CALENDARS;
  if (accepted.length < min) throw new AttestError("IO_ERROR", `only ${accepted.length} calendar(s) accepted the digest, need ${min}: ${problems.join("; ")}`);
  const file: OtsFile = { hashOp: "sha256", digest, timestamp: root };
  return { ots: serializeOts(file), file, accepted, problems };
}

export interface UpgradedOpenTimestamps {
  readonly ots: Uint8Array;
  readonly changed: boolean;
  readonly notes: readonly string[];
}

/** Ask the calendars a pending proof names for their Bitcoin attestation; keep the proof as it was when none has one yet. */
export async function upgradeOpenTimestamps(bytes: Uint8Array, opts: { readonly fetch: FetchBytes; readonly knownCalendars?: readonly string[] }): Promise<UpgradedOpenTimestamps> {
  const file = await parseOts(bytes);
  const known = opts.knownCalendars ?? KNOWN_OTS_CALENDARS;
  const notes: string[] = [];
  let changed = false;
  const walk = async (t: OtsTimestamp): Promise<void> => {
    for (const a of [...t.attestations]) {
      if (a.kind !== "pending") continue;
      const base = a.uri.replace(/\/+$/, "");
      if (!known.includes(base)) {
        notes.push(`skipped ${base} (not a known calendar)`);
        continue;
      }
      try {
        const res = await opts.fetch(`${base}/timestamp/${bytesToHex(t.msg)}`, { method: "GET", headers: { Accept: "application/vnd.opentimestamps.v1" } });
        if (!res.ok) {
          notes.push(`${base.replace(/^https?:\/\//, "")}: HTTP ${res.status}`);
          continue;
        }
        const got = await parseOtsTimestamp(await res.bytes(), t.msg);
        if (otsLeaves(got).some((l) => l.attestation.kind === "bitcoin")) {
          mergeOtsTimestamps(t, got);
          changed = true;
        } else {
          notes.push(`${base.replace(/^https?:\/\//, "")}: not in a block yet`);
        }
      } catch (e) {
        notes.push(`${base.replace(/^https?:\/\//, "")}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    for (const { next } of t.ops) await walk(next);
  };
  await walk(file.timestamp);
  return { ots: changed ? serializeOts(file) : bytes, changed, notes };
}
