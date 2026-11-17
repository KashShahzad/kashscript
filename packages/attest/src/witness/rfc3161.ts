/**
 * RFC 3161 — the second public witness, requested and read here, its signature
 * left to `openssl ts -verify` (KS-Q4; GOV-5's `anchors/anchor.py` does the
 * same for the decision log).
 *
 * What this file does: builds a `TimeStampReq` in DER (SHA-256, a nonce, the
 * certificate asked for), sends it when given a `fetch`, and reads a
 * `TimeStampResp` far enough to know whether it was granted and what it stamps
 * — the digest, the time, the serial, the nonce, the policy, the signing
 * certificates' fingerprints. **What it does not do, in this version:** verify
 * the CMS signature and its chain to a pinned root. That takes an X.509 path
 * validator, which `openssl` already is; the CLI runs it when asked. Until a
 * caller says the signature was checked, the verdict is `unchecked` — the time
 * is read, not relied on. Said in every report.
 */

import { bytesToHex, hexToBytes } from "../chain";
import { AttestError } from "../errors";
import type { WitnessVerdict } from "./verdict";

/* ── DER, just enough ──────────────────────────────────────────────────── */

function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return [0x80 | bytes.length, ...bytes];
}

function der(tag: number, content: Uint8Array): Uint8Array {
  return Uint8Array.from([tag, ...derLength(content.length), ...content]);
}
const concatBytes = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
};
const derSequence = (...parts: Uint8Array[]): Uint8Array => der(0x30, concatBytes(...parts));
const derNull = (): Uint8Array => Uint8Array.of(0x05, 0x00);
const derBoolean = (v: boolean): Uint8Array => Uint8Array.of(0x01, 0x01, v ? 0xff : 0x00);
const derOctetString = (b: Uint8Array): Uint8Array => der(0x04, b);

/** A positive INTEGER from unsigned big-endian bytes: leading zeros dropped, one kept when the top bit is set. */
function derUnsignedInteger(bytes: Uint8Array): Uint8Array {
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const body = bytes.slice(i);
  return der(0x02, body[0]! & 0x80 ? concatBytes(Uint8Array.of(0), body) : body);
}

function derOid(dotted: string): Uint8Array {
  const arcs = dotted.split(".").map((a) => Number(a));
  if (arcs.length < 2 || arcs.some((a) => !Number.isSafeInteger(a) || a < 0)) throw new AttestError("INVALID_INPUT", `not an OID: ${dotted}`);
  const out: number[] = [arcs[0]! * 40 + arcs[1]!];
  for (const arc of arcs.slice(2)) {
    const bytes: number[] = [];
    let v = arc;
    do {
      bytes.unshift(v % 128);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < bytes.length - 1; i++) bytes[i]! |= 0x80;
    out.push(...bytes);
  }
  return der(0x06, Uint8Array.from(out));
}

function oidToDotted(content: Uint8Array): string {
  if (content.length === 0) return "";
  const first = content[0]!;
  const arcs = [Math.floor(first / 40) > 2 ? 2 : Math.floor(first / 40), Math.floor(first / 40) > 2 ? first - 80 : first % 40];
  let v = 0;
  for (let i = 1; i < content.length; i++) {
    v = v * 128 + (content[i]! & 0x7f);
    if ((content[i]! & 0x80) === 0) {
      arcs.push(v);
      v = 0;
    }
  }
  return arcs.join(".");
}

export const OID_SHA256 = "2.16.840.1.101.3.4.2.1";
export const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";
export const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const OID_COMMON_NAME = "2.5.4.3";

interface Tlv {
  readonly tag: number;
  readonly start: number;
  readonly end: number;
  /** Offset of the tag byte, for taking the whole element. */
  readonly from: number;
}

function readTlv(b: Uint8Array, at: number): Tlv {
  if (at >= b.length) throw new AttestError("MALFORMED_TOKEN", "DER ends early");
  const tag = b[at]!;
  if ((tag & 0x1f) === 0x1f) throw new AttestError("MALFORMED_TOKEN", "multi-byte DER tags are not read here");
  let pos = at + 1;
  if (pos >= b.length) throw new AttestError("MALFORMED_TOKEN", "DER ends early");
  let length = b[pos++]!;
  if (length === 0x80) throw new AttestError("MALFORMED_TOKEN", "indefinite lengths are not DER");
  if (length & 0x80) {
    const n = length & 0x7f;
    if (n > 4 || pos + n > b.length) throw new AttestError("MALFORMED_TOKEN", "a DER length is malformed");
    length = 0;
    for (let i = 0; i < n; i++) length = length * 256 + b[pos++]!;
  }
  if (pos + length > b.length) throw new AttestError("MALFORMED_TOKEN", "a DER element runs past the end");
  return { tag, start: pos, end: pos + length, from: at };
}

function children(b: Uint8Array, t: Tlv): Tlv[] {
  const out: Tlv[] = [];
  let at = t.start;
  while (at < t.end) {
    const c = readTlv(b, at);
    out.push(c);
    at = c.end;
  }
  return out;
}

const content = (b: Uint8Array, t: Tlv): Uint8Array => b.slice(t.start, t.end);
const whole = (b: Uint8Array, t: Tlv): Uint8Array => b.slice(t.from, t.end);
const expect = (t: Tlv | undefined, tag: number, what: string): Tlv => {
  if (t === undefined || t.tag !== tag) throw new AttestError("MALFORMED_TOKEN", `${what}: expected tag 0x${tag.toString(16)}, found ${t === undefined ? "nothing" : "0x" + t.tag.toString(16)}`);
  return t;
};

function readInteger(b: Uint8Array, t: Tlv): { readonly hex: string; readonly small: number | null } {
  const bytes = content(b, t);
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0) i++;
  const body = bytes.slice(i);
  const hex = bytesToHex(body);
  return { hex, small: body.length <= 6 ? Number.parseInt(hex, 16) : null };
}

/** `YYYYMMDDHHMMSS[.fff]Z` → unix seconds. */
function readGeneralizedTime(text: string): number {
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.\d+)?Z$/.exec(text);
  if (m === null) throw new AttestError("MALFORMED_TOKEN", `genTime is not a UTC GeneralizedTime: ${text}`);
  const [, y, mo, d, h, mi, s] = m;
  return Math.floor(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), Number(s)) / 1000);
}

/* ── the request ───────────────────────────────────────────────────────── */

/** A `TimeStampReq` for a SHA-256 digest: version 1, the imprint, a nonce, and the certificate asked for. */
export function rfc3161Request(digestHex: string, nonceHex: string): Uint8Array {
  if (!/^[0-9a-f]{64}$/.test(digestHex)) throw new AttestError("INVALID_INPUT", "a digest is 64 lowercase hex characters");
  if (!/^[0-9a-f]{2,32}$/.test(nonceHex) || nonceHex.length % 2 !== 0) throw new AttestError("INVALID_INPUT", "a nonce is 1 to 16 bytes, hex");
  return derSequence(
    derUnsignedInteger(Uint8Array.of(1)),
    derSequence(derSequence(derOid(OID_SHA256), derNull()), derOctetString(hexToBytes(digestHex))),
    derUnsignedInteger(hexToBytes(nonceHex)),
    derBoolean(true),
  );
}

/** A fresh 8-byte nonce, hex. */
export function newRfc3161Nonce(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(8)));
}

/** An INTEGER's value as hex with no leading zero bytes — how a nonce is compared, whatever padding either side wrote. */
function integerHex(h: string): string {
  let s = h.toLowerCase();
  if (s.length % 2 === 1) s = `0${s}`;
  while (s.length > 2 && s.startsWith("00")) s = s.slice(2);
  return s;
}

/* ── the response ──────────────────────────────────────────────────────── */

export interface Rfc3161Token {
  /** PKIStatus: 0 granted, 1 granted with modifications, 2 rejection, 3 waiting, 4 revocation warning, 5 revocation notification. */
  readonly status: number;
  readonly granted: boolean;
  readonly statusText: string | null;
  readonly policy: string | null;
  readonly hashAlgorithm: string;
  readonly digestHex: string;
  readonly serialHex: string;
  readonly genTimeUnix: number;
  readonly genTime: string;
  readonly nonceHex: string | null;
  readonly tsaName: string | null;
  /** SHA-256 fingerprints of the certificates the token carries, hex — the signer's first, usually. */
  readonly certificateFingerprints: readonly string[];
  readonly signerInfos: number;
}

function readName(b: Uint8Array, name: Tlv): string | null {
  // Name ::= SEQUENCE OF SET OF SEQUENCE { OID, value }
  for (const rdn of children(b, name)) {
    for (const atv of children(b, rdn)) {
      const parts = children(b, atv);
      if (parts.length === 2 && parts[0]!.tag === 0x06 && oidToDotted(content(b, parts[0]!)) === OID_COMMON_NAME) {
        return new TextDecoder().decode(content(b, parts[1]!));
      }
    }
  }
  return null;
}

/** Read a `TimeStampResp`. Throws `AttestError("MALFORMED_TOKEN")` for anything that is not one. Verifies no signature. */
export async function readRfc3161Token(tsr: Uint8Array): Promise<Rfc3161Token> {
  const resp = expect(readTlv(tsr, 0), 0x30, "TimeStampResp");
  if (resp.end !== tsr.length) throw new AttestError("MALFORMED_TOKEN", "trailing bytes after the response");
  const [statusInfo, contentInfo] = children(tsr, resp);
  const statusParts = children(tsr, expect(statusInfo, 0x30, "PKIStatusInfo"));
  const status = readInteger(tsr, expect(statusParts[0], 0x02, "PKIStatus")).small ?? -1;
  let statusText: string | null = null;
  const freeText = statusParts.find((p) => p.tag === 0x30);
  if (freeText !== undefined) {
    const strings = children(tsr, freeText).map((s) => new TextDecoder().decode(content(tsr, s)));
    statusText = strings.length > 0 ? strings.join(" ") : null;
  }
  const granted = status === 0 || status === 1;
  if (!granted || contentInfo === undefined) {
    throw new AttestError("MALFORMED_TOKEN", `the authority did not grant a token (status ${status}${statusText !== null ? `: ${statusText}` : ""})`);
  }

  const ci = children(tsr, expect(contentInfo, 0x30, "ContentInfo"));
  if (oidToDotted(content(tsr, expect(ci[0], 0x06, "contentType"))) !== OID_SIGNED_DATA) throw new AttestError("MALFORMED_TOKEN", "the token is not CMS SignedData");
  const signedData = expect(children(tsr, expect(ci[1], 0xa0, "content"))[0], 0x30, "SignedData");
  const sd = children(tsr, signedData);
  // version, digestAlgorithms, encapContentInfo, [certificates], [crls], signerInfos
  const encap = expect(sd[2], 0x30, "EncapsulatedContentInfo");
  const encapParts = children(tsr, encap);
  if (oidToDotted(content(tsr, expect(encapParts[0], 0x06, "eContentType"))) !== OID_TST_INFO) throw new AttestError("MALFORMED_TOKEN", "the signed content is not a TSTInfo");
  const eContent = expect(children(tsr, expect(encapParts[1], 0xa0, "eContent"))[0], 0x04, "eContent OCTET STRING");
  const certificateFingerprints: string[] = [];
  let signerInfos = 0;
  for (const part of sd.slice(3)) {
    if (part.tag === 0xa0) {
      for (const cert of children(tsr, part)) {
        certificateFingerprints.push(bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", whole(tsr, cert) as unknown as BufferSource))));
      }
    } else if (part.tag === 0x31) {
      signerInfos = children(tsr, part).length;
    }
  }

  const tst = content(tsr, eContent);
  const info = children(tst, expect(readTlv(tst, 0), 0x30, "TSTInfo"));
  const version = readInteger(tst, expect(info[0], 0x02, "TSTInfo.version")).small;
  if (version !== 1) throw new AttestError("MALFORMED_TOKEN", `TSTInfo version ${String(version)} is not read here`);
  const policy = info[1]?.tag === 0x06 ? oidToDotted(content(tst, info[1])) : null;
  const imprint = children(tst, expect(info[2], 0x30, "messageImprint"));
  const alg = children(tst, expect(imprint[0], 0x30, "hashAlgorithm"));
  const hashAlgorithm = oidToDotted(content(tst, expect(alg[0], 0x06, "hashAlgorithm.algorithm")));
  const digestHex = bytesToHex(content(tst, expect(imprint[1], 0x04, "hashedMessage")));
  const serialHex = readInteger(tst, expect(info[3], 0x02, "serialNumber")).hex;
  const genTimeText = new TextDecoder().decode(content(tst, expect(info[4], 0x18, "genTime")));
  const genTimeUnix = readGeneralizedTime(genTimeText);
  let nonceHex: string | null = null;
  let tsaName: string | null = null;
  for (const opt of info.slice(5)) {
    if (opt.tag === 0x02) nonceHex = readInteger(tst, opt).hex;
    else if (opt.tag === 0xa0) {
      // GeneralName: [4] directoryName → Name
      const gn = children(tst, opt)[0];
      if (gn !== undefined && gn.tag === 0xa4) {
        const name = children(tst, gn)[0];
        tsaName = name !== undefined ? readName(tst, name) : null;
      }
    }
  }
  return {
    status,
    granted,
    statusText,
    policy,
    hashAlgorithm,
    digestHex,
    serialHex,
    genTimeUnix,
    genTime: new Date(genTimeUnix * 1000).toISOString().replace(".000Z", "Z"),
    nonceHex,
    tsaName,
    certificateFingerprints,
    signerInfos,
  };
}

export interface VerifyRfc3161Options {
  /** The nonce the request carried; the token must echo it. */
  readonly nonceHex?: string;
  /** The caller checked the CMS signature and its chain to a pinned root (openssl ts -verify). Only then is the time final. */
  readonly signatureVerified?: boolean;
  readonly authority?: string;
}

/**
 * Read a token against the digest it should stamp. `final` only when the
 * caller says the signature was verified; otherwise `unchecked` with the time
 * read — never relied on. Never throws.
 */
export async function verifyRfc3161Digest(tsr: Uint8Array, digestHex: string, opts: VerifyRfc3161Options = {}): Promise<WitnessVerdict> {
  const by = opts.authority ?? "an RFC 3161 authority";
  let token: Rfc3161Token;
  try {
    token = await readRfc3161Token(tsr);
  } catch (e) {
    return { kind: "rfc3161", state: "invalid", timeUnix: null, digestOk: false, by: "nobody", detail: e instanceof Error ? e.message : String(e) };
  }
  if (token.hashAlgorithm !== OID_SHA256) return { kind: "rfc3161", state: "invalid", timeUnix: null, digestOk: false, by: "nobody", detail: `the token's imprint is not SHA-256 (${token.hashAlgorithm})` };
  if (token.digestHex !== digestHex) {
    return { kind: "rfc3161", state: "invalid", timeUnix: null, digestOk: false, by: "nobody", detail: `the token stamps ${token.digestHex.slice(0, 16)}…, not ${digestHex.slice(0, 16)}…` };
  }
  if (opts.nonceHex !== undefined && (token.nonceHex === null || integerHex(token.nonceHex) !== integerHex(opts.nonceHex))) {
    return { kind: "rfc3161", state: "invalid", timeUnix: null, digestOk: true, by: "nobody", detail: "the token does not echo the request's nonce" };
  }
  const who = token.tsaName !== null ? `${token.tsaName} (RFC 3161)` : by;
  if (opts.signatureVerified === true) {
    return { kind: "rfc3161", state: "final", timeUnix: token.genTimeUnix, digestOk: true, by: who, detail: `granted ${token.genTime}, serial ${token.serialHex}; signature and chain verified by the caller` };
  }
  return {
    kind: "rfc3161",
    state: "unchecked",
    timeUnix: null,
    digestOk: true,
    by: who,
    detail: `the token says ${token.genTime} (serial ${token.serialHex}) over this digest — its signature and chain were not checked here: run openssl ts -verify against the pinned root, then the time stands`,
  };
}

/* ── asking an authority (the one networked function; `fetch` is injected) ── */

/** DigiCert's public authority, as GOV-5 uses it. It answers over plain HTTP only; the request is a hash and the reply is signed. */
export const DEFAULT_RFC3161_URL = "http://timestamp.digicert.com";

export type FetchTimestamp = (url: string, init: { method: "POST"; body: Uint8Array; headers: Record<string, string> }) => Promise<{ ok: boolean; status: number; bytes(): Promise<Uint8Array> }>;

/** Ask an authority for a token over `digestHex`. Returns the raw reply and what it says; verifies no signature. */
export async function rfc3161Stamp(digestHex: string, opts: { readonly fetch: FetchTimestamp; readonly url?: string; readonly nonceHex?: string }): Promise<{ readonly tsr: Uint8Array; readonly token: Rfc3161Token; readonly nonceHex: string }> {
  const nonceHex = opts.nonceHex ?? newRfc3161Nonce();
  const res = await opts.fetch(opts.url ?? DEFAULT_RFC3161_URL, {
    method: "POST",
    body: rfc3161Request(digestHex, nonceHex),
    headers: { "Content-Type": "application/timestamp-query", Accept: "application/timestamp-reply" },
  });
  if (!res.ok) throw new AttestError("IO_ERROR", `the authority answered HTTP ${res.status}`);
  const tsr = await res.bytes();
  const token = await readRfc3161Token(tsr);
  if (token.digestHex !== digestHex) throw new AttestError("MALFORMED_TOKEN", "the token stamps another digest");
  if (token.nonceHex === null || integerHex(token.nonceHex) !== integerHex(nonceHex)) throw new AttestError("MALFORMED_TOKEN", "the token does not echo the nonce");
  return { tsr, token, nonceHex };
}
