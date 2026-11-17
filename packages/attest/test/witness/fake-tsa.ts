/**
 * A test double for an RFC 3161 authority: a `TimeStampResp` built here, granted,
 * over a digest, at a time, with no signature anybody could check. Used only to
 * generate SAMPLE witness files and to exercise the token reader. A verdict
 * built on one of these is `final` only because the test tells the verifier
 * the signature was checked — the way the CLI does after `openssl ts -verify`.
 */

import { OID_SHA256, OID_SIGNED_DATA, OID_TST_INFO } from "../../src/witness/rfc3161";

const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

function len(n: number): number[] {
  if (n < 0x80) return [n];
  const b: number[] = [];
  let v = n;
  while (v > 0) {
    b.unshift(v & 0xff);
    v = Math.floor(v / 256);
  }
  return [0x80 | b.length, ...b];
}
const der = (tag: number, body: Uint8Array): Uint8Array => Uint8Array.from([tag, ...len(body.length), ...body]);
const cat = (...parts: Uint8Array[]): Uint8Array => Uint8Array.from(parts.flatMap((p) => [...p]));
const seq = (...parts: Uint8Array[]): Uint8Array => der(0x30, cat(...parts));
const set = (...parts: Uint8Array[]): Uint8Array => der(0x31, cat(...parts));
const int = (bytes: Uint8Array): Uint8Array => der(0x02, bytes[0]! & 0x80 ? cat(Uint8Array.of(0), bytes) : bytes);
const nul = (): Uint8Array => Uint8Array.of(0x05, 0x00);
const oid = (dotted: string): Uint8Array => {
  const a = dotted.split(".").map(Number);
  const out = [a[0]! * 40 + a[1]!];
  for (const arc of a.slice(2)) {
    const b: number[] = [];
    let v = arc;
    do {
      b.unshift(v % 128);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < b.length - 1; i++) b[i]! |= 0x80;
    out.push(...b);
  }
  return der(0x06, Uint8Array.from(out));
};
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);
const generalizedTime = (unix: number): Uint8Array => der(0x18, utf8(new Date(unix * 1000).toISOString().replace(/[-:T]/g, "").replace(/\.\d{3}Z$/, "Z")));

export interface FakeTsaInput {
  readonly digestHex: string;
  readonly genTimeUnix: number;
  readonly serialHex?: string;
  readonly nonceHex?: string;
  /** A common name for the `tsa` field, so the reader's name extraction is exercised. */
  readonly tsaName?: string;
  readonly status?: number;
}

/** A granted (status 0) `TimeStampResp` carrying a TSTInfo and one placeholder certificate. Not signed by anything. */
export function fakeTimeStampResp(input: FakeTsaInput): Uint8Array {
  const status = input.status ?? 0;
  const statusInfo = seq(int(Uint8Array.of(status)));
  if (status > 1) return seq(statusInfo);
  const tsa = input.tsaName === undefined ? new Uint8Array(0) : der(0xa0, der(0xa4, seq(set(seq(oid("2.5.4.3"), der(0x0c, utf8(input.tsaName)))))));
  const tstInfo = seq(
    int(Uint8Array.of(1)),
    oid("1.3.6.1.4.1.99999.1"),
    seq(seq(oid(OID_SHA256), nul()), der(0x04, hex(input.digestHex))),
    int(hex(input.serialHex ?? "0a1b2c3d")),
    generalizedTime(input.genTimeUnix),
    ...(input.nonceHex !== undefined ? [int(hex(input.nonceHex))] : []),
    tsa,
  );
  // A placeholder "certificate": a SEQUENCE a reader fingerprints and nothing verifies.
  const certificate = seq(seq(int(Uint8Array.of(2)), int(Uint8Array.of(1))), seq(oid("1.2.840.113549.1.1.11"), nul()), der(0x03, Uint8Array.of(0, 1, 2, 3)));
  const signerInfo = seq(int(Uint8Array.of(1)), seq(seq(set(seq(oid("2.5.4.3"), der(0x0c, utf8("SAMPLE TSA"))))), int(Uint8Array.of(1))), seq(oid(OID_SHA256), nul()), seq(oid("1.2.840.113549.1.1.11"), nul()), der(0x04, Uint8Array.of(9, 9, 9, 9)));
  const signedData = seq(int(Uint8Array.of(3)), set(seq(oid(OID_SHA256), nul())), seq(oid(OID_TST_INFO), der(0xa0, der(0x04, tstInfo))), der(0xa0, certificate), set(signerInfo));
  return seq(statusInfo, seq(oid(OID_SIGNED_DATA), der(0xa0, signedData)));
}
