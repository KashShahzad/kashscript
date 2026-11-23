/**
 * Just enough of an X.509 certificate to check a verifier's signed request
 * (OpenID4VP 1.0 §5.9, client identifier prefixes `x509_hash` and
 * `x509_san_dns`): the leaf's SHA-256, its public key, its DNS names and its
 * validity. A small DER walker, no dependency.
 *
 * What this does NOT do, on purpose: it validates no chain and trusts no
 * anchor. The wallet has no X.509 trust list (KS-C1's R4 is the founder's), so
 * `x509_hash` is the only prefix that binds a key by itself — the hash is in the
 * client identifier. A request checked under `x509_san_dns` is checked against
 * the leaf's own names, and says so.
 */

import { base64ToBytes, bytesToBase64Url } from "./bytes";
import { buf } from "./bytes";

interface Tlv {
  readonly tag: number;
  /** The whole element, header included. */
  readonly whole: Uint8Array;
  /** The contents. */
  readonly value: Uint8Array;
}

function readTlv(bytes: Uint8Array, at: number): { tlv: Tlv; next: number } {
  if (at + 2 > bytes.length) throw new Error("DER: truncated");
  const tag = bytes[at]!;
  if ((tag & 0x1f) === 0x1f) throw new Error("DER: multi-byte tags are not used in certificates");
  let len = bytes[at + 1]!;
  let p = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || p + n > bytes.length) throw new Error("DER: bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[p + i]!;
    p += n;
  }
  if (p + len > bytes.length) throw new Error("DER: element runs past its parent");
  return { tlv: { tag, whole: bytes.subarray(at, p + len), value: bytes.subarray(p, p + len) }, next: p + len };
}

function children(value: Uint8Array): Tlv[] {
  const out: Tlv[] = [];
  let at = 0;
  while (at < value.length) {
    const { tlv, next } = readTlv(value, at);
    out.push(tlv);
    at = next;
  }
  return out;
}

const SEQUENCE = 0x30;
const OID_SAN = "551d11"; // 2.5.29.17, its DER contents in hex
const DNS_NAME = 0x82; // GeneralName dNSName, [2] IMPLICIT IA5String

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

function parseTime(t: Tlv): number {
  const s = new TextDecoder().decode(t.value);
  // UTCTime YYMMDDHHMMSSZ (0x17) or GeneralizedTime YYYYMMDDHHMMSSZ (0x18).
  const m = t.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (m === null) throw new Error("DER: a time this reader does not know");
  let year = Number(m[1]);
  if (t.tag === 0x17) year += year < 50 ? 2000 : 1900;
  return Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6])) / 1000;
}

export interface LeafCertificate {
  /** `base64url(SHA-256(DER))` — what an `x509_hash:` client identifier names. */
  readonly sha256: string;
  /** The SubjectPublicKeyInfo, DER, for WebCrypto's `spki` import. */
  readonly spki: Uint8Array;
  readonly dnsNames: readonly string[];
  readonly notBefore: number;
  readonly notAfter: number;
}

/** Read the leaf of an `x5c` header (standard base64 DER). Throws when it is not a certificate this reader can read. */
export async function readLeaf(x5c0: string): Promise<LeafCertificate> {
  const der = base64ToBytes(x5c0);
  const cert = readTlv(der, 0);
  if (cert.tlv.tag !== SEQUENCE || cert.next !== der.length) throw new Error("not one DER certificate");
  const [tbs] = children(cert.tlv.value);
  if (tbs === undefined || tbs.tag !== SEQUENCE) throw new Error("no tbsCertificate");
  const f = children(tbs.value);
  let i = f[0]?.tag === 0xa0 ? 1 : 0; // [0] version
  i += 3; // serialNumber, signature, issuer
  const validity = f[i++];
  i++; // subject
  const spki = f[i++];
  if (validity === undefined || validity.tag !== SEQUENCE || spki === undefined || spki.tag !== SEQUENCE) throw new Error("no validity or public key");
  const [nb, na] = children(validity.value);
  if (nb === undefined || na === undefined) throw new Error("bad validity");
  const dnsNames: string[] = [];
  for (const ext of f.slice(i)) {
    if (ext.tag !== 0xa3) continue; // [3] extensions
    const [list] = children(ext.value);
    for (const e of list === undefined ? [] : children(list.value)) {
      const parts = children(e.value);
      if (parts[0]?.tag !== 0x06 || hex(parts[0].value) !== OID_SAN) continue;
      const octets = parts[parts.length - 1]!;
      const [names] = children(octets.value);
      for (const n of names === undefined ? [] : children(names.value)) if (n.tag === DNS_NAME) dnsNames.push(new TextDecoder().decode(n.value));
    }
  }
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf(der)));
  return { sha256: bytesToBase64Url(digest), spki: spki.whole, dnsNames, notBefore: parseTime(nb), notAfter: parseTime(na) };
}

/**
 * ES256 over a JWS signing input, under a certificate's P-256 key. WebCrypto's
 * ECDSA accepts either `s` — a verifier's request is not ours to hold to
 * low-S, which attest requires only of what the ecosystem itself signs.
 */
export async function verifyEs256WithSpki(spki: Uint8Array, signingInput: Uint8Array, rawSignature: Uint8Array): Promise<boolean> {
  if (rawSignature.length !== 64) return false;
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey("spki", buf(spki), { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    return false; // not a P-256 key: nothing this wallet verifies
  }
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, buf(rawSignature), buf(signingInput));
}
