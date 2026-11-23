/**
 * A test-only certificate maker: a structurally real X.509 leaf around a fresh
 * P-256 key, with chosen DNS names. Its own signature is filler — the wallet
 * validates no chain (KS-C1 R4), so nothing reads it. Plus a signer for request
 * objects under that key, as a verifier would sign them.
 */

import { buf, bytesToBase64, bytesToBase64Url } from "../src/crypto/bytes";

const enc = new TextEncoder();

function der(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const head = len < 0x80 ? [tag, len] : len < 0x100 ? [tag, 0x81, len] : [tag, 0x82, len >> 8, len & 0xff];
  const out = new Uint8Array(head.length + len);
  out.set(head, 0);
  let at = head.length;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

const seq = (...p: Uint8Array[]) => der(0x30, ...p);
const oid = (hex: string) => der(0x06, Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16))));
const utc = (s: string) => der(0x17, enc.encode(s));

export interface TestVerifier {
  readonly x5c0: string;
  readonly privateKey: CryptoKey;
  /** base64url SHA-256 of the DER: the `x509_hash:` value. */
  readonly hash: string;
  sign(header: Record<string, unknown>, payload: Record<string, unknown>): Promise<string>;
}

export async function makeTestVerifier(dnsNames: readonly string[], validity: { from: string; to: string } = { from: "250101000000Z", to: "350101000000Z" }): Promise<TestVerifier> {
  const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  const ecdsaSha256 = seq(oid("2a8648ce3d040302"));
  const name = seq();
  const san = seq(oid("551d11"), der(0x04, seq(...dnsNames.map((n) => der(0x82, enc.encode(n))))));
  const tbs = seq(der(0xa0, der(0x02, Uint8Array.of(2))), der(0x02, Uint8Array.of(1)), ecdsaSha256, name, seq(utc(validity.from), utc(validity.to)), name, spki, der(0xa3, seq(san)));
  const cert = seq(tbs, ecdsaSha256, der(0x03, Uint8Array.of(0, 0x30, 0x00)));
  const hash = bytesToBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", buf(cert))));
  const x5c0 = bytesToBase64(cert);
  return {
    x5c0,
    privateKey: pair.privateKey,
    hash,
    async sign(header, payload) {
      const input = `${bytesToBase64Url(enc.encode(JSON.stringify({ alg: "ES256", typ: "oauth-authz-req+jwt", x5c: [x5c0], ...header })))}.${bytesToBase64Url(enc.encode(JSON.stringify(payload)))}`;
      const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, pair.privateKey, enc.encode(input)));
      return `${input}.${bytesToBase64Url(sig)}`;
    },
  };
}
