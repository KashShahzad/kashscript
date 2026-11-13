// Content addressing for refined records — CIDv1 (raw codec, sha2-256) over
// the JCS-canonical bytes. This is the change-detection key the indexer dedups
// on. Distinct from a repo's native dag-cbor CID; this addresses the canonical
// app-view value.
//
// WebCrypto only — isomorphic across Bun, Node 20+, Deno, and browsers,
// matching @kashscript/identity-core's zero-dependency posture. Ported verbatim
// from the @indus/muffler seed (M3 of the protocol Manifestation, ADR-0016) so
// a record content-addressed by the venture re-addresses byte-for-byte.

const BASE32_LOWER = "abcdefghijklmnopqrstuvwxyz234567";

export function base32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_LOWER[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_LOWER[(value << (5 - bits)) & 31];
  return out;
}

export async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return new Uint8Array(digest);
}

// CIDv1 prefix: version 0x01, raw codec 0x55, sha2-256 0x12, length 0x20.
const CIDV1_RAW_SHA256 = Uint8Array.of(0x01, 0x55, 0x12, 0x20);

export async function cidForBytes(bytes: Uint8Array): Promise<string> {
  const digest = await sha256(bytes);
  const cid = new Uint8Array(CIDV1_RAW_SHA256.length + digest.length);
  cid.set(CIDV1_RAW_SHA256);
  cid.set(digest, CIDV1_RAW_SHA256.length);
  return "b" + base32(cid);
}
