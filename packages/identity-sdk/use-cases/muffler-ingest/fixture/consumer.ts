/**
 * InduslandConsumer — represents the Indusland client app side of the
 * Muffler-ingest use case.
 *
 * Owns a `Signer` (the user's identity). When the user composes a
 * `kash.social.post` body, the consumer:
 *   1. Computes a CIDv1-style content identifier over the canonical body bytes.
 *   2. Builds the envelope header (did, lexicon, iat, nonce, cid, rkey).
 *   3. Signs the envelope via the Signer (uses the kash-record-v1 DST).
 *   4. Hands the resulting `SignedKashEvent` to the Muffler host.
 *
 * The consumer is *frontend code*. It has no host secret, no network token —
 * everything that authenticates the publish is in the signature itself. A
 * real Indusland app would do the same dance from the browser; the only
 * difference is the `Signer` would be Passkey-bound instead of in-memory.
 */

import { Signer } from "@kashscript/identity-core/signer";
import { canonicalizeBytes } from "@kashscript/identity-core/canonical";
import type {
  KashEvent,
  KashHeader,
  KashSignature,
} from "@kashscript/lexicons/envelope";
import { KASH_SOCIAL_POST_ID, type KashSocialPostBody } from "@kashscript/lexicons/extensions/social";
import type { MufflerHost, MufflerIngestResult } from "./muffler-stub";

// identity-core now emits multibase signatures by default (no `encoding`
// field on the output), matching the lexicons KashSignature schema exactly.
// The signature-bridge from earlier rounds is no longer needed.

/**
 * Base32-lower (RFC 4648 §6, alphabet `abcdefghijklmnopqrstuvwxyz234567`).
 *
 * `identity-core` does not ship a base32 module today — only base58, base64url,
 * hex. We need base32-lowercase to compose CIDv1 multibase identifiers
 * (multibase prefix `b` requires base32-lowercase) so the lexicon engine's
 * `format: "cid"` validator (`/^bafy[a-z2-7]{52,}$/`) accepts the output.
 *
 * Inlined here rather than added to identity-core to keep the use-case
 * self-contained. Promote to identity-core/base32 when a second consumer
 * appears.
 */
const BASE32_ALPHA = "abcdefghijklmnopqrstuvwxyz234567";
function encodeBase32Lower(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHA[(value >>> bits) & 31];
    }
  }
  if (bits > 0) out += BASE32_ALPHA[(value << (5 - bits)) & 31];
  return out;
}

/**
 * Mint a CIDv1-shape identifier for the canonical body bytes.
 *
 *   • prefix `bafyrei` is the multibase + multicodec marker for
 *     "base32-lowercase · CIDv1 · dag-cbor · sha2-256 · length-32".
 *   • the tail is the base32-lower-encoded SHA-256 of the canonical body bytes.
 *
 * Real production CIDs would round-trip through a full multiformats library;
 * the lexicon engine's `format: "cid"` check only enforces the string shape,
 * so a prefix-plus-base32 SHA-256 is sufficient for the use case + verifiably
 * derived from the body bytes.
 */
async function cidFromBody(body: unknown): Promise<string> {
  const bytes = canonicalizeBytes(body);
  // crypto.subtle.digest's BufferSource accepts Uint8Array<ArrayBuffer> but
  // TS 5.7+'s lib.dom narrows the typed-array generic; copy into a fresh
  // ArrayBuffer view to satisfy it.
  const buf = bytes.buffer instanceof ArrayBuffer
    ? bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
    : new Uint8Array(bytes).buffer;
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
  return `bafyrei${encodeBase32Lower(digest)}`;
}

/** Cryptographically-strong nonce in lower-hex. 32 bytes → 64 hex chars. */
function freshNonce(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Optional fields the caller may set on every publish (rkey for deterministic
 * record naming, iatOverride for replay-testing).
 */
export interface PublishPostOptions {
  /** Override the rkey (default: a fresh one derived from the cid). */
  readonly rkey?: string;
  /** Override the iat (default: now). */
  readonly iatOverride?: string;
}

export class InduslandConsumer {
  constructor(
    private readonly signer: Signer,
    private readonly host: MufflerHost,
  ) {}

  /** The user's DID — surfaced for assertions in tests. */
  get did(): string {
    return this.signer.did;
  }

  /** End-to-end publish: build envelope → sign → POST to Muffler. */
  async publishPost(
    body: KashSocialPostBody,
    opts: PublishPostOptions = {},
  ): Promise<MufflerIngestResult> {
    const cid = await cidFromBody(body);
    const header: KashHeader = {
      did: this.signer.did,
      lexicon: KASH_SOCIAL_POST_ID,
      iat: opts.iatOverride ?? new Date().toISOString(),
      nonce: freshNonce(),
      cid,
      ...(opts.rkey !== undefined ? { rkey: opts.rkey } : { rkey: `post-${cid.slice(7, 19)}` }),
    } as KashHeader;

    // identity-core's default multibase output IS the lexicons KashSignature
    // shape — no bridging needed since GAP-001 was closed.
    const signature = (await this.signer.sign(
      header as unknown as Readonly<Record<string, unknown>>,
      body,
    )) as unknown as KashSignature;
    const event: KashEvent<KashSocialPostBody> = { header, body, signature };
    return await this.host.ingest(event);
  }

  /**
   * Convenience: produce a SignedKashEvent without posting. Useful for
   * tampering-tests (the test mutates the envelope, then calls
   * `host.ingest(tamperedEvent)` to confirm the host rejects).
   */
  async sealPost(
    body: KashSocialPostBody,
    opts: PublishPostOptions = {},
  ): Promise<KashEvent<KashSocialPostBody>> {
    const cid = await cidFromBody(body);
    const header: KashHeader = {
      did: this.signer.did,
      lexicon: KASH_SOCIAL_POST_ID,
      iat: opts.iatOverride ?? new Date().toISOString(),
      nonce: freshNonce(),
      cid,
      ...(opts.rkey !== undefined ? { rkey: opts.rkey } : { rkey: `post-${cid.slice(7, 19)}` }),
    } as KashHeader;
    const signature = (await this.signer.sign(
      header as unknown as Readonly<Record<string, unknown>>,
      body,
    )) as unknown as KashSignature;
    return { header, body, signature };
  }
}
