/**
 * Canonical identifiers + content digests for the ecosystem.
 *
 * ECOSYSTEM-AUDIT-2026-07-25 §2.1 found `ulid()` implemented three times and
 * §2.2 found `sha256Hex` re-implemented across the stack. ECOSYSTEM decision 13
 * ("single source of truth") bans exactly that class of drift, and attest is
 * where it belongs: the evidence commons already owns JCS canonicalization and
 * the hash-chain recipe, and **an id that appears in a signed claim, or a digest
 * that a signature is taken over, is part of the wire format.** A digest that
 * drifts between the signer and the verifier is a signature bug, not a style
 * issue — which is why these live here and not in a new utility package.
 *
 * ── FOR VENTURE SESSIONS (uplift notes; do the swaps in OA-A5 / DD-A1) ───────
 *
 * Import from `@kashscript/attest/ids` and DELETE the local copy in the same
 * change (decision 13: no parallel copies, no keep-just-in-case — git remembers).
 * The known duplicates at the time of writing:
 *
 *   OA-A5 · Oreoasis
 *     - `packages/sdk/src/receipt.ts` — its local `ulid()` carries a comment
 *       saying it is "STILL LOCAL, on purpose… when the canonical `./ids`
 *       subpath ships, delete this and import it." This is that subpath.
 *       `ulid(nowMs?)` below is signature-compatible, so the swap is the import
 *       line plus deleting the function. Its `sha256Hex(string | Uint8Array)`
 *       wrapper is replaced by `sha256HexOf` below.
 *     - `apps/oreoasis-core-host/src/ulid.ts` — `generateUlid()` is this exact
 *       algorithm; re-export or replace call sites with `ulid()`. Its
 *       `ULID_ALPHABET` / `ULID_PATTERN` are re-exported here unchanged.
 *
 *   DD-A1 · Duedale
 *     - `ks-adapters/identity` — local `sha256Hex`; import `sha256Hex` here.
 *
 *   Indusland edge functions keep their copies: decision 13's sole exception
 *   (a hard Deno runtime constraint), which is pinned by a contract test rather
 *   than removed.
 *
 * NOT a duplicate, despite appearing in the audit's §2.1 list:
 * `packages/kash/src/commands/neuron.ts`'s `ulidFor(seed)` mints a
 * **deterministic** ULID-shaped id from a content hash. It is a different
 * primitive with a different contract (same input → same id, no clock, no
 * randomness) and swapping it for `ulid()` would change behaviour. Left alone
 * on purpose.
 */

import { AttestError } from "./errors";
import { sha256Hex } from "./chain";

/**
 * `sha256Hex(bytes)` — SHA-256 → lowercase hex. Re-exported from `./chain`, so
 * this subpath adds a name, never a second implementation.
 *
 * Bytes only — a string throws a typed `AttestError` naming the fix. When your
 * input may be a string, reach for {@link sha256HexOf} instead; the two are
 * documented as a pair on purpose.
 */
export { sha256Hex } from "./chain";

/** Crockford base32 — the ULID alphabet (no I, L, O or U). */
export const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ" as const;

/**
 * Strict ULID format check: 26 Crockford-base32 characters.
 *
 * Deliberately the *lenient* form the ventures already validate with — it does
 * not additionally require the first character to be `0`–`7` (the 48-bit
 * timestamp only fills 48 of the leading 50 bits). Tightening it here would
 * reject nothing real and would fork the ventures' validators.
 */
export const ULID_PATTERN = /^[0-9A-HJKMNP-TV-Z]{26}$/;

/**
 * Mint a ULID — 26 Crockford-base32 characters: a 48-bit millisecond timestamp
 * (10 chars) followed by 80 bits of cryptographic randomness (16 chars).
 *
 * Lexicographically sortable to the millisecond. **Not** monotonic *within* a
 * millisecond: two ULIDs minted in the same millisecond sort by their random
 * bytes rather than by mint order. That is the ULID spec's optional monotonic
 * clause, deliberately unimplemented — it requires cross-call state, and every
 * caller in the ecosystem is either rate-limited upstream or does not depend on
 * intra-millisecond ordering. If one ever does, it needs a monotonic factory,
 * not a patched global.
 *
 * @param nowMs Millisecond timestamp to encode. Defaults to `Date.now()`;
 *              injectable so tests can pin the time half.
 * @throws {AttestError} `CRYPTO_UNAVAILABLE` if there is no CSPRNG. Minting a
 *         `Math.random()` id that lands in a signed claim is worse than failing.
 */
export function ulid(nowMs: number = Date.now()): string {
  if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
    throw new AttestError(
      "CRYPTO_UNAVAILABLE",
      "crypto.getRandomValues is unavailable — refusing to mint a non-cryptographic ULID",
    );
  }
  if (!Number.isFinite(nowMs) || nowMs < 0) {
    throw new AttestError("INVALID_INPUT", `ulid: nowMs must be a non-negative finite number (got ${nowMs})`);
  }

  // 48-bit ms timestamp → 10 Crockford chars (50 bits; the top 2 are zero).
  let t = BigInt(Math.floor(nowMs));
  let timePart = "";
  for (let i = 0; i < 10; i++) {
    timePart = ULID_ALPHABET[Number(t & 31n)]! + timePart;
    t >>= 5n;
  }

  // 80-bit randomness → 16 Crockford chars.
  const random = new Uint8Array(10);
  crypto.getRandomValues(random);
  let acc = 0n;
  for (let i = 0; i < 10; i++) acc = (acc << 8n) | BigInt(random[i]!);
  let randPart = "";
  for (let i = 0; i < 16; i++) {
    randPart = ULID_ALPHABET[Number(acc & 31n)]! + randPart;
    acc >>= 5n;
  }

  return timePart + randPart;
}

/** True when `value` is a well-formed ULID. */
export function isUlid(value: string): boolean {
  return ULID_PATTERN.test(value);
}

/**
 * Recover the millisecond timestamp encoded in a ULID's first 10 characters.
 * Useful for verifying that a receipt id agrees with the claim's `timestamp`.
 *
 * @throws {AttestError} `INVALID_INPUT` if `value` is not a well-formed ULID.
 */
export function ulidTimeMs(value: string): number {
  if (!isUlid(value)) {
    throw new AttestError("INVALID_INPUT", `ulidTimeMs: not a ULID: ${JSON.stringify(value)}`);
  }
  let acc = 0n;
  for (let i = 0; i < 10; i++) acc = acc * 32n + BigInt(ULID_ALPHABET.indexOf(value[i]!));
  return Number(acc);
}

/**
 * SHA-256 → lowercase hex over a UTF-8 string *or* raw bytes.
 *
 * The convenience half of `sha256Hex`, which takes bytes only (and throws a
 * typed `AttestError` pointing here when handed a string). It exists so the
 * venture wrappers that currently do the `TextEncoder` dance locally have
 * nothing left to keep (see the uplift notes above). The digest is `sha256Hex`'s
 * — there is still exactly one implementation.
 */
export async function sha256HexOf(input: string | Uint8Array): Promise<string> {
  return sha256Hex(typeof input === "string" ? new TextEncoder().encode(input) : input);
}
