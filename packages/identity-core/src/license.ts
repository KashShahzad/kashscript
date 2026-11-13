/**
 * @kashscript/identity-core/license
 *
 * Runtime license-key verifier for the commercial Foundry artifacts
 * (Trade-SDK, Neuron, the SNARK prover in identity-zkp). Apache-substrate
 * packages (identity-core itself, identity-sdk, lexicons) do NOT call this
 * — they are unconditionally free under SSLA Schedule A.
 *
 * # The token
 *
 * A license key is a base64url-encoded JSON document with the shape:
 *
 *   {
 *     v:   1,              // schema version
 *     did: "did:kash:…",   // licensee's DID (whoever paid)
 *     tier: "trial" | "paid" | "team" | "enterprise",
 *     iat: 1735689600,     // issued-at,  unix seconds
 *     exp: 1735776000,     // expires-at, unix seconds
 *     sig: "<base64url Ed25519 signature over canonicalize({v,did,tier,iat,exp})>"
 *   }
 *
 * The signature is Ed25519 over RFC-8785 canonical bytes of the claims (sans
 * `sig`). The verifier checks the signature against a public key the consumer
 * provides. Each commercial artifact bakes the canonical Kash-Registry public
 * key into its own source, so the npm package never has to phone home.
 *
 * # The wire flow (consumer side)
 *
 *   1. User runs `kash login` → device binds to a did:kash via WebAuthn.
 *   2. User subscribes (Stripe/LemonSqueezy) → Kash-Registry records the DID
 *      + tier in its server-side ledger.
 *   3. User runs `kash license issue --tier paid` → Registry mints a fresh
 *      token signed with its Ed25519 private key, returns the base64url string.
 *   4. User exports `KASH_LICENSE_KEY=<token>` in their deployment environment.
 *   5. Trade-SDK / Neuron call `assertLicense({ pkgName, registryPubkey })` at
 *      module init. The key is read from `process.env.KASH_LICENSE_KEY`; the
 *      Registry's pubkey is baked into the package.
 *   6. Expired? Wrong tier? Missing? Throw `LicenseError` with a stable code.
 *
 * The Registry is the only server-side piece KashScript runs. The npm packages
 * stay sovereign — no telemetry, no fetch home, no opaque blob.
 *
 * # Local development
 *
 * In dev (`NODE_ENV !== "production"`) the assertion is soft — a missing or
 * expired key prints one warning and the package continues. This lets
 * contributors run the full test suite without standing up a license server
 * (the test suites themselves never call `assertLicense`).
 *
 * # Why this lives in identity-core
 *
 * Every commercial artifact already depends on identity-core (Ed25519 +
 * canonical bytes are foundational). Putting the verifier here means zero
 * new packages, and the same canonicalisation that signs Kash-Events signs
 * license tokens — one less inconsistency surface to maintain.
 */

import { canonicalizeBytes } from "./canonical";
import { decodeBase64Url } from "./base64url";

/* ─────────────────────────────────────────────────────────────────
 *  Token shape
 * ───────────────────────────────────────────────────────────────── */

/** The five Plan tiers KashScript ships. (The site card that mirrored them, `apps/kashscript/content/pricing.ts`, was removed 2026-10-09.) */
export type LicenseTier = "trial" | "paid" | "team" | "enterprise";

export interface LicenseClaims {
  /** Schema version. Bump when the claim set or signature scheme changes. */
  readonly v: 1;
  /** Licensee's `did:kash:…`. Whose payment minted this token. */
  readonly did: string;
  /** Plan tier the licensee currently holds. */
  readonly tier: LicenseTier;
  /** Issued-at, unix seconds. */
  readonly iat: number;
  /** Expires-at, unix seconds. The Registry uses short TTLs:
   *  - trial: ≤ 1 hour
   *  - paid:  ≤ 7 days
   *  - team / enterprise: ≤ 30 days
   *  A leaked key auto-burns inside that window. */
  readonly exp: number;
}

/** Wire shape — claims plus a base64url Ed25519 signature over their canonical bytes. */
export interface SignedLicense extends LicenseClaims {
  readonly sig: string;
}

/* ─────────────────────────────────────────────────────────────────
 *  Errors — stable wire-format codes; consuming products can match
 *  on `err.code` to render different UI per failure mode.
 * ───────────────────────────────────────────────────────────────── */

export type LicenseErrorCode =
  | "KEY_MISSING"
  | "KEY_MALFORMED"
  | "SIGNATURE_INVALID"
  | "EXPIRED"
  | "TIER_INSUFFICIENT"
  | "VERSION_UNSUPPORTED"
  | "REGISTRY_PUBKEY_INVALID";

export class LicenseError extends Error {
  public override readonly name = "LicenseError" as const;
  constructor(
    message: string,
    public readonly code: LicenseErrorCode,
  ) {
    super(message);
  }
}

/* ─────────────────────────────────────────────────────────────────
 *  Tier ladder — for `requiredTier` gates.
 *  Higher rank ⊇ everything below it. Enterprise covers paid, paid
 *  covers trial. A free user (no token at all) holds rank 0; not
 *  encoded in the token because the token wouldn't exist.
 * ───────────────────────────────────────────────────────────────── */

const TIER_RANK: Readonly<Record<LicenseTier, number>> = {
  trial: 1,
  paid: 2,
  team: 3,
  enterprise: 4,
};

/* ─────────────────────────────────────────────────────────────────
 *  verifyLicense — pure crypto.
 *
 *  Takes a token (base64url string from KASH_LICENSE_KEY) and the
 *  Registry's Ed25519 public key (32 bytes raw). Returns the verified
 *  claims, or throws `LicenseError` with a typed code.
 * ───────────────────────────────────────────────────────────────── */

export async function verifyLicense(
  token: string,
  registryPublicKey: Uint8Array,
): Promise<LicenseClaims> {
  if (registryPublicKey.length !== 32) {
    throw new LicenseError(
      `registry public key must be 32 bytes; got ${registryPublicKey.length}`,
      "REGISTRY_PUBKEY_INVALID",
    );
  }

  // Decode + parse
  let parsed: SignedLicense;
  try {
    const jsonBytes = decodeBase64Url(token);
    parsed = JSON.parse(new TextDecoder().decode(jsonBytes)) as SignedLicense;
  } catch {
    throw new LicenseError(
      "license key is not a valid base64url-encoded JSON token",
      "KEY_MALFORMED",
    );
  }

  // Version gate
  if (parsed.v !== 1) {
    throw new LicenseError(
      `unsupported license schema version: ${String(parsed.v)} (expected 1)`,
      "VERSION_UNSUPPORTED",
    );
  }

  // Shape gate
  if (
    typeof parsed.did !== "string" ||
    typeof parsed.tier !== "string" ||
    !(parsed.tier in TIER_RANK) ||
    typeof parsed.iat !== "number" ||
    typeof parsed.exp !== "number" ||
    typeof parsed.sig !== "string"
  ) {
    throw new LicenseError("license token is missing required fields", "KEY_MALFORMED");
  }

  // Re-canonicalise the claims (sans `sig`) and verify
  const claims: LicenseClaims = {
    v: parsed.v,
    did: parsed.did,
    tier: parsed.tier,
    iat: parsed.iat,
    exp: parsed.exp,
  };
  const payload = canonicalizeBytes(claims);

  let sigBytes: Uint8Array;
  try {
    sigBytes = decodeBase64Url(parsed.sig);
  } catch {
    throw new LicenseError("license signature is not valid base64url", "KEY_MALFORMED");
  }
  if (sigBytes.length !== 64) {
    throw new LicenseError(
      `license signature must be 64 bytes; got ${sigBytes.length}`,
      "SIGNATURE_INVALID",
    );
  }

  let cryptoKey: CryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      "raw",
      // A fresh copy's buffer holds exactly these bytes; a pooled Buffer's `.slice().buffer` is the whole pool.
      new Uint8Array(registryPublicKey).buffer,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch {
    throw new LicenseError("WebCrypto rejected the registry public key", "REGISTRY_PUBKEY_INVALID");
  }

  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    cryptoKey,
    new Uint8Array(sigBytes).buffer,
    new Uint8Array(payload).buffer,
  );
  if (!valid) {
    throw new LicenseError(
      "license signature does not verify under the kash-registry public key — token may be forged, edited, or signed by a different registry",
      "SIGNATURE_INVALID",
    );
  }

  // Expiry gate (last so signature-verify errors take precedence)
  const nowSec = Math.floor(Date.now() / 1000);
  if (claims.exp < nowSec) {
    throw new LicenseError(
      `license expired at ${new Date(claims.exp * 1000).toISOString()} ` +
      `(now ${new Date().toISOString()}). Run \`kash license refresh\`.`,
      "EXPIRED",
    );
  }

  return claims;
}

/* ─────────────────────────────────────────────────────────────────
 *  assertLicense — opinionated entry point for commercial packages.
 *
 *  Reads KASH_LICENSE_KEY from process.env, verifies it, gates on
 *  required tier if specified. In production mode (NODE_ENV) a
 *  missing or expired key throws; in dev mode it warns once and
 *  returns null (free-tier semantics).
 * ───────────────────────────────────────────────────────────────── */

export interface AssertLicenseOpts {
  /** Package calling the assertion — appears in error messages. */
  readonly pkgName: string;
  /** Registry's canonical Ed25519 public key (32 bytes, raw). Each commercial
   *  package bakes its own constant; passing it in keeps the verifier
   *  generic and lets a self-hosting enterprise swap the trust anchor. */
  readonly registryPublicKey: Uint8Array;
  /** Minimum tier required for this artifact's full feature surface.
   *  Omit to require ANY valid token (just gates on signature + expiry). */
  readonly requiredTier?: LicenseTier;
  /** Mode override. By default inferred from `NODE_ENV`:
   *  - `production` → missing key throws KEY_MISSING
   *  - `development` → missing key warns once and returns null */
  readonly mode?: "production" | "development";
  /** Optional override for the env var name (default: `KASH_LICENSE_KEY`). */
  readonly envVar?: string;
}

let _warnedNoKey = false;

export async function assertLicense(
  opts: AssertLicenseOpts,
): Promise<LicenseClaims | null> {
  const mode = opts.mode ?? inferMode();
  const envVar = opts.envVar ?? "KASH_LICENSE_KEY";
  const token = readEnv(envVar);

  if (token === undefined || token === "") {
    if (mode === "production") {
      throw new LicenseError(
        `${opts.pkgName} is operating in production mode (NODE_ENV=production) ` +
        `but ${envVar} is not set. Mint a token with \`kash license issue\` and ` +
        `export it before deploy. See https://www.kashscript.com/foundry for tiers.`,
        "KEY_MISSING",
      );
    }
    if (!_warnedNoKey) {
      _warnedNoKey = true;
      // eslint-disable-next-line no-console
      console.warn(
        `[${opts.pkgName}] dev mode: ${envVar} is unset. ` +
        `Set it before NODE_ENV=production — production callers will throw. ` +
        `See https://www.kashscript.com/foundry.`,
      );
    }
    return null;
  }

  const claims = await verifyLicense(token, opts.registryPublicKey);

  if (opts.requiredTier !== undefined) {
    const have = TIER_RANK[claims.tier];
    const need = TIER_RANK[opts.requiredTier];
    if (have < need) {
      throw new LicenseError(
        `${opts.pkgName} requires tier "${opts.requiredTier}" or higher; ` +
        `your license tier is "${claims.tier}". Upgrade at https://www.kashscript.com/foundry.`,
        "TIER_INSUFFICIENT",
      );
    }
  }

  return claims;
}

/* ─────────────────────────────────────────────────────────────────
 *  Helpers
 * ───────────────────────────────────────────────────────────────── */

function inferMode(): "production" | "development" {
  // Browsers + edge runtimes without process: default to dev (the consumer
  // will gate on its own ServerComponents / API-route flags upstream).
  // Node / Bun / Deno-with-node-compat: read NODE_ENV.
  const env = readEnv("NODE_ENV");
  return env === "production" ? "production" : "development";
}

function readEnv(name: string): string | undefined {
  // process.env (Node, Bun, Deno --unstable-node-modules, Edge runtimes that
  // shim it). Browsers without a process shim return undefined.
  const p = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
  return p?.env?.[name];
}

/* ─────────────────────────────────────────────────────────────────
 *  Test helper — reset the once-per-process warning flag. Internal.
 * ───────────────────────────────────────────────────────────────── */

/** @internal */
export function _resetWarnedForTest(): void {
  _warnedNoKey = false;
}
