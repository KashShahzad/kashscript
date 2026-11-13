/**
 * WebAuthn (Passkey) wrapper.
 *
 * Wraps the browser's `navigator.credentials` API with a typed, error-coded
 * surface. Every entry point validates the ceremony's `clientDataJSON` —
 * comparing `origin`, `challenge`, and `type` byte-for-byte with what the
 * relying party expected — to foreclose Man-in-the-Middle attacks where a
 * proxy injects a different origin or replays a stale challenge.
 *
 * Pure logic. No React imports, no storage imports.
 */

import { decodeBase64Url, encodeBase64Url } from "@kashscript/identity-core";
import { KashSdkError } from "./errors";

/** Result of a successful registration ceremony. */
export interface CreatedPasskey {
  /** Stable opaque credential id assigned by the authenticator. */
  readonly credentialId: Uint8Array;
  /** SPKI-encoded public key bytes returned by the authenticator. */
  readonly publicKey: Uint8Array;
  /** COSE algorithm identifier (e.g., -7 for ES256). */
  readonly algorithm: number;
  /** Raw `clientDataJSON` bytes (signed by the authenticator). */
  readonly clientDataJSON: Uint8Array;
}

/** Result of a successful assertion ceremony. */
export interface PasskeyAssertion {
  readonly credentialId: Uint8Array;
  readonly authenticatorData: Uint8Array;
  readonly clientDataJSON: Uint8Array;
  /** Authenticator's signature over `authenticatorData || SHA-256(clientDataJSON)`. */
  readonly signature: Uint8Array;
}

/** Parameters for the registration ceremony. */
export interface CreatePasskeyOptions {
  /** RP-generated random bytes (>= 16 recommended; 32 typical). */
  readonly challenge: Uint8Array;
  /** Stable user id (e.g., DID bytes, or random bytes during initial registration). */
  readonly userId: Uint8Array;
  /** WebAuthn `user.name` — usually the user's handle. */
  readonly userName: string;
  /** Display name for the OS prompt. */
  readonly userDisplayName: string;
  /** RP id — defaults to `window.location.hostname`. */
  readonly rpId?: string;
  /** RP name shown in the OS prompt — defaults to `"Kash"`. */
  readonly rpName?: string;
  /** WebAuthn timeout in ms. Default 60_000. */
  readonly timeoutMs?: number;
  /** Origin to expect in clientDataJSON. Defaults to `window.location.origin`. */
  readonly expectedOrigin?: string;
  /**
   * F3: credentials the user already has on this authenticator for this RP.
   * Passed through as WebAuthn `excludeCredentials` so the OS prompt refuses
   * to overwrite an existing credential (the user sees "you already have a
   * Passkey for this site" instead of silently minting a duplicate).
   */
  readonly excludeCredentialIds?: readonly Uint8Array[];
}

/** Parameters for the assertion ceremony. */
export interface AssertPasskeyOptions {
  readonly challenge: Uint8Array;
  /** If provided, restrict the prompt to a specific credential. */
  readonly credentialId?: Uint8Array;
  readonly rpId?: string;
  readonly timeoutMs?: number;
  readonly expectedOrigin?: string;
}

/* ── ceremony entry points ───────────────────────────────────────── */

/** Run a WebAuthn registration ceremony and return the new credential. */
export async function createPasskey(opts: CreatePasskeyOptions): Promise<CreatedPasskey> {
  ensureWebAuthn();
  const expectedOrigin = opts.expectedOrigin ?? readOrigin();
  const rpId           = opts.rpId           ?? readHostname();

  let credential: PublicKeyCredential;
  try {
    const result = await navigator.credentials.create({
      publicKey: {
        challenge: bufferSource(opts.challenge),
        rp:   { id: rpId, name: opts.rpName ?? "Kash" },
        user: {
          id: bufferSource(opts.userId),
          name: opts.userName,
          displayName: opts.userDisplayName,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -8 },  // EdDSA (Ed25519) — preferred when supported
          { type: "public-key", alg: -7 },  // ES256 (P-256) — universal fallback
        ],
        authenticatorSelection: {
          residentKey: "preferred",
          userVerification: "required",
        },
        timeout: opts.timeoutMs ?? 60_000,
        attestation: "none",
        ...(opts.excludeCredentialIds && opts.excludeCredentialIds.length > 0
          ? {
              excludeCredentials: opts.excludeCredentialIds.map((id) => ({
                type: "public-key" as const,
                id: bufferSource(id),
              })),
            }
          : {}),
      },
    });
    if (!result) throw new KashSdkError("Authenticator returned null.", "WEBAUTHN_CANCELLED");
    credential = result as PublicKeyCredential;
  } catch (err) {
    throw wrapBrowserError(err);
  }

  const response = credential.response as AuthenticatorAttestationResponse;
  if (typeof response.getPublicKey !== "function") {
    throw new KashSdkError(
      "Authenticator response did not expose getPublicKey().",
      "WEBAUTHN_UNEXPECTED_CREDENTIAL",
    );
  }

  const clientDataJSON = new Uint8Array(response.clientDataJSON);
  verifyClientData(clientDataJSON, {
    expectedType: "webauthn.create",
    expectedChallenge: opts.challenge,
    expectedOrigin,
  });

  const publicKeyBuf = response.getPublicKey();
  if (publicKeyBuf === null) {
    throw new KashSdkError(
      "Authenticator did not return a public key.",
      "WEBAUTHN_UNEXPECTED_CREDENTIAL",
    );
  }

  return {
    credentialId: new Uint8Array(credential.rawId),
    publicKey:    new Uint8Array(publicKeyBuf),
    algorithm:    response.getPublicKeyAlgorithm() ?? 0,
    clientDataJSON,
  };
}

/** Run a WebAuthn assertion ceremony and return the signed assertion. */
export async function assertPasskey(opts: AssertPasskeyOptions): Promise<PasskeyAssertion> {
  ensureWebAuthn();
  const expectedOrigin = opts.expectedOrigin ?? readOrigin();
  const rpId           = opts.rpId           ?? readHostname();

  let credential: PublicKeyCredential;
  try {
    const result = await navigator.credentials.get({
      publicKey: {
        challenge: bufferSource(opts.challenge),
        rpId,
        allowCredentials: opts.credentialId
          ? [{ type: "public-key", id: bufferSource(opts.credentialId) }]
          : [],
        userVerification: "required",
        timeout: opts.timeoutMs ?? 60_000,
      },
    });
    if (!result) throw new KashSdkError("Authenticator returned null.", "WEBAUTHN_CANCELLED");
    credential = result as PublicKeyCredential;
  } catch (err) {
    throw wrapBrowserError(err);
  }

  const response = credential.response as AuthenticatorAssertionResponse;
  const clientDataJSON = new Uint8Array(response.clientDataJSON);
  verifyClientData(clientDataJSON, {
    expectedType: "webauthn.get",
    expectedChallenge: opts.challenge,
    expectedOrigin,
  });

  return {
    credentialId:      new Uint8Array(credential.rawId),
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJSON,
    signature:         new Uint8Array(response.signature),
  };
}

/* ── F3: discoverable-credential probe ──────────────────────────── */

/**
 * Discoverable-credential probe. Runs an assertion ceremony WITHOUT a
 * specific `allowCredentials` list — the authenticator surfaces whatever
 * credentials it holds for the RP and the user picks one.
 *
 * Use case: detect that the user already has a Passkey registered for this
 * RP on this device. The SDK calls this at registration time so the user
 * cannot accidentally mint a second credential that orphans the first.
 *
 * Returns `null` if no credential is available or the user cancels the
 * prompt; returns the discovered `credentialId` bytes otherwise.
 *
 * NOTE — this is interactive (the OS shows a prompt). For silent discovery,
 * use `PublicKeyCredential.isConditionalMediationAvailable()` + `mediation:
 * "conditional"` on a focused `<input>`, which is out of scope here.
 */
export async function discoverExistingCredential(opts: {
  readonly rpId?: string;
  readonly expectedOrigin?: string;
  readonly timeoutMs?: number;
}): Promise<Uint8Array | null> {
  ensureWebAuthn();
  const rpId           = opts.rpId           ?? readHostname();
  const expectedOrigin = opts.expectedOrigin ?? readOrigin();
  const probeChallenge = crypto.getRandomValues(new Uint8Array(32));

  let credential: PublicKeyCredential;
  try {
    const result = await navigator.credentials.get({
      publicKey: {
        challenge: bufferSource(probeChallenge),
        rpId,
        allowCredentials: [],                // <-- discoverable
        userVerification: "preferred",
        timeout: opts.timeoutMs ?? 30_000,
      },
    });
    if (!result) return null;
    credential = result as PublicKeyCredential;
  } catch (err) {
    if (err instanceof DOMException && (err.name === "NotAllowedError" || err.name === "AbortError")) {
      return null;                           // user cancelled / no credential
    }
    throw wrapBrowserError(err);
  }

  const response = credential.response as AuthenticatorAssertionResponse;
  // Validate the response so a hostile authenticator can't return junk.
  verifyClientData(new Uint8Array(response.clientDataJSON), {
    expectedType: "webauthn.get",
    expectedChallenge: probeChallenge,
    expectedOrigin,
  });
  return new Uint8Array(credential.rawId);
}

/* ── clientDataJSON validation ───────────────────────────────────── */

interface ClientData {
  readonly type:      string;
  readonly challenge: string;   // base64url, no padding (per WebAuthn spec)
  readonly origin:    string;
  readonly crossOrigin?: boolean;
}

interface ClientDataExpectations {
  readonly expectedType: "webauthn.create" | "webauthn.get";
  readonly expectedChallenge: Uint8Array;
  readonly expectedOrigin: string;
}

/** Parse and validate the `clientDataJSON` bytes. Throws on mismatch. */
export function verifyClientData(
  clientDataJSON: Uint8Array,
  expect: ClientDataExpectations,
): ClientData {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(clientDataJSON);

  let parsed: ClientData;
  try {
    parsed = JSON.parse(text) as ClientData;
  } catch (err) {
    throw new KashSdkError("clientDataJSON is not valid JSON.", "WEBAUTHN_UNEXPECTED_CREDENTIAL", err);
  }

  if (parsed.type !== expect.expectedType) {
    throw new KashSdkError(
      `clientDataJSON.type "${parsed.type}" !== expected "${expect.expectedType}".`,
      "WEBAUTHN_TYPE_MISMATCH",
    );
  }

  if (parsed.origin !== expect.expectedOrigin) {
    throw new KashSdkError(
      `clientDataJSON.origin "${parsed.origin}" !== expected "${expect.expectedOrigin}".`,
      "WEBAUTHN_ORIGIN_MISMATCH",
    );
  }

  // F2: refuse a ceremony that ran inside a cross-origin frame. An iframe
  // embedding the RP and triggering Passkey assertions can pass the origin
  // check (the top frame's origin) while phishing the user under a hostile
  // top context. Per WebAuthn Level 3 §6.3.3, clientDataJSON.crossOrigin
  // is `true` exactly when the call happened in a non-top frame.
  if (parsed.crossOrigin === true) {
    throw new KashSdkError(
      `clientDataJSON.crossOrigin is true — the WebAuthn ceremony ran inside an embedded frame, which is refused.`,
      "WEBAUTHN_CROSS_ORIGIN",
    );
  }

  // WebAuthn challenge is base64url-no-padding of the original bytes.
  let challengeBytes: Uint8Array;
  try {
    challengeBytes = decodeBase64Url(parsed.challenge);
  } catch (err) {
    throw new KashSdkError(
      "clientDataJSON.challenge is not valid base64url.",
      "WEBAUTHN_CHALLENGE_MISMATCH",
      err,
    );
  }
  if (!bytesEqual(challengeBytes, expect.expectedChallenge)) {
    throw new KashSdkError(
      `clientDataJSON.challenge does not match expected challenge.`,
      "WEBAUTHN_CHALLENGE_MISMATCH",
    );
  }

  return parsed;
}

/* ── internal helpers ─────────────────────────────────────────────── */

function ensureWebAuthn(): void {
  if (typeof window === "undefined" || typeof window.PublicKeyCredential === "undefined") {
    throw new KashSdkError(
      "WebAuthn is not available in this environment.",
      "WEBAUTHN_UNAVAILABLE",
    );
  }
  if (!window.navigator?.credentials) {
    throw new KashSdkError(
      "navigator.credentials is not available in this environment.",
      "WEBAUTHN_UNAVAILABLE",
    );
  }
}

function readOrigin(): string {
  if (typeof window === "undefined") {
    throw new KashSdkError("window is not defined; cannot determine origin.", "WEBAUTHN_UNAVAILABLE");
  }
  return window.location.origin;
}

function readHostname(): string {
  if (typeof window === "undefined") {
    throw new KashSdkError("window is not defined; cannot determine hostname.", "WEBAUTHN_UNAVAILABLE");
  }
  return window.location.hostname;
}

function bufferSource(bytes: Uint8Array): BufferSource {
  return bytes as unknown as BufferSource;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  // Constant-time compare. Defends against timing leaks even though the
  // values being compared (challenges, origins) aren't strictly secret.
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function wrapBrowserError(err: unknown): KashSdkError {
  if (err instanceof KashSdkError) return err;
  if (err instanceof DOMException) {
    if (err.name === "NotFoundError") {
      // F3: the named credential id is not present on this authenticator.
      // Storage was cleared, the device was wiped, or the Passkey was deleted
      // from the OS keychain. Surface a distinct code so the provider can
      // route to the recovery flow.
      return new KashSdkError(
        `WebAuthn credential not found on this authenticator (NotFoundError). The Passkey appears to be orphaned — recovery is required.`,
        "WEBAUTHN_ORPHANED_CREDENTIAL",
        err,
      );
    }
    if (err.name === "NotAllowedError" || err.name === "AbortError") {
      return new KashSdkError(
        `WebAuthn ceremony cancelled or denied (${err.name}).`,
        "WEBAUTHN_CANCELLED",
        err,
      );
    }
  }
  return new KashSdkError(
    `WebAuthn ceremony failed: ${(err as Error)?.message ?? String(err)}`,
    "WEBAUTHN_UNEXPECTED_CREDENTIAL",
    err,
  );
}

/* ── small encoding helpers re-exported for ergonomics ──────────── */

/** Encode arbitrary bytes as base64url-no-padding (alias of identity-core helper). */
export { encodeBase64Url, decodeBase64Url };
