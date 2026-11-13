/**
 * MufflerHost — in-process stub of the Indusland PDS/DWN host.
 *
 * Receives `SignedKashEvent` records via `ingest()`, performs the full
 * verification path that a real Muffler host would (envelope shape →
 * lexicon validation → cryptographic signature verification → derived-DID
 * coherence check), and stores accepted records in an in-memory map keyed
 * by `(did, lexicon, rkey)`. Returns a typed result discriminated by `ok`.
 *
 * The stub deliberately mirrors the verification posture we'd expect a
 * production host to take. Every reject reason maps to an entry in
 * `../errors.md`, so the use-case test can assert specific error codes
 * rather than just "it failed".
 *
 * No network, no persistence, no thread-safety concerns — single-process
 * single-test usage only.
 */

import { deriveDid, type KashDid } from "@kashscript/identity-core/did";
import { verifyEvent, type SignedKashEvent } from "@kashscript/identity-core/signatures";
import { decodeBase58 } from "@kashscript/identity-core/base58";
import { validateEvent, type LexiconRegistry } from "@kashscript/lexicons";

/** Discriminated result the host returns from `ingest()`. */
export type MufflerIngestResult =
  | {
      readonly ok: true;
      readonly storageKey: string;
      readonly storedAt: string;
      readonly recordCid: string;
    }
  | {
      readonly ok: false;
      readonly code: MufflerIngestErrorCode;
      readonly message: string;
      readonly details?: Record<string, unknown>;
    };

/**
 * Every reason a Muffler ingest can fail. The codes are stable wire-format;
 * messages are diagnostic-only. See ../errors.md for the operator's
 * remediation guide per code.
 */
export type MufflerIngestErrorCode =
  | "ENVELOPE_MALFORMED"
  | "LEXICON_UNKNOWN"
  | "LEXICON_VALIDATION_FAILED"
  | "DID_DERIVE_FAILED"
  | "SIGNATURE_INVALID"
  | "DID_MISMATCH"
  | "DST_MISMATCH"
  | "RKEY_DUPLICATE";

/**
 * Stored record envelope as the host sees it post-verification.
 */
export interface MufflerStoredRecord {
  readonly storageKey: string;
  readonly event: SignedKashEvent;
  readonly storedAtIso: string;
}

/**
 * Operational policy the host enforces. Surfaced so a test can opt into
 * a non-default DST or lock a particular lexicon set. Documented in
 * ../policies.md.
 */
export interface MufflerHostPolicy {
  /** DST the signature MUST carry. Default matches identity-core's DEFAULT_KASH_RECORD_DST. */
  readonly requiredDst: string;
  /** If set, reject lexicons not in this allowlist. Default: open. */
  readonly lexiconAllowlist?: readonly string[];
}

const DEFAULT_POLICY: MufflerHostPolicy = {
  requiredDst: "kash-record-v1\n",
};

export class MufflerHost {
  private readonly records = new Map<string, MufflerStoredRecord>();
  private readonly policy: MufflerHostPolicy;
  constructor(
    private readonly registry: LexiconRegistry,
    policy: Partial<MufflerHostPolicy> = {},
  ) {
    this.policy = { ...DEFAULT_POLICY, ...policy };
  }

  /**
   * The canonical ingest path. Mirrors what a real Muffler host would do
   * at the HTTP boundary — full verification, then store-or-reject.
   *
   * Stages:
   *   1. Envelope shape validation (lexicons engine catches missing fields).
   *   2. Lexicon allowlist check (if policy declared one).
   *   3. Body validation against the declared lexicon (`validateEvent`).
   *   4. Derive pubkey from header.did (did:kash encodes the pubkey).
   *   5. Cryptographic signature verification (`verifyEvent`).
   *   6. DST coherence — confirm the signed DST matches policy.
   *   7. rkey uniqueness within (did, lexicon).
   *   8. Store + return success.
   *
   * Every reject returns a typed code + diagnostic; never throws.
   */
  async ingest(event: unknown): Promise<MufflerIngestResult> {
    // Stage 1 + 3: validate envelope shape + body against the lexicon.
    const validation = validateEvent(event, this.registry);
    if (!validation.ok) {
      // Lexicon-engine surfaces both "envelope malformed" and "lexicon unknown"
      // and "body schema mismatch" as a single discriminated failure. Map them
      // to our stable code-set.
      const firstIssue = validation.errors[0];
      const path = firstIssue?.path?.join(".") ?? "";
      const msg = firstIssue?.message ?? "validation failed";
      // Heuristic — the lexicon engine puts "unknown lexicon" issues on the
      // header.lexicon path; envelope-shape issues elsewhere. Body issues
      // start with "body.".
      let code: MufflerIngestErrorCode = "ENVELOPE_MALFORMED";
      if (path === "header.lexicon" || /unknown lexicon/i.test(msg)) {
        code = "LEXICON_UNKNOWN";
      } else if (path.startsWith("body.")) {
        code = "LEXICON_VALIDATION_FAILED";
      }
      return { ok: false, code, message: msg, details: { path, issues: validation.errors } };
    }
    const env = validation.value;

    // Stage 2: lexicon allowlist.
    if (
      this.policy.lexiconAllowlist &&
      !this.policy.lexiconAllowlist.includes(env.header.lexicon)
    ) {
      return {
        ok: false,
        code: "LEXICON_UNKNOWN",
        message: `Host policy rejects lexicon "${env.header.lexicon}" (not in allowlist).`,
      };
    }

    // Stage 4: derive pubkey from the did:kash. did:kash:<base58btc(pubkey)>.
    let pubkey: Uint8Array;
    try {
      const didMethodBody = env.header.did.slice("did:kash:".length);
      pubkey = decodeBase58(didMethodBody);
    } catch (e) {
      return {
        ok: false,
        code: "DID_DERIVE_FAILED",
        message: `Could not decode pubkey from ${env.header.did}: ${(e as Error).message}`,
      };
    }

    // Stage 4.5: re-derive the DID from the pubkey and confirm it matches.
    // Catches a malicious envelope that claims a DID it doesn't own.
    let derivedDid: KashDid;
    try {
      derivedDid = deriveDid(pubkey);
    } catch (e) {
      return {
        ok: false,
        code: "DID_DERIVE_FAILED",
        message: `deriveDid failed: ${(e as Error).message}`,
      };
    }
    if (derivedDid !== env.header.did) {
      return {
        ok: false,
        code: "DID_MISMATCH",
        message: `Header DID ${env.header.did} does not match key-derived DID ${derivedDid}.`,
      };
    }

    // Stage 5: signature verification.
    //
    // GAP-001 was closed in identity-core — multibase is now the default
    // output of Signer.sign() AND verifyEvent() decodes multibase natively.
    // The wire shape (lexicons KashSignature) IS the identity-core shape
    // now; no bridge needed.
    let ok: boolean;
    try {
      ok = await verifyEvent(
        // The envelope is already in lexicons shape; verifyEvent's input
        // type accepts identity-core's SignedKashEvent which now overlaps
        // with the lexicons KashEvent for the default multibase case.
        { header: env.header, body: env.body, signature: env.signature } as unknown as
          Parameters<typeof verifyEvent>[0],
        pubkey,
      );
    } catch (e) {
      return {
        ok: false,
        code: "SIGNATURE_INVALID",
        message: `verifyEvent threw: ${(e as Error).message}`,
      };
    }
    if (!ok) {
      return {
        ok: false,
        code: "SIGNATURE_INVALID",
        message: "Ed25519 signature failed verification against the DID's pubkey.",
      };
    }

    // Stage 6: DST coherence — must match policy.
    if (env.signature.dst !== this.policy.requiredDst) {
      return {
        ok: false,
        code: "DST_MISMATCH",
        message: `Signature DST ${JSON.stringify(env.signature.dst)} does not match host policy ${JSON.stringify(this.policy.requiredDst)}.`,
      };
    }

    // Stage 7: rkey uniqueness inside (did, lexicon).
    const storageKey = composeStorageKey(env.header.did, env.header.lexicon, env.header.rkey);
    if (this.records.has(storageKey)) {
      return {
        ok: false,
        code: "RKEY_DUPLICATE",
        message: `rkey "${env.header.rkey ?? "(default)"}" already stored for (${env.header.did}, ${env.header.lexicon}).`,
      };
    }

    // Stage 8: store.
    const storedAtIso = new Date().toISOString();
    // `event` is the lexicons KashEvent<unknown>; the host stores it under
    // the identity-core SignedKashEvent contract. The two share a structural
    // shape but diverge on the alg enum ("bls12-381" vs "bls12-381-g2") —
    // tracked separately as an upstream naming reconciliation.
    this.records.set(storageKey, {
      storageKey,
      event: env as unknown as SignedKashEvent,
      storedAtIso,
    });

    return {
      ok: true,
      storageKey,
      storedAt: storedAtIso,
      recordCid: env.header.cid,
    };
  }

  /** Read back a stored record. Returns undefined for misses. */
  get(did: string, lexicon: string, rkey?: string): MufflerStoredRecord | undefined {
    return this.records.get(composeStorageKey(did, lexicon, rkey));
  }

  /** List every record stored under (did, lexicon). */
  listByCollection(did: string, lexicon: string): readonly MufflerStoredRecord[] {
    return [...this.records.values()].filter(
      (r) => r.event.header.did === did && r.event.header.lexicon === lexicon,
    );
  }

  size(): number {
    return this.records.size;
  }
}

function composeStorageKey(did: string, lexicon: string, rkey?: string): string {
  return `${did}|${lexicon}|${rkey ?? "_default"}`;
}
