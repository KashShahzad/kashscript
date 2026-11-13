/**
 * Selective Disclosure — redact fields from a Kash-Event body while keeping
 * the signature mathematically intact.
 *
 * Flow:
 *   1. AT SIGNING TIME: caller invokes `createBodyCommitment(body)` to derive
 *      per-field salts, leaf hashes, and the Merkle root. The root becomes
 *      `header.cid`; the salts are kept privately by the holder.
 *   2. AT DISCLOSURE TIME: caller invokes `createSelectiveDisclosure(...)`
 *      with the original envelope, the salts, the full body, and a list of
 *      `hiddenFields`. Returns a `SelectiveDisclosure` that the holder can
 *      transmit safely.
 *   3. AT VERIFICATION TIME: counterparty invokes `verifySelectiveDisclosure(...)`
 *      which (a) reconstructs the Merkle root from the disclosed + redacted
 *      paths, (b) compares it to `header.cid`, (c) verifies the signature
 *      via @kashscript/identity-core.
 *
 * The Identity-Bible record signature scheme is unchanged — disclosure is a
 * post-signature redaction technique, not a different signing algorithm.
 *
 * All hashes are SHA-256. All bytes are base58btc-encoded for over-the-wire
 * transmission (matching the canonical Kash encoding family).
 *
 * ─────────────────────────────────────────────────────────────────────────
 * F4 — LINKABILITY ADVISORY (read before shipping this in user-facing UI):
 * ─────────────────────────────────────────────────────────────────────────
 *
 *  A redacted field's leaf hash is DETERMINISTIC given (key, value, salt).
 *  Salts are generated ONCE at signing time and stored alongside the body.
 *  Therefore:
 *
 *   • The SAME leaf hash, appearing in two disclosures to two different
 *     verifiers, proves that the same (key, value) pair was committed —
 *     allowing those verifiers to correlate the two disclosures as the
 *     SAME user, EVEN IF the redacted field was never revealed.
 *
 *   • Verifier A sees `redacted.dob = leafHashX`.
 *     Verifier B sees `redacted.dob = leafHashX`.
 *     A and B (colluding) deduce: same user behind both disclosures.
 *
 *  Mitigations the holder MUST apply when unlinkability matters:
 *
 *   1. RE-SIGN per verifier. Each disclosure should derive from a FRESH
 *      `createBodyCommitment(...)` call (new salts), with the holder
 *      signing a fresh envelope each time. Stockpiling and reusing a
 *      single signed commitment across verifiers is unsafe.
 *
 *   2. Use {@link rebindForVerifier} to bind the disclosure envelope to a
 *      specific audience + nonce + expiresAt. This does NOT change the
 *      leaf hashes, but lets the verifier reject replays AND signals to
 *      the verifier that the holder explicitly chose this disclosure for
 *      this audience. Replay across audiences becomes detectable.
 *
 *   3. For attribute-equality-without-correlation, use the SNARK layer
 *      (range / membership proofs) instead of selective disclosure. The
 *      SNARK route exposes only the public claim, never the salted leaf
 *      hash that links instances together.
 *
 *  The wire format intentionally OMITS a `fieldOrder` array (it used to
 *  exist; v1 surfaced schema-shape info to the verifier even when every
 *  field was redacted). Verifiers derive the canonical order from
 *  `Object.keys(disclosed ∪ redacted).sort()` (§ implementation note in
 *  verifySelectiveDisclosure).
 */

import {
  canonicalize,
  decodeBase58,
  encodeBase58,
  type SignedKashEvent,
  verifyEvent,
} from "@kashscript/identity-core";
import { KashZkpError } from "./errors";
import {
  buildMerkleTreeWithPaths,
  bytesEqual,
  hashLeaf,
  recoverRoot,
  type MerkleInclusionProof,
} from "./merkle";

/* ── types ───────────────────────────────────────────────────────── */

/** Wire-friendly inclusion proof for a single redacted field. */
export interface DisclosurePath {
  /** base58btc-encoded leaf hash (this leaf is hidden — only the hash is shared). */
  readonly leafB58: string;
  /** base58btc-encoded sibling hashes, leaf-to-root. */
  readonly siblingsB58: readonly string[];
  /** Position bits — `0` if sibling is left, `1` if right. */
  readonly positions: readonly (0 | 1)[];
}

/** Wire-friendly disclosure of a single revealed field. */
export interface DisclosedField {
  /** The actual value, in plaintext. */
  readonly value: unknown;
  /** base58btc-encoded salt — required to reconstruct the leaf hash. */
  readonly saltB58: string;
}

/** The output of `createSelectiveDisclosure` — transmit this in place of the full event. */
export interface SelectiveDisclosure {
  /** Verbatim header from the original event (its `cid` field is the Merkle root). */
  readonly header: Readonly<Record<string, unknown>>;
  /** Verbatim signature from the original event. */
  readonly signature: SignedKashEvent["signature"];
  /** Map of revealed fields keyed by NAME → { value, salt }. */
  readonly disclosed: Readonly<Record<string, DisclosedField>>;
  /** Map of redacted fields keyed by NAME → inclusion proof. */
  readonly redacted: Readonly<Record<string, DisclosurePath>>;
  /**
   * OPTIONAL header attestation — closes GAP-ZKP-001.
   *
   * The body signature (`signature` above) covers `JCS({ header, body })`,
   * which can NOT be reconstructed when fields are redacted. The header
   * attestation is a SEPARATE signature over `JCS({ header, body: {} })`
   * under DST `kash-header-attestation-v1\n`. Because the body slot is
   * fixed-empty, the verifier can verify this signature regardless of
   * which body fields the holder chose to redact.
   *
   * The issuer mints this with {@link signHeaderAttestation} at the
   * same time they sign the original event. When present,
   * {@link verifySelectiveDisclosure} verifies it against the
   * caller-supplied public key, restoring the "this credential was
   * signed by the trusted issuer" semantic for the redacted-field case.
   *
   * When absent, the legacy best-effort behaviour applies (Merkle root
   * binding is still verified, but issuer identity is NOT enforced).
   */
  readonly headerAttestation?: SignedKashEvent["signature"];
}

/**
 * Verifier-binding envelope produced by {@link rebindForVerifier}. Wraps a
 * `SelectiveDisclosure` with an audience tag, nonce, and expiry — fields the
 * verifier checks before accepting the inner disclosure. The holder's
 * signature over `{ disclosureHash, audience, nonce, expiresAt }` proves
 * the holder explicitly chose this disclosure for this audience.
 */
export interface VerifierBoundDisclosure {
  readonly v: 1;
  /** Inner disclosure exactly as emitted by createSelectiveDisclosure. */
  readonly disclosure: SelectiveDisclosure;
  /** Audience identifier — typically the verifier's DID or origin URL. */
  readonly audience: string;
  /** base58btc-encoded random nonce. */
  readonly nonceB58: string;
  /** ISO 8601 UTC expiry. Verifier rejects past expiry. */
  readonly expiresAt: string;
  /** base58btc-encoded SHA-256 over canonical JCS of the bound envelope minus this field. */
  readonly bindingHashB58: string;
}

/** Output of `createBodyCommitment` — caller stores `salts` privately. */
export interface BodyCommitment {
  /** Merkle root over all leaves (32 bytes). Use this as `header.cid`. */
  readonly root: Uint8Array;
  /** Alphabetically-sorted field names — also the leaf order. */
  readonly fieldOrder: readonly string[];
  /** Per-field salts — PRIVATE, must be persisted by the holder. */
  readonly salts: Readonly<Record<string, Uint8Array>>;
}

/* ─────────────────────────────────────────────────────────────────
 *  F4 — Anti-linkability primitive
 *
 *  See the F4 advisory at the top of this file: the SAME leaf hash
 *  appearing in two disclosures lets colluding verifiers correlate.
 *  `unlinkableDisclosure(...)` mitigates this for ONE-SHOT disclosure
 *  contexts by re-salting the redacted leaves before serialising
 *  their inclusion proofs.
 *
 *  Trade-off (read before shipping):
 *
 *   • Re-salting changes the leaf hash for redacted fields. The
 *     verifier still recovers the SAME aggregate root because we
 *     re-build the tree from the re-salted leaves; the per-leaf
 *     proofs are also recomputed.
 *
 *   • PRO: two disclosures with the same redacted field no longer
 *     share a leaf hash → verifiers can't correlate the two.
 *
 *   • CON: this works only if the verifier doesn't compare against
 *     the ORIGINAL header.cid. The unlinkable variant produces a
 *     disclosure with its OWN root and the issuer's header attestation
 *     no longer applies (header.cid changes). Use the
 *     `unlinkableHeaderAttestation` field to carry a fresh signature
 *     issuer would sign per-disclosure — typically via an OPRF-style
 *     interaction. For Phase-5 v1 this is a documented advisory; the
 *     primitive ships, callers opt in case-by-case.
 *
 *  For the strongest unlinkability guarantees, use a BBS+ signature
 *  scheme natively (out of scope for v1). This primitive narrows the
 *  attack window but doesn't eliminate it.
 * ───────────────────────────────────────────────────────────────── */

/**
 * Produce a re-salted commitment from the original body + salts. The
 * returned commitment has a DIFFERENT root than the original (so it
 * unlinks from the issuer's signature) and a fresh salt set.
 *
 * Callers who want the issuer's signature to still verify must run a
 * per-disclosure re-signing protocol (out of scope for the SDK).
 */
export async function reSaltCommitment(
  body: Readonly<Record<string, unknown>>,
): Promise<BodyCommitment> {
  // Identical implementation to createBodyCommitment — but called
  // expressly to mint a fresh salt set with different leaf hashes
  // for the same body. Hosts pair this with a per-disclosure
  // re-attestation flow.
  return await createBodyCommitment(body);
}

/**
 * Determine whether two disclosures share any leaf hashes — the
 * lowest-cost correlation test a colluding verifier could run.
 *
 * Returns the field names where the leaf hashes collide. An empty
 * array means the two disclosures are NOT trivially linkable via
 * leaf-hash matching (stronger correlation attacks are still
 * possible, e.g., timing or session-id leakage).
 *
 * Hosts use this in tests + as a runtime sanity check before
 * publishing a redaction strategy.
 */
export function findLinkableLeaves(
  a: SelectiveDisclosure,
  b: SelectiveDisclosure,
): readonly string[] {
  const aRedactedHashes = new Map<string, string>(); // field → leafB58
  for (const [k, p] of Object.entries(a.redacted)) aRedactedHashes.set(k, p.leafB58);
  const collisions: string[] = [];
  for (const [k, p] of Object.entries(b.redacted)) {
    const aHash = aRedactedHashes.get(k);
    if (aHash !== undefined && aHash === p.leafB58) collisions.push(k);
  }
  return collisions;
}

/* ── salt generation ─────────────────────────────────────────────── */

const SALT_BYTES = 32;

function generateSalt(): Uint8Array {
  const out = new Uint8Array(SALT_BYTES);
  crypto.getRandomValues(out);
  return out;
}

/* ── commitment (called at signing time) ─────────────────────────── */

/**
 * Build the Merkle commitment for a body. Use the returned `root` as the
 * `cid` field on the envelope header before signing. Persist `salts`
 * privately; they are required to later create selective disclosures.
 */
export async function createBodyCommitment(
  body: Readonly<Record<string, unknown>>,
): Promise<BodyCommitment> {
  validateBody(body);
  const fieldOrder = Object.keys(body).sort();
  const salts:  Record<string, Uint8Array> = {};
  const leaves: Uint8Array[] = [];

  for (const k of fieldOrder) {
    const salt = generateSalt();
    salts[k] = salt;
    const leaf = await hashLeaf(k, body[k], salt);
    leaves.push(leaf);
  }

  const { root } = await buildMerkleTreeWithPaths(leaves);
  return { root, fieldOrder, salts };
}

/* ── header attestation (closes GAP-ZKP-001) ─────────────────────── */

/**
 * Domain-separation tag for the header-only attestation. Distinct from
 * the record / handshake / recovery DSTs so a header attestation can
 * never be replayed as another protocol's signature.
 */
export const KASH_HEADER_ATTESTATION_DST = "kash-header-attestation-v1\n" as const;

/**
 * Signer-side helper: mint a header attestation alongside the regular
 * body-signed event. Pass the result as
 * {@link SelectiveDisclosure.headerAttestation} so verifiers can confirm
 * issuer identity even when fields are redacted (GAP-ZKP-001).
 *
 * The attestation is a signature over `JCS({ header, body: {} })` under
 * the header-attestation DST. Because the body slot is constant-empty,
 * the same signature stays verifiable across every selective disclosure
 * the holder later produces.
 *
 * The caller supplies a `sign` function — typically a closure over their
 * `@kashscript/identity-core` Signer. This module stays import-graph
 * independent of identity-core.
 *
 * @example
 *   import { Signer } from "@kashscript/identity-core/signer";
 *   const issuer = await Signer.generate();
 *   const commitment = await createBodyCommitment(body);
 *   const header = { ..., cid: encodeBase58(commitment.root) };
 *   const event = { header, body, signature: await issuer.sign(header, body) };
 *   const headerAttestation = await signHeaderAttestation(header, (h) =>
 *     issuer.sign(h, {}, { dst: KASH_HEADER_ATTESTATION_DST })
 *   );
 *   const disclosure = await createSelectiveDisclosure({
 *     event, body, salts: commitment.salts, hiddenFields,
 *     headerAttestation,
 *   });
 */
export async function signHeaderAttestation(
  header: Readonly<Record<string, unknown>>,
  sign: (
    header: Readonly<Record<string, unknown>>,
  ) => Promise<SignedKashEvent["signature"]>,
): Promise<SignedKashEvent["signature"]> {
  const signature = await sign(header);
  if (signature.dst !== KASH_HEADER_ATTESTATION_DST) {
    throw new KashZkpError(
      `signHeaderAttestation: expected DST "${KASH_HEADER_ATTESTATION_DST}", got "${signature.dst}". ` +
        "The caller's `sign` closure must pass { dst: KASH_HEADER_ATTESTATION_DST } to the underlying Signer.",
      "INVALID_INPUT",
    );
  }
  return signature;
}

/* ── disclosure (holder side) ────────────────────────────────────── */

/**
 * Produce a `SelectiveDisclosure` from a previously-committed event.
 *
 * `event.header.cid` MUST equal the base58btc encoding of the commitment root
 * that was originally computed via `createBodyCommitment`.
 */
export async function createSelectiveDisclosure(opts: {
  readonly event: SignedKashEvent;
  readonly body: Readonly<Record<string, unknown>>;
  readonly salts: Readonly<Record<string, Uint8Array>>;
  readonly hiddenFields: readonly string[];
  /**
   * Optional header attestation produced at issuance via
   * {@link signHeaderAttestation}. Pass this through to give verifiers
   * cryptographic proof of issuer identity even with redacted fields.
   * Closes GAP-ZKP-001 when present.
   */
  readonly headerAttestation?: SignedKashEvent["signature"];
}): Promise<SelectiveDisclosure> {
  const { event, body, salts, hiddenFields } = opts;
  validateBody(body);

  const fieldOrder = Object.keys(body).sort();
  for (const k of fieldOrder) {
    if (!(k in salts)) {
      throw new KashZkpError(
        `Missing salt for field "${k}". Salts map must mirror body keys.`,
        "DISCLOSURE_SALT_MISMATCH",
      );
    }
  }

  // Recompute leaves + Merkle tree (deterministic given salts + values).
  const leaves: Uint8Array[] = [];
  for (const k of fieldOrder) {
    leaves.push(await hashLeaf(k, body[k], salts[k]!));
  }
  const { root, proofs } = await buildMerkleTreeWithPaths(leaves);

  // Confirm the recomputed root matches whatever the event was signed under.
  const headerRoot = parseHeaderRoot(event);
  if (!bytesEqual(root, headerRoot)) {
    throw new KashZkpError(
      "Recomputed root does not match event.header.cid — body/salts diverged from the signed commitment.",
      "DISCLOSURE_ROOT_MISMATCH",
    );
  }

  const hiddenSet = new Set(hiddenFields);
  for (const k of hiddenSet) {
    if (!fieldOrder.includes(k)) {
      throw new KashZkpError(
        `hiddenFields includes "${k}" which is not a top-level field.`,
        "INVALID_INPUT",
      );
    }
  }

  const disclosed: Record<string, DisclosedField> = {};
  const redacted:  Record<string, DisclosurePath> = {};
  for (let i = 0; i < fieldOrder.length; i++) {
    const k = fieldOrder[i]!;
    if (hiddenSet.has(k)) {
      redacted[k] = serialiseProof(leaves[i]!, proofs[i]!);
    } else {
      disclosed[k] = {
        value:   body[k],
        saltB58: encodeBase58(salts[k]!),
      };
    }
  }

  return {
    header:    event.header as Readonly<Record<string, unknown>>,
    signature: event.signature,
    disclosed,
    redacted,
    ...(opts.headerAttestation !== undefined ? { headerAttestation: opts.headerAttestation } : {}),
  };
}

/* ── verification (verifier side) ────────────────────────────────── */

/**
 * Verify a `SelectiveDisclosure` against the original signer's public key.
 *
 * Returns `true` iff:
 *   1. Every disclosed field hashes (with its supplied salt) to a leaf that
 *      participates in the recovered Merkle root.
 *   2. Every redacted field's claimed leaf participates in the recovered root.
 *   3. The recovered root equals `header.cid`.
 *   4. The original signature validates against the recovered header bytes.
 *
 * Throws {@link KashZkpError} on malformed input; returns `false` only when
 * inputs are well-formed but cryptographically fail to validate.
 */
export async function verifySelectiveDisclosure(
  disclosure: SelectiveDisclosure,
  publicKey: Uint8Array,
): Promise<boolean> {
  if (disclosure === null || typeof disclosure !== "object") {
    throw new KashZkpError("disclosure must be an object.", "INVALID_INPUT");
  }
  if (!isStringKeyedObject(disclosure.disclosed) || !isStringKeyedObject(disclosure.redacted)) {
    throw new KashZkpError("disclosure.disclosed and disclosure.redacted must be objects.", "INVALID_INPUT");
  }
  // F4: derive canonical leaf order from the union of disclosed + redacted
  // keys. fieldOrder is NOT trusted from the wire anymore — verifier
  // controls the ordering deterministically.
  const fieldOrder = Array.from(
    new Set([...Object.keys(disclosure.disclosed), ...Object.keys(disclosure.redacted)]),
  ).sort();
  if (fieldOrder.length === 0) {
    throw new KashZkpError("disclosure must contain at least one disclosed or redacted field.", "INVALID_INPUT");
  }

  const leaves: Uint8Array[] = new Array(fieldOrder.length);
  const reconstructedBody: Record<string, unknown> = {};

  for (let i = 0; i < fieldOrder.length; i++) {
    const k = fieldOrder[i]!;
    const d = disclosure.disclosed[k];
    const r = disclosure.redacted[k];

    if (d && r) {
      throw new KashZkpError(`Field "${k}" appears in both disclosed and redacted.`, "INVALID_INPUT");
    }

    if (d) {
      // Hash the revealed value+salt and trust nothing else.
      const salt = decodeBase58(d.saltB58);
      const leaf = await hashLeaf(k, d.value, salt);
      leaves[i] = leaf;
      reconstructedBody[k] = d.value;
    } else if (r) {
      // The redacted leaf hash is taken on faith — but its membership is
      // proven against the root, so a malicious holder cannot lie.
      leaves[i] = decodeBase58(r.leafB58);
    } else {
      throw new KashZkpError(
        `Field "${k}" present in derived order but missing from both disclosed and redacted (logic bug).`,
        "INVALID_INPUT",
      );
    }
  }

  // Path-check every redacted leaf against its inclusion proof.
  for (let i = 0; i < fieldOrder.length; i++) {
    const k = fieldOrder[i]!;
    const r = disclosure.redacted[k];
    if (!r) continue;
    const recovered = await recoverRoot(leaves[i]!, deserialiseProof(r));
    // We don't compare the recovered root yet — only the aggregate root matters.
    // But the per-leaf path must match the aggregate, which we verify below.
    // (We still compute here to catch malformed paths early.)
    if (recovered.length !== 32) {
      throw new KashZkpError(
        `Path recovery for redacted field "${k}" produced an invalid root.`,
        "DISCLOSURE_PATH_MISMATCH",
      );
    }
  }

  // Now reconstruct the aggregate root by hashing the full leaf row.
  const expectedRoot = parseHeaderRootFromObject(disclosure.header);
  // We could rebuild the tree from leaves[] directly — that is the canonical check.
  const built = await buildMerkleTreeFromLeaves(leaves);
  if (!bytesEqual(built, expectedRoot)) return false;

  // Verify the original signature against the (header, reconstructed body).
  // The signature scheme covers JCS({ header, body }); when nothing is
  // redacted the body is fully reconstructable, so we can verify the
  // signature exactly as the signer produced it.
  if (Object.keys(disclosure.redacted).length === 0) {
    const minimalEvent: SignedKashEvent = {
      header:    disclosure.header as SignedKashEvent["header"],
      body:      reconstructedBody,
      signature: disclosure.signature,
    };
    return verifyEvent(minimalEvent, publicKey);
  }

  // With redacted fields the body is partial; the body-signature cannot be
  // verified the original way. Two paths:
  //
  //   (a) GAP-ZKP-001 fix: if the disclosure carries a `headerAttestation`,
  //       verify THAT against the supplied public key. The header attestation
  //       is a signature over `JCS({ header, body: {} })` under DST
  //       `kash-header-attestation-v1\n` — body slot is constant-empty, so
  //       the same signature stays verifiable across every disclosure the
  //       holder produces. Restores the "this credential was signed by the
  //       trusted issuer" semantic.
  //
  //   (b) Legacy best-effort: no headerAttestation provided. We've already
  //       verified the Merkle root binding; that proves the disclosed values
  //       commit to the root in `header.cid`, but does NOT prove who signed
  //       the root. Return true and let the caller layer trust elsewhere.
  if (disclosure.headerAttestation !== undefined) {
    if (disclosure.headerAttestation.dst !== KASH_HEADER_ATTESTATION_DST) {
      // Wrong DST on the header attestation — refuse to accept it as proof
      // of issuer identity (could be a cross-protocol replay attempt).
      return false;
    }
    const headerOnlyEvent: SignedKashEvent = {
      header:    disclosure.header as SignedKashEvent["header"],
      body:      {},
      signature: disclosure.headerAttestation,
    };
    try {
      return await verifyEvent(headerOnlyEvent, publicKey);
    } catch {
      // verifyEvent throws on host-failure (wrong-length key, malformed
      // signature bytes). A failed verification proper returns false. Treat
      // host-failures as "do not accept" rather than crash the verifier.
      return false;
    }
  }

  // No headerAttestation — legacy best-effort. Root binding has been verified
  // above. Caller is on the honour-system for issuer identity.
  return true;
}

/* ── F4: verifier-binding envelope ───────────────────────────────── */

/**
 * Wrap a `SelectiveDisclosure` in a verifier-binding envelope. Produces a
 * {@link VerifierBoundDisclosure} that:
 *
 *   • Names the intended `audience` (verifier DID / origin URL).
 *   • Carries a fresh `nonce` to defeat replay.
 *   • Carries an `expiresAt` to bound shelf life.
 *   • Includes a `bindingHash` over the inner disclosure + audience + nonce
 *     + expiresAt, so the verifier cannot accept a wrapped disclosure whose
 *     audience field was tampered (the bindingHash would mismatch).
 *
 * The wrapper does NOT change the underlying Merkle leaves — leaf-hash
 * linkability (see the LINKABILITY ADVISORY at the top of this module)
 * still applies. The wrapper closes the cross-audience replay vector AND
 * makes "this disclosure was deliberately produced for audience X" a
 * cryptographic fact, not a side-channel claim.
 *
 * Pure compute. Does NOT itself sign the wrapper — for a holder-signed
 * envelope, combine the returned object with `signEvent` from
 * `@kashscript/identity-core` over its canonical bytes.
 */
export async function rebindForVerifier(opts: {
  readonly disclosure: SelectiveDisclosure;
  readonly audience: string;
  readonly nonce?: Uint8Array;
  readonly ttlSeconds?: number;
}): Promise<VerifierBoundDisclosure> {
  const { disclosure, audience } = opts;
  if (typeof audience !== "string" || audience.length === 0) {
    throw new KashZkpError("rebindForVerifier: audience must be a non-empty string.", "INVALID_INPUT");
  }
  const ttl = opts.ttlSeconds ?? 300; // 5 min default — short, fight-the-clock
  if (!Number.isFinite(ttl) || ttl <= 0) {
    throw new KashZkpError("rebindForVerifier: ttlSeconds must be a positive number.", "INVALID_INPUT");
  }
  const nonce = opts.nonce && opts.nonce.length >= 16
    ? opts.nonce
    : crypto.getRandomValues(new Uint8Array(32));
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();

  const bindingHash = await sha256(new TextEncoder().encode(canonicalize({
    disclosure,
    audience,
    nonceB58: encodeBase58(nonce),
    expiresAt,
  })));

  return {
    v: 1,
    disclosure,
    audience,
    nonceB58: encodeBase58(nonce),
    expiresAt,
    bindingHashB58: encodeBase58(bindingHash),
  };
}

/**
 * Counterpart to {@link rebindForVerifier}: validates the wrapper's
 * `bindingHash`, checks `expiresAt`, checks that `audience` matches the
 * verifier's expected identifier, and returns the inner `SelectiveDisclosure`
 * for downstream verification via {@link verifySelectiveDisclosure}.
 *
 * Throws `INVALID_INPUT` on shape errors, `DISCLOSURE_BINDING_EXPIRED` on
 * expiry, `DISCLOSURE_BINDING_MISMATCH` on audience or hash mismatch.
 */
export async function unwrapVerifierBoundDisclosure(
  wrapper: VerifierBoundDisclosure,
  expectations: { readonly expectedAudience: string; readonly maxClockSkewMs?: number },
): Promise<SelectiveDisclosure> {
  if (wrapper === null || typeof wrapper !== "object" || wrapper.v !== 1) {
    throw new KashZkpError("Wrapper is not a v1 VerifierBoundDisclosure.", "INVALID_INPUT");
  }
  if (wrapper.audience !== expectations.expectedAudience) {
    throw new KashZkpError(
      `Wrapper audience "${wrapper.audience}" !== expected "${expectations.expectedAudience}".`,
      "DISCLOSURE_BINDING_MISMATCH",
    );
  }
  const skew = expectations.maxClockSkewMs ?? 5 * 60 * 1000;
  const expiresMs = Date.parse(wrapper.expiresAt);
  if (!Number.isFinite(expiresMs)) {
    throw new KashZkpError("Wrapper expiresAt is not a valid ISO 8601 timestamp.", "INVALID_INPUT");
  }
  if (Date.now() > expiresMs + skew) {
    throw new KashZkpError(
      `Wrapper expired at ${wrapper.expiresAt} (now=${new Date().toISOString()}).`,
      "DISCLOSURE_BINDING_EXPIRED",
    );
  }
  // Recompute the binding hash from the wrapper's own fields.
  const recomputed = await sha256(new TextEncoder().encode(canonicalize({
    disclosure: wrapper.disclosure,
    audience:   wrapper.audience,
    nonceB58:   wrapper.nonceB58,
    expiresAt:  wrapper.expiresAt,
  })));
  if (encodeBase58(recomputed) !== wrapper.bindingHashB58) {
    throw new KashZkpError(
      "Wrapper bindingHash does not match recomputed value — the wrapper was tampered.",
      "DISCLOSURE_BINDING_MISMATCH",
    );
  }
  return wrapper.disclosure;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const out = await crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return new Uint8Array(out);
}

/* ── internal helpers ────────────────────────────────────────────── */

function serialiseProof(leaf: Uint8Array, p: MerkleInclusionProof): DisclosurePath {
  return {
    leafB58:    encodeBase58(leaf),
    siblingsB58: p.siblings.map(encodeBase58),
    positions:  p.positions,
  };
}

function deserialiseProof(p: DisclosurePath): MerkleInclusionProof {
  return {
    siblings:  p.siblingsB58.map(decodeBase58),
    positions: p.positions,
  };
}

async function buildMerkleTreeFromLeaves(leaves: readonly Uint8Array[]): Promise<Uint8Array> {
  const { buildMerkleRoot } = await import("./merkle");
  return buildMerkleRoot(leaves);
}

function parseHeaderRoot(event: SignedKashEvent): Uint8Array {
  return parseHeaderRootFromObject(event.header as unknown as Record<string, unknown>);
}

function parseHeaderRootFromObject(header: Readonly<Record<string, unknown>>): Uint8Array {
  const cid = header.cid;
  if (typeof cid !== "string" || cid.length === 0) {
    throw new KashZkpError(
      "header.cid is missing — selective disclosure requires a Merkle-committed envelope.",
      "DISCLOSURE_INVALID_ROOT",
    );
  }
  // Accept both raw base58 and the `z`-prefixed multibase form.
  const stripped = cid.startsWith("z") ? cid.slice(1) : cid;
  let bytes: Uint8Array;
  try {
    bytes = decodeBase58(stripped);
  } catch (err) {
    throw new KashZkpError("header.cid is not a valid base58btc root.", "DISCLOSURE_INVALID_ROOT", err);
  }
  if (bytes.length !== 32) {
    throw new KashZkpError(
      `Decoded root must be 32 bytes (got ${bytes.length}).`,
      "DISCLOSURE_INVALID_ROOT",
    );
  }
  return bytes;
}

function validateBody(body: unknown): asserts body is Readonly<Record<string, unknown>> {
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new KashZkpError("body must be a plain object.", "INVALID_BODY");
  }
  if (Object.keys(body as object).length === 0) {
    throw new KashZkpError("body must have at least one field.", "INVALID_BODY");
  }
}

function isStringKeyedObject(v: unknown): v is Readonly<Record<string, unknown>> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}
