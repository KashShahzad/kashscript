# `@kashscript/attest` — Red-Team Audit (Round 1)
**`specs/attest-audit-r1.md`**

> **Auditor scope:** the full `packages/attest/src` tree (`dsse.ts`, `chain.ts`, `ledger.ts`,
> `witness/index.ts`, `bundle.ts`, `ed25519.ts`, `compat/*`, `bin/attest.ts`) plus the load-bearing
> `identity-core` canonicalize/signatures/base58 substrate, verified with executable probes (M6, ADR-0016).
> **Outcome:** 6 findings (1 High, 3 Medium, 2 Low/Info). 3 fixed this round (F2, F3, F5); F1 deferred to a
> coordinated anchor-format v2; F4, F6 logged as design non-guarantees.
> **Severity scale:** *Critical* = silent forgery/verification bypass · *High* = collision / denial-of-
> verification · *Medium* = crash-DoS / unsafe default · *Low/Info* = hardening / documentation.

---

## Part I — Findings

### F1 — Anchor Merkle-root construction is delimiter-injectable (hash collision) · **High** · DESIGN-GAP · DEFERRED
- **Location:** `witness/index.ts` `computeAnchorMerkleRoot`.
- **The hole:** the pre-image is the newline-join `${sessionId}\n${latestHash}\n${latestStepIndex}\n`.
  Because `sessionId`/`latestHash` are free strings and `\n` is the only delimiter, two distinct tip-sets
  can serialize to identical bytes. **Proven:** `{sessionId:"a\nb", latestHash:"c"}` and
  `{sessionId:"a", latestHash:"b\nc"}` both → `a\nb\nc\n0\n` → same root.
- **Disposition — DEFERRED (wire-format).** The injective fix (canonical-JSON / length-prefixed encoding)
  changes every anchor root, which would invalidate anchors a real venture has **already witnessed** to a
  public log (Rekor/OTS). Per consumer-as-acceptance + the hudhud-last guard, this MUST land behind an
  anchor-format **version bump** coordinated with re-anchoring at the venture swap — not a unilateral break.
  The M1 acceptance fixture (a real Oreoasis bundle) confirms the format is wire-locked. An inline
  `⚠️ audit r1 F1 (KNOWN, deferred)` note now documents it at the call site.
- **Mitigation today:** the single-session `verifyAuditBundle` path independently binds
  `tip.latestHash === tail.currentTransactionBlockHash` (a 64-hex string that cannot hold `\n`), so a
  forged multi-field collision does not verify there. The exposure is the exported multi-session primitive.

### F2 — `verifyEnvelope` throws on a malformed sibling signature, discarding valid ones · **Medium** · CODE-BUG · **FIXED r1**
- **Location:** `dsse.ts` signature loop.
- **The hole:** appending one junk signature entry (`{keyid:123}`) made verification `throw
  MALFORMED_SIGNATURE`, nuking an otherwise-valid envelope — a trivial unauthenticated denial-of-verification.
  DSSE's model is "≥1 signature verifies."
- **Fix:** `continue` past a malformed sibling instead of throwing; a valid signature still counts.
  Regression test in `test/units.test.ts` ("honours a valid signature even when a malformed sibling is appended").

### F3 — Malformed `publicKeyHex` / `alg` throws an uncaught non-`TamperError` (fail-to-crash DoS) · **Medium** · CODE-BUG · **FIXED r1 (bundle path)**
- **Location:** `bundle.ts` `resolve` (`hexToBytes(entry.publicKeyHex)`); also `compat/duedale-report.ts` (`alg`).
- **The hole:** an attacker-supplied non-hex `publicKeyHex` in a bundle made `verifyAuditBundle` throw
  `KashCryptoError` uncaught (the CLI only special-cases `TamperError`), violating the stated
  "malformed → ok:false" contract.
- **Fix:** the bundle `resolve` closure now catches a decode failure and returns `null` (key unresolvable →
  signature simply won't verify → `ok:false`). The compat `alg` vector (a Duedale-report shim) is **logged**
  for the same treatment — lower priority (it fails loud, not silent).

### F4 — `verifyAuditBundle` trusts payload-embedded keys by default (self-attestation) · **Medium** · DESIGN-GAP · LOGGED
- **The hole:** with no `trustedKeysByDid`/`requireSignerDid`, keys are resolved from the bundle's own
  (unauthenticated) payload and `requiredSignerVerified` defaults `true` — "signed by whoever the bundle
  says signed it." `ok` conflates internally-consistent with trustworthy.
- **Disposition — LOGGED.** The intended usage passes a trust anchor (the acceptance test + CLI do); flipping
  the default to fail-closed would break those callers. **Patch direction (next round):** when neither trust
  option is supplied, surface `report.trustAnchored = false` and force `ok:false`, or require an explicit
  `allowSelfDescribedKeys: true`. Documented as a known posture until then.

### F5 — `KASH_DID_PATTERN` is unused in `register()` AND the comment cited colon-DIDs it rejects · **Low** · SPEC-GAP · **FIXED r1 (comment)**
- **The hole:** the exported base58-only pattern is never enforced, and the module comment justified a
  "relaxed guard" with `did:kash:oreoasis:kernel:host` — which the pattern rejects, and which M5's ledger
  reconciliation retired in favour of base58 `did:kash`.
- **Fix:** corrected the stale comment (the registry is deliberately a pluggable resolver; canonical actor
  DIDs are base58 `did:kash`; format validation is the write side's job). Enforcing the pattern in
  `register()` is logged as optional hardening (could reject legitimate pluggable resolvers).

### F6 — Row `emittedAt` / `localId` are neither signed nor chained · **Low/Info** · DESIGN-GAP · LOGGED
- **The hole:** the signed/hashed field set excludes `emittedAt`/`localId`, so a rewritten row timestamp
  still passes `forensicConsistencyScan` (only `stepIndex` ordering is authenticated).
- **Disposition — LOGGED.** May be acceptable (the external witness provides trusted time). Documented as a
  non-guarantee; fold `emittedAt` into the signed header if row timestamps must be court-trustworthy.

---

## Part II — Disposition Summary

| Finding | Severity | Disposition | Where |
|---|---|---|---|
| F1 anchor collision | High | **DEFERRED** (anchor-format v2 + re-anchor) | `witness/index.ts` (noted) |
| F2 malformed-sibling DoV | Medium | **FIXED r1** | `dsse.ts` + test |
| F3 malformed-input crash | Medium | **FIXED r1** (bundle); logged (compat alg) | `bundle.ts` |
| F4 default self-attestation | Medium | LOGGED (fail-closed default next round) | `bundle.ts` |
| F5 dead pattern / stale note | Low | **FIXED r1** (comment) | `ledger.ts` |
| F6 unsigned row metadata | Low/Info | LOGGED (non-guarantee) | `ledger.ts` |

## Part III — What the package gets right
- **DSSE PAE / payload binding** — `pae()` implements `DSSEv1 SP LEN(type) SP type SP LEN(body) SP body`
  correctly; verification is over the decoded payload bytes (swapping bytes breaks it). Raw Ed25519 via
  WebCrypto with strict 32/64-byte gating; no hash truncation.
- **JCS canonicalization** — RFC 8785 on the JSON subset: key sorting, `-0→"0"`, hard rejection of
  non-finite/BigInt/symbol/undefined-in-array/circular. Prototype pollution is not applicable (canonicalize
  only reads `Object.keys().sort()`; DSSE hashes raw bytes, never a re-parsed object).
- **Chain/ledger tamper detection** — `forensicConsistencyScan` enforces stepIndex monotonicity, prev-hash
  linkage (genesis special-cased), recomputes the block hash **including the signature**, and re-verifies
  each Ed25519 signature, throwing `TamperError` closed on the first variance.
- **ReDoS** — all regexes are linear (bounded `{n}` or single character-class `*`). Witness client never
  throws and never fabricates a receipt.

## Part IV — Residual Risks Carried Forward
- **F1 anchor injectivity** is a live (bounded) exposure until the coordinated anchor-format v2 ships.
- **F4 trust posture** — callers who invoke `verifyAuditBundle` with no trust anchor get a "consistent, not
  authenticated" `ok:true`; the fail-closed default is the next round's normative change.

---
**End of Round 1.** F2/F3/F5 fixed with tests this session; F1 deferred to the anchor-format migration;
F4/F6 carried as documented postures. Round 2 replays these against the venture swap.
