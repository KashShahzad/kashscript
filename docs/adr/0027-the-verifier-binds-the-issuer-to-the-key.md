# ADR-0027: The verifier binds the issuer to the key and counts signers by key — it reports only what it verified

- **Status:** Accepted (AU-3, built 2026-11-12; published by hand under `alpha` the same day, without provenance, per d97(n); `latest` moved 2026-11-13)
- **Date:** 2026-11-12
- **Decision drivers:** ECOSYSTEM d11 (no claimed verification that did not happen), d26 (the other party signs), d27 rule 4 (verification is free and unmonopolised), d28 (verification never requires us), d41 (two signatures or it is not proof), d43 (every predicate names its rule version; nothing scores a person), d62(d)2 (organisations sign as themselves), d84(f) P6 (the security baseline), d91 (the attestation, and who answers for it); AUDIT-2026-11-11 A7-01 to A7-08 and A10-03

## Context

The audit of 2026-11-11 read the signing core every engine pins — attest, identity-core, predicate — and found that the kernel reported things it had not verified.

- **A7-01 (critical).** `verifySdJwt` resolved the issuer's key from the header's `kid` first, verified under it, and then reported the payload's `iss` as the issuer. Any self-certifying `did:kash` in `kid` resolves, so anyone could issue a predicate — `answer: true` under Oreoasis's DID — or a decision receipt under a door's DID, and every consumer trusted `sd.issuer`.
- **A7-02 (high).** The countersign verifier counted independent signers as distinct keyid strings, while key resolution strips `#fragment`: `did:kash:X` and `did:kash:X#c` are one key counted as two, so one key met *two signatures or it is not proof*. Nothing refused a countersigner that is the requester.
- **A7-03 (high).** A record's id hashed the whole container, so a re-wrapped record — an extra field, a junk sibling signature — got a new id and `checkPacket` counted it again toward a threshold.
- **A7-04 to A7-08.** Verifiers documented as never throwing threw on one junk sibling signature or a non-JSON payload; a missing `keyCustody` read as `subject-generated`; the CLI exited 0 on an audit bundle whose only key came from the file; Ed25519 edge cases were left to each runtime's WebCrypto; `checkPacket` never bounded a key binding's age.
- **A10-03 (high).** No package's test suite ran in CI, in the publish workflow's gates, or in the publish script.

## Decision

1. **The key is the issuer's.** An SD-JWT's key is resolved through `iss` only (self-certifying, a pinned trust list's key under that id, or a held key). A `kid` must name `iss`, a `#fragment` apart, or the credential is refused as `KID_NOT_ISSUER`; no `iss` is `ISSUER_KEY_UNRESOLVED`. A trust-listed, non-self-certifying issuer already puts the listed keyid in `iss` (`specs/presentation.md`), so no resolver changes shape.
2. **Signers are keys, not spellings.** `canonicalSignerOf(keyid)` is the canonical `did:kash` of the key a keyid resolves to; `keyIdentityOf` names a resolved key's material. The countersign verifier counts distinct keys, reports every signer canonically, and marks each acceptance `independent` (its key is not the requester's). `twoSignatureProof` needs two keys over the bytes and one acceptance that is `ok` and `independent`. A bundle whose only verifying acceptance is the requester's own fails as `COUNTERSIGNER_IS_REQUESTER`. The requester's own acceptance stays `ok` as a signature: the cohort profile has the teacher's organisation accept its own request, and the CLI's per-party label reads `ok`. Whether the requester signed the subject is a fact (`requesterSignedSubject`), not a rule: an organisation requests on its doer's record without signing it.
3. **One content identity for counting.** `contentIdOf` names what the issuer signed: the PAE bytes of a DSSE or countersign subject, the JCS of a Kash-Event's `{header, body}`, an SD-JWT's issuer JWT. `ReceiptView.contentId` carries it; `checkPacket`, the checklist and `evaluateCriterion` dedupe on it. `id` and the artifact binding's `artifact_sha256` are unchanged.
4. **Never throws means never throws.** `verifyEnvelope` skips a sibling signature that is not base64 and reports a non-JSON payload as `payloadJson: undefined`; `verifyCountersignBundle` returns `MALFORMED_BUNDLE` for anything it cannot read, and `RUNTIME_CANNOT_CHECK` for the one runtime fault; `verifyHeldRecord`, `readReceipt` and `checkPacket` report one bad item and judge the rest. The holder layer and the audit-bundle verifier still call a non-JSON payload malformed — a record is JSON — without throwing or crashing.
5. **Unknown custody is unknown.** The report's custody is `subject-generated`, `delegated-mint`, or `unknown` (`ReportedKeyCustody`); only the first is subject-held. The two words a signer may write (`KeyCustody`) are unchanged. The same in key claims.
6. **The exit code tells the truth.** `verifyAuditBundle` reports `selfAsserted` when no trusted key was supplied (`--signer-did` alone lifts nothing: that string is in the file too). `attest verify` prints `RESULT: INTEGRITY ONLY` and exits **3** for an audit bundle or an Every-Rupee report checked with no `--key`; `ok` keeps its integrity meaning for library callers.
7. **The Ed25519 acceptance rule is pinned** in identity-core (`ed25519-strict.ts`) and applied before WebCrypto in both Kash-Event and raw verification: `S < L`; `A` and `R` decoded strictly; neither of small order; then the engine's cofactorless equation. Vectors: Wycheproof's 210, ed25519-speccheck's 12, attest's 28, with one pinned verdict per case asserted under bun, node and Chromium.
8. **A key binding's age is bounded.** `checkPacket` refuses a binding further than ten minutes from `asOf` unless the desk passes `freshness.maxKbAgeSec`; a binding with no time does not count. Single-use nonces remain the desk's own defence.
9. **Every open package's suite gates CI and every publish.** `scripts/test-packages.ts` runs each package's own `test` script sequentially (the suites share one rebuilt CLI bundle and spawn node and a browser); `ci.yml` has a `test` job that `validate` waits for, `publish.yml`'s gates run it, and `publish-to-npmjs.ts` runs each package's tests before it builds, with no skip flag.

Every fault has a committed failing vector, written first: `attest/test/vectors/au3` (generated once, keys thrown away), `attest/test/vectors/ed25519`, and the tests beside each module.

## Consequences

### Positive
- A predicate or a decision in another organisation's name is refused by name, at the kernel, before any desk reads `issuer`.
- One key under two spellings is one signer everywhere a count is made; every signer in a report is comparable as a key.
- A threshold is met by records, not encodings.
- A junk entry anyone can append is a problem line, never a 500 at a door or a failed wallet export.
- A reader of the exit code can no longer take a fabricated audit trail for a pass.
- Three runtimes give one verdict on Ed25519's edges; a signature of zeros under the identity key, which BoringSSL alone accepts for any message, no longer verifies.
- A regression in the countersign or SD-JWT verifier fails CI and the publish, not a consumer's pin bump.

### Negative / accepted trade-offs
- Consumers that print the countersign `reason` see `COUNTERSIGNER_IS_REQUESTER` where they saw `NOT_COUNTERSIGNED` for a requester-only bundle; Oreoasis's own `COUNTERSIGNER_NOT_INDEPENDENT` check now sits behind the kernel's (AU-3b).
- `CountersignAcceptanceReport.keyCustody` widens to three values; a consumer that switched on two must handle `unknown`.
- Scripts that relied on exit 0 from `attest verify <audit bundle>` without a key must pass `--key`.
- `checkPacket` refuses honest packets older than ten minutes unless the desk widens the window; the wallet's headless desk and every test build and check at one instant.
- A non-JSON DSSE payload that verified by signature is now `MALFORMED_ARTIFACT` in a wallet, as it was before by exception.
- The Ed25519 rule rejects inputs some engines accepted (small-order keys, one non-canonical key encoding). No honest key or signature is affected: every Wycheproof `valid` case still verifies.
- Rejecting unknown top-level fields in a countersign bundle (the audit's optional hardening) was not done: the committed fixture carries a `verify` field, and consumers add notes.
- Published by hand, without provenance (d97(n)): identity-core `0.4.0-alpha.1`, attest `0.2.0-alpha.9`, predicate `0.3.0-alpha.1` on 2026-11-12, and identity-core `0.4.0-alpha.2` on 2026-11-13 — `0.4.0-alpha.1` cleared bit 255 of a key handed in as a Node Buffer (`Buffer.prototype.slice` is a view), so every check after the first failed for keys with that bit set; attest `0.2.0-alpha.9` and predicate `0.3.0-alpha.1` pin `0.4.0-alpha.1` exactly, so attest `0.2.0-alpha.10` and predicate `0.3.0-alpha.2` were published the same day pinning `0.4.0-alpha.2`. `latest` points at identity-core `0.4.0-alpha.2`, attest `0.2.0-alpha.10` and predicate `0.3.0-alpha.2` since 2026-11-13. Both scripted publish paths refuse while the repository is private — A10-04's open question — so this one release went out by hand; the next carries provenance from the opened repository (AU-11).

## Alternatives considered
- **Refuse the requester's own acceptance outright (`ok: false`):** lost, because the cohort profile has the requester accept its own request by design and the CLI's per-party label reads `ok`; marking it `independent: false` and failing only a bundle with nothing independent keeps every honest shape and still refuses the alias.
- **Require the requester among the subject's signers (`REQUESTER_NOT_IN_ENVELOPE`):** lost, because Oreoasis's acceptance path has the organisation request on its doer's record; reported as a fact instead.
- **Return `ok: false` from `verifyAuditBundle` with no trusted key:** lost, because library callers (Oreoasis's standalone verifier) read `ok` as chain integrity; the CLI's exit code carries the distinction.
- **A day-wide freshness window for SD-JWT bindings:** unnecessary — the packet builder puts the full time in both bindings; only the own-word credential's `iat` is day-rounded.
- **Keep Ed25519 edge cases with WebCrypto and only document them:** lost, because the same record is checked by Bun, Node and three browsers, and *anyone can check it offline* must give one answer.
