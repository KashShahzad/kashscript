# ADR-0035: `did:kash` retired for standard identifiers — `did:key` names a self-certifying key, `did:web` an organisation; everything already signed reads for ever

- **Status:** Accepted
- **Date:** 2026-11-26
- **Decision drivers:**
  - ECOSYSTEM d97(h) (RW-19, branch B): no DID method is registered; where a stranger must resolve an identifier, a standard method is used; the plan says what a self-certifying key is called; every record already signed stays checkable for ever.
  - d91(e): the wire formats are the standard ones — `did:web` for organisations; attest's envelope is an internal convenience.
  - d71 (STRATEGY): build on the international rails; no format of our own.
  - d60(a): a public record is its publisher's DID plus a path; a changed identifier gets a signed pointer, and the old record is never rewritten.
  - d99: identifiers inside signed records and the engines' opaque ids are kept; renaming them is a kernel format revision.
  - AU-3 / A7-02: two spellings of one key give one name wherever signers are counted or compared.

## Context

`did:kash` is self-certifying (ADR-0020): the body is the key, base58btc — raw 32 bytes for Ed25519, the `p256-pub` multicodec and compressed point for P-256, which is byte-for-byte what `did:key` carries after its `z`. It was never registered, and d97(h) rules it never will be: a stranger's standard tooling cannot read an unregistered method, and registering one would be a format of our own (d71). Meanwhile the kernel already half-knew the answer: `kash.attestation@1.0.0` accepts `did:web` parties (RW-14), and attest's `resolveVerificationKey` reads `did:key` keyids (AU-3) through a private copy of the parsing. The public-record lexicons, though, pinned every id and publisher to `did:kash`, the holder's resolution order and trust-list pinning compared exact spellings, a rule read only a self-certifying author, and no document told a stranger what `did:kash` is. There is no resolver to alias: `services/kash-resolver` was never built and `services/kash-registry` never published — branch B's "redirecting alias for one year" is vacuous and is recorded as such, not faked.

## Decision

1. **The names.** An organisation a stranger resolves is `did:web` on its own domain. A self-certifying key is called `did:key` wherever it is written anew for a stranger; a publisher without a domain roots its records under its `did:key`. `did:kash` is the same key's house spelling: read for ever in everything already signed, kept as the kernel's internal canonical comparison form (`canonicalSignerOf`) and in the engines' opaque internal ids (d99), and written no more where a stranger reads.
2. **One implementation of the mapping**, in `@kashscript/identity-core`: `did-key.ts` (`deriveDidKey`, `parseDidKeyMethod`, `toDidKey`, `fromDidKey`, `parseAnyKeyDid`; lossless both ways, P-256 the literal `z`-prepend) and `did-web.ts` (`DID_WEB_SOURCE`, the one grammar `kash.attestation` already publishes; `parseDidWeb`; `didWebUrl`, derivation only, never a fetch). attest's private did:key parsing is replaced by it.
3. **Two spellings are one party on every comparing path:** attest's keyid resolution and the holder's step 1 (`selfCertifyingTypedKey` reads both), trust-list publisher pinning, version choice and self-listed issuers (canonical comparison), predicate's rule author match, `signRule`'s signer check and DCQL `kash_issuer` values, the wallet's restore refusal.
4. **The public records re-issued in new versions** — `kash.place@1.1.0`, `kash.place.pointer@1.1.0`, `kash.listing@1.1.0`, `kash.guide@1.1.0`, `kash.rule@1.3.0`, `kash.adoption@1.1.0`, `kash.trust-list@1.1.0` — whose publisher grammar is the superset `did:kash | did:key | did:web` (the registry resolves a 1.x record with the newest 1.x schema, so a superset is the only widening that keeps old records valid). The trust list's publisher stays self-certifying, either spelling, never `did:web`. The published JSON Schemas are regenerated; `kash.status-list` needs no new version (its issuer was already free text). Moving a live record to its `did:web` id is d60(a)'s pointer, unchanged.
5. **A `did:web`-authored rule reads offline only with its key handed in** (`readRule`'s `resolveKey`, mirroring attest's `RecordCheckOptions`): a pinned trust list's or a held key, never fetched; without one the refusal says exactly what to hand in.
6. **Emission does not flip in this release.** What signers write inside envelopes (wallet keyids, the engines' issuer lines, `kash.attestation`'s own `PARTY_DID_PATTERN`/`KEY_DID_PATTERN`) flips to the standard spellings in a later release, after both engines re-pin and read both spellings end to end — the reversible order for an identifier change. `specs/did-kash.md` lists the re-pins.
7. **The retirement is permanent and documented where a stranger looks:** `specs/did-kash.md` (what `did:kash` was, the names, the mapping with the live ceremony key as a worked row, every identifier class in use and its disposition, the resolver truth, the re-pin list); the attestation profile's §1.1 settled and open problem 39 closed; both services' READMEs dated.

## Consequences

- A stranger meeting this ecosystem's new records needs only registered methods; one page explains every `did:kash` they will ever meet in old ones, which verify for ever.
- Old readers (engines pinned to earlier lexicons) refuse a `did:web`-rooted record until they re-pin — correct and expected; the re-pin list names them.
- Versions this run leaves in-tree, published only by the founder: identity-core `0.5.0-alpha.0`, attest `0.3.0-alpha.4`, lexicons `0.7.0-alpha.0`, predicate `0.3.0-alpha.6`, wallet `0.1.0-alpha.8`.
- The acceptance test is in the lexicons: every example resolves under `did:web` (`test/did-web.test.ts`), the pointer carries a place from its old identifier, old fixtures still validate, and the copied grammar sources are byte-equal to identity-core's.
