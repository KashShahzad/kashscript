# ADR-0020: We add ES256 beside Ed25519 with the algorithm always taken from the key, and recover lost keys by succession through a helper quorum — never by copying

- **Status:** Accepted
- **Date:** 2026-10-01
- **Decision drivers:** ECOSYSTEM d47(g) (a hardware root that signs no records; signing keys per relationship that sign in hardware where it holds the algorithm; ES256 beside Ed25519 for SD-JWT and OpenID4VP; recovery by succession, never by copying); d41 (*separate identifiers per relationship*); d27.1 (the subject holds the key); d28 (verification needs nobody); d11 (say what is not checked)

## Context

The kernel signed Ed25519 only. A phone's secure chip holds P-256 only (the iPhone's Secure Enclave without exception), and SD-JWT VC / OpenID4VP ecosystems expect ES256. So a person's keys could either live in software — sealed, but copyable — or the kernel had to sign and verify P-256. d47(g) chose the second, and made recovery succession: a key in a chip cannot leave it, so a lost phone's keys are gone and only their **authority** can move.

Four constraints shaped the design:

1. **Every existing identifier, artifact and vector stays untouched.** `did:kash` is a bare base58 Ed25519 key with about 255 call sites to `parseDid` across the kernel.
2. **Algorithm confusion.** An Ed25519 signature and a raw ES256 signature are both 64 bytes; a DSSE signature names no algorithm at all.
3. **ECDSA malleability.** `(r, n − s)` verifies wherever `(r, s)` does, and WebCrypto accepts both.
4. **Helpers must not become a linkage point.** A helper set shown to two places must not let them join the person (d41), and helpers must never see a record.

## Decision

**A P-256 `did:kash` is `did:kash:<base58btc(0x80 0x24 ‖ 33-byte compressed point)>`** — the multicodec `p256-pub` prefix, so the body is byte-identical to `did:key`'s (`did:kash:Dn…` ↔ `did:key:zDn…`). An Ed25519 `did:kash` stays a bare 32-byte body. The lengths differ (32 vs 35), so the two never collide, and a parser older than this one rejects a P-256 identifier with `INVALID_KEY_BYTES` — closed, not open. **`parseDid` / `deriveDid` / `isKashDid` keep their exact Ed25519 meaning**; the typed functions are `parseDidKey`, `didKeyType`, `deriveDidP256` and `deriveDidForKey`. The DID document carries a `Multikey` with codec `0x8024`.

**The algorithm always comes from the key.** A DSSE resolver returns a bare 32-byte key (Ed25519, as before) or a typed key; a Kash-Event is verified by `verifyEventForKey`, which requires the signature's `alg` to match the key's type; a JWS header's `alg` must equal the one its key implies (EdDSA for OKP Ed25519, ES256 for EC P-256), and anything else is false. A 32-byte key is never read as P-256, nor a 33/65-byte key as Ed25519.

**Each family's own encoding, low-S always.** Kash-Event `es256` and JWS: raw `r ‖ s` (64 bytes, RFC 7518). **DSSE: strict ASN.1 DER**, because Sigstore tooling verifies ECDSA DSSE that way and `dsse.ts` promises standard-tool verification. Signing normalises to low-S — including a hardware signer's DER — and verifying rejects high-S, out-of-range scalars, and non-minimal DER. One signed thing has one signature.

**A runtime without Ed25519** (older browsers, some WebViews) reports `RUNTIME_CANNOT_CHECK` — nothing judged — never an invalid signature. ES256 verifies there.

**Recovery by a helper quorum, through the existing key-claim DST.** One new DST, registered first: `kash-recovery-helpers-v1` — a helper set a key signs **in advance**, naming helper keys and `need`. A helper claim is ADR-0018's claim body plus `by:"helpers"` and the set's digest, signed by the successor and by the helpers; prior-key claims are byte-identical to ADR-0018's. `need` is **at least two and a strict majority**, adopted from `identity-sdk/recovery.ts`, so any two quorums share a helper and a fork exposes the helper who signed both; two successors for one key are trusted by nobody. The successor always signs, so a claim names only a key someone holds. Succession runs either way across algorithms.

**No helper key links two places.** Each helper enrols with a pool of 32 fresh keys for one person, and each place's key names a different key from every pool. A pool key is never reused; a place past the pool waits uncovered. **The platform is never a helper by default** — a wallet starts with none.

**Hardware keys are generated per relationship and recorded in the wallet's registry.** The root stays agree-only; ES256 relationship and copy keys are separate keys in the chip. identity-server's HKDF derivation stays for server-side ceremonies only, and its source is not touched.

## Consequences

### Positive

- A person's keys can live in the phone's secure chip and never leave it; the ecosystem can present to ES256-only verifiers.
- Verification still needs nobody: both key types are inside their identifiers, and every new artifact verifies offline in Node 22 and in a browser build.
- Every Ed25519 identifier, artifact and vector is untouched; nothing was re-signed.
- A lost phone is recoverable without a seed phrase, a server-held key or a copy of any key.

### Negative / accepted trade-offs

- **Rejecting high-S is stricter than RFC 7518.** An outside ES256 signer that does not normalise fails about half the time. Acceptable while the trust list is ecosystem-only (d47(e)); revisit when an outside issuer is listed.
- **Keys are not people.** One person with two phones can hold two helper keys; the wallet refuses what it can see (its own keys, repeats, a second enrolment from one phone) and says the rest plainly.
- **A helper set that never lapses stays valid until superseded** where shown. Lapsing would lock ordinary people out — the worse failure. Offline, absence of a newer set or a conflicting claim cannot be proven.
- **Recovery needs a copy saved off the phone.** Records and helper sets come back from it; without one, nothing does.
- **Copies bound to a lost key cannot be shown**; their issuer re-issues. Re-issue on a presented succession is not built.
- **A helper who colludes with a place** can tell it the person recovered there.

## Alternatives considered

- **A second DID method (`did:key` or a new `did:kash` sub-method)** — rejected: every holder identifier stays `did:kash`, and the multicodec body already gives `did:key` interoperability.
- **Extend `parseDid` to return either key** — rejected: about 255 call sites assume 32 bytes; a typed parallel function fails closed instead.
- **Raw `r ‖ s` in DSSE** — rejected: breaks verification with Sigstore tooling.
- **One helper key per helper, shared by every place** — rejected: it is a cross-relationship identifier the moment two places are shown a succession (d41).
- **Helper keys derived per place by key blinding** — deferred: needs curve arithmetic WebCrypto does not expose and a chip cannot perform; pools give the same unlinkability with no new mathematics, and the format does not change if derivation replaces them.
- **Recovering by restoring a key backup** — kept only as the escape hatch the holder chooses (holder contract §2); never the default, and never possible for a key in a chip.
- **Reusing `identity-sdk/recovery`** — its rule (strict majority) was adopted; its format was not: Ed25519 only, the new key never proves possession, the quorum reference is unconstrained, and its DSTs `kash-recovery-v1` / `kash-rotation-v1` are not in the registry (a finding, not fixed here).
