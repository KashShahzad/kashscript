# ADR-0003: Self-certifying `did:kash` identifiers; DID resolver deferred

- **Status:** Accepted (recorded retroactively 2026-07-04)
- **Date:** 2026-07-04
- **Decision drivers:** offline verifiability, no trusted third party, shipping the minimum service surface

## Context

Every actor in the system — human, agent, contract — needs a stable decentralized
identifier. DID methods split into two families: **ledger/log-anchored** (AT Protocol's
`did:plc`: the DID is a hash of a genesis operation, and a resolver replays an op log to get
the current document) and **self-certifying** (Nostr-style: the identifier *is* the public
key, so the document is reconstructible locally with zero network).

A log-anchored method supports stable DIDs across key rotation but requires operating a
resolver/witness infrastructure from day one. A self-certifying method needs no
infrastructure but ties the identifier to one key.

## Decision

The **implemented** method is self-certifying: `did:kash:<base58btc(Ed25519 pubkey)>`
(`identity-core/src/did.ts`: `deriveDid` / `parseDid`; document reconstruction via
`createDidDocument()` — local, offline, zero network).

The mutation history that a self-certifying DID cannot carry is handled **peer-to-peer
instead of by lookup**:

- **Key rotation** → a signed **succession chain** (`identity-sdk/rotation`): a counterparty
  that pinned the genesis DID walks the chain to the current key.
- **Total-loss recovery** → an **M-of-N advisor quorum** (`identity-sdk/recovery`), also a
  verifiable signed artifact.

Consequently `services/kash-resolver` is **intentionally not built**. Its README is a
placeholder recording the explicit build triggers: (1) mutation history must be discoverable
by parties who never received the chain out-of-band, (2) handle → DID resolution at scale,
(3) a witness/timestamping tier (CT-for-DIDs). If built, it must stay
**distrusted-by-default** — every response independently verifiable by replay.

### Known spec divergence (must be reconciled)

The Identity Bible v1.1 (`specs/identity-protocol-v1.md`) specifies **`did:ks`** as a
hash-of-genesis-op method with a full op log, four-tier key hierarchy, and witness tier —
i.e. the log-anchored family. The shipped `identity-core` implements the self-certifying
`did:kash` described above. The Bible is the **target architecture** and this ADR the
**implemented position** — reconciled 2026-07-04 by **Amendment A1** in the Bible's
header, which is the spec's own prescribed mechanism for deviations. The DID `@context`
is `https://kashscript.com/ns/did/v1` — bare host, never `www.` (ADR-0013).

## Consequences

### Positive

- Zero resolver infrastructure to operate, secure, or DDoS-protect; verification works
  offline and in air-gapped audits.
- No trusted third party is introduced into the identity layer — matching the "Foundry never
  custodies" posture (ADR-0012).

### Negative / accepted trade-offs

- The genesis identifier is burned if the genesis key must be abandoned *and* the
  counterparty never receives the succession chain — the exact gap a resolver would close.
- Handle → DID resolution (`alsoKnownAs`) has no serving path yet.
- The op-log tier of the Bible remains unimplemented; Amendment A1 documents the gap but
  the migration path to `did:ks` (if ever needed) is still undesigned.

## Alternatives considered

- **Ship `did:ks` per the v1.1 Bible now** — rejected for now: requires resolver + witness
  operations before any product needs them.
- **Use `did:key` / `did:plc` as-is** — `did:key` lacks the PDS service-endpoint binding;
  `did:plc` hard-depends on Bluesky-operated infrastructure.

> **Dated note, 2026-10-01 (PL-2).** `did:kash` now has a second, P-256 form —
> `did:kash:<base58btc(0x80 0x24 ‖ compressed point)>` — beside the Ed25519 form above, which is
> unchanged. The **wallet's** total-loss recovery is the helper-quorum key claim of ADR-0020 and
> `specs/recovery.md`, not `identity-sdk/recovery`; that SDK primitive stands as written.
