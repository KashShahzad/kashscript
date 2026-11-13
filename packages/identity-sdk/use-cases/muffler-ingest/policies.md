# Policies — Muffler ingest

Operational rules the host enforces. Each policy maps to a config knob on `MufflerHost`, a wire-format constraint, or a refusal posture.

---

## P-001 · Required DST

**Rule:** every accepted signature MUST carry `dst === "kash-record-v1\n"` (the default), unless the host operator overrides via `MufflerHostPolicy.requiredDst`.

**Why:** the DST scopes a signature to a subprotocol. A trade-tier or handshake-tier signature happens to use a different DST. Without this check, a malicious actor could capture a `kash-record-v1` signature and try to replay it as, say, a `kash-trade-v1` settle-signal.

**Configurable:** yes (`requiredDst` field on the host policy). Most deployments leave it at default.

**Error code:** `DST_MISMATCH`.

---

## P-002 · Lexicon allowlist (optional)

**Rule:** if `policy.lexiconAllowlist` is set, the host rejects every lexicon NOT in the list.

**Why:** a single Muffler host may want to specialise. E.g., a profile-host accepts `kash.id.profile@1.0.0` only and rejects everything else. The allowlist is the simplest enforcement.

**Configurable:** yes (omit the field for "open"; supply an array to lock down).

**Error code:** `LEXICON_UNKNOWN` (same code as "lexicon not in the registry" — both mean "I won't serve this kind of record").

---

## P-003 · DID-pubkey coherence

**Rule:** the host MUST verify that `deriveDid(pubkey) === header.did`. The pubkey comes from base58btc-decoding the DID method body.

**Why:** without this check, an attacker could mint an envelope claiming someone else's DID. The signature would have been made with the attacker's key; the verifier needs to confirm the *DID being claimed* actually corresponds to the *key that signed*.

**Configurable:** no — non-negotiable for sovereignty.

**Error code:** `DID_MISMATCH` (when re-derivation produces a different DID) or `DID_DERIVE_FAILED` (when the method body isn't a valid base58btc 32-byte pubkey).

---

## P-004 · Nonce minimum entropy

**Rule:** `header.nonce` must be at least 32 hex chars (128 bits of entropy). The format is enforced by the lexicon engine's envelope schema.

**Why:** prevents trivial nonce collisions across the host's record set. Also makes brute-forcing a colliding header very expensive.

**Configurable:** no.

**Error code:** `ENVELOPE_MALFORMED` (the validator surfaces the field path).

---

## P-005 · rkey uniqueness per `(did, lexicon)`

**Rule:** the host rejects an ingest where `(did, lexicon, rkey)` is already stored.

**Why:** records are addressed by `(did, lexicon, rkey)`. Two writes to the same address would require the host to choose a winner, which is bad. Make the consumer be explicit: delete-then-write, or use a fresh rkey.

**Configurable:** no in v1. Future: an `--upsert` flag may flip this to "replace".

**Error code:** `RKEY_DUPLICATE`.

---

## P-006 · Body size limits (deferred)

**Rule:** v1 has no host-level body-size limit. The lexicon constraints cap individual fields (e.g., `text` ≤ 1000 chars), but a malicious actor could pack 16 media refs with very long altText fields.

**Why:** real Muffler deployments will need this. Stub doesn't enforce it because the use case is about correctness, not abuse-resistance.

**Configurable:** to be added in v2 — `MufflerHostPolicy.maxBodyBytes`.

**Error code:** TBD — likely `BODY_TOO_LARGE`.

---

## P-007 · No read-side authentication

**Rule:** `get()` and `listByCollection()` return records to anyone. The host is a public surface.

**Why:** records carry their own author signatures; anyone can verify them. There's no secrecy in a published record — secrecy belongs to the unpublished state. If a consumer needs private records, they don't publish them.

**Configurable:** a future "private record" mode is plausible (encrypted body with a separate access-control DID-set), but it's a different lexicon.

---

## P-008 · No timestamp verification

**Rule:** `header.iat` is accepted as-is. The host does NOT compare it against wall-clock time.

**Why:** clock drift, time-zone confusion, and replay defence via `iat` is brittle. The nonce + rkey-uniqueness checks already prevent replay; iat is informational metadata.

**Configurable:** a future "freshness window" may add a `maxIatDriftSeconds` policy for high-security deployments.

**Error code:** none today. Future: `IAT_OUT_OF_RANGE`.

---

## P-009 · Single-process; not thread-safe

**Rule:** the stub uses an in-memory `Map`. No coordination across processes.

**Why:** stub. Production hosts will need transactional writes (e.g., Postgres `INSERT ... ON CONFLICT FAIL`).

**Configurable:** the entire `MufflerHost` storage layer is replaceable. The verification logic is decoupled from storage.

---

## Default policy summary

```ts
{
  requiredDst: "kash-record-v1\n",
  lexiconAllowlist: undefined,           // open
  // future:
  // maxBodyBytes: undefined,             // unlimited
  // maxIatDriftSeconds: undefined,       // unchecked
}
```

For most Indusland-style deployments, the default is fine. Schools, government partners, and other regulated tenants would tighten with an allowlist + body-size limit.
