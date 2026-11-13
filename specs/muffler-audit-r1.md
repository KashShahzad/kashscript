# `@kashscript/muffler` — Red-Team Audit (Round 1)
**`specs/muffler-audit-r1.md`**

> **Auditor scope:** the full `packages/muffler/src` tree (PDS client, firehose indexer, sinks
> memory/Supabase, the injected Refiner) + the `services/muffler-pds` dev host + the `identity-core` /
> `lexicons` primitives it leans on, with runtime probes (M6, ADR-0016). **Outcome:** 8 findings (3 High,
> 2 Medium, 2 Low, 1 Info). 4 fixed this round (F2, F3, F5, F6 + the underlying lexicons bug); F1, F4, F7, F8
> logged (transport-authentication contract / dev-host).
> **Severity scale:** *High* = data loss / unauthenticated destructive action / pollution · *Medium* =
> integrity gap · *Low/Info* = keying / dev-host.

The package's core is sound — CID construction is a correct CIDv1-raw-sha256 over JCS bytes, and
`verifyOrgBindingRecord` is genuinely trust-free. The weaknesses cluster at the **firehose→app-view trust
boundary**: the indexer authenticates nothing about the events it ingests.

---

## Part I — Findings

### F1 — Firehose events are wholly unauthenticated · **High** · DESIGN-GAP · LOGGED (+FLAG)
- **Location:** `indexer.ts` `processCommit` / `processMessage`.
- **The hole:** `processCommit(did, ops)` takes `did` straight off the wire and builds the record key with
  **no repo-commit signature check** — a hostile/MITM'd source projects records under any victim DID. The
  package ships `verifyOrgBindingRecord` but the indexer never calls it.
- **Disposition — LOGGED + FLAGGED.** Commit authentication is properly the **transport's contract** (atproto
  `#commit` signature over the MST root), not something the generic indexer can synthesize. **Patch
  direction:** document `FirehoseTransport` MUST verify commit signatures before yielding; add an optional
  `verifyCommit?(msg)` hook to `IndexerOptions` and drop unverified commits. This is the top design finding.

### F2 — `op.cid` is never verified against the record bytes · **Medium** · DESIGN-GAP · **FIXED r1**
- **The hole:** `processCommit` recomputed `refined.cid` from `op.record` but ignored the advertised
  `op.cid`, so a body/CID swap was silent.
- **Fix:** when `op.cid` is present, the indexer now asserts it equals the recomputed content address and
  **skips (reports, does not index)** a mismatch. (Its integrity value fully lands once F1's commit-signature
  check makes `op.cid` itself trustworthy.)

### F3 — Run-loop advanced the cursor past a transiently-failed record (silent data loss) · **High** · CODE-BUG · **FIXED r1**
- **The hole:** on a caught error the loop called `onError` but **continued**; the next message's success
  called `saveCursor(laterSeq)`, permanently skipping the failed seq. (A poison record is already a
  `RefineError` skip *inside* `processCommit`; only unexpected/transient errors — sink failure — reached here.)
- **Fix:** the run-loop now **halts** on an unexpected error (the un-saved cursor forces re-delivery from the
  last good seq on the next run — at-least-once). Documented that poison records remain a per-op skip.

### F4 — A spoofed `account{active:false}` purges an entire repo · **High** · DESIGN-GAP · LOGGED
- **The hole:** `if (!message.active) purgeRepo(message.did)` acts on an unauthenticated field; one forged
  frame `DELETE`s every row for a victim DID.
- **Disposition — LOGGED (ties to F1).** Gated behind the same transport authentication as F1; **patch
  direction:** prefer a reversible tombstone (mark inactive) over a hard delete, with reconciliation before
  permanent removal.

### F5 — `__proto__`/`constructor` survive lexicon validation + the value is returned by reference · **Medium** · CODE-BUG · **FIXED r1**
- **The hole:** two compounding bugs. (a) `validate()` returned the input object **by reference**; (b) the
  lexicons unknown-key check used `k in s.properties`, which is `true` for `__proto__` via `Object.prototype`
  — so a `__proto__` key passed even a strict (`additionalProperties:false`) schema. A prototype-polluting
  record reached venture sinks verbatim.
- **Fix (two packages):** (a) the muffler refiner now **deep-clones** the validated value and drops
  `__proto__`/`constructor`/`prototype` own-keys before returning (`sanitizeRecord`); (b) `@kashscript/lexicons`
  `validateObject` now uses `Object.prototype.hasOwnProperty.call(s.properties, k)`, so a strict schema
  correctly rejects those keys. Regression test: "a `__proto__` key never pollutes and never survives."

### F6 — `MemoryRecordSink` composite key is delimiter-ambiguous · **Low** · CODE-BUG · **FIXED r1**
- **The hole:** keys were `${did}|${collection}|${rkey}` and `purgeRepo` used a `startsWith` prefix — a `|`
  inside an (unvalidated) `did` made distinct records collide / over-purge.
- **Fix:** the key is now `JSON.stringify([did, collection, rkey])` (injective), and `purgeRepo` matches the
  exact decoded `did`. Regression test: "purgeRepo removes only the exact did, not a delimiter-collision."

### F7 — No bound on per-commit `ops` length or record size · **Low** · DESIGN-GAP · LOGGED
- **The hole:** `processCommit` loops `ops` unbounded; a huge `ops[]` / multi-MB record blocks the
  single-threaded indexer.
- **Disposition — LOGGED.** **Patch direction:** cap `ops.length` + serialized record size (reject oversize
  as a skip-with-report); document that production transports must bound frame size.

### F8 — Dev host recomputes CID over `JSON.stringify` (insertion-order), not JCS · **Info** · CODE-BUG · LOGGED
- **The hole:** `services/muffler-pds` `putRecord` hashes non-canonical JSON, so its returned `cid` differs
  from the indexer's JCS CID (intentional for a dev host, but a copy-toward-production trap).
- **Disposition — LOGGED.** **Patch direction:** compute the dev-host CID via `canonicalizeBytes`, or annotate
  the call site (not just the file header) that the returned `cid` is non-canonical.

---

## Part II — Disposition Summary

| Finding | Severity | Disposition |
|---|---|---|
| F1 unauthenticated firehose | High | LOGGED + FLAG (transport contract; add verifyCommit hook) |
| F2 unverified op.cid | Medium | **FIXED r1** (assert + skip on mismatch) |
| F3 cursor-past-failure data loss | High | **FIXED r1** (halt, don't advance) |
| F4 spoofed account purge | High | LOGGED (reversible tombstone; gate on F1) |
| F5 prototype pollution | Medium | **FIXED r1** (refiner sanitize + lexicons hasOwnProperty) + test |
| F6 memory-sink key ambiguity | Low | **FIXED r1** (JSON key) + test |
| F7 unbounded ops/size | Low | LOGGED (cap + document) |
| F8 dev-host non-JCS CID | Info | LOGGED |

## Part III — What the package gets right
- **CID integrity — solid.** CIDv1 raw+sha256 over JCS-canonical bytes, recomputed deterministically on
  write + index; the app-view value re-addresses byte-for-byte.
- **Binding-record auth — solid.** `verifyOrgBindingRecord` re-derives the pubkey from the claimed
  `did:kash`, checks the bound atproto DID, and re-verifies the Ed25519 signature — no server trust. (The
  gap is that the indexer doesn't *use* it — F1.)
- **Supabase injection — solid.** All values go through PostgREST-parameterized `.eq()`/`.upsert()`; record
  fields are not a SQL-injection vector; the Supabase peer is quarantined behind `./sink-supabase`.
- **Refiner gating — solid.** The indexer strictly gates on `refiner.handles(collection)` and only indexes
  what `refine()` returns; validation failure is a non-fatal skip.

## Part IV — Residual Risks Carried Forward
- **Firehose authentication (F1/F4)** is the transport's responsibility; muffler's contract must state it
  loudly and offer the `verifyCommit` hook. Until then, a muffler deployment MUST pair with an authenticated
  firehose source.
- **Resource bounds (F7)** — an unbounded hostile frame can stall the indexer until the cap lands.

---
**End of Round 1.** F2/F3/F5/F6 fixed with tests this session (+ the underlying lexicons pollution bug);
F1/F4/F7/F8 carried with patch directions.
