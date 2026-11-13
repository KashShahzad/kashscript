# `@kashscript/muffler` — the Data Protocol (PDS + firehose)

**`specs/muffler.md` — v0.1 · BUILT in M3 · red-team audited round 1 (M6). Apache-2.0.**

> **Security:** [`muffler-audit-r1.md`](muffler-audit-r1.md). Fixed this round: F3 (run-loop advanced the
> cursor past a transient failure → data loss), F5 (prototype pollution through the refiner + a lexicons
> unknown-key bug), F2 (unverified `op.cid`), F6 (memory-sink key ambiguity). Logged (transport-authentication
> contract): F1 (unauthenticated firehose) + F4 (spoofed account purge) — a muffler deployment MUST pair with
> an authenticated firehose source.

> Status: **draft — built, consumer-acceptance pending.** The package is implemented and its own test
> suite is green (M3, [ADR-0016](../docs/adr/0016-protocol-manifestation.md)), but per the
> consumer-as-acceptance rule the API stays `0.x` until `@indus/muffler` thins onto the published
> package and its indexer test stays green. Every API is **derived from the `@indus/muffler` venture
> seed**; nothing is invented. **Licence: Apache-2.0 — portable hosting is free.**

## Purpose

Portable, `did:kash`-bound data hosting: an **atproto-style PDS + firehose** (DWN dropped — ECOSYSTEM
decision 2). Where record hosting/sync is the concern, ventures consume Muffler and never reach beneath
it (ECOSYSTEM decision 12). Third in the publish order (`attest → identity-server → muffler → whiffin →
hudhud`). Depends only on `@kashscript/identity-core` (JCS canonicalization + KashEvent signing) and
`@kashscript/lexicons` (record validation); peerDep `@supabase/supabase-js` (type-only, for the sink).

## Seeds (the API oracles — M3 derives from these)

- **Indusland `packages/muffler/src/{cid,identity,client,indexer,sinks/*}.ts`** — the generic client,
  CID content-addressing, `did:kash`↔atproto binding, firehose indexer, and sink adapters. Ported
  verbatim where generic; the two `app.indusland`-specific couplings (`refine`, `isMufflerCollection`)
  become the injected `Refiner`.
- **Duedale `identity-kernel` PDS read/write** — the record contract (already the `PdsStore` interface
  + reference in [`identity-server`](identity-server.md), M2). Muffler is the *durable* PDS that layer's
  contract points at.

## The generic surface

| Module | Exports | Notes |
|---|---|---|
| `cid` | `cidForBytes`, `base32`, `sha256` | CIDv1, raw codec, sha2-256 over the JCS bytes — the change-detection key. Ported verbatim. |
| `refine` | `Refiner`, `RefineError`, `RefinedRecord`, `createLexiconRefiner` | The refinement seam (below). |
| `indexer` | `MufflerIndexer`, `RecordSink`, `RecordKey`, `IndexedRecord`, `CommitOp`, `FirehoseMessage`, `FirehoseTransport` | Subscribes a firehose, refines each record, upserts/removes into a sink keyed by `(did, collection, rkey)`. Cursor-persistent; per-message failures isolated; **account deactivation purges the whole repo**. |
| `client` | `MufflerClient`, `XrpcTransport`, `BlobRef`, `tid` | Transport-agnostic `put`/`deleteRecord`/`uploadBlob`/`listRecords`; writes to a handled collection are refined before they leave the process. |
| `identity` | `mintOrgIdentity`, `createOrgBindingRecord`, `verifyOrgBindingRecord`, `KASH_ATPROTO_BINDING_{NSID,DST}` | Binds a sovereign `did:kash` to the atproto repo it publishes to; verifiable with **no server round-trip** (key-only DID resolution). NSID/DST parameterized (neutral kash defaults; a venture passes its own for wire-compat). |
| sinks | `MemoryRecordSink` (barrel), `SupabaseRecordSink` (`./sink-supabase`) | The Supabase sink's `rm_*` projections + table map are **injected config**; it ships behind a subpath so the barrel never imports the `@supabase/supabase-js` peer-dep. |

### The Refiner seam (how the venture keeps its rules)

The indexer + client depend only on the `Refiner` interface — never a concrete schema:

```
interface Refiner {
  handles(collection: string): boolean;
  refine(collection: string, record: unknown): Promise<RefinedRecord>;  // validate · canonicalize · content-address
}
```

A venture supplies its own refiner (wrapping its Zod schemas); `createLexiconRefiner({ registry,
collectionToLexiconId, postValidate? })` is the **reference implementation**, backed by
`@kashscript/lexicons` `validateBody` (ROADMAP M3 item 4). It validates the record body against its
registered lexicon, runs an optional post-validation hook (generalizes the seed's per-subcategory
attribute validator), then JCS-canonicalizes (identity-core) and CIDs. On failure it throws
`RefineError`; the indexer treats a `RefineError` as a **skip-with-report** (non-fatal), anything else
aborts the message.

## Reference host — `services/muffler-pds` (dev-grade, `private`)

`InMemoryPdsHost(did)` implements **both** `XrpcTransport` (a client writes into it) and
`FirehoseTransport` (an indexer subscribes to the commits it emits): an in-memory repo + an append-only
seq-numbered commit log + account tombstones + a blob store. A thin `createMufflerPdsServer(host)`
exposes it over HTTP (`Bun.serve` fetch handler + SSE firehose). This is "serve repos, emit firehose"
for labs/tests — **not production hosting** (no persistence, no auth, single in-process repo, no MST/
dag-cbor).

## Stays venture-side (guard b, ADR-0016)

The `app.indusland.*` lexicons + `lexicons/*.json` docs; the Zod `refine` **rules** (the concrete
schemas + attribute validators — the venture implements `Refiner`); the `rm_*` **projections** + the
Supabase **schema**/migrations (injected into `SupabaseRecordSink` as config); the venture's
`COLLECTIONS` map + typed `put*` client conveniences.

## Done when

1. **Indexer behaviors reproduced** — the generic `MufflerIndexer` + `MemoryRecordSink` + an example
   `createLexiconRefiner` pass the seed's behavior suite: project (size 2), cursor→3, update-in-place,
   0 errors on valid; resume-from-cursor, invalid record → **exactly 1 error (non-fatal)**, delete,
   account-deactivation **purges the whole repo** (size 0), cursor→6. ✅
2. **CID** determinism + construction; **identity** binding round-trip (+ wrong-did / malformed
   rejection + custom NSID/DST); **refine** validate/canonicalize/CID + `RefineError` paths + the
   postValidate hook; **client** refines-before-transport + `tid()`; **reference host** end-to-end
   round-trip. ✅
3. `typecheck` + `test` (both packages) + `check-boundary.ts` + full-workspace typecheck green. ✅
4. **Venture-side follow-up (post-publish):** `@indus/muffler` thins to `lexicons + refine(implements
   Refiner) + rm_* projections` importing `@kashscript/muffler`; its `indexer.test.ts` runs green
   against the published package (consumer-as-acceptance closes M3).

## Change Log

| Version | Date | Summary |
|---|---|---|
| **v0.1 · audit r1** | 2026-07-05 | Round-1 red-team audit (M6): F2/F3/F5/F6 fixed inline (op.cid verification, cursor-no-advance-on-failure, prototype-pollution sanitize + a `@kashscript/lexicons` unknown-key fix, injective memory-sink key); F1/F4/F7/F8 logged (firehose auth is the transport's contract). 19 tests green. See [`muffler-audit-r1.md`](muffler-audit-r1.md). |
| **v0.1** | 2026-07-05 | Built in M3 (ROADMAP Manifestation). Extracted the generic PDS client + firehose indexer + CID + `did:kash`↔atproto binding + memory/Supabase sinks from the `@indus/muffler` seed; made record refinement an injected `Refiner` (`createLexiconRefiner` reference via `@kashscript/lexicons`); shipped the `services/muffler-pds` dev-grade reference host. 19 tests green. API stays `0.x` pending the Indusland consumer swap. |
| **v0.0** | 2026-07-05 | DRAFT skeleton created in M0. |
