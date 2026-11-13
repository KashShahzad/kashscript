# @kashscript/muffler — the Data Protocol (PDS + firehose)

**Portable hosting is free.** Apache-2.0. Where record hosting/sync is the concern, ventures consume
Muffler and never reach beneath it.

Built in phase **M3** of the protocol Manifestation
([ADR-0016](../../docs/adr/0016-protocol-manifestation.md)). An **atproto-style PDS + firehose**: a
transport-agnostic client writes `did:kash`-bound repos, a firehose indexer projects them into read
models, records are content-addressed (CIDv1) and validated through an injectable **Refiner**. The
generic machinery is derived from the `@indus/muffler` venture seed; the venture-specific lexicons,
refine *rules*, `rm_*` projections, and Supabase schema stay venture-side. Full contract:
[`specs/muffler.md`](../../specs/muffler.md).

## What's inside

- **`client`** — `MufflerClient(transport, did, refiner?)`: `put`/`deleteRecord`/`uploadBlob`/`listRecords`
  over a transport-agnostic `XrpcTransport` seam (+ `tid()` sortable rkeys). Writes to a handled
  collection are refined (validated + JCS-canonical) before they leave the process.
- **`indexer`** — `MufflerIndexer`: subscribes a `FirehoseTransport`, refines each record, and pushes
  idempotent upserts/removes into a `RecordSink` keyed by `(did, collection, rkey)`. **Account
  deactivation purges the whole repo** — the decentralization guarantee, operational. Cursor-persistent,
  per-message failures isolated (an invalid record is dropped, not fatal).
- **`refine`** — the **`Refiner`** seam (`handles` + `refine` → validate · canonicalize · content-address).
  A venture supplies its own; `createLexiconRefiner` is the reference, backed by
  [`@kashscript/lexicons`](../lexicons) (`validateBody`).
- **`cid`** — `cidForBytes` (CIDv1, raw codec, sha2-256 over the JCS bytes) — the change-detection key.
- **`identity`** — `mintOrgIdentity` + `createOrgBindingRecord`/`verifyOrgBindingRecord`: bind a sovereign
  `did:kash` to the atproto repo it publishes to, verifiable with **no server round-trip**.
- **sinks** — `MemoryRecordSink` (in the barrel) and `SupabaseRecordSink` (behind the
  **`@kashscript/muffler/sink-supabase`** subpath, `@supabase/supabase-js` peer-dep) whose `rm_*`
  projections are injected as config.

## The seam

The indexer + client depend only on the `Refiner` interface — never a concrete schema. A venture keeps
its lexicons + refine rules + read-model projections and injects them:

```ts
import { MufflerIndexer, MemoryRecordSink, createLexiconRefiner } from "@kashscript/muffler";

const refiner = createLexiconRefiner({
  registry,                                     // a @kashscript/lexicons LexiconRegistry
  collectionToLexiconId: (c) => `${c}@1.0.0`,   // NSID -> lexicon id
});
await new MufflerIndexer({ firehose, sink: new MemoryRecordSink(), refiner }).run();
```

A dev-grade reference host that serves repos + emits a firehose ships as
`@kashscript/muffler-pds`, an operated service kept out of the open source.

## Status

`0.x` — the API stays `0.x` until the venture consumer (`@indus/muffler`) thins onto the published
package and its indexer test stays green (consumer-as-acceptance, ADR-0016). Depends on
[`@kashscript/identity-core`](../identity-core) + [`@kashscript/lexicons`](../lexicons).

Licensed Apache-2.0 — see `LICENSE`.
