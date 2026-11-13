// MufflerIndexer — projects did:kash-bound repos into an app-view.
//
// Subscribes to a firehose (FirehoseTransport — an atproto subscribeRepos
// adapter in production), refines each record through an injected Refiner, and
// pushes idempotent upserts/removes into a RecordSink keyed by
// (did, collection, rkey). Account-deactivation tombstones purge the whole
// repo — a provider pulling their data removes it from the app-view
// mechanically, which is the decentralization guarantee made operational.
//
// The core is transport-, sink-, AND refiner-agnostic so it round-trips
// against an in-memory sink + example lexicons in tests; production wires the
// atproto firehose, the venture's refiner, and a durable sink. Ported from the
// @indus/muffler seed (M3, ADR-0016); the sole change is that `refine` +
// `isMufflerCollection` — both venture-specific in the seed — are now the
// injected `Refiner` (the venture supplies its rules; guard b).

import { RefineError } from "./refine";
import type { Refiner } from "./refine";

export interface RecordKey {
  did: string;
  collection: string;
  rkey: string;
}

export interface IndexedRecord extends RecordKey {
  cid: string;
  value: unknown;
  indexedAt: string;
}

export interface RecordSink {
  upsert(record: IndexedRecord): Promise<void>;
  remove(key: RecordKey): Promise<void>;
  purgeRepo(did: string): Promise<void>;
  loadCursor(): Promise<number | null>;
  saveCursor(seq: number): Promise<void>;
}

export interface CommitOp {
  action: "create" | "update" | "delete";
  collection: string;
  rkey: string;
  record?: unknown;
  cid?: string;
}

export type FirehoseMessage =
  | { kind: "commit"; seq: number; did: string; ops: CommitOp[] }
  | { kind: "account"; seq: number; did: string; active: boolean }
  | { kind: "identity"; seq: number; did: string };

export interface FirehoseTransport {
  events(cursor: number | null): AsyncIterable<FirehoseMessage>;
}

export interface IndexerOptions {
  firehose: FirehoseTransport;
  sink: RecordSink;
  /** The record-refinement seam (validate + canonicalize + content-address).
   *  The venture supplies its rules; `createLexiconRefiner` is the reference. */
  refiner: Refiner;
  // Per-message failures are isolated so one bad record can't stall the
  // stream. Validation rejections (RefineError) land here too (skipped, not fatal).
  onError?: (err: unknown, message: FirehoseMessage) => void;
  now?: () => string;
}

export class MufflerIndexer {
  private readonly firehose: FirehoseTransport;
  private readonly sink: RecordSink;
  private readonly refiner: Refiner;
  private readonly onError: (err: unknown, message: FirehoseMessage) => void;
  private readonly now: () => string;

  constructor(opts: IndexerOptions) {
    this.firehose = opts.firehose;
    this.sink = opts.sink;
    this.refiner = opts.refiner;
    this.onError = opts.onError ?? (() => {});
    this.now = opts.now ?? (() => new Date().toISOString());
  }

  async run(signal?: AbortSignal): Promise<void> {
    const cursor = await this.sink.loadCursor();
    for await (const message of this.firehose.events(cursor)) {
      if (signal?.aborted) return;
      try {
        await this.processMessage(message);
        await this.sink.saveCursor(message.seq);
      } catch (err) {
        // audit r1 F3: an UNEXPECTED error (sink failure, or a non-RefineError)
        // means this seq's cursor was never saved — HALT rather than continue, so
        // a later message's success can't commit a cursor BEYOND the gap and drop
        // the failed record forever. A re-run re-delivers from the last good
        // cursor (at-least-once). Poison records are already skipped as
        // RefineError inside processCommit and never reach here.
        this.onError(err, message);
        return;
      }
    }
  }

  async processMessage(message: FirehoseMessage): Promise<void> {
    switch (message.kind) {
      case "commit":
        await this.processCommit(message.did, message.ops);
        return;
      case "account":
        if (!message.active) await this.sink.purgeRepo(message.did);
        return;
      case "identity":
        return;
    }
  }

  private async processCommit(did: string, ops: CommitOp[]): Promise<void> {
    for (const op of ops) {
      if (!this.refiner.handles(op.collection)) continue;
      const key: RecordKey = { did, collection: op.collection, rkey: op.rkey };

      if (op.action === "delete") {
        await this.sink.remove(key);
        continue;
      }

      let refined;
      try {
        refined = await this.refiner.refine(op.collection, op.record);
      } catch (err) {
        // A record that fails validation is dropped, not indexed — but it
        // must not abort the rest of the commit.
        if (err instanceof RefineError) {
          this.onError(err, { kind: "commit", seq: -1, did, ops: [op] });
          continue;
        }
        throw err;
      }

      // audit r1 F2: if the commit advertised a CID, it MUST equal the record's
      // recomputed content address. A body/CID mismatch is a tamper signal — skip
      // it (report, don't index) rather than store bytes that don't match the CID
      // the repo committed.
      if (op.cid !== undefined && op.cid !== refined.cid) {
        this.onError(
          new RefineError("INVALID_RECORD", `CID_MISMATCH: ${op.collection}/${op.rkey} advertised ${op.cid} but record hashes to ${refined.cid}`),
          { kind: "commit", seq: -1, did, ops: [op] },
        );
        continue;
      }

      await this.sink.upsert({
        ...key,
        cid: refined.cid,
        value: refined.value,
        indexedAt: this.now(),
      });
    }
  }
}
