// In-memory RecordSink — for tests and local indexer dry-runs. Mirrors a
// durable sink's keying ((did, collection, rkey)) so a round-trip proven here
// matches production semantics. Ported verbatim from the @indus/muffler seed.

import type { IndexedRecord, RecordKey, RecordSink } from "../indexer";

// audit r1 F6: JSON-encode the composite key so it is INJECTIVE — the old
// `${did}|${collection}|${rkey}` form let a `|` inside an (unvalidated) did/
// collection/rkey make two distinct records collide, and made `purgeRepo`'s
// prefix match over-purge. A JSON array has unambiguous field boundaries.
function keyOf(k: RecordKey): string {
  return JSON.stringify([k.did, k.collection, k.rkey]);
}

export class MemoryRecordSink implements RecordSink {
  private readonly store = new Map<string, IndexedRecord>();
  private cursor: number | null = null;

  async upsert(record: IndexedRecord): Promise<void> {
    this.store.set(keyOf(record), record);
  }

  async remove(key: RecordKey): Promise<void> {
    this.store.delete(keyOf(key));
  }

  async purgeRepo(did: string): Promise<void> {
    for (const k of [...this.store.keys()]) {
      if ((JSON.parse(k) as [string, string, string])[0] === did) this.store.delete(k);
    }
  }

  async loadCursor(): Promise<number | null> {
    return this.cursor;
  }

  async saveCursor(seq: number): Promise<void> {
    this.cursor = seq;
  }

  get(key: RecordKey): IndexedRecord | undefined {
    return this.store.get(keyOf(key));
  }

  all(): IndexedRecord[] {
    return [...this.store.values()];
  }

  get size(): number {
    return this.store.size;
  }

  get cursorValue(): number | null {
    return this.cursor;
  }
}
