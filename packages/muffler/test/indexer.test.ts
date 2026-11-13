// M3 acceptance (ROADMAP done-when #1): the @indus/muffler indexer test
// BEHAVIORS, reproduced against @kashscript/muffler's generic indexer with an
// injected refiner + example lexicons. Projects, replaces in place, validates
// (invalid skipped, non-fatal), deletes, and purges on account deactivation;
// the cursor advances and resumes. Mirrors the seed's src/indexer.test.ts.

import { describe, it, expect } from "bun:test";
import { MufflerIndexer } from "../src/indexer";
import type { FirehoseMessage, FirehoseTransport } from "../src/indexer";
import { MemoryRecordSink } from "../src/sinks/memory";
import { EXAMPLE, exampleRefiner } from "./example-lexicons";

const DID = "did:plc:karavan";
const NOW = "2026-06-11T00:00:00.000Z";

function firehoseOf(messages: FirehoseMessage[]): FirehoseTransport {
  return {
    async *events(cursor) {
      for (const m of messages) if (cursor == null || m.seq > cursor) yield m;
    },
  };
}

describe("MufflerIndexer — projects, replaces, validates, deletes, and purges", () => {
  it("runs the full seed behavior suite", async () => {
    const sink = new MemoryRecordSink();
    const refiner = exampleRefiner();
    const errors: unknown[] = [];

    const first = firehoseOf([
      {
        kind: "commit",
        seq: 1,
        did: DID,
        ops: [{ action: "create", collection: EXAMPLE.profile, rkey: "self", record: { displayName: "Karavan Tours" } }],
      },
      {
        kind: "commit",
        seq: 2,
        did: DID,
        ops: [
          {
            action: "create",
            collection: EXAMPLE.experience,
            rkey: "e1",
            record: { title: "Old City food walk", subcategories: ["food-tours"] },
          },
        ],
      },
      {
        kind: "commit",
        seq: 3,
        did: DID,
        ops: [
          {
            action: "update",
            collection: EXAMPLE.experience,
            rkey: "e1",
            record: { title: "Walled City food walk", subcategories: ["food-tours"] },
          },
        ],
      },
    ]);

    await new MufflerIndexer({ firehose: first, sink, refiner, onError: (e) => errors.push(e), now: () => NOW }).run();

    expect(sink.size).toBe(2); // profile + one experience indexed
    expect(sink.cursorValue).toBe(3); // cursor advanced to last seq
    const exp = sink.get({ did: DID, collection: EXAMPLE.experience, rkey: "e1" });
    expect((exp?.value as { title: string }).title).toBe("Walled City food walk"); // update replaced in place
    expect(errors.length).toBe(0); // no errors on valid records

    // Resume from the saved cursor: an invalid record is skipped (not fatal),
    // a delete removes one record, then account deactivation purges the repo.
    const second = firehoseOf([
      {
        kind: "commit",
        seq: 4,
        did: DID,
        ops: [{ action: "create", collection: EXAMPLE.experience, rkey: "bad", record: { title: "missing subcategories" } }],
      },
      {
        kind: "commit",
        seq: 5,
        did: DID,
        ops: [{ action: "delete", collection: EXAMPLE.experience, rkey: "e1" }],
      },
      { kind: "account", seq: 6, did: DID, active: false },
    ]);

    await new MufflerIndexer({ firehose: second, sink, refiner, onError: (e) => errors.push(e), now: () => NOW }).run();

    expect(errors.length).toBe(1); // invalid record reported once, stream continued
    expect(sink.size).toBe(0); // account deactivation purged the whole repo
    expect(sink.cursorValue).toBe(6); // cursor advanced through the purge
  });

  it("skips ops for collections the refiner does not handle", async () => {
    const sink = new MemoryRecordSink();
    const firehose = firehoseOf([
      {
        kind: "commit",
        seq: 1,
        did: DID,
        ops: [{ action: "create", collection: "com.other.unhandled", rkey: "x", record: { anything: true } }],
      },
    ]);
    await new MufflerIndexer({ firehose, sink, refiner: exampleRefiner() }).run();
    expect(sink.size).toBe(0);
    expect(sink.cursorValue).toBe(1); // cursor still advances past the ignored commit
  });
});
