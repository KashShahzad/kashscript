// KS-N1 — ECOSYSTEM d28: an index rebuilt from the records alone equals the original. The indexer, with the
// guard, projects a set of public records; the records it holds are published again, as records and nothing
// else, into a fresh sink; the two sinks agree on every (did, collection, rkey, cid, value), every CID
// recomputes from its record's canonical bytes, and the planted person's record is in neither.

import { describe, expect, it } from "bun:test";
import { canonicalizeBytes } from "@kashscript/identity-core";
import { createStatusBitstring, encodeStatusList } from "@kashscript/attest/holder";
import { cidForBytes } from "../src/cid";
import { createPublicRecordGuard } from "../src/guard";
import { MufflerIndexer, type CommitOp, type FirehoseMessage, type FirehoseTransport, type IndexedRecord } from "../src/indexer";
import { RefineError } from "../src/refine";
import { MemoryRecordSink } from "../src/sinks/memory";
import { OTHER, PUB, guide, hunza, listing, pointer, rule, skardu, statusList, trustList } from "./public-records";

const INDUSLAND = "did:plc:indusland"; // the repositories' own ids: hosting plumbing, bound to a did:kash by the binding record
const KARAVAN = "did:plc:karavan";
const AT = "2026-11-16T00:00:00.000Z";

function firehoseOf(messages: FirehoseMessage[]): FirehoseTransport {
  return {
    async *events(cursor) {
      for (const m of messages) if (cursor == null || m.seq > cursor) yield m;
    },
  };
}

const strip = (r: IndexedRecord) => ({ did: r.did, collection: r.collection, rkey: r.rkey, cid: r.cid, value: r.value });
const sorted = (rs: readonly IndexedRecord[]) => rs.map(strip).sort((a, b) => JSON.stringify([a.did, a.collection, a.rkey]).localeCompare(JSON.stringify([b.did, b.collection, b.rkey])));

describe("d28 — an index rebuilt from the records alone equals the original", () => {
  it("projects, republishes what it holds, and the two indexes agree", async () => {
    const encodedList = await encodeStatusList(createStatusBitstring());
    const published: { did: string; ops: CommitOp[] }[] = [
      {
        did: INDUSLAND,
        ops: [
          { action: "create", collection: "kash.place", rkey: "skardu", record: skardu },
          { action: "create", collection: "kash.place", rkey: "hunza", record: hunza },
          { action: "create", collection: "kash.place.pointer", rkey: "lahore", record: pointer },
          { action: "create", collection: "kash.guide", rkey: "bolor-in-autumn", record: guide },
          { action: "create", collection: "kash.rule", rkey: "door", record: rule },
          { action: "create", collection: "kash.trust-list", rkey: "ecosystem-issuers", record: trustList(PUB, OTHER) },
          { action: "create", collection: "kash.status-list", rkey: "work-records-2026-q4", record: statusList(PUB, encodedList) },
          // The planted violation: a person's own profile, in the protocol's namespace.
          { action: "create", collection: "kash.id.profile", rkey: "self", record: { displayName: "Amina" } },
        ],
      },
      { did: KARAVAN, ops: [{ action: "create", collection: "kash.listing", rkey: "old-city-food-walk", record: listing }] },
    ];

    // The original index.
    const original = new MemoryRecordSink();
    const errors: unknown[] = [];
    await new MufflerIndexer({
      firehose: firehoseOf(published.map((p, i) => ({ kind: "commit", seq: i + 1, did: p.did, ops: p.ops }))),
      sink: original,
      refiner: createPublicRecordGuard(),
      onError: (e) => errors.push(e),
      now: () => AT,
    }).run();

    expect(original.size).toBe(8); // nine published, one refused
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(RefineError);
    expect((errors[0] as RefineError).code).toBe("PERSON_RECORD");
    expect(original.all().some((r) => r.collection === "kash.id.profile")).toBe(false);

    // What it holds, as records alone — no cid, no time — published again into a fresh index, in another order.
    const records = original.all().map((r) => ({ did: r.did, collection: r.collection, rkey: r.rkey, record: r.value })).reverse();
    const rebuilt = new MemoryRecordSink();
    const again: unknown[] = [];
    await new MufflerIndexer({
      firehose: firehoseOf(records.map((r, i) => ({ kind: "commit", seq: 100 + i, did: r.did, ops: [{ action: "create", collection: r.collection, rkey: r.rkey, record: r.record }] }))),
      sink: rebuilt,
      refiner: createPublicRecordGuard(),
      onError: (e) => again.push(e),
      now: () => "2027-01-01T00:00:00.000Z",
    }).run();

    expect(again).toHaveLength(0);
    expect(sorted(rebuilt.all())).toEqual(sorted(original.all()));

    // Every CID is the record's own: sha2-256 over its RFC 8785 bytes, so anyone recomputes it from the record.
    for (const r of original.all()) expect(r.cid).toBe(await cidForBytes(canonicalizeBytes(r.value)));
  });

  it("a record changed in transit does not match its CID and is not indexed", async () => {
    const sink = new MemoryRecordSink();
    const errors: unknown[] = [];
    const honest = await cidForBytes(canonicalizeBytes(skardu));
    await new MufflerIndexer({
      firehose: firehoseOf([
        { kind: "commit", seq: 1, did: INDUSLAND, ops: [{ action: "create", collection: "kash.place", rkey: "skardu", record: { ...skardu, name: "Skardu City" }, cid: honest }] },
      ]),
      sink,
      refiner: createPublicRecordGuard(),
      onError: (e) => errors.push(e),
    }).run();
    expect(sink.size).toBe(0);
    expect(errors).toHaveLength(1);
    expect(String((errors[0] as Error).message)).toContain("CID_MISMATCH");
  });
});
