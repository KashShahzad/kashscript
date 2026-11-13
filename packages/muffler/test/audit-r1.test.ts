// Red-team audit round 1 — muffler regression tests (specs/muffler-audit-r1.md).
// F5: prototype-pollution can't ride a record through validation/refinement.
// F6: the in-memory sink's composite key is injective (purgeRepo targets one did).

import { describe, it, expect } from "bun:test";
import { exampleRefiner, EXAMPLE } from "./example-lexicons";
import { MemoryRecordSink } from "../src/sinks/memory";

describe("audit r1 F5 — no prototype pollution through the refiner", () => {
  it("a __proto__ key never pollutes Object.prototype and never survives into refined.value", async () => {
    const refiner = exampleRefiner();
    // JSON.parse makes `__proto__` a real OWN key (a literal would set the proto).
    const malicious = JSON.parse('{"title":"T","subcategories":["x"],"__proto__":{"polluted":true}}');
    let refined: Awaited<ReturnType<typeof refiner.refine>> | undefined;
    try {
      refined = await refiner.refine(EXAMPLE.experience, malicious);
    } catch {
      // Strict lexicon (additionalProperties:false) now REJECTS the __proto__ key
      // (audit r1 F5b) — also a safe outcome.
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    if (refined) {
      expect(Object.prototype.hasOwnProperty.call(refined.value, "__proto__")).toBe(false);
    }
  });
});

describe("audit r1 F6 — MemoryRecordSink composite key is injective", () => {
  it("purgeRepo removes only the exact did, not a delimiter-collision", async () => {
    const sink = new MemoryRecordSink();
    const now = "2026-05-14T00:00:00Z";
    await sink.upsert({ did: "did:kash:alice", collection: "c", rkey: "1", cid: "b1", value: {}, indexedAt: now });
    // A record whose fields, joined by the OLD `|` delimiter, would collide with
    // "did:kash:alice|c|1" if keying weren't injective.
    await sink.upsert({ did: "did:kash:alice|c", collection: "1", rkey: "x", cid: "b2", value: {}, indexedAt: now });
    expect(sink.size).toBe(2);

    await sink.purgeRepo("did:kash:alice");
    // Only alice's record is gone; the other did survives (no prefix over-purge).
    expect(sink.get({ did: "did:kash:alice", collection: "c", rkey: "1" })).toBeUndefined();
    expect(sink.get({ did: "did:kash:alice|c", collection: "1", rkey: "x" })).toBeDefined();
  });
});
