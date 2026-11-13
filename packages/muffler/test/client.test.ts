import { describe, it, expect } from "bun:test";
import { MufflerClient, tid } from "../src/client";
import type { PutRecordInput, XrpcTransport } from "../src/client";
import { EXAMPLE, exampleRefiner } from "./example-lexicons";

function recordingTransport(): { transport: XrpcTransport; puts: PutRecordInput[] } {
  const puts: PutRecordInput[] = [];
  const transport: XrpcTransport = {
    async putRecord(input) {
      puts.push(input);
      return { uri: `at://did/${input.collection}/${input.rkey}`, cid: "bcid" };
    },
    async deleteRecord() {},
    async uploadBlob(bytes, mimeType) {
      return { cid: "bblob", mimeType, size: bytes.length };
    },
    async listRecords() {
      return { records: [] };
    },
  };
  return { transport, puts };
}

describe("MufflerClient", () => {
  it("refines a handled record and forwards the validated value to the transport", async () => {
    const { transport, puts } = recordingTransport();
    const client = new MufflerClient(transport, "did:plc:x", exampleRefiner());
    await client.put(EXAMPLE.experience, "e1", { title: "T", subcategories: ["x"] });
    expect(puts.length).toBe(1);
    expect(puts[0]?.record).toEqual({ title: "T", subcategories: ["x"] });
  });

  it("rejects an invalid handled record before the transport sees it", async () => {
    const { transport, puts } = recordingTransport();
    const client = new MufflerClient(transport, "did:plc:x", exampleRefiner());
    await expect(client.put(EXAMPLE.experience, "bad", { title: "no subs" })).rejects.toBeTruthy();
    expect(puts.length).toBe(0);
  });

  it("passes an unhandled collection through unrefined", async () => {
    const { transport, puts } = recordingTransport();
    const client = new MufflerClient(transport, "did:plc:x", exampleRefiner());
    const raw = { anything: true };
    await client.put("com.other.thing", "r1", raw);
    expect(puts[0]?.record).toEqual(raw);
  });

  it("works with no refiner (writes through as-is)", async () => {
    const { transport, puts } = recordingTransport();
    const client = new MufflerClient(transport, "did:plc:x");
    await client.put(EXAMPLE.experience, "e1", { anything: "goes" });
    expect(puts[0]?.record).toEqual({ anything: "goes" });
  });

  it("tid() is monotonic, sortable, and 13 chars", () => {
    const a = tid();
    const b = tid();
    const c = tid();
    expect(a < b).toBe(true);
    expect(b < c).toBe(true);
    expect(a.length).toBe(13);
  });
});
