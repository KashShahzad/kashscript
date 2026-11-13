import { describe, it, expect } from "bun:test";
import { createOrgBindingRecord, mintOrgIdentity, verifyOrgBindingRecord } from "../src/identity";

const ATPROTO = "did:plc:abc123karavan";
const AT = "2026-07-05T00:00:00.000Z";

describe("identity — did:kash <-> atproto binding", () => {
  it("mints, binds, and verifies with no server round-trip", async () => {
    const org = await mintOrgIdentity();
    expect(org.did.startsWith("did:kash:")).toBe(true);
    const record = await createOrgBindingRecord(org.keyPair, ATPROTO, AT);
    expect(await verifyOrgBindingRecord(record, org.did, ATPROTO)).toBe(true);
  });

  it("rejects a wrong atproto did, a wrong kash did, and a malformed did", async () => {
    const org = await mintOrgIdentity();
    const record = await createOrgBindingRecord(org.keyPair, ATPROTO, AT);
    expect(await verifyOrgBindingRecord(record, org.did, "did:plc:someone-else")).toBe(false);
    const other = await mintOrgIdentity();
    expect(await verifyOrgBindingRecord(record, other.did, ATPROTO)).toBe(false);
    expect(await verifyOrgBindingRecord(record, "not-a-did", ATPROTO)).toBe(false);
  });

  it("supports a custom NSID/DST for venture wire-compat", async () => {
    const org = await mintOrgIdentity();
    const record = await createOrgBindingRecord(org.keyPair, ATPROTO, AT, {
      nsid: "app.indusland.org.identity",
      dst: "indus.org.identity.v1\n",
    });
    expect((record.header as { typ: string }).typ).toBe("app.indusland.org.identity");
    expect(await verifyOrgBindingRecord(record, org.did, ATPROTO)).toBe(true);
  });
});
