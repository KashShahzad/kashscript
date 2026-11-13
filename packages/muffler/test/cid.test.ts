import { describe, it, expect } from "bun:test";
import { base32, cidForBytes } from "../src/cid";

describe("cid — CIDv1 (raw codec, sha2-256)", () => {
  it("is deterministic and b-prefixed base32 of a 36-byte CID", async () => {
    const bytes = new TextEncoder().encode("hello");
    const cid = await cidForBytes(bytes);
    expect(cid).toBe(await cidForBytes(bytes)); // deterministic
    expect(cid.startsWith("b")).toBe(true);
    expect(cid.length).toBe(59); // "b" + base32(4-byte prefix + 32-byte digest)
  });

  it("differs for different content", async () => {
    const a = await cidForBytes(new TextEncoder().encode("a"));
    const b = await cidForBytes(new TextEncoder().encode("b"));
    expect(a).not.toBe(b);
  });

  it("matches the CIDv1 raw-sha256 construction b + base32(0x01 0x55 0x12 0x20 ‖ sha256)", async () => {
    const input = new TextEncoder().encode("kashscript");
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", input));
    const cidBytes = new Uint8Array([0x01, 0x55, 0x12, 0x20, ...digest]);
    expect(await cidForBytes(input)).toBe("b" + base32(cidBytes));
  });
});
