import { afterEach, describe, expect, it } from "bun:test";
import {
  DST_STATUS_LIST,
  STATUS_LIST_FORMAT,
  createStatusBitstring,
  decodeStatusList,
  encodeStatusList,
  getInflate,
  setInflate,
  setZlibProvider,
  makeKeyResolver,
  setStatusBit,
  signStatusList,
  verifyStatusList,
  type StatusListPayload,
} from "../src/holder";
import { generateKeyPair, deriveDid } from "@kashscript/identity-core";
import { gunzipSync } from "node:zlib";

describe("injected inflate — status lists when node:zlib is unavailable", () => {
  afterEach(() => {
    setInflate(null);
    setZlibProvider(() => import("node:zlib"));
  });

  it("fails to decode when zlib is unavailable and no inflate is injected", async () => {
    const bits = createStatusBitstring();
    setStatusBit(bits, 42, true);
    const encoded = await encodeStatusList(bits);

    // Make node:zlib unavailable (simulating React Native / Hermes)
    setZlibProvider(async () => {
      throw new Error("node:zlib is unavailable on this device");
    });
    setInflate(null);

    await expect(decodeStatusList(encoded)).rejects.toThrow("node:zlib is unavailable on this device");
  });

  it("decodes through the injected inflate when zlib is unavailable", async () => {
    const bits = createStatusBitstring();
    setStatusBit(bits, 42, true);
    setStatusBit(bits, 1000, true);
    const encoded = await encodeStatusList(bits);

    // Simulate React Native: zlib throws
    setZlibProvider(async () => {
      throw new Error("node:zlib is unavailable on this device");
    });

    // Provide injected inflate (e.g. from pure JS decompressor)
    setInflate((bytes) => new Uint8Array(gunzipSync(bytes)));
    expect(getInflate()).not.toBeNull();

    const decoded = await decodeStatusList(encoded);
    expect(decoded).toEqual(bits);
  });

  it("verifyStatusList succeeds with injected inflate when zlib is unavailable", async () => {
    const kp = await generateKeyPair();
    const did = deriveDid(kp.publicKey);
    const signer = { keyid: did, privateKey: kp.privateKey, publicKey: kp.publicKey };

    const bits = createStatusBitstring();
    setStatusBit(bits, 7, true);
    const encoded = await encodeStatusList(bits);

    const payload: StatusListPayload = {
      format: STATUS_LIST_FORMAT,
      type: "BitstringStatusList",
      id: "https://status.example.org/list/1",
      issuer: did,
      statusPurpose: "revocation",
      encodedList: encoded,
      issuedAtUnix: 1_700_000_000,
      validUntilUnix: 2_100_000_000,
    };
    const envelope = await signStatusList(payload, signer);

    // Make zlib unavailable
    setZlibProvider(async () => {
      throw new Error("node:zlib is unavailable on this device");
    });

    // Without injected inflate, status list report is undecodable
    setInflate(null);
    const failReport = await verifyStatusList(envelope, {
      resolveKey: makeKeyResolver(new Map(), new Map()),
      nowSec: 1_750_000_000,
    });
    expect(failReport.ok).toBe(false);
    expect(failReport.reason).toBe("STATUS_LIST_UNDECODABLE");

    // With injected inflate, status list report is ok
    setInflate((bytes) => new Uint8Array(gunzipSync(bytes)));
    const okReport = await verifyStatusList(envelope, {
      resolveKey: makeKeyResolver(new Map(), new Map()),
      nowSec: 1_750_000_000,
    });
    expect(okReport.ok).toBe(true);
    expect(okReport.bits).not.toBeNull();
    expect(okReport.bits![0]).toBe(bits[0]);
  });
});
