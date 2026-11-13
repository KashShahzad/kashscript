/**
 * KS-U1 — `wallet.sign.dsse`: the holder's signature on a record they author,
 * with the key for one place. The switch decides first; the key is the
 * relationship key and nothing else; only a short list of record types is
 * signable; the result carries no key.
 */

import { describe, expect, it } from "bun:test";
import { isRegisteredDst, lookupDst } from "@kashscript/attest";
import { verifyEnvelope } from "@kashscript/attest/dsse";
import { resolveVerificationKey } from "@kashscript/attest/signing";
import { SESSION_EVENT_DST } from "@kashscript/attest/exchange";
import { createHeadlessWallet } from "../src/headless";
import { HOLDER_SIGNABLE_PAYLOAD_TYPES, MAX_SIGNED_PAYLOAD_BYTES, isWalletError } from "../src";

const WORK_RECORD = "application/vnd.oreoasis.work-record+json";
const EXPORT_REQUEST = "application/vnd.oreoasis.holder-export-request+json";
const OREOASIS = "https://api.oreoasis.example";
const OTHER = "https://other.example";
const record = { spec: "work-record/1", what: "a shop's menu, rebuilt", doneAt: 1_760_000_000 };

async function person(opts: { hardware: boolean }) {
  return createHeadlessWallet({ practice: true, seed: `ks-u1-${opts.hardware}`, hardwareSigning: opts.hardware });
}

async function refused(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (isWalletError(e, "SIGN_REFUSED")) return e.detail ?? "";
    throw e;
  }
  throw new Error("expected SIGN_REFUSED");
}

describe("the switch decides first (d49(a))", () => {
  it("unset: needs a choice, signs nothing, and leaves no key and no trace", async () => {
    const h = await person({ hardware: true });
    const before = h.inspect.snapshot();
    const r = await h.wallet.sign.dsse(OREOASIS, WORK_RECORD, record);
    expect(r).toEqual({ status: "needs-choice", counterparty: OREOASIS });
    expect(h.inspect.snapshot()).toBe(before);
    expect(h.inspect.chipKeys()).toBe(0);
  });

  it("off: signs nothing and leaves no trace", async () => {
    const h = await person({ hardware: true });
    await h.wallet.proof.set(OREOASIS, "off");
    const before = h.inspect.snapshot();
    expect(await h.wallet.sign.dsse(OREOASIS, WORK_RECORD, record)).toEqual({ status: "off" });
    expect(h.inspect.snapshot()).toBe(before);
    expect(h.inspect.chipKeys()).toBe(0);
  });
});

describe("on: the relationship key for that origin signs", () => {
  it("a phone's chip key signs ES256, DER, and the envelope verifies under its did:kash", async () => {
    const h = await person({ hardware: true });
    await h.wallet.proof.set(OREOASIS, "on");
    const r = await h.wallet.sign.dsse(OREOASIS, WORK_RECORD, record);
    if (r.status !== "signed") throw new Error(r.status);
    const rel = (await h.wallet.relationships.list()).find((x) => x.counterparty === OREOASIS)!;
    expect(r.envelope.payloadType).toBe(WORK_RECORD);
    expect(r.envelope.signatures.length).toBe(1);
    expect(r.envelope.signatures[0]!.keyid).toBe(rel.keyId!);
    expect(resolveVerificationKey(rel.keyId!)?.type).toBe("P-256");
    const checked = await verifyEnvelope(r.envelope, resolveVerificationKey);
    expect(checked.ok).toBe(true);
    expect(checked.verifiedKeyids).toEqual([rel.keyId!]);
    expect(checked.payloadJson).toEqual(record);
    expect(h.inspect.chipKeys()).toBe(1);
  });

  it("a software key signs Ed25519 and verifies the same way", async () => {
    const h = await person({ hardware: false });
    await h.wallet.proof.set(OREOASIS, "on");
    const r = await h.wallet.sign.dsse(OREOASIS, EXPORT_REQUEST, { holder: "me" });
    if (r.status !== "signed") throw new Error(r.status);
    const keyid = r.envelope.signatures[0]!.keyid;
    expect(resolveVerificationKey(keyid)?.type).toBe("Ed25519");
    expect((await verifyEnvelope(r.envelope, resolveVerificationKey)).ok).toBe(true);
  });

  it("one key per place: the same origin signs under one name, two origins under two", async () => {
    const h = await person({ hardware: true });
    await h.wallet.proof.set(OREOASIS, "on");
    await h.wallet.proof.set(OTHER, "on");
    const kid = async (o: string, n: number) => {
      const r = await h.wallet.sign.dsse(o, WORK_RECORD, { ...record, n });
      if (r.status !== "signed") throw new Error(r.status);
      return r.envelope.signatures[0]!.keyid;
    };
    const a1 = await kid(OREOASIS, 1);
    expect(await kid(OREOASIS, 2)).toBe(a1);
    expect(await kid(OTHER, 1)).not.toBe(a1);
    // A path under the same origin is the same place.
    const r = await h.wallet.sign.dsse(`${OREOASIS}/api/v1/receipts`, WORK_RECORD, record);
    expect(r.status === "signed" && r.envelope.signatures[0]!.keyid).toBe(a1);
  });

  it("canonical: true signs the JCS bytes, so key order does not change them", async () => {
    const h = await person({ hardware: false });
    await h.wallet.proof.set(OREOASIS, "on");
    const a = await h.wallet.sign.dsse(OREOASIS, WORK_RECORD, { a: 1, b: 2 }, { canonical: true });
    const b = await h.wallet.sign.dsse(OREOASIS, WORK_RECORD, { b: 2, a: 1 }, { canonical: true });
    if (a.status !== "signed" || b.status !== "signed") throw new Error("not signed");
    expect(a.envelope.payload).toBe(b.envelope.payload);
    const faithful = await h.wallet.sign.dsse(OREOASIS, WORK_RECORD, { b: 2, a: 1 });
    expect(faithful.status === "signed" && faithful.envelope.payload).not.toBe(a.envelope.payload);
  });

  it("hands back no key: the result is the envelope and nothing else, for a chip key and a software key", async () => {
    for (const hardware of [true, false]) {
      const h = await person({ hardware });
      await h.wallet.proof.set(OREOASIS, "on");
      const r = await h.wallet.sign.dsse(OREOASIS, WORK_RECORD, record);
      expect(Object.keys(r).sort()).toEqual(["envelope", "status"]);
      if (r.status !== "signed") throw new Error("not signed");
      expect(Object.keys(r.envelope).sort()).toEqual(["payload", "payloadType", "signatures"]);
      expect(Object.keys(r.envelope.signatures[0]!).sort()).toEqual(["keyid", "sig"]);
      expect(JSON.stringify(r)).not.toMatch(/privateKey|seed|handle|practice-chip-key/);
    }
  });
});

describe("narrow: only what a holder authors, and only a small JSON object", () => {
  it("refuses a session line, a trust list, a status list and an unregistered type — before any key is made", async () => {
    const h = await person({ hardware: true });
    await h.wallet.proof.set(OREOASIS, "on");
    const before = h.inspect.snapshot();
    for (const t of [SESSION_EVENT_DST, "application/vnd.kash.trust-list+json", "application/vnd.kash.status-list+json", "application/vnd.example.anything+json", ""]) {
      await refused(h.wallet.sign.dsse(OREOASIS, t, record));
    }
    expect(h.inspect.snapshot()).toBe(before);
    expect(h.inspect.chipKeys()).toBe(0);
  });

  it("refuses a payload that is not a plain object, or is too large", async () => {
    const h = await person({ hardware: false });
    await h.wallet.proof.set(OREOASIS, "on");
    for (const p of [[1, 2], "text", 7, null, undefined, new Date(0), Object.assign(Object.create({ inherited: 1 }), { a: 1 })]) {
      await refused(h.wallet.sign.dsse(OREOASIS, WORK_RECORD, p));
    }
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    await refused(h.wallet.sign.dsse(OREOASIS, WORK_RECORD, cyclic));
    await refused(h.wallet.sign.dsse(OREOASIS, WORK_RECORD, { blob: "x".repeat(MAX_SIGNED_PAYLOAD_BYTES) }));
  });

  it("every signable type is a registered DSSE type — a renamed or retired tag fails here", () => {
    expect(HOLDER_SIGNABLE_PAYLOAD_TYPES.length).toBeGreaterThan(0);
    for (const t of HOLDER_SIGNABLE_PAYLOAD_TYPES) {
      expect(isRegisteredDst(t)).toBe(true);
      expect(lookupDst(t)?.family).toBe("dsse-type");
      expect(lookupDst(t)?.reserved).not.toBe(true);
    }
    expect(HOLDER_SIGNABLE_PAYLOAD_TYPES).not.toContain(SESSION_EVENT_DST);
  });
});
