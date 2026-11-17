/**
 * KS-Q4 — the two public witnesses, read offline. OpenTimestamps against the
 * project's own example proof (`hello-world.txt.ots`, Bitcoin block 358391) and
 * a real upgraded proof from the decision log's anchors (GOV-5; block 974281);
 * RIPEMD-160 against its published vectors; RFC 3161 against a real DigiCert
 * token and the fake authority. Nothing here goes online: every `fetch` is a
 * stub (test/offline-guard.cjs forbids sockets).
 */

import { describe, expect, it } from "bun:test";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { bytesToBase64 } from "../src/ed25519";
import {
  DEFAULT_RFC3161_URL,
  OID_SHA256,
  checkBitcoinHeader,
  mergeOtsTimestamps,
  otsLeaves,
  parseOts,
  parseOtsTimestamp,
  readRfc3161Token,
  rfc3161Request,
  rfc3161Stamp,
  serializeOts,
  stampOpenTimestamps,
  upgradeOpenTimestamps,
  verifyOpenTimestamps,
  verifyRfc3161Digest,
  witnessVerdictsFor,
  type BitcoinHeader,
  type OtsTimestamp,
} from "../src/witness";
import { ripemd160 } from "../src/witness/ripemd160";
import { fakeTimeStampResp } from "./witness/fake-tsa";

const W = join(import.meta.dir, "vectors", "witness");
const file = (name: string): Uint8Array => new Uint8Array(readFileSync(join(W, name)));
const header = (height: number): BitcoinHeader => {
  const j = JSON.parse(readFileSync(join(W, `header-${height}.json`), "utf8")) as { height: number; header: string };
  return { height: j.height, headerHex: j.header };
};
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

const HELLO_DIGEST = "03ba204e50d126e4674c005e04d82e84c21366780af1f43bd54a37816b6ab340";
const VISION_DIGEST = "4b9b3d92b26d1ac3960cb3ebafe5a3d5710d60f496beb32ef77c4a4ade1971ff";

describe("RIPEMD-160", () => {
  it("matches the function's published vectors", () => {
    expect(hex(ripemd160(utf8("")))).toBe("9c1185a5c5e9fc54612808977ee8f548b2258d31");
    expect(hex(ripemd160(utf8("a")))).toBe("0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
    expect(hex(ripemd160(utf8("abc")))).toBe("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    expect(hex(ripemd160(utf8("message digest")))).toBe("5d0689ef49d2fae572b881b123a85ffa21595f36");
    expect(hex(ripemd160(utf8("abcdefghijklmnopqrstuvwxyz")))).toBe("f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
    expect(hex(ripemd160(utf8("12345678901234567890".repeat(4))))).toBe("9b752e45573d4b39f4dbd3323cab82bf63326bfb");
  });
});

describe("OpenTimestamps — the project's own example proof", () => {
  it("parses: SHA-256 of 'Hello World!\\n', one Bitcoin attestation at block 358391, through ripemd160", async () => {
    const f = await parseOts(file("hello-world.txt.ots"));
    expect(f.hashOp).toBe("sha256");
    expect(hex(f.digest)).toBe(HELLO_DIGEST);
    expect(hex(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8("Hello World!\n") as unknown as BufferSource)))).toBe(HELLO_DIGEST);
    const leaves = otsLeaves(f.timestamp);
    expect(leaves.map((l) => l.attestation)).toEqual([{ kind: "bitcoin", height: 358391 }]);
    expect(f.timestamp.ops[0]?.op.op).toBe("ripemd160");
    // The message at the attestation is the block's Merkle root, as the python library reads it.
    expect(hex(leaves[0]!.msg)).toBe("007ee445d23ad061af4a36b809501fab1ac4f2d7e7a739817dd0cbb7ec661b8a");
  });

  it("re-serialises byte for byte", async () => {
    for (const name of ["hello-world.txt.ots", "vision-4b9b3d92b26d.ots"]) {
      const original = file(name);
      expect(hex(serializeOts(await parseOts(original)))).toBe(hex(original));
    }
  });

  it("verifies against the block's header: final, at the block's time", async () => {
    const v = await verifyOpenTimestamps(file("hello-world.txt.ots"), HELLO_DIGEST, { headers: [header(358391)] });
    expect(v.state).toBe("final");
    expect(v.digestOk).toBe(true);
    expect(v.by).toBe("Bitcoin block 358391");
    const checked = await checkBitcoinHeader(header(358391).headerHex);
    expect(v.timeUnix).toBe(checked.timeUnix);
    expect(new Date((v.timeUnix as number) * 1000).toISOString().slice(0, 7)).toBe("2015-05");
    expect(checked.hashHex).toBe("000000000000000003e892881a8cdcdc117c06d444057c98b6f04a9ee75a2319");
  });

  it("without the header: unchecked, naming the block; over another digest: invalid; a corrupted operation: invalid", async () => {
    const none = await verifyOpenTimestamps(file("hello-world.txt.ots"), HELLO_DIGEST);
    expect([none.state, none.digestOk, none.by]).toEqual(["unchecked", true, "Bitcoin block 358391"]);
    expect(none.detail).toContain("header was not supplied");
    const wrong = await verifyOpenTimestamps(file("hello-world.txt.ots"), VISION_DIGEST, { headers: [header(358391)] });
    expect([wrong.state, wrong.digestOk]).toEqual(["invalid", false]);
    const broken = file("hello-world.txt.ots");
    broken[0x50] = broken[0x50]! ^ 1; // inside the prepended transaction bytes
    const v = await verifyOpenTimestamps(broken, HELLO_DIGEST, { headers: [header(358391)] });
    expect(v.state).toBe("invalid");
    expect(v.detail).toContain("do not reach the header's Merkle root");
    expect((await verifyOpenTimestamps(utf8("not a proof"), HELLO_DIGEST)).state).toBe("invalid");
  });
});

describe("OpenTimestamps — a real upgraded proof from the decision log's anchors", () => {
  it("names three Bitcoin blocks and the calendars still pending; verifies at the earliest block whose header is supplied", async () => {
    const f = await parseOts(file("vision-4b9b3d92b26d.ots"));
    expect(hex(f.digest)).toBe(VISION_DIGEST);
    const atts = otsLeaves(f.timestamp).map((l) => l.attestation);
    expect(atts.filter((a) => a.kind === "bitcoin").map((a) => (a as { height: number }).height).sort()).toEqual([974281, 974281, 974295, 974322]);
    expect(atts.filter((a) => a.kind === "pending").length).toBe(4);
    // The nonce `ots stamp` appends is the first operation.
    expect(f.timestamp.ops[0]?.op.op).toBe("append");
    const only295 = await verifyOpenTimestamps(file("vision-4b9b3d92b26d.ots"), VISION_DIGEST, { headers: [header(974295)] });
    expect([only295.state, only295.by]).toEqual(["final", "Bitcoin block 974295"]);
    const all = await verifyOpenTimestamps(file("vision-4b9b3d92b26d.ots"), VISION_DIGEST, { headers: [header(974281), header(974295), header(974322)] });
    expect(all.by).toBe("Bitcoin block 974281");
    expect(all.timeUnix).toBe((await checkBitcoinHeader(header(974281).headerHex)).timeUnix);
    // The decision log's own record: ECOSYSTEM's earliest attested time is 2026-11-02 (GOV-5); this proof's block is of that day.
    expect(new Date((all.timeUnix as number) * 1000).toISOString().slice(0, 10)).toBe("2026-11-02");
  });

  it("a header claiming too little work, or not meeting its own target, is refused", async () => {
    const h = header(974281).headerHex;
    // bits at 72..76 (little-endian): set an easy target, 0x207fffff.
    const easy = `${h.slice(0, 144)}ffff7f20${h.slice(152)}`;
    await expect(checkBitcoinHeader(easy)).rejects.toThrow("less than 64 bits of work");
    const corrupt = `${h.slice(0, 10)}00${h.slice(12)}`;
    await expect(checkBitcoinHeader(corrupt)).rejects.toThrow("proof-of-work");
    await expect(checkBitcoinHeader("abcd")).rejects.toThrow("80 bytes");
  });
});

describe("OpenTimestamps — stamping and upgrading through an injected fetch", () => {
  const calendars = ["https://a.sample.example", "https://b.sample.example", "https://c.sample.example"];
  const pendingFor = (uri: string, msg: Uint8Array): Uint8Array => serializeOts({ hashOp: "sha256", digest: msg, timestamp: { msg, attestations: [{ kind: "pending", uri }], ops: [] } }).slice(31 + 1 + 1 + 32);

  it("appends a nonce, hashes, submits the commitment to every calendar, and needs two to accept", async () => {
    const seen: string[] = [];
    const nonce = new Uint8Array(16).fill(7);
    const stamped = await stampOpenTimestamps(HELLO_DIGEST, {
      calendars,
      nonce,
      fetch: async (url, init) => {
        seen.push(url);
        expect(init.method).toBe("POST");
        expect(init.body?.length).toBe(32); // the calendar receives 32 bytes and nothing else
        if (url.startsWith("https://c.")) return { ok: false, status: 500, bytes: async () => new Uint8Array(0) };
        return { ok: true, status: 200, bytes: async () => pendingFor(url.replace("/digest", ""), init.body!) };
      },
    });
    expect(seen.sort()).toEqual(calendars.map((c) => `${c}/digest`));
    expect([...stamped.accepted].sort()).toEqual(["https://a.sample.example", "https://b.sample.example"]);
    expect(stamped.problems).toEqual(["https://c.sample.example: HTTP 500"]);
    const f = await parseOts(stamped.ots);
    expect(hex(f.digest)).toBe(HELLO_DIGEST);
    expect(f.timestamp.ops.map((o) => o.op)).toEqual([{ op: "append", arg: nonce }]);
    expect(f.timestamp.ops[0]!.next.ops.map((o) => o.op.op)).toEqual(["sha256"]);
    expect(otsLeaves(f.timestamp).map((l) => l.attestation)).toEqual([
      { kind: "pending", uri: "https://a.sample.example" },
      { kind: "pending", uri: "https://b.sample.example" },
    ]);
    const v = await verifyOpenTimestamps(stamped.ots, HELLO_DIGEST);
    expect([v.state, v.digestOk]).toEqual(["pending", true]);
    expect(v.by).toBe("calendars a.sample.example, b.sample.example");
    // The nonce keeps a calendar from learning the digest: the commitment is not the digest.
    expect(seen.length).toBe(3);
    await expect(
      stampOpenTimestamps(HELLO_DIGEST, { calendars, fetch: async (url) => ({ ok: url.startsWith("https://a."), status: 503, bytes: async () => pendingFor(url.replace("/digest", ""), new Uint8Array(32)) }) }),
    ).rejects.toThrow("only 1 calendar(s) accepted");
  });

  it("upgrades a pending proof from a known calendar when it answers with a block attestation, and leaves it as it was otherwise", async () => {
    const nonce = new Uint8Array(16).fill(1);
    const known = ["https://alice.btc.calendar.opentimestamps.org", "https://bob.btc.calendar.opentimestamps.org"];
    const stamped = await stampOpenTimestamps(HELLO_DIGEST, { calendars: known, nonce, fetch: async (url, init) => ({ ok: true, status: 200, bytes: async () => pendingFor(url.replace("/digest", ""), init.body!) }) });
    const commitment = stamped.file.timestamp.ops[0]!.next.ops[0]!.next.msg;
    const blockStamp = (msg: Uint8Array): Uint8Array => {
      const t: OtsTimestamp = { msg, attestations: [], ops: [{ op: { op: "sha256" }, next: { msg: new Uint8Array(32), attestations: [{ kind: "bitcoin", height: 1 }], ops: [] } }] };
      return serializeOts({ hashOp: "sha256", digest: msg, timestamp: t }).slice(31 + 1 + 1 + 32);
    };
    const notYet = await upgradeOpenTimestamps(stamped.ots, { fetch: async () => ({ ok: false, status: 404, bytes: async () => new Uint8Array(0) }) });
    expect(notYet.changed).toBe(false);
    expect(hex(notYet.ots)).toBe(hex(stamped.ots));
    expect(notYet.notes).toEqual(["alice.btc.calendar.opentimestamps.org: HTTP 404", "bob.btc.calendar.opentimestamps.org: HTTP 404"]);
    const asked: string[] = [];
    const upgraded = await upgradeOpenTimestamps(stamped.ots, {
      fetch: async (url) => {
        asked.push(url);
        return url.startsWith("https://alice") ? { ok: true, status: 200, bytes: async () => blockStamp(commitment) } : { ok: false, status: 404, bytes: async () => new Uint8Array(0) };
      },
    });
    expect(asked).toEqual([`https://alice.btc.calendar.opentimestamps.org/timestamp/${hex(commitment)}`, `https://bob.btc.calendar.opentimestamps.org/timestamp/${hex(commitment)}`]);
    expect(upgraded.changed).toBe(true);
    const atts = otsLeaves((await parseOts(upgraded.ots)).timestamp).map((l) => l.attestation);
    expect(atts).toEqual(expect.arrayContaining([{ kind: "bitcoin", height: 1 }, { kind: "pending", uri: "https://bob.btc.calendar.opentimestamps.org" }]));
    // A calendar not on the known list is skipped, never asked.
    const unknown = await stampOpenTimestamps(HELLO_DIGEST, { calendars: ["https://x.example", "https://y.example"], nonce, fetch: async (url, init) => ({ ok: true, status: 200, bytes: async () => pendingFor(url.replace("/digest", ""), init.body!) }) });
    const skipped = await upgradeOpenTimestamps(unknown.ots, { fetch: async () => { throw new Error("must not be called"); } });
    expect(skipped.notes).toEqual(["skipped https://x.example (not a known calendar)", "skipped https://y.example (not a known calendar)"]);
  });

  it("merging unites attestations and shares operations; parsing a bare timestamp needs the message it starts from", async () => {
    const msg = new Uint8Array(32).fill(3);
    const a: OtsTimestamp = { msg, attestations: [{ kind: "pending", uri: "https://a.example" }], ops: [] };
    const b: OtsTimestamp = { msg, attestations: [{ kind: "pending", uri: "https://a.example" }, { kind: "bitcoin", height: 5 }], ops: [{ op: { op: "sha256" }, next: { msg: new Uint8Array(32), attestations: [{ kind: "bitcoin", height: 6 }], ops: [] } }] };
    mergeOtsTimestamps(a, b);
    expect(a.attestations).toEqual([{ kind: "pending", uri: "https://a.example" }, { kind: "bitcoin", height: 5 }]);
    expect(a.ops.length).toBe(1);
    const bytes = serializeOts({ hashOp: "sha256", digest: msg, timestamp: a }).slice(31 + 1 + 1 + 32);
    const back = await parseOtsTimestamp(bytes, msg);
    // The format writes attestations in the reference client's order (by tag), so compare as sets.
    const asSet = (t: OtsTimestamp): string[] => otsLeaves(t).map((l) => JSON.stringify(l.attestation)).sort();
    expect(asSet(back)).toEqual(asSet(a));
    expect(() => mergeOtsTimestamps(a, { msg: new Uint8Array(32), attestations: [], ops: [] })).toThrow();
  });
});

describe("RFC 3161 — a real DigiCert token, read", () => {
  it("reads the token's status, imprint, time, serial, nonce and certificates", async () => {
    const t = await readRfc3161Token(file("vision-4b9b3d92b26d.tsr"));
    expect(t.granted).toBe(true);
    expect(t.status).toBe(0);
    expect(t.hashAlgorithm).toBe(OID_SHA256);
    expect(t.digestHex).toBe(VISION_DIGEST);
    expect(t.genTime).toBe("2026-11-02T16:50:16Z");
    expect(t.serialHex).toBe("a86d52fa1889b31ae38aac94d75d8342");
    expect(t.nonceHex).toBe("c918ff98eb861b21");
    expect(t.policy).toBe("2.16.840.1.114412.7.1");
    expect(t.certificateFingerprints.length).toBeGreaterThanOrEqual(2);
    expect(t.certificateFingerprints.every((f) => /^[0-9a-f]{64}$/.test(f))).toBe(true);
    expect(t.signerInfos).toBe(1);
  });

  it("the verdict: unchecked until the caller says the signature was verified; invalid over another digest or nonce", async () => {
    const tsr = file("vision-4b9b3d92b26d.tsr");
    const unchecked = await verifyRfc3161Digest(tsr, VISION_DIGEST);
    expect([unchecked.state, unchecked.digestOk, unchecked.timeUnix]).toEqual(["unchecked", true, null]);
    expect(unchecked.detail).toContain("openssl ts -verify");
    const final = await verifyRfc3161Digest(tsr, VISION_DIGEST, { signatureVerified: true, nonceHex: "c918ff98eb861b21" });
    expect([final.state, final.digestOk]).toEqual(["final", true]);
    expect(final.timeUnix).toBe(Math.floor(Date.UTC(2026, 10, 2, 16, 50, 16) / 1000));
    const wrong = await verifyRfc3161Digest(tsr, HELLO_DIGEST, { signatureVerified: true });
    expect([wrong.state, wrong.digestOk]).toEqual(["invalid", false]);
    const badNonce = await verifyRfc3161Digest(tsr, VISION_DIGEST, { signatureVerified: true, nonceHex: "0102" });
    expect(badNonce.state).toBe("invalid");
    expect((await verifyRfc3161Digest(utf8("junk"), VISION_DIGEST)).state).toBe("invalid");
    // Through the dispatcher, as a log proof carries it.
    const verdicts = await witnessVerdictsFor([{ kind: "rfc3161", proofBase64: bytesToBase64(tsr) }, { kind: "rfc3161", proofBase64: "!!" }], VISION_DIGEST, { verifyRfc3161Signature: async () => true });
    expect(verdicts.map((v) => v.state)).toEqual(["final", "invalid"]);
    const refused = await witnessVerdictsFor([{ kind: "rfc3161", proofBase64: bytesToBase64(tsr) }], VISION_DIGEST, { verifyRfc3161Signature: async () => { throw new Error("no openssl"); } });
    expect(refused[0]?.state).toBe("unchecked");
  });

  it("through openssl, against DigiCert's pinned root, the real token's signature and chain verify as of its own time", async () => {
    const { opensslAvailable, opensslRfc3161Check } = await import("../src/bin/openssl");
    if (!opensslAvailable()) {
      console.warn("openssl not found — the DigiCert signature check was skipped");
      return;
    }
    const { check, rootSha256 } = opensslRfc3161Check(join(W, "digicert-trusted-root-g4.crt"));
    // The fingerprint GOV-5 pinned for the decision log's anchors (A-List anchors/README.md).
    expect(rootSha256).toBe("552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988");
    expect(await check(file("vision-4b9b3d92b26d.tsr"), VISION_DIGEST)).toBe(true);
    expect(await check(file("vision-4b9b3d92b26d.tsr"), HELLO_DIGEST)).toBe(false);
    const verdicts = await witnessVerdictsFor([{ kind: "rfc3161", proofBase64: bytesToBase64(file("vision-4b9b3d92b26d.tsr")) }], VISION_DIGEST, { verifyRfc3161Signature: check });
    expect([verdicts[0]?.state, verdicts[0]?.timeUnix]).toEqual(["final", Math.floor(Date.UTC(2026, 10, 2, 16, 50, 16) / 1000)]);
  });

  it("openssl reads the real token the same way, when openssl is on this machine", () => {
    const probe = spawnSync("openssl", ["version"], { encoding: "utf8" });
    if (probe.error !== undefined || probe.status !== 0) {
      console.warn("openssl not found — the cross-check with openssl ts -reply was skipped");
      return;
    }
    const out = spawnSync("openssl", ["ts", "-reply", "-in", join(W, "vision-4b9b3d92b26d.tsr"), "-text"], { encoding: "utf8" });
    expect(out.stdout).toContain("Status: Granted.");
    expect(out.stdout).toContain("Nov  2 16:50:16 2026 GMT");
    expect(out.stdout).toContain("0xC918FF98EB861B21");
  });
});

describe("RFC 3161 — the request, and the fake authority", () => {
  it("builds a DER request openssl reads: SHA-256, the digest, the nonce, a certificate asked for", () => {
    const req = rfc3161Request(VISION_DIGEST, "c918ff98eb861b21");
    expect(req[0]).toBe(0x30);
    expect(hex(req)).toContain("0609608648016503040201"); // the SHA-256 OID
    expect(hex(req)).toContain(VISION_DIGEST);
    expect(hex(req)).toContain("0209" + "00c918ff98eb861b21"); // the nonce, positive
    expect(hex(req).endsWith("0101ff")).toBe(true); // certReq TRUE
    expect(() => rfc3161Request("short", "01")).toThrow();
    const probe = spawnSync("openssl", ["version"], { encoding: "utf8" });
    if (probe.error === undefined && probe.status === 0) {
      const dir = mkdtempSync(join(tmpdir(), "ks-q4-tsq-"));
      writeFileSync(join(dir, "r.tsq"), req);
      const out = spawnSync("openssl", ["ts", "-query", "-in", join(dir, "r.tsq"), "-text"], { encoding: "utf8" });
      expect(out.stdout).toContain("Hash Algorithm: sha256");
      expect(out.stdout).toContain("Nonce: 0xC918FF98EB861B21");
      expect(out.stdout).toContain("Certificate required: yes");
    }
  });

  it("the fake authority's token reads, names its TSA, echoes a nonce, and a refusal is said", async () => {
    const tsr = fakeTimeStampResp({ digestHex: HELLO_DIGEST, genTimeUnix: 1_800_000_000, nonceHex: "0102", tsaName: "SAMPLE Time Authority" });
    const t = await readRfc3161Token(tsr);
    expect([t.granted, t.digestHex, t.genTimeUnix, t.nonceHex, t.tsaName, t.certificateFingerprints.length]).toEqual([true, HELLO_DIGEST, 1_800_000_000, "0102", "SAMPLE Time Authority", 1]);
    const v = await verifyRfc3161Digest(tsr, HELLO_DIGEST, { signatureVerified: true, nonceHex: "0102" });
    expect([v.state, v.by]).toEqual(["final", "SAMPLE Time Authority (RFC 3161)"]);
    await expect(readRfc3161Token(fakeTimeStampResp({ digestHex: HELLO_DIGEST, genTimeUnix: 1, status: 2 }))).rejects.toThrow("did not grant");
  });

  it("asks an authority through an injected fetch and refuses a token over another digest or nonce", async () => {
    const calls: { url: string; headers: Record<string, string> }[] = [];
    const ok = await rfc3161Stamp(HELLO_DIGEST, {
      nonceHex: "0a0b",
      fetch: async (url, init) => {
        calls.push({ url, headers: init.headers });
        expect(init.body[0]).toBe(0x30);
        return { ok: true, status: 200, bytes: async () => fakeTimeStampResp({ digestHex: HELLO_DIGEST, genTimeUnix: 5, nonceHex: "0a0b" }) };
      },
    });
    expect(calls).toEqual([{ url: DEFAULT_RFC3161_URL, headers: { "Content-Type": "application/timestamp-query", Accept: "application/timestamp-reply" } }]);
    expect(ok.token.genTimeUnix).toBe(5);
    await expect(rfc3161Stamp(HELLO_DIGEST, { nonceHex: "0a0b", fetch: async () => ({ ok: true, status: 200, bytes: async () => fakeTimeStampResp({ digestHex: VISION_DIGEST, genTimeUnix: 5, nonceHex: "0a0b" }) }) })).rejects.toThrow("another digest");
    await expect(rfc3161Stamp(HELLO_DIGEST, { nonceHex: "0a0b", fetch: async () => ({ ok: true, status: 200, bytes: async () => fakeTimeStampResp({ digestHex: HELLO_DIGEST, genTimeUnix: 5, nonceHex: "0a0c" }) }) })).rejects.toThrow("nonce");
    await expect(rfc3161Stamp(HELLO_DIGEST, { fetch: async () => ({ ok: false, status: 503, bytes: async () => new Uint8Array(0) }) })).rejects.toThrow("HTTP 503");
  });
});
