/**
 * PY-5 — the record of a batch accepted on a sample, `kash.attestation@1.1.0` (`specs/attestation/batch.md`
 * §2, §5). A receipt signed by both sides that a stranger checks offline: the seal named by the reference, the
 * stamp below the draw block, the headers linked and above the floor, the draw recomputed, every position found
 * short among the drawn, the plan and the bound exact — and each refusal with its code.
 *
 * The chain here is synthetic, mined at about 8 bits of work: the default floor refuses it, so the tests that
 * need it to stand pass their own floor, and the report says so. The worked examples carry a real one.
 */

import { beforeAll, describe, expect, test } from "bun:test";
import { validate } from "@kashscript/lexicons/schema";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalizeBytes } from "@kashscript/identity-core";
import { bytesToHex, hexToBytes } from "../src/chain";
import { bytesToBase64 } from "../src/ed25519";
import { signEnvelope } from "../src/dsse";
import {
  KASH_ATTESTATION_1_1_BODY_SCHEMA,
  KASH_ATTESTATION_BODY_SCHEMA,
  MANDATE_DST,
  checkAttestation,
  copyClaimsOf,
  verifyAttestationRecord,
  type AttestationBody,
  type MandateBody,
} from "../src/attestation";
import { OVER_PLAN_REASON, SEED_MIN_WORK_BITS, boundOf, checkDrawBlocks, itemTree, limitOf, sealDigestOf, verifyBatchItems, verifyItemPath, type Batch, type BatchSeal } from "../src/batch";
import { TEST_FLOOR, batchOf, party, receiptOf, sampledBatch, signRecord, syntheticDraw, type Party, type SampledBatch } from "./helpers/batch";

let asker: Party;
let approver: Party;
let sb: SampledBatch;
const floor = { batchMinWorkBits: TEST_FLOOR };

beforeAll(async () => {
  asker = await party();
  approver = await party();
  sb = await sampledBatch();
}, 60_000);

const codes = (faults: readonly { code: string }[]): string[] => faults.map((f) => f.code);
const body = (found: readonly number[] = [], over: Partial<AttestationBody> = {}): AttestationBody => receiptOf(asker, approver, batchOf(sb, found), sb.sealDigest, over);
const withBatch = (b: Partial<Batch>, over: Partial<AttestationBody> = {}): AttestationBody => ({ ...body([], over), batch: { ...batchOf(sb, []), ...b } });
const withSeal = (s: Partial<BatchSeal>): AttestationBody => withBatch({ seal: { ...sb.seal, ...s } });

describe("a sampled batch that checks", () => {
  test("its body passes the shape and every rule", () => {
    expect(checkAttestation(body()).faults).toEqual([]);
    expect(checkAttestation(body([sb.drawn[3]!], { outcome: "not-yet", reasons: [OVER_PLAN_REASON] })).faults).toEqual([]);
  });

  test("signed by both, it verifies — the seal, the stamp, the blocks, the draw recomputed — at the test's floor, which the report names", async () => {
    const r = await verifyAttestationRecord(await signRecord(body(), asker, approver), floor);
    expect(r.problems).toEqual([]);
    expect(r.ok).toBe(true);
    expect(r.batch?.drawn).toEqual(sb.drawn);
    expect(r.batch?.sealDigest).toBe(sb.sealDigest);
    expect(r.batch?.stampHeight).toBe(900_000);
    expect(r.batch?.blocksStand).toBe(true);
    expect(r.notChecked.some((n) => n.includes(`floor of ${TEST_FLOOR} bits`))).toBe(true);
    expect(r.notChecked.some((n) => n.includes("Bitcoin's own chain"))).toBe(true);
    expect(r.notChecked.some((n) => n.includes("sealed no other version"))).toBe(true);
    expect(r.notChecked.some((n) => n.includes("--batch"))).toBe(true);
  });

  test("at the default floor of 76 bits the synthetic chain is refused: a header mined cheaply draws nothing", async () => {
    const r = await verifyAttestationRecord(await signRecord(body(), asker, approver));
    expect(r.ok).toBe(false);
    expect(codes(r.problems)).toContain("BATCH_DRAW");
    expect(r.problems.find((p) => p.code === "BATCH_DRAW")!.message).toContain(`less than ${SEED_MIN_WORK_BITS} bits of work`);
    // The draw is still recomputed from the last header given, so a reader sees it — and is told it does not count.
    expect(r.batch?.drawn).toEqual(sb.drawn);
    expect(r.batch?.blocksStand).toBe(false);
  });

  test("a position found short and drawn may still be accepted, under a plan that accepts one — that item is not covered", async () => {
    const one = await sampledBatch({ accept: 1, sample: 45 });
    const b = receiptOf(asker, approver, batchOf(one, [one.drawn[0]!]), one.sealDigest);
    const r = await verifyAttestationRecord(await signRecord(b, asker, approver), floor);
    expect(r.problems).toEqual([]);
  });

  test("one signature is a request, not a record", async () => {
    const r = await verifyAttestationRecord(await signRecord(body(), asker), floor);
    expect(codes(r.problems)).toContain("COUNTERPARTY_SIGNATURE");
  });
});

describe("a census: every item checked", () => {
  test("carries no draw, stamp or blocks; its bound is the count found; it verifies at the default floor", async () => {
    const ds = sb.digests.slice(0, 40);
    const tree = await itemTree(sb.salt, ds);
    const seal: BatchSeal = { format: "kash-batch-seal/1", root: tree.root, size: 40, plan: { sample: 40, accept: 1, alpha: { num: 1, den: 20 }, limit: limitOf({ size: 40, sample: 40, accept: 1, alpha: { num: 1, den: 20 } }) } };
    expect(seal.plan.limit).toBe(1);
    const digest = await sealDigestOf(seal);
    const b: AttestationBody = receiptOf(asker, approver, { seal, found: [12], bound: 1 }, digest);
    const r = await verifyAttestationRecord(await signRecord(b, asker, approver));
    expect(r.problems).toEqual([]);
    expect(r.batch?.census).toBe(true);
    expect(r.batch?.drawn).toBeNull();
    expect(checkAttestation({ ...b, batch: { ...b.batch!, bound: 2 } }).faults.map((f) => f.code)).toContain("BATCH_BOUND");
  });
});

describe("the refusals", () => {
  test("BATCH_KIND — a batch rides only on a receipt", () => {
    const f = checkAttestation(body([], { kind: "assurance", outcome: "accepted" })).faults;
    expect(codes(f)).toContain("BATCH_KIND");
  });

  test("BATCH_REFERENCE — the reference is the seal: an artefact, and its digest", async () => {
    expect(codes(checkAttestation(body([], { reference: { kind: "agreement", sha256: sb.sealDigest } })).faults)).toContain("BATCH_REFERENCE");
    const r = await verifyAttestationRecord(await signRecord(body([], { reference: { kind: "artefact", sha256: "ab".repeat(32) } }), asker, approver), floor);
    expect(codes(r.problems)).toContain("BATCH_REFERENCE");
  });

  test("BATCH_BY_A_PERSON — an organisation's own key, grade 3, or an agent's mandate answers for no batch", async () => {
    expect(codes(checkAttestation(body([], { counterparty: "did:web:client.example", grade: 3 })).faults)).toContain("BATCH_BY_A_PERSON");
    expect(codes(checkAttestation(body([], { grade: 3 })).faults)).toContain("BATCH_BY_A_PERSON");
    // The client company's agent signs under the company's mandate: refused once the mandate is presented.
    const company = await party();
    const agent = await party();
    const mandate: MandateBody = {
      id: `${company.did}/mandate/batch-agent`,
      principal: company.did,
      delegate: { key: agent.did, kind: "agent" },
      scope: { kinds: ["receipt"], outcomes: ["accepted", "not-yet"] },
      dates: { from: "2026-11-01T00:00:00Z", until: "2027-10-31T00:00:00Z" },
      credentialStatus: { type: "BitstringStatusListEntry", statusPurpose: "revocation", statusListIndex: "7", statusListCredential: "https://client.example/status/1" },
      practice: true,
    };
    const menv = await signEnvelope(mandate, MANDATE_DST, company, { canonical: true });
    const hash = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", canonicalizeBytes(mandate) as unknown as BufferSource)));
    const b = body([], { counterparty: company.did, counterpartyMandate: { id: mandate.id, hash } });
    const r = await verifyAttestationRecord(await signRecord(b, asker, agent), { ...floor, counterpartyMandate: menv });
    expect(codes(r.problems)).toContain("BATCH_BY_A_PERSON");
    expect(r.problems.find((p) => p.code === "BATCH_BY_A_PERSON")!.message).toContain("never a rule or a model");
    // The same under a seat's mandate is a person answering.
    const seatMandate: MandateBody = { ...mandate, id: `${company.did}/mandate/batch-seat`, delegate: { key: agent.did, kind: "seat" } };
    const senv = await signEnvelope(seatMandate, MANDATE_DST, company, { canonical: true });
    const shash = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", canonicalizeBytes(seatMandate) as unknown as BufferSource)));
    const sbody = body([], { counterparty: company.did, counterpartyMandate: { id: seatMandate.id, hash: shash } });
    const sr = await verifyAttestationRecord(await signRecord(sbody, asker, agent), { ...floor, counterpartyMandate: senv });
    expect(codes(sr.problems)).not.toContain("BATCH_BY_A_PERSON");
  });

  test("BATCH_LIMITS — a plan that accepts as many as it draws, a chance above 1 in 2, a draw larger than the batch", () => {
    expect(codes(checkAttestation(withSeal({ plan: { ...sb.seal.plan, accept: 30 } })).faults)).toContain("BATCH_LIMITS");
    expect(codes(checkAttestation(withSeal({ plan: { ...sb.seal.plan, alpha: { num: 3, den: 4 } } })).faults)).toContain("BATCH_LIMITS");
    expect(codes(checkAttestation(withSeal({ plan: { ...sb.seal.plan, sample: 300 } })).faults)).toContain("BATCH_LIMITS");
  });

  test("BATCH_CENSUS — a census with a draw or a coinbase; a sampled batch without its stamp, blocks or coinbase", () => {
    expect(codes(checkAttestation(withSeal({ plan: { ...sb.seal.plan, sample: 200, limit: 0 } })).faults)).toContain("BATCH_CENSUS");
    const { stamp: _s, ...noStamp } = batchOf(sb, []);
    expect(codes(checkAttestation({ ...body(), batch: noStamp }).faults)).toContain("BATCH_CENSUS");
    const { blocks: _b, ...noBlocks } = batchOf(sb, []);
    expect(codes(checkAttestation({ ...body(), batch: noBlocks }).faults)).toContain("BATCH_CENSUS");
    // PY-5r: the draw block's coinbase is what names its height.
    const { coinbase: _c, ...noCoinbase } = batchOf(sb, []);
    expect(codes(checkAttestation({ ...body(), batch: noCoinbase }).faults)).toContain("BATCH_CENSUS");
    const census: Batch = { seal: { ...sb.seal, size: 30, plan: { ...sb.seal.plan, sample: 30, limit: 0 } }, coinbase: sb.draw.coinbase, found: [], bound: 0 };
    const { draw: _d, ...noDraw } = census.seal;
    expect(codes(checkAttestation({ ...body(), batch: { ...census, seal: noDraw } }).faults)).toContain("BATCH_CENSUS");
  });

  test("BATCH_FOUND — out of order, repeated, outside the batch; and, once the draw is recomputed, a position that was not drawn", async () => {
    const [a, b] = [sb.drawn[0]!, sb.drawn[1]!];
    const notYet = { outcome: "not-yet" as const, reasons: [OVER_PLAN_REASON] };
    expect(codes(checkAttestation(body([b, a], notYet)).faults)).toContain("BATCH_FOUND");
    expect(codes(checkAttestation(body([a, a], notYet)).faults)).toContain("BATCH_FOUND");
    expect(codes(checkAttestation(body([200], notYet)).faults)).not.toContain("SHAPE");
    expect(codes(checkAttestation(body([200], notYet)).faults)).toContain("BATCH_FOUND");
    const undrawn = Array.from({ length: 200 }, (_, i) => i).find((i) => !sb.drawn.includes(i))!;
    const r = await verifyAttestationRecord(await signRecord(body([undrawn], notYet), asker, approver), floor);
    expect(codes(r.problems)).toContain("BATCH_FOUND");
    expect(r.problems.find((p) => p.code === "BATCH_FOUND")!.message).toContain(`not drawn: ${undrawn}`);
  });

  test("BATCH_OVER_PLAN — more found short than the plan accepts is only a not yet, and says so; never accepted", () => {
    const f = checkAttestation(body([sb.drawn[0]!])).faults;
    expect(codes(f)).toContain("BATCH_OVER_PLAN");
    expect(f.find((x) => x.code === "BATCH_OVER_PLAN")!.message).toContain("never an automatic no");
    expect(codes(checkAttestation(body([sb.drawn[0]!], { outcome: "not-yet", reasons: ["wrong-dialect"] })).faults)).toContain("BATCH_OVER_PLAN");
    expect(codes(checkAttestation(body([sb.drawn[0]!], { outcome: "not-yet", reasons: [OVER_PLAN_REASON, "wrong-dialect"] })).faults)).not.toContain("BATCH_OVER_PLAN");
  });

  // PY-5r: the converse. Within the plan the reason says what is not so, in a record both sides sign.
  test("BATCH_OVER_PLAN — a not yet within the plan does not give the over-the-plan reason", () => {
    const f = checkAttestation(body([], { outcome: "not-yet", reasons: [OVER_PLAN_REASON] })).faults;
    expect(codes(f)).toContain("BATCH_OVER_PLAN");
    expect(f.find((x) => x.code === "BATCH_OVER_PLAN")!.message).toContain("within the plan");
    expect(codes(checkAttestation(body([], { outcome: "not-yet", reasons: ["wrong-dialect"] })).faults)).not.toContain("BATCH_OVER_PLAN");
  });

  test("BATCH_PLAN and BATCH_BOUND — a limit or a bound one off, either way, is refused, saying which way", () => {
    const L = sb.seal.plan.limit;
    for (const [limit, way] of [[L - 1, "too low"], [L + 1, "too high"]] as const) {
      const f = checkAttestation(withSeal({ plan: { ...sb.seal.plan, limit } })).faults;
      expect(codes(f)).toContain("BATCH_PLAN");
      expect(f.find((x) => x.code === "BATCH_PLAN")!.message).toContain(`${limit}, is ${way}`);
    }
    const B = boundOf({ size: 200, sample: 30, found: 0, alpha: { num: 1, den: 20 } });
    for (const [bound, way] of [[B - 1, "too low"], [B + 1, "too high"]] as const) {
      const f = checkAttestation(withBatch({ bound })).faults;
      expect(codes(f)).toContain("BATCH_BOUND");
      expect(f.find((x) => x.code === "BATCH_BOUND")!.message).toContain(`${bound}, is ${way}`);
    }
  });

  // PY-5r: a checker certifies a stated figure with two evaluations and never searches (batch.md §4). The faults'
  // words searched for the exact figure — about two minutes each at the caps, so a record shaped to be wrong held a
  // checker for four (measured 2026-11-26).
  test("a batch shaped to be slow — the caps, half the draw found short, a wrong limit and a wrong bound — is refused quickly, never searched", () => {
    const alpha = { num: 1, den: 20 };
    const seal: BatchSeal = { ...sb.seal, size: 1_000_000, plan: { sample: 10_000, accept: 5000, alpha, limit: 12_345 } };
    const found = Array.from({ length: 5000 }, (_, i) => i * 7);
    const t = performance.now();
    const f = checkAttestation(withBatch({ seal, found, bound: 6000 })).faults;
    expect(codes(f)).toContain("BATCH_PLAN");
    expect(codes(f)).toContain("BATCH_BOUND");
    expect(performance.now() - t).toBeLessThan(3000);
  }, 30_000);

  test("BATCH_DRAW — a stamp over another digest, a stamp that reaches no block below the draw, broken links, a draw height the blocks do not reach", async () => {
    const check = async (b: AttestationBody) => verifyAttestationRecord(await signRecord(b, asker, approver), floor);
    // A stamp over another seal's digest.
    const other = await syntheticDraw("cd".repeat(32), { stampHeight: 900_000, gap: 3 });
    let r = await check(withBatch({ stamp: other.stamp }));
    expect(r.problems.find((p) => p.code === "BATCH_DRAW")?.message).toContain("not over this seal's digest");
    // The stamp's Bitcoin attestation names another height than the blocks give it.
    const late = await syntheticDraw(sb.sealDigest, { stampHeight: 900_000, gap: 3, attestAt: 900_003 });
    r = await check(withBatch({ stamp: late.stamp, blocks: late.blocks }));
    expect(r.problems.find((p) => p.code === "BATCH_DRAW")?.message).toContain("no Bitcoin attestation at block 900000");
    // A header that does not name the one before it.
    const broken = [...sb.draw.blocks];
    broken[2] = sb.draw.blocks[1]!;
    r = await check(withBatch({ blocks: broken }));
    expect(r.problems.find((p) => p.code === "BATCH_DRAW")?.message).toContain("does not name block");
    // The seal names a height the blocks do not reach: the stamp's height then misses.
    r = await check(withSeal({ draw: { source: "bitcoin/1", height: 900_004 } }));
    expect(codes(r.problems)).toContain("BATCH_DRAW");
  });

  // PY-5r: a block header does not carry its height, and the stamp's Bitcoin attestation names one in a number
  // nothing signs. The checker read the draw block's height from the two together, so an asker who edited that
  // number and handed in more headers moved the draw to any of the next 144 real blocks — and chose among them.
  test("BATCH_DRAW — a stamp whose height was edited, with more headers given, cannot move the draw to a later block", async () => {
    // The chain: the stamp lands in block 900,000 and the seal names 900,003. The asker gives eight headers, not four,
    // and edits the stamp to say 899,996 — so that block 900,007 would pass as block 900,003.
    const chain = await syntheticDraw(sb.sealDigest, { stampHeight: 900_000, gap: 7, attestAt: 900_003 - 7 });
    expect(chain.blocks.slice(0, 4)).toEqual([...sb.draw.blocks]);
    const check = async (b: AttestationBody) => verifyAttestationRecord(await signRecord(b, asker, approver), floor);
    // With block 900,007's own first transaction, which names its height: refused.
    let r = await check(withBatch({ stamp: chain.stamp, blocks: chain.blocks, coinbase: chain.coinbase }));
    expect(r.ok).toBe(false);
    expect(r.problems.find((p) => p.code === "BATCH_DRAW")?.message).toContain("names height 900007, not 900003");
    // With block 900,003's, which is not the last header's: refused.
    r = await check(withBatch({ stamp: chain.stamp, blocks: chain.blocks, coinbase: sb.draw.coinbase }));
    expect(r.ok).toBe(false);
    expect(r.problems.find((p) => p.code === "BATCH_DRAW")?.message).toContain("does not reach the draw block's Merkle root");
    // The honest record — four headers, the stamp as the calendar wrote it — still stands.
    r = await check(body());
    expect(r.problems).toEqual([]);
  });

  test("BATCH_DRAW — nor to an earlier block; and with no coinbase at all the draw block's height is not shown", async () => {
    // The seal names 900,003. The asker gives three headers, to block 900,002, and edits the stamp to say 900,001.
    const early = await syntheticDraw(sb.sealDigest, { stampHeight: 900_000, gap: 2, attestAt: 900_001 });
    const r = await verifyAttestationRecord(await signRecord(withBatch({ stamp: early.stamp, blocks: early.blocks, coinbase: early.coinbase }), asker, approver), floor);
    expect(r.problems.find((p) => p.code === "BATCH_DRAW")?.message).toContain("names height 900002, not 900003");
    const bare = await checkDrawBlocks({ stamp: sb.draw.stamp, sealDigest: sb.sealDigest, blocks: sb.draw.blocks, drawHeight: 900_003, minWorkBits: TEST_FLOOR });
    expect(bare.ok).toBe(false);
    expect(bare.problems.join(" ")).toContain("the draw block's height is not shown");
    const whole = await checkDrawBlocks({ stamp: sb.draw.stamp, sealDigest: sb.sealDigest, blocks: sb.draw.blocks, coinbase: sb.draw.coinbase, drawHeight: 900_003, minWorkBits: TEST_FLOOR });
    expect(whole.problems).toEqual([]);
  });

  test("the shape: one header is no draw; more than a day of blocks is refused unread", async () => {
    expect(codes(checkAttestation(withBatch({ blocks: [sb.draw.blocks[0]!] })).faults)).toContain("SHAPE");
    expect(codes(checkAttestation(withBatch({ blocks: Array.from({ length: 146 }, () => sb.draw.blocks[0]!) })).faults)).toContain("SHAPE");
  });
});

describe("what stays as it was", () => {
  test("the 1.0.0 shape is frozen and refuses a batch; 1.1.0 reads it", () => {
    expect(validate(KASH_ATTESTATION_BODY_SCHEMA, body()).ok).toBe(false);
    expect(validate(KASH_ATTESTATION_1_1_BODY_SCHEMA, body()).ok).toBe(true);
  });

  test("every 1.0.0 conformance case reaches the same result under 1.1.0's reader", () => {
    const file = JSON.parse(readFileSync(join(import.meta.dir, "..", "..", "..", "specs", "attestation", "tck", "kash.attestation@1.0.0", "cases.json"), "utf8")) as { cases: { name: string; body: unknown; valid: boolean; faults: string[] }[] };
    for (const c of file.cases) {
      const r = checkAttestation(c.body);
      expect(r.ok).toBe(c.valid);
      const got: string[] = [...new Set(r.faults.map((f) => f.code as string))].sort();
      expect(got).toEqual([...new Set(c.faults)].sort());
    }
  });

  // PY-5r: the file was checked only when it was written, so nothing would have noticed the code moving away from it.
  test("kash.attestation@1.1.0's conformance file: every case reaches its stated result, and every rule that needs no hashing is exercised", () => {
    const file = JSON.parse(readFileSync(join(import.meta.dir, "..", "..", "..", "specs", "attestation", "tck", "kash.attestation@1.1.0", "cases.json"), "utf8")) as { lexicon: string; cases: { name: string; body: unknown; valid: boolean; faults?: string[] }[] };
    expect(file.lexicon).toBe("kash.attestation@1.1.0");
    for (const c of file.cases) {
      const r = checkAttestation(c.body);
      expect({ name: c.name, ok: r.ok, faults: [...new Set(r.faults.map((f) => f.code as string))].sort() }).toEqual({ name: c.name, ok: c.valid, faults: [...new Set(c.faults ?? [])].sort() });
    }
    const used = new Set(file.cases.flatMap((c) => c.faults ?? []));
    for (const code of ["SHAPE", "BATCH_KIND", "BATCH_REFERENCE", "BATCH_BY_A_PERSON", "BATCH_LIMITS", "BATCH_CENSUS", "BATCH_FOUND", "BATCH_OVER_PLAN", "BATCH_PLAN", "BATCH_BOUND"]) expect(used.has(code)).toBe(true);
    expect(file.cases.some((c) => c.name.includes("coinbase"))).toBe(true);
  });

  test("a batch record gets no copy: its holder is its issuer, and its size would make a class of one", async () => {
    const env = await signRecord(body(), asker, approver);
    await expect(copyClaimsOf(env, { iatUnix: 1_795_000_000 }, floor)).rejects.toThrow(/no copy in this version/);
  });
});

describe("items swapped after the draw", () => {
  test("a drawn item replaced after sealing fails its path and the items file", async () => {
    const tree = await itemTree(sb.salt, sb.digests);
    const p = sb.drawn[0]!;
    const swapped = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("SAMPLE a better item"))));
    expect(await verifyItemPath({ size: 200, salt: sb.salt, root: sb.seal.root, position: p, digest: tree.digestAt(p), path: tree.path(p) })).toBe(true);
    expect(await verifyItemPath({ size: 200, salt: sb.salt, root: sb.seal.root, position: p, digest: swapped, path: tree.path(p) })).toBe(false);
    const ds = sb.digests.map((d) => (d === tree.digestAt(p) ? swapped : d));
    expect((await verifyBatchItems(batchOf(sb, []), { format: "kashscript-batch-items/1", salt: sb.salt, digests: ds })).ok).toBe(false);
  });
});

describe("the work floor against real Bitcoin headers", () => {
  test("this month's blocks pass 76 bits; the synthetic chain does not; the floor's date is in the record of the measurement", async () => {
    const { checkBitcoinHeader } = await import("../src/witness/ots");
    for (const h of [974281, 974295, 974322]) {
      const v = JSON.parse(readFileSync(join(import.meta.dir, "vectors", "witness", `header-${h}.json`), "utf8")) as { header: string; hash: string };
      const checked = await checkBitcoinHeader(v.header, SEED_MIN_WORK_BITS);
      expect(checked.hashHex).toBe(v.hash);
    }
    await expect(checkBitcoinHeader(sb.draw.blocks[0]!, SEED_MIN_WORK_BITS)).rejects.toThrow(/less than 76 bits of work/);
  });
});

describe("the worked examples (generated once by scripts/batch-example.ts)", () => {
  const EXAMPLES = join(import.meta.dir, "..", "..", "..", "specs", "attestation", "examples");
  const read = <T>(...p: string[]): T => JSON.parse(readFileSync(join(EXAMPLES, ...p), "utf8")) as T;

  test("the census: its body is the record's canonical payload, the record verifies at the default floor, its items make the root, its words are the ones written", async () => {
    const b = read<AttestationBody>("receipt-batch-all", "body.json");
    const record = read<Parameters<typeof verifyAttestationRecord>[0]>("receipt-batch-all", "record.dsse.json");
    expect(Buffer.from(record.payload, "base64").equals(Buffer.from(canonicalizeBytes(b)))).toBe(true);
    const r = await verifyAttestationRecord(record);
    expect(r.problems).toEqual([]);
    expect(r.batch?.census).toBe(true);
    const items = read<{ format: "kashscript-batch-items/1"; salt: string; digests: string[] }>("receipt-batch-all", "items.json");
    expect((await verifyBatchItems(b.batch!, items)).ok).toBe(true);
    const ctx = read<{ words: string[] }>("receipt-batch-all", "context.json");
    const { batchWords } = await import("../src/batch");
    const w = batchWords(b);
    expect([...w.lines, ...w.doesNotProve]).toEqual(ctx.words);
    expect(JSON.stringify(record)).not.toMatch(/"(?:seed|secretKey|privateKey|d)"\s*:/);
  });
});

void hexToBytes;
void bytesToBase64;
