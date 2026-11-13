/**
 * Ed25519 edge-case vectors (AU-3, A7-07) — the pinned verdicts, generated ONCE.
 *
 *   bun packages/attest/test/vectors/ed25519/gen-ed25519-vectors.ts
 *
 * Writes two files beside the upstream sets it reads:
 *
 *   • expected.v1.json  — one verdict per case, from the rule: a Wycheproof `valid`
 *     case verifies, an `invalid` one does not, an `acceptable` one verifies only
 *     when its key is of mixed order (`MixedOrderPublicKey`) and not when it is of
 *     small order (`SmallOrderPublicKey`); of ed25519-speccheck's twelve cases only
 *     case 3 verifies (mixed-order A and R under the cofactorless equation); and each
 *     of attest's own cases below as the pre-check names it.
 *   • generated.v1.json — attest's own cases: one honest signature, its S plus L,
 *     S = L, a canonical but wrong S, R and A at each of the eight small-order
 *     points, and non-canonical encodings of R and A. The honest key is fresh and
 *     thrown away; never regenerate.
 *
 * `webcryptoAlone` records what this machine's WebCrypto said with no pre-check,
 * for the README only — it is the engine's answer, not the rule's.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import {
  addEd25519Points,
  decodeEd25519Point,
  ED25519_ORDER_L,
  ed25519LittleEndianToBigInt,
  ed25519Precheck,
  encodeEd25519Point,
  generateKeyPair,
  type Ed25519Point,
} from "@kashscript/identity-core";
import { signRaw } from "../../../src/ed25519";
import { hexBytes, type SpeccheckCase, type WycheproofFile } from "../../ed25519/verdicts";

const DIR = import.meta.dir;
const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
const enc = new TextEncoder();

function littleEndian(v: bigint): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

async function webcryptoAlone(pk: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean | "throws"> {
  try {
    const key = await crypto.subtle.importKey("raw", pk as unknown as BufferSource, { name: "Ed25519" }, false, ["verify"]);
    return await crypto.subtle.verify({ name: "Ed25519" }, key, sig as unknown as BufferSource, msg as unknown as BufferSource);
  } catch {
    return "throws";
  }
}

/** The eight torsion points, from a point of order 8 (ed25519-speccheck's case-0 key). */
function torsion(): Ed25519Point[] {
  const t = decodeEd25519Point(hexBytes("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"))!;
  const out: Ed25519Point[] = [];
  let p: Ed25519Point = { x: 0n, y: 1n };
  for (let k = 0; k < 8; k++) {
    out.push(p);
    p = addEd25519Points(p, t);
  }
  return out;
}

async function main(): Promise<void> {
  const wy = JSON.parse(readFileSync(join(DIR, "wycheproof-ed25519_test.json"), "utf8")) as WycheproofFile;
  const sc = JSON.parse(readFileSync(join(DIR, "speccheck-cases.json"), "utf8")) as SpeccheckCase[];

  const kp = await generateKeyPair();
  const msg = enc.encode("attest ed25519 vector — the rule, not the engine, decides");
  const honest = await signRaw(msg, kp.privateKey, kp.publicKey);
  const r = honest.subarray(0, 32);
  const s = ed25519LittleEndianToBigInt(honest.subarray(32));
  const withS = (v: bigint): Uint8Array => {
    const out = honest.slice();
    out.set(littleEndian(v), 32);
    return out;
  };
  const withR = (rBytes: Uint8Array): Uint8Array => {
    const out = honest.slice();
    out.set(rBytes, 0);
    return out;
  };
  const zeros = new Uint8Array(64);
  zeros[0] = 1; // R = identity, S = 0: [0]B = O = R + k·A for every A of small order

  const nonCanonical = {
    pPlusOne: (() => { const b = new Uint8Array(32).fill(0xff); b[0] = 0xee; b[31] = 0x7f; return b; })(), // y = p + 1 ≡ 1, non-canonical
    p: (() => { const b = new Uint8Array(32).fill(0xff); b[0] = 0xed; b[31] = 0x7f; return b; })(), // y = p ≡ 0, non-canonical
    identitySigned: (() => { const b = new Uint8Array(32); b[0] = 1; b[31] = 0x80; return b; })(), // x = 0 with the sign bit
    notOnCurve: littleEndian(2n), // y = 2 has no square root for x
  };

  const cases: { name: string; pk: string; msg: string; sig: string; precheck: string; webcryptoAlone: boolean | "throws"; note: string }[] = [];
  const add = async (name: string, pk: Uint8Array, sig: Uint8Array, note: string): Promise<void> => {
    cases.push({ name, pk: hex(pk), msg: hex(msg), sig: hex(sig), precheck: ed25519Precheck(pk, sig), webcryptoAlone: await webcryptoAlone(pk, msg, sig), note });
  };

  await add("honest", kp.publicKey, honest, "a fresh key's signature over the message");
  await add("s-plus-l", kp.publicKey, withS(s + ED25519_ORDER_L), "the honest S plus L — the malleated twin, non-canonical");
  await add("s-equals-l", kp.publicKey, withS(ED25519_ORDER_L), "S = L exactly");
  await add("s-canonical-wrong", kp.publicKey, withS(ED25519_ORDER_L - 1n), "a canonical S that is not the signature — refused by the equation, not the rule");
  await add("r-non-canonical-p-plus-one", kp.publicKey, withR(nonCanonical.pPlusOne), "R encoded as y = p + 1");
  await add("r-non-canonical-p", kp.publicKey, withR(nonCanonical.p), "R encoded as y = p");
  await add("r-identity-with-sign", kp.publicKey, withR(nonCanonical.identitySigned), "R = the identity with the sign bit set");
  await add("r-not-on-curve", kp.publicKey, withR(nonCanonical.notOnCurve), "R with a y that has no x on the curve");
  await add("a-non-canonical-p-plus-one", nonCanonical.pPlusOne, honest, "A encoded as y = p + 1");
  await add("a-non-canonical-p", nonCanonical.p, honest, "A encoded as y = p");
  await add("a-identity-with-sign", nonCanonical.identitySigned, honest, "A = the identity with the sign bit set");
  await add("a-not-on-curve", nonCanonical.notOnCurve, honest, "A with a y that has no x on the curve");
  torsion().forEach((p, i) => void 0);
  const points = torsion();
  for (const [i, p] of points.entries()) {
    const e = encodeEd25519Point(p);
    await add(`r-small-order-${i}`, kp.publicKey, withR(e), `R = torsion point ${i} (${i === 0 ? "the identity" : "small order"})`);
    await add(`a-small-order-${i}-zero-signature`, e, zeros, `A = torsion point ${i} with R = identity and S = 0 — verifies any message under a cofactorless engine that accepts small-order keys`);
  }
  // sanity: the honest case passes the rule, and R is where we think it is
  if (cases[0]!.precheck !== "ok" || hex(r) !== cases[0]!.sig.slice(0, 64)) throw new Error("the honest vector does not pass its own rule");

  const expectedGenerated: Record<string, boolean> = {};
  for (const c of cases) expectedGenerated[c.name] = c.precheck === "ok" && c.webcryptoAlone === true;
  if (expectedGenerated.honest !== true) throw new Error("the honest vector must verify");
  if (expectedGenerated["s-canonical-wrong"] !== false) throw new Error("a wrong S must not verify");

  const expectedWycheproof: Record<string, boolean> = {};
  for (const g of wy.testGroups) {
    for (const t of g.tests) {
      const verdict = t.result === "valid" ? true : t.result === "invalid" ? false : t.flags.includes("MixedOrderPublicKey") && !t.flags.includes("SmallOrderPublicKey");
      expectedWycheproof[String(t.tcId)] = verdict;
    }
  }
  const expectedSpeccheck = sc.map((_, i) => i === 3);

  writeFileSync(join(DIR, "generated.v1.json"), `${JSON.stringify({ note: "attest's own Ed25519 cases (AU-3, A7-07). webcryptoAlone is what one engine said with no pre-check, for the record; expected.v1.json carries the rule's verdict.", message: new TextDecoder().decode(msg), cases }, null, 2)}\n`);
  writeFileSync(
    join(DIR, "expected.v1.json"),
    `${JSON.stringify(
      {
        note: "One verdict per case under the Ed25519 acceptance rule (identity-core/src/ed25519-strict.ts), asserted under bun, node and a browser. Wycheproof: valid → true, invalid → false, acceptable → true only for a mixed-order key. speccheck: only case 3. generated: see generated.v1.json.",
        wycheproof: expectedWycheproof,
        speccheck: expectedSpeccheck,
        generated: expectedGenerated,
      },
      null,
      2,
    )}\n`,
  );
  console.log(`wrote generated.v1.json (${cases.length} cases) and expected.v1.json (${Object.keys(expectedWycheproof).length} wycheproof, ${expectedSpeccheck.length} speccheck)`);
  console.log("webcrypto alone accepted:", cases.filter((c) => c.webcryptoAlone === true && c.precheck !== "ok").map((c) => c.name).join(", ") || "nothing the rule refuses");
}

await main();
