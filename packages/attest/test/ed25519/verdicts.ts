/**
 * One verdict per Ed25519 edge case, computed by attest's own raw verifier
 * (`verifyRaw`: the pre-check of identity-core's acceptance rule, then
 * WebCrypto). The same function runs under bun (test/ed25519-vectors.test.ts),
 * node (./node-entry.ts, bundled) and a browser (test/browser/entry.ts), and
 * each run is held to test/vectors/ed25519/expected.v1.json — so the three
 * runtimes are shown to answer alike, case by case.
 */

import { verifyRaw } from "../../src/ed25519";

export interface WycheproofFile {
  readonly testGroups: readonly {
    readonly publicKey: { readonly pk: string };
    readonly tests: readonly { readonly tcId: number; readonly msg: string; readonly sig: string; readonly result: string; readonly flags: readonly string[] }[];
  }[];
}
export interface SpeccheckCase {
  readonly message: string;
  readonly pub_key: string;
  readonly signature: string;
}
export interface GeneratedFile {
  readonly cases: readonly { readonly name: string; readonly pk: string; readonly msg: string; readonly sig: string }[];
}
export interface Ed25519VectorSet {
  readonly wycheproof: WycheproofFile;
  readonly speccheck: readonly SpeccheckCase[];
  readonly generated: GeneratedFile;
}
export interface Ed25519Verdicts {
  readonly wycheproof: Record<string, boolean>;
  readonly speccheck: readonly boolean[];
  readonly generated: Record<string, boolean>;
}

/** Hex to bytes without Buffer, so the same code runs in a browser. */
export function hexBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export async function ed25519Verdicts(v: Ed25519VectorSet): Promise<Ed25519Verdicts> {
  const wycheproof: Record<string, boolean> = {};
  for (const g of v.wycheproof.testGroups) {
    const pk = hexBytes(g.publicKey.pk);
    for (const t of g.tests) wycheproof[String(t.tcId)] = await verifyRaw(hexBytes(t.sig), hexBytes(t.msg), pk);
  }
  const speccheck: boolean[] = [];
  for (const c of v.speccheck) speccheck.push(await verifyRaw(hexBytes(c.signature), hexBytes(c.message), hexBytes(c.pub_key)));
  const generated: Record<string, boolean> = {};
  for (const c of v.generated.cases) generated[c.name] = await verifyRaw(hexBytes(c.sig), hexBytes(c.msg), hexBytes(c.pk));
  return { wycheproof, speccheck, generated };
}
